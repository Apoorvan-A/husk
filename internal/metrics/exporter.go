// Package metrics exposes per-container resource usage as Prometheus metrics.
//
// Everything published here is read directly from cgroup control files at scrape
// time. There is no agent inside the container, no sidecar and no polling
// goroutine keeping a cache warm — the kernel is already maintaining these
// counters because it needs them to schedule, and a scrape is just a handful of
// small reads from a virtual filesystem.
//
// That design is why the collector is implemented as a prometheus.Collector
// rather than a set of package-level Gauges updated on a timer. A timer-driven
// exporter has to choose an update interval, and any choice is wrong: too fast
// and it burns CPU on containers nobody is looking at, too slow and the values
// are stale by an unknown amount at scrape time. Collecting on demand makes the
// scrape interval the only interval, which is what an operator expects.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/Apoorvan-A/husk/internal/cgroups"
	"github.com/Apoorvan-A/husk/internal/state"
)

// Labels every series carries. Kept to two: an id and a human-meaningful image
// name. Each additional label multiplies the number of series a Prometheus
// server has to hold in memory, and container ids are already high-cardinality
// enough to be careful with.
var labels = []string{"container", "image"}

type Collector struct {
	states   *state.Store
	cgParent string

	memoryCurrent *prometheus.Desc
	memoryPeak    *prometheus.Desc
	memoryMax     *prometheus.Desc
	oomKills      *prometheus.Desc
	memHighEvents *prometheus.Desc
	swapCurrent   *prometheus.Desc

	cpuUsage      *prometheus.Desc
	cpuThrottled  *prometheus.Desc
	cpuPeriods    *prometheus.Desc
	throttledSecs *prometheus.Desc

	pidsCurrent *prometheus.Desc
	pidsMax     *prometheus.Desc

	ioRead  *prometheus.Desc
	ioWrite *prometheus.Desc

	up *prometheus.Desc
}

func NewCollector(states *state.Store, cgParent string) *Collector {
	d := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc("husk_"+name, help, labels, nil)
	}
	return &Collector{
		states:   states,
		cgParent: cgParent,

		memoryCurrent: d("memory_usage_bytes", "Current memory charged to the container, from memory.current."),
		memoryPeak:    d("memory_peak_bytes", "High-water mark of memory usage, from memory.peak."),
		memoryMax:     d("memory_limit_bytes", "Hard memory limit from memory.max. Absent when unlimited."),
		oomKills:      d("oom_kills_total", "Processes killed by the cgroup OOM killer, from memory.events oom_kill."),
		memHighEvents: d("memory_high_events_total", "Times allocation was throttled at memory.high, from memory.events high."),
		// Swap usage is worth a series of its own: a container quietly paging
		// rather than being OOM-killed looks healthy on a memory-usage graph
		// while degrading every other workload on the same disk.
		swapCurrent: d("swap_usage_bytes", "Swap in use by the container, from memory.swap.current."),

		// CPU time is exported in seconds even though the kernel reports
		// microseconds: Prometheus convention is base units, and every dashboard
		// and recording rule in the ecosystem assumes it.
		cpuUsage:      d("cpu_usage_seconds_total", "Cumulative CPU time consumed, from cpu.stat usage_usec."),
		cpuThrottled:  d("cpu_throttled_periods_total", "Scheduling periods in which the container hit its quota, from cpu.stat nr_throttled."),
		cpuPeriods:    d("cpu_periods_total", "Scheduling periods elapsed, from cpu.stat nr_periods."),
		throttledSecs: d("cpu_throttled_seconds_total", "Time spent descheduled at the quota boundary, from cpu.stat throttled_usec."),

		pidsCurrent: d("pids_current", "Processes and threads in the container, from pids.current."),
		pidsMax:     d("pids_limit", "Process limit from pids.max. Absent when unlimited."),

		ioRead:  d("io_read_bytes_total", "Bytes read from block devices, summed across devices from io.stat."),
		ioWrite: d("io_write_bytes_total", "Bytes written to block devices, summed across devices from io.stat."),

		up: d("container_up", "1 when the container's init process is alive, 0 otherwise."),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs() {
		ch <- d
	}
}

func (c *Collector) descs() []*prometheus.Desc {
	return []*prometheus.Desc{
		c.memoryCurrent, c.memoryPeak, c.memoryMax, c.oomKills, c.memHighEvents, c.swapCurrent,
		c.cpuUsage, c.cpuThrottled, c.cpuPeriods, c.throttledSecs,
		c.pidsCurrent, c.pidsMax, c.ioRead, c.ioWrite, c.up,
	}
}

// Collect samples every known container.
//
// A container that disappears between List and Stats is skipped rather than
// reported as an error. That race is not exceptional — containers exit while
// being scraped all the time — and failing the whole scrape because one series
// vanished would lose the other containers' data too.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	states, err := c.states.List()
	if err != nil {
		return
	}

	for _, st := range states {
		image := st.Image
		if image == "" {
			image = "none"
		}

		alive := 0.0
		if st.Status == state.StatusRunning || st.Status == state.StatusCreated {
			alive = 1.0
		}
		c.gauge(ch, c.up, alive, st.ID, image)

		cg := cgroups.New(st.ID, c.cgParent)
		s, err := cg.Stats()
		if err != nil {
			continue
		}

		c.gauge(ch, c.memoryCurrent, float64(s.MemoryCurrent), st.ID, image)
		c.gauge(ch, c.memoryPeak, float64(s.MemoryPeak), st.ID, image)
		if s.MemoryMax >= 0 {
			c.gauge(ch, c.memoryMax, float64(s.MemoryMax), st.ID, image)
		}
		c.gauge(ch, c.swapCurrent, float64(s.SwapCurrent), st.ID, image)
		c.counter(ch, c.oomKills, float64(s.OOMKills), st.ID, image)
		c.counter(ch, c.memHighEvents, float64(s.HighEvents), st.ID, image)

		c.counter(ch, c.cpuUsage, float64(s.CPUUsageUsec)/1e6, st.ID, image)
		c.counter(ch, c.cpuThrottled, float64(s.NrThrottled), st.ID, image)
		c.counter(ch, c.cpuPeriods, float64(s.NrPeriods), st.ID, image)
		c.counter(ch, c.throttledSecs, float64(s.ThrottledUsec)/1e6, st.ID, image)

		c.gauge(ch, c.pidsCurrent, float64(s.PidsCurrent), st.ID, image)
		if s.PidsMax >= 0 {
			c.gauge(ch, c.pidsMax, float64(s.PidsMax), st.ID, image)
		}

		c.counter(ch, c.ioRead, float64(s.IOReadBytes), st.ID, image)
		c.counter(ch, c.ioWrite, float64(s.IOWriteBytes), st.ID, image)
	}
}

// The gauge/counter distinction is not cosmetic. rate() and increase() assume a
// counter only ever grows and treat any decrease as a reset, extrapolating
// across it. Publishing a fluctuating value such as memory.current as a counter
// makes every dip look like a container restart and produces nonsense rates.
func (c *Collector) gauge(ch chan<- prometheus.Metric, d *prometheus.Desc, v float64, lv ...string) {
	ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, lv...)
}

func (c *Collector) counter(ch chan<- prometheus.Metric, d *prometheus.Desc, v float64, lv ...string) {
	ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, lv...)
}
