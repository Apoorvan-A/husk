package cgroups

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Stats is one sample of a container's resource usage, read straight from the
// cgroup control files. There is no daemon, no agent inside the container and no
// instrumentation of the workload: the kernel is already accounting all of this
// for its own scheduling decisions, and these files are that accounting made
// readable.
type Stats struct {
	// Memory, in bytes.
	MemoryCurrent int64
	MemoryPeak    int64
	MemoryMax     int64 // -1 when unlimited
	MemoryHigh    int64 // -1 when unlimited
	SwapCurrent   int64
	SwapMax       int64 // -1 when unlimited

	// memory.events counters. OOMKills is the one that matters for alerting:
	// OOM counts allocations that entered the OOM path, while OOMKills counts
	// processes actually killed. A container can register OOM events and
	// recover; an increment of OOMKills means something died.
	OOM        int64
	OOMKills   int64
	HighEvents int64 // times memory.high was breached and reclaim was forced
	MaxEvents  int64 // times allocation was blocked at memory.max

	// cpu.stat, in microseconds.
	CPUUsageUsec  int64
	CPUUserUsec   int64
	CPUSystemUsec int64

	// Throttling. NrThrottled over NrPeriods is the throttle *ratio*, which is
	// the number worth graphing — the absolute count grows forever and says
	// nothing about current health, whereas the ratio is directly comparable
	// across containers and over time.
	NrPeriods     int64
	NrThrottled   int64
	ThrottledUsec int64

	PidsCurrent int64
	PidsMax     int64 // -1 when unlimited

	// io.stat, summed across every block device.
	IOReadBytes  int64
	IOWriteBytes int64
	IOReadIOs    int64
	IOWriteIOs   int64
}

// ThrottleRatio is the fraction of scheduling periods in which the container hit
// its CPU quota and was descheduled. Anything sustained above a few percent on a
// latency-sensitive service is worth investigating before the CPU average is.
func (s Stats) ThrottleRatio() float64 {
	if s.NrPeriods == 0 {
		return 0
	}
	return float64(s.NrThrottled) / float64(s.NrPeriods)
}

// Stats samples the container's cgroup.
func (m *Manager) Stats() (Stats, error) {
	var s Stats
	dir := m.Path()

	if _, err := os.Stat(dir); err != nil {
		return s, fmt.Errorf("cgroup %s: %w", dir, err)
	}

	s.MemoryCurrent = readInt(dir, "memory.current")
	s.MemoryPeak = readInt(dir, "memory.peak")
	s.MemoryMax = readLimit(dir, "memory.max")
	s.MemoryHigh = readLimit(dir, "memory.high")
	s.SwapCurrent = readInt(dir, "memory.swap.current")
	s.SwapMax = readLimit(dir, "memory.swap.max")

	events := readKeyed(dir, "memory.events")
	s.HighEvents = events["high"]
	s.MaxEvents = events["max"]
	s.OOM = events["oom"]
	s.OOMKills = events["oom_kill"]

	cpu := readKeyed(dir, "cpu.stat")
	s.CPUUsageUsec = cpu["usage_usec"]
	s.CPUUserUsec = cpu["user_usec"]
	s.CPUSystemUsec = cpu["system_usec"]
	s.NrPeriods = cpu["nr_periods"]
	s.NrThrottled = cpu["nr_throttled"]
	s.ThrottledUsec = cpu["throttled_usec"]

	s.PidsCurrent = readInt(dir, "pids.current")
	s.PidsMax = readLimit(dir, "pids.max")

	readIOStat(dir, &s)
	return s, nil
}

// readInt reads a control file holding a single integer. A missing file means
// the controller is not enabled here, which is not an error worth propagating
// through a metrics scrape.
func readInt(dir, name string) int64 {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// readLimit reads a limit file, which uses the literal string "max" rather than
// a sentinel number to mean unlimited. Parsing that as an integer is a classic
// source of a limit silently reading as 0.
func readLimit(dir, name string) int64 {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return -1
	}
	text := strings.TrimSpace(string(data))
	if text == "max" {
		return -1
	}
	// cpu.max is "QUOTA PERIOD"; take the quota.
	if f := strings.Fields(text); len(f) > 1 {
		text = f[0]
	}
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return -1
	}
	return v
}

// readKeyed parses the "key value" line format used by memory.events, cpu.stat
// and friends.
func readKeyed(dir, name string) map[string]int64 {
	out := map[string]int64{}
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			out[fields[0]] = v
		}
	}
	return out
}

// readIOStat parses io.stat, which is one line per block device:
//
//	8:0 rbytes=1024 wbytes=2048 rios=10 wios=20 dbytes=0 dios=0
//
// Values are summed across devices. Keeping them per-device would be more
// faithful but turns a single container into an unbounded number of metric
// series, which is the wrong trade for a runtime whose containers rarely span
// more than one filesystem.
func readIOStat(dir string, s *Stats) {
	f, err := os.Open(filepath.Join(dir, "io.stat"))
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		for _, field := range strings.Fields(sc.Text())[1:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			v, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				continue
			}
			switch key {
			case "rbytes":
				s.IOReadBytes += v
			case "wbytes":
				s.IOWriteBytes += v
			case "rios":
				s.IOReadIOs += v
			case "wios":
				s.IOWriteIOs += v
			}
		}
	}
}
