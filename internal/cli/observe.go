package cli

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"

	"github.com/apoorvan10/husk/internal/cgroups"
	"github.com/apoorvan10/husk/internal/metrics"
)

func metricsCommand(args []string) error {
	fs := flag.NewFlagSet("metrics", flag.ContinueOnError)
	var c commonFlags
	addr := fs.String("listen", "127.0.0.1:9723", "address to serve /metrics on")
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	fs.StringVar(&c.cgParent, "cgroup-parent", "", "cgroup parent containers were created under")
	if err := fs.Parse(args); err != nil {
		return err
	}

	e := newEnv(&c)

	// A private registry rather than the default one. prometheus.DefaultRegisterer
	// carries the Go runtime and process collectors, which describe the
	// *exporter* — its heap, its goroutines — and have nothing to do with the
	// containers being measured. Mixing them makes a dashboard where husk's own
	// memory usage sits next to the containers' and is easy to misread.
	reg := prometheus.NewRegistry()
	if err := reg.Register(metrics.NewCollector(e.states, c.cgParent)); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !cgroups.Available() {
			http.Error(w, "cgroup v2 unified hierarchy not mounted", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		// A scrape that hangs must not hold a connection open forever; Prometheus
		// will retry on the next interval regardless.
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, unix.SIGINT, unix.SIGTERM)
	go func() {
		<-stop
		_ = srv.Close()
	}()

	fmt.Fprintf(os.Stderr, "husk: serving metrics on http://%s/metrics\n", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func topCommand(args []string) error {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	var c commonFlags
	interval := fs.Duration("interval", time.Second, "refresh interval")
	once := fs.Bool("once", false, "print a single sample and exit")
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	fs.StringVar(&c.cgParent, "cgroup-parent", "", "cgroup parent containers were created under")
	if err := fs.Parse(args); err != nil {
		return err
	}

	e := newEnv(&c)

	// CPU percentage needs two samples: cpu.stat reports cumulative time, so a
	// single read tells you how much CPU a container has used since it started,
	// which is not what anyone means by "CPU usage". The rate between
	// consecutive samples is.
	previous := map[string]sample{}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, unix.SIGINT, unix.SIGTERM)

	for {
		states, err := e.states.List()
		if err != nil {
			return err
		}

		if !*once {
			// Clear and home the cursor. Redrawing in place rather than
			// scrolling keeps the output readable at a one-second refresh.
			fmt.Print("\033[H\033[2J")
		}

		w := newTabWriter()
		fmt.Fprintln(w, "CONTAINER\tSTATUS\tCPU%\tTHROTTLE%\tMEM\tMEM LIMIT\tPEAK\tOOM\tPIDS\tIO R/W")

		now := time.Now()
		for _, st := range states {
			cg := cgroups.New(st.ID, c.cgParent)
			s, err := cg.Stats()
			if err != nil {
				continue
			}

			cpuPct := 0.0
			if prev, ok := previous[st.ID]; ok {
				elapsed := now.Sub(prev.at).Seconds()
				if elapsed > 0 {
					used := float64(s.CPUUsageUsec-prev.cpuUsec) / 1e6
					cpuPct = used / elapsed * 100
				}
			}
			previous[st.ID] = sample{at: now, cpuUsec: s.CPUUsageUsec}

			fmt.Fprintf(w, "%s\t%s\t%.1f\t%.1f\t%s\t%s\t%s\t%d\t%d\t%s/%s\n",
				short(st.ID), st.Status,
				cpuPct, s.ThrottleRatio()*100,
				humanBytes(s.MemoryCurrent), humanLimit(s.MemoryMax), humanBytes(s.MemoryPeak),
				s.OOMKills, s.PidsCurrent,
				humanBytes(s.IOReadBytes), humanBytes(s.IOWriteBytes))
		}
		if err := w.Flush(); err != nil {
			return err
		}

		if *once {
			return nil
		}
		select {
		case <-stop:
			return nil
		case <-time.After(*interval):
		}
	}
}

type sample struct {
	at      time.Time
	cpuUsec int64
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(b)/float64(div), "KMGTPE"[exp])
}

func humanLimit(b int64) string {
	if b < 0 {
		return "unlimited"
	}
	return humanBytes(b)
}
