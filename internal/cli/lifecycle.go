package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Apoorvan-A/husk/internal/cgroups"
	"github.com/Apoorvan-A/husk/internal/hlog"
	"github.com/Apoorvan-A/husk/internal/state"
)

func startCommand(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	var c commonFlags
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return fmt.Errorf("usage: husk start CONTAINER")
	}

	e := newEnv(&c)
	st, err := e.states.Load(id)
	if err != nil {
		return err
	}
	if st.Status != state.StatusCreated {
		return fmt.Errorf("container %q is %s, not created", id, st.Status)
	}

	// Opening the read end of the FIFO is the entire start operation. The init
	// process has been blocked in open(O_WRONLY) since it finished setup; this
	// open completes the rendezvous and both sides proceed. Nothing is
	// signalled, no PID is looked up, and there is no window in which the
	// container is half-started.
	//
	// O_NONBLOCK on the open, though, is not optional. A blocking O_RDONLY open
	// waits for a writer, and if the init process has died there will never be
	// one — `husk start` would hang forever with no diagnostic. A non-blocking
	// open returns immediately and still completes the rendezvous, because the
	// waiting O_WRONLY open unblocks as soon as *any* reader appears, blocking
	// or not. The wait then moves to the read, where it can be bounded.
	fd, err := unix.Open(e.states.FifoPath(id), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open exec fifo: %w", err)
	}
	f := os.NewFile(uintptr(fd), "exec.fifo")
	defer f.Close()

	// The byte the init process writes confirms it was still alive at the
	// rendezvous rather than having died during setup.
	if err := awaitFifoByte(f, st.Pid, 10*time.Second); err != nil {
		return fmt.Errorf("start container %q: %w", id, err)
	}

	st.Status = state.StatusRunning
	if err := e.states.Save(st); err != nil {
		return err
	}
	hlog.Event("container.start", id, "pid", st.Pid)
	return nil
}

// awaitFifoByte waits for the init process to write its confirmation byte,
// giving up if the process dies or the deadline passes.
//
// The fd is non-blocking, so a read with no data yet returns EAGAIN rather than
// waiting. Polling around that is what makes it possible to also check whether
// the writer is still alive — a blocking read cannot be interrupted to ask.
func awaitFifoByte(f *os.File, pid int, timeout time.Duration) error {
	buf := make([]byte, 1)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		n, err := f.Read(buf)
		if n > 0 {
			return nil
		}
		if err == io.EOF {
			return fmt.Errorf("the init process closed the fifo without starting; it exited during setup")
		}
		if err != nil && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("read exec fifo: %w", err)
		}
		if pid > 0 && unix.Kill(pid, 0) != nil {
			return fmt.Errorf("the init process (pid %d) is gone; it exited before start", pid)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s waiting for the init process to reach the start fifo", timeout)
}

func stateCommand(args []string) error {
	fs := flag.NewFlagSet("state", flag.ContinueOnError)
	var c commonFlags
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return fmt.Errorf("usage: husk state CONTAINER")
	}

	e := newEnv(&c)
	st, err := e.states.Load(id)
	if err != nil {
		return err
	}
	st.Refresh()

	// The runtime-spec defines exactly these six fields for `state` output, and
	// husk's own bookkeeping is deliberately excluded so the response validates
	// against the spec rather than merely resembling it.
	out := map[string]any{
		"ociVersion": st.OCIVersion,
		"id":         st.ID,
		"status":     string(st.Status),
		"pid":        st.Pid,
		"bundle":     st.Bundle,
	}
	if len(st.Annotations) > 0 {
		out["annotations"] = st.Annotations
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func killCommand(args []string) error {
	fs := flag.NewFlagSet("kill", flag.ContinueOnError)
	var c commonFlags
	all := fs.Bool("all", false, "signal every process in the container, not just its init")
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	fs.StringVar(&c.cgParent, "cgroup-parent", "", "cgroup parent used at create time")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return fmt.Errorf("usage: husk kill CONTAINER [SIGNAL]")
	}

	sig := unix.SIGTERM
	if s := fs.Arg(1); s != "" {
		parsed, err := parseSignal(s)
		if err != nil {
			return err
		}
		sig = parsed
	}

	e := newEnv(&c)
	st, err := e.states.Load(id)
	if err != nil {
		return err
	}
	st.Refresh()
	if st.Status == state.StatusStopped {
		return fmt.Errorf("container %q is not running", id)
	}

	if *all {
		// Signalling the whole cgroup rather than the init process. Necessary
		// when init has already exited but left descendants, and when the
		// workload is a process group that does not forward signals itself.
		cg := cgroups.New(id, c.cgParent)
		if sig == unix.SIGKILL {
			return cg.KillAll()
		}
		pids, err := cg.Processes()
		if err != nil {
			return err
		}
		for _, pid := range pids {
			_ = unix.Kill(pid, sig)
		}
		return nil
	}

	if err := unix.Kill(st.Pid, sig); err != nil {
		return fmt.Errorf("signal container %q: %w", id, err)
	}
	hlog.Event("container.kill", id, "signal", sig.String(), "pid", st.Pid)
	return nil
}

func deleteCommand(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	var c commonFlags
	force := fs.Bool("force", false, "kill the container first if it is still running")
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	fs.StringVar(&c.dataRoot, "data-root", "", "image and layer store (default /var/lib/husk)")
	fs.StringVar(&c.cgParent, "cgroup-parent", "", "cgroup parent used at create time")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return fmt.Errorf("usage: husk delete CONTAINER")
	}

	e := newEnv(&c)
	st, err := e.states.Load(id)
	if err != nil {
		return err
	}
	st.Refresh()

	cg := cgroups.New(id, c.cgParent)

	if st.Status != state.StatusStopped {
		if !*force {
			// The spec requires delete on a running container to fail. Silently
			// killing it would make an accidental delete unrecoverable.
			return fmt.Errorf("container %q is %s; use -force to kill it first", id, st.Status)
		}
		if err := cg.KillAll(); err != nil {
			return fmt.Errorf("kill container: %w", err)
		}
		// Give the kernel a moment to finish tearing the processes down before
		// rmdir, which fails with EBUSY on a cgroup that still has members.
		waitForEmpty(cg, 2*time.Second)
	}

	var ports = st.Config.Network.Ports
	usedStorage := len(st.Layers) > 0
	if err := e.teardown(id, ports, cg, usedStorage); err != nil {
		fmt.Fprintf(os.Stderr, "husk: cleanup: %v\n", err)
	}
	if err := e.states.Remove(id); err != nil {
		return err
	}
	hlog.Event("container.delete", id)
	return nil
}

// waitForEmpty polls until the cgroup has no processes left or the deadline
// passes. Polling is acceptable here because the alternative — cgroup.events
// with an inotify watch on the populated field — is a lot of machinery for a
// path that runs once per container teardown.
func waitForEmpty(cg *cgroups.Manager, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pids, err := cg.Processes()
		if err != nil || len(pids) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// logsCommand prints what a detached container wrote. There is nothing clever
// here — the file exists because a detached container's stdio has to go
// somewhere that outlives the runtime process, and once it does, reading it back
// is free. Foreground `husk run` containers write to the caller's terminal and
// have no log to show.
func logsCommand(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	var c commonFlags
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return fmt.Errorf("usage: husk logs CONTAINER")
	}

	e := newEnv(&c)
	if _, err := e.states.Load(id); err != nil {
		return err
	}

	f, err := os.Open(filepath.Join(e.states.Dir(id), LogName))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("container %q has no captured output; only containers started with "+
				"`husk create` write to a log, since `husk run` streams to the terminal instead", id)
		}
		return err
	}
	defer f.Close()

	_, err = io.Copy(os.Stdout, f)
	return err
}

func psCommand(args []string) error {
	fs := flag.NewFlagSet("ps", flag.ContinueOnError)
	var c commonFlags
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	e := newEnv(&c)
	states, err := e.states.List()
	if err != nil {
		return err
	}

	w := newTabWriter()
	fmt.Fprintln(w, "ID\tSTATUS\tPID\tIMAGE\tIP\tCREATED\tCOMMAND")
	for _, st := range states {
		var ip, cmd string
		if st.Config != nil {
			ip = st.Config.Network.IP
			cmd = strings.Join(st.Config.Args, " ")
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			st.ID, st.Status, st.Pid, orDash(st.Image), orDash(ip),
			humanAge(st.Created), cmd)
	}
	return w.Flush()
}

func versionCommand() error {
	fmt.Printf("husk %s\n", Version)
	fmt.Printf("oci runtime-spec %s\n", state.OCIVersion)
	return nil
}

// Version is set at build time with -ldflags "-X .../cli.Version=...".
var Version = "dev"

// parseSignal accepts "TERM", "SIGTERM", or a number, matching what runc and
// docker both take.
func parseSignal(s string) (unix.Signal, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return unix.Signal(n), nil
	}
	name := strings.ToUpper(s)
	if !strings.HasPrefix(name, "SIG") {
		name = "SIG" + name
	}
	signals := map[string]unix.Signal{
		"SIGHUP": unix.SIGHUP, "SIGINT": unix.SIGINT, "SIGQUIT": unix.SIGQUIT,
		"SIGKILL": unix.SIGKILL, "SIGUSR1": unix.SIGUSR1, "SIGUSR2": unix.SIGUSR2,
		"SIGTERM": unix.SIGTERM, "SIGSTOP": unix.SIGSTOP, "SIGCONT": unix.SIGCONT,
		"SIGWINCH": unix.SIGWINCH, "SIGABRT": unix.SIGABRT,
	}
	if sig, ok := signals[name]; ok {
		return sig, nil
	}
	return 0, fmt.Errorf("unknown signal %q", s)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func humanAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
