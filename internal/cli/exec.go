package cli

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Apoorvan-A/husk/internal/cgroups"
	"github.com/Apoorvan-A/husk/internal/state"
)

// husk exec joins an existing container. This is the one operation where Go's
// runtime actively fights the kernel API, and the reason runc ships a C
// constructor called nsexec that runs before Go starts.
//
// The problem. setns(2) attaches the *calling thread* to a namespace, not the
// process. For a mount namespace the kernel additionally refuses if the caller
// shares its fs_struct — its root and working directory — with anything else,
// because attaching one thread to a different mount namespace while its siblings
// keep the old one would leave the process with an incoherent idea of what "/"
// means. Go's runtime creates threads with CLONE_FS, so every goroutine's thread
// shares one fs_struct and setns(CLONE_NEWNS) returns EINVAL. There is no Go
// code that can run early enough to avoid this, because the runtime has already
// started threads before main().
//
// runc's answer is to not be Go at that moment: nsexec is a C function marked
// __attribute__((constructor)), so the dynamic loader runs it before the Go
// runtime initialises, while the process is genuinely single-threaded. It does
// the setns work and re-execs.
//
// husk's answer keeps the binary cgo-free. unshare(CLONE_FS) on a thread gives
// that thread a private fs_struct, which satisfies the kernel's check. Pinning
// the goroutine to that thread with LockOSThread, unsharing, and then calling
// setns on it produces a single thread correctly attached to the container's
// namespaces; forking from that thread gives a child that inherits all of them.
//
// The honest trade-off, worth stating rather than glossing: this is more fragile
// than nsexec. It depends on the Go scheduler honouring LockOSThread for the
// whole sequence, and it leaves the rest of the process's threads outside the
// container, so any goroutine that touches the filesystem between the unshare
// and the fork sees the wrong root. The sequence below therefore does nothing
// between those two points except the setns calls themselves.
func execCommand(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	var c commonFlags
	tty := fs.Bool("tty", false, "allocate a terminal")
	workdir := fs.String("workdir", "", "working directory inside the container")
	envs := stringList{}
	fs.Var(&envs, "e", "environment variable KEY=VALUE (repeatable)")
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	fs.StringVar(&c.cgParent, "cgroup-parent", "", "cgroup parent used at create time")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: husk exec [flags] CONTAINER COMMAND [ARG...]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		fs.Usage()
		return fmt.Errorf("need a container and a command")
	}
	id, cmdArgs := fs.Arg(0), fs.Args()[1:]

	e := newEnv(&c)
	st, err := e.states.Load(id)
	if err != nil {
		return err
	}
	st.Refresh()
	if st.Status != state.StatusRunning {
		return fmt.Errorf("container %q is %s", id, st.Status)
	}

	// Open every namespace file before touching any of them. Once the first
	// setns succeeds the process's view of /proc has changed, and paths opened
	// afterwards may resolve somewhere else entirely.
	//
	// Order matters on the way in as well: the user namespace must come first,
	// because joining it is what grants the capabilities needed to join the
	// rest, and the mount namespace must come last, since it is the one with the
	// fs_struct restriction and joining it early would break the /proc lookups
	// for the others.
	order := []string{"user", "ipc", "uts", "net", "pid", "cgroup", "mnt"}
	fds := make(map[string]int, len(order))
	defer func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	for _, ns := range order {
		path := fmt.Sprintf("/proc/%d/ns/%s", st.Pid, ns)
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			if err == unix.ENOENT {
				continue // kernel built without this namespace type
			}
			return fmt.Errorf("open %s: %w", path, err)
		}

		// Skip any namespace we are already in. Namespace files are identified
		// by their inode, so comparing inodes is how you ask "is this the same
		// namespace" — the paths always differ and always exist, even for a
		// container that never created one of its own.
		//
		// This is not just an optimisation for the user namespace. setns into a
		// user namespace requires the caller to be single-threaded, with no
		// CLONE_FS escape hatch, so calling it from Go always returns EINVAL —
		// even when the target is the namespace we are already in and the call
		// would be a no-op. Skipping identical namespaces is what makes exec
		// work at all for the common case of a container without CLONE_NEWUSER.
		same, err := sameNamespace(path)
		if err != nil {
			unix.Close(fd)
			return err
		}
		if same {
			unix.Close(fd)
			continue
		}

		if ns == "user" {
			unix.Close(fd)
			// The honest limitation. runc solves this with nsexec, a C
			// constructor that runs before the Go runtime creates any threads,
			// at which point the process really is single-threaded and setns
			// succeeds. husk has no cgo, so it cannot run code that early.
			return fmt.Errorf("cannot exec into a container with its own user namespace: " +
				"setns(CLONE_NEWUSER) requires a single-threaded caller and the Go runtime is " +
				"multi-threaded before main() runs. See docs/ARCHITECTURE.md; use nsenter(1) " +
				"against the container's pid as a workaround")
		}
		fds[ns] = fd
	}

	// Open the container's cgroup.procs now, while the host's filesystem is still
	// the one this process sees.
	//
	// After the setns calls below, /sys/fs/cgroup/husk/<id> does not resolve any
	// more, and for two independent reasons: the mount namespace switch replaces
	// /sys/fs/cgroup with the container's own read-only cgroup2 mount, and the
	// cgroup namespace switch rebases that hierarchy so the container's own
	// cgroup *is* the root and has no husk/<id> path beneath it. The failure is
	// ENOENT, which reads like a missing cgroup rather than what it is.
	//
	// A file descriptor is immune to both, because it refers to the open file
	// rather than to a path.
	cg := cgroups.New(id, c.cgParent)
	cgProcs, err := os.OpenFile(filepath.Join(cg.Path(), "cgroup.procs"), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open container cgroup: %w", err)
	}
	defer cgProcs.Close()

	// Everything below runs on one pinned thread and must not yield to code that
	// touches the filesystem.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Detach this thread's fs_struct from the rest of the runtime's threads.
	// Without it the setns for the mount namespace fails with EINVAL.
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("unshare CLONE_FS (required before joining a mount namespace from Go): %w", err)
	}

	for _, ns := range order {
		fd, ok := fds[ns]
		if !ok {
			continue
		}
		if err := unix.Setns(fd, 0); err != nil {
			return fmt.Errorf("setns %s: %w", ns, err)
		}
	}

	// Joining a PID namespace does not renumber the caller — it cannot, for the
	// same reason CLONE_NEWPID does not move the cloner. It takes effect for
	// children, so the fork below is what actually produces a process inside the
	// container's PID namespace.
	proc := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	proc.Stdin, proc.Stdout, proc.Stderr = os.Stdin, os.Stdout, os.Stderr
	proc.Dir = *workdir
	if proc.Dir == "" {
		proc.Dir = "/"
	}
	proc.Env = envs
	if len(proc.Env) == 0 {
		proc.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	}
	if *tty {
		proc.Env = append(proc.Env, "TERM="+os.Getenv("TERM"))
	}

	if err := proc.Start(); err != nil {
		return fmt.Errorf("exec %s in %s: %w", strings.Join(cmdArgs, " "), id, err)
	}

	// Put the new process under the container's limits too. Without this an
	// `exec` runs in the runtime's cgroup, so a debugging shell could allocate
	// past the container's memory.max and destabilise the host instead of
	// hitting the limit the container is supposed to be under.
	//
	// The PID written is the one *this* process sees. We joined the container's
	// PID namespace for our children only — setns(CLONE_NEWPID) never renumbers
	// the caller — so we are still numbering in the host's namespace, which is
	// exactly what cgroup.procs expects.
	if _, err := cgProcs.WriteString(strconv.Itoa(proc.Process.Pid)); err != nil {
		fmt.Fprintf(os.Stderr, "husk: could not place exec process in container cgroup: %v\n", err)
	}

	err = proc.Wait()
	if ee, ok := err.(*exec.ExitError); ok {
		os.Exit(ee.ExitCode())
	}
	return err
}

// sameNamespace reports whether the namespace at path is the one this process is
// already in, by comparing inode numbers. Two paths naming the same namespace
// always stat to the same device and inode; that identity is the only reliable
// way to compare namespaces, since there is no name or id exposed anywhere else.
func sameNamespace(path string) (bool, error) {
	var target, self unix.Stat_t
	if err := unix.Stat(path, &target); err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	selfPath := "/proc/self/ns/" + path[strings.LastIndex(path, "/")+1:]
	if err := unix.Stat(selfPath, &self); err != nil {
		return false, fmt.Errorf("stat %s: %w", selfPath, err)
	}
	return target.Dev == self.Dev && target.Ino == self.Ino, nil
}
