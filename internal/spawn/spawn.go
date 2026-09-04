// Package spawn is the runtime side of container creation: it clones `husk
// init` into new namespaces and performs every setup step the child is not
// privileged enough to do for itself.
package spawn

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/Apoorvan-A/husk/internal/container"
	"github.com/Apoorvan-A/husk/internal/initproc"
	"github.com/Apoorvan-A/husk/internal/ipc"
	"github.com/Apoorvan-A/husk/internal/namespaces"
	"github.com/Apoorvan-A/husk/internal/security"
)

// ExtraFiles slots, which the child sees as descriptors 3 and up.
const (
	slotSyncRead = iota
	slotSyncWrite
	slotStateDir
	slotSelfExe
)

// ParentSetup runs after the child exists and before it is released. Everything
// that needs the child's PID and the parent's privileges belongs here: cgroup
// membership, moving a veth peer into the netns, publishing state.
//
// It returns the network configuration because that is the one part of the
// container's config which cannot be known before the child exists — an address
// is only allocated, and a veth peer only moved, once there is a PID to move it
// into. The result is delivered to the child alongside the release signal rather
// than in the initial config.
type ParentSetup func(pid int) (container.Network, error)

// Options describes one container start.
type Options struct {
	Config *container.Config

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// StateDir is /run/husk/<id>. It is passed to the child as an open
	// directory descriptor so the exec FIFO stays reachable after pivot_root.
	StateDir string

	// Detached means the runtime process will exit while the container keeps
	// running, which is what `husk create` does. It suppresses PR_SET_PDEATHSIG;
	// see buildCmd.
	Detached bool

	Setup ParentSetup
}

// Handle is a started container from the runtime's point of view.
type Handle struct {
	Pid     int
	Network container.Network

	cmd  *exec.Cmd
	pipe *ipc.Pipe
}

// Start clones the child, drives the handshake to completion, and returns once
// the container is fully constructed. It does not wait for the workload.
func Start(opts Options) (*Handle, error) {
	parentPipe, childPipe, err := ipc.Pair()
	if err != nil {
		return nil, err
	}

	stateDir, err := os.Open(opts.StateDir)
	if err != nil {
		parentPipe.Close()
		childPipe.Close()
		return nil, fmt.Errorf("open state dir: %w", err)
	}
	defer stateDir.Close()

	// Re-exec from a sealed in-memory copy of ourselves rather than
	// /proc/self/exe. On a kernel too old for memfd sealing, fall back to the
	// plain path and accept the older exposure rather than refusing to run.
	execPath := "/proc/self/exe"
	selfExe, err := security.SealedSelfExe()
	if err == nil {
		defer selfExe.Close()
		// The child sees the sealed copy at a fixed descriptor because
		// ExtraFiles are dup'd to consecutive numbers starting at 3. execve
		// resolves this path before the fd table is flushed, so MFD_CLOEXEC
		// does not interfere.
		execPath = fmt.Sprintf("/proc/self/fd/%d", 3+slotSelfExe)
	} else {
		selfExe = nil
	}

	cmd := buildCmd(execPath, opts, childPipe, stateDir, selfExe)
	return start(cmd, opts, parentPipe, childPipe)
}

func buildCmd(execPath string, opts Options, childPipe *ipc.Pipe, stateDir, selfExe *os.File) *exec.Cmd {
	cfg := opts.Config

	cmd := exec.Command(execPath, "init")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = opts.Stdin, opts.Stdout, opts.Stderr

	files := childPipe.Files() // slots 0 and 1
	files = append(files, stateDir)
	if selfExe != nil {
		files = append(files, selfExe)
	}
	cmd.ExtraFiles = files

	// The child re-enters this same binary; the marker keeps a stray `husk init`
	// typed by a human from doing anything.
	cmd.Env = append(os.Environ(), "HUSK_INIT=1")

	attr := &syscall.SysProcAttr{
		Cloneflags: namespaces.CloneFlags(cfg.Namespaces),
	}

	// PR_SET_PDEATHSIG. If the runtime process dies — crash, SIGKILL, a terminal
	// closing — the kernel signals the child immediately, so a container cannot
	// outlive the thing responsible for cleaning up its cgroup, its veth pair
	// and its netfilter rules. Without it an ungracefully killed `husk run`
	// leaks a running container plus every host resource attached to it.
	//
	// It must not be set on the detached path, and getting that wrong is a
	// genuinely confusing bug: `husk create` is *supposed* to exit while the
	// container keeps waiting on its start FIFO, so pdeathsig kills the
	// container the instant create succeeds. The symptom is a container that
	// reports "created", has a plausible PID, and is already dead — followed by
	// `husk start` blocking forever on a FIFO whose writer no longer exists.
	//
	// A detached container is instead re-parented to PID 1 when the runtime
	// exits, and its cleanup is the state file's job rather than the kernel's.
	if !opts.Detached {
		attr.Pdeathsig = syscall.SIGKILL
	}

	if cfg.Namespaces.User {
		uidMaps, gidMaps := namespaces.SysProcIDMaps(cfg.IDMaps)
		attr.UidMappings = uidMaps
		attr.GidMappings = gidMaps
		// Left false so the runtime writes "deny" to /proc/<pid>/setgroups
		// before gid_map. See namespaces.SysProcIDMaps for why that ordering is
		// a security requirement.
		attr.GidMappingsEnableSetgroups = false
	}

	cmd.SysProcAttr = attr
	return cmd
}

func start(cmd *exec.Cmd, opts Options, parentPipe, childPipe *ipc.Pipe) (*Handle, error) {
	// Pdeathsig is delivered when the *thread* that cloned the child exits, not
	// the process. Go multiplexes goroutines across threads and retires idle
	// ones, so without pinning, a perfectly healthy runtime can lose the thread
	// that happened to run fork and the container dies for no reason. Locking
	// holds that thread for the life of this goroutine.
	runtime.LockOSThread()

	if err := cmd.Start(); err != nil {
		runtime.UnlockOSThread()
		parentPipe.Close()
		childPipe.Close()
		return nil, fmt.Errorf("clone init: %w", err)
	}

	// The parent must drop its duplicates of the child's pipe ends. While it
	// still holds the write end, a dead child never produces EOF on the read
	// side and the next Await blocks forever instead of reporting the failure.
	parentPipe.CloseChildCopies(childPipe)

	h := &Handle{Pid: cmd.Process.Pid, cmd: cmd, pipe: parentPipe}

	if err := h.handshake(opts); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		parentPipe.Close()
		runtime.UnlockOSThread()
		return nil, err
	}
	return h, nil
}

func (h *Handle) handshake(opts Options) error {
	if err := h.pipe.SendJSON(ipc.StageConfig, opts.Config); err != nil {
		return fmt.Errorf("send config: %w", err)
	}
	if err := h.pipe.Await(ipc.StageChildBooted); err != nil {
		return err
	}

	var netCfg container.Network
	if opts.Setup != nil {
		var err error
		netCfg, err = opts.Setup(h.Pid)
		if err != nil {
			// Tell the child rather than leaving it blocked on a signal that
			// will never come; it exits and reports a real message.
			_ = h.pipe.Fail(err)
			return fmt.Errorf("parent setup: %w", err)
		}
	}
	h.Network = netCfg

	if err := h.pipe.SendJSON(ipc.StageParentReady, netCfg); err != nil {
		return fmt.Errorf("release child: %w", err)
	}
	return h.pipe.Await(ipc.StageChildJailed)
}

// Wait blocks until the container process exits and returns its exit code.
func (h *Handle) Wait() (int, error) {
	defer runtime.UnlockOSThread()
	err := h.cmd.Wait()
	h.pipe.Close()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if ok := asExitError(err, &ee); ok {
		return ee.ExitCode(), nil
	}
	return -1, err
}

// Detach releases the runtime's hold without killing the container. Used by
// `husk create`, which returns while the container waits on its start FIFO.
func (h *Handle) Detach() error {
	defer runtime.UnlockOSThread()
	// Release the child from the process table without reaping it; the state
	// file records the PID so `husk kill` and `husk delete` can find it again.
	if err := h.cmd.Process.Release(); err != nil {
		return err
	}
	return h.pipe.Close()
}

// FifoName is re-exported so callers creating the state directory do not have to
// import the child package for a filename.
const FifoName = initproc.FifoName

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}
