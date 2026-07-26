// Package initproc is the container side of the fork. Everything in here runs
// after clone(2) has placed the process in fresh namespaces and before the
// user's command exists.
//
// It is a separate entry point on the same binary rather than a library call,
// because the namespaces only take effect for a newly cloned process and the
// mount work must happen in a process that is already inside the new mount
// namespace. `husk init` is never meant to be typed by a human.
package initproc

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/apoorvan10/husk/internal/container"
	"github.com/apoorvan10/husk/internal/ipc"
	"github.com/apoorvan10/husk/internal/mounts"
	"github.com/apoorvan10/husk/internal/security"
)

// Descriptor numbers the parent guarantees. Go's exec.Cmd assigns ExtraFiles
// starting at 3, after the three standard streams.
const (
	fdSyncRead  = 3
	fdSyncWrite = 4
	fdExecFifo  = 5 // present only on the OCI create/start path
)

// Run executes the whole container-side setup and never returns on success: it
// either execve()s the user command or becomes the reaping init shim.
func Run() error {
	// Pin this goroutine to its OS thread for the entire life of the setup, and
	// never release it.
	//
	// Capabilities in Linux are a property of a *thread*, not a process. So is
	// the seccomp filter, and so is the no_new_privs latch. The Go scheduler is
	// free to move a goroutine to a different OS thread at any function call or
	// channel operation, and if that happens between dropping capabilities and
	// exec-ing the workload, the exec inherits the credentials of whichever
	// thread it lands on — which still has the full set. The container then runs
	// with every capability despite the drop having "succeeded".
	//
	// This failure is completely silent. The drop returns no error, the code
	// looks correct, and the only way to notice is to read CapBnd from inside a
	// running container. It is caught here by test/escape TestCapabilitiesAreDropped.
	//
	// The seccomp install sidesteps the same problem differently, with
	// SECCOMP_FILTER_FLAG_TSYNC, because there is no equivalent flag for
	// capabilities.
	runtime.LockOSThread()

	pipe := ipc.NewPipe(
		os.NewFile(fdSyncRead, "sync-read"),
		os.NewFile(fdSyncWrite, "sync-write"),
	)

	var cfg container.Config
	if err := pipe.AwaitJSON(ipc.StageConfig, &cfg); err != nil {
		return fmt.Errorf("receive config: %w", err)
	}

	// Tell the parent we exist. Until this lands the parent does not know the
	// clone succeeded, and it must not start writing to /proc/<pid>/ paths that
	// might belong to a recycled PID.
	if err := pipe.Signal(ipc.StageChildBooted); err != nil {
		return fmt.Errorf("report boot: %w", err)
	}

	// Block until the parent has done everything that requires privileges we no
	// longer hold: uid/gid maps, cgroup membership, the veth peer moved into our
	// netns. Proceeding early would run the user's command outside its limits.
	//
	// The release also carries the network configuration, which could not have
	// been in the initial config: the address was only allocated once this
	// process had a PID for the parent to attach an interface to.
	if err := pipe.AwaitJSON(ipc.StageParentReady, &cfg.Network); err != nil {
		return err
	}

	if err := setup(&cfg); err != nil {
		// Report the real cause upward; otherwise the parent only sees a
		// non-zero exit status with no explanation.
		_ = pipe.Fail(err)
		return err
	}

	if err := pipe.Signal(ipc.StageChildJailed); err != nil {
		return fmt.Errorf("report jailed: %w", err)
	}

	// The create/start split: the container is fully constructed but must not
	// run yet. Opening the FIFO for writing blocks until someone opens the read
	// end, which is what `husk start` does. See docs/ARCHITECTURE.md.
	if cfg.AwaitStart {
		if err := awaitStartSignal(); err != nil {
			return err
		}
	}

	return launch(&cfg)
}

// setup performs, in order, every irreversible narrowing of the container's
// view. The order is not stylistic:
//
//   - hostname before the pivot, because CLONE_NEWUTS is already active and the
//     rootfs may ship an /etc/hostname we would rather not race with.
//   - filesystem before capabilities, because pivot_root and mount() need
//     CAP_SYS_ADMIN, which the capability drop removes.
//   - no_new_privs before seccomp, because installing a filter without
//     CAP_SYS_ADMIN is only permitted once no_new_privs is set.
//   - seccomp last, because the filter denies several of the syscalls used
//     above.
func setup(cfg *container.Config) error {
	if cfg.Namespaces.UTS && cfg.Hostname != "" {
		if err := unix.Sethostname([]byte(cfg.Hostname)); err != nil {
			return fmt.Errorf("sethostname: %w", err)
		}
	}

	if !cfg.NoPivot {
		if err := mounts.SetupRoot(cfg); err != nil {
			return fmt.Errorf("root filesystem: %w", err)
		}
		if cfg.Namespaces.Cgroup {
			if err := mounts.MountCgroupNamespace(); err != nil {
				return fmt.Errorf("cgroup mount: %w", err)
			}
		}
	}

	if err := configureNetwork(cfg); err != nil {
		return fmt.Errorf("network: %w", err)
	}

	if cfg.Cwd != "" {
		if err := unix.Chdir(cfg.Cwd); err != nil {
			return fmt.Errorf("chdir %s: %w", cfg.Cwd, err)
		}
	}

	return security.Apply(cfg.Security)
}

// launch hands control to the user's command.
func launch(cfg *container.Config) error {
	if len(cfg.Args) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Resolve against PATH *inside* the container. This is why the lookup
	// happens here and not in the parent: the parent's filesystem view has
	// nothing to do with what exists in the image.
	bin, err := exec.LookPath(cfg.Args[0])
	if err != nil {
		return fmt.Errorf("exec %s: %w", cfg.Args[0], err)
	}

	env := cfg.Env
	if len(env) == 0 {
		env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	}

	if cfg.InitProcess {
		return superviseAsPID1(bin, cfg.Args, env)
	}

	// execve replaces this image entirely, so the user's command inherits PID 1
	// along with every namespace, the cgroup, the capability set and the seccomp
	// filter. Nothing of husk survives in the container — there is no agent, no
	// supervisor, no shim. That is what makes the container's exit status
	// genuinely the command's exit status.
	return unix.Exec(bin, cfg.Args, env)
}
