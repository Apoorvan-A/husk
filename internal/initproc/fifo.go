package initproc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// FifoName is the rendezvous file inside the container's state directory.
const FifoName = "exec.fifo"

// awaitStartSignal implements the create/start split that the OCI runtime-spec
// requires: after `create` the container exists, holds its namespaces, sits in
// its cgroup and has its network attached, but the user's command has not run.
// `start` is a separate call that may arrive much later, from a different
// process.
//
// A FIFO is the mechanism because of one property no flag or file has: open(2)
// on a FIFO with O_WRONLY blocks until some other process opens the read end.
// The block is done by the kernel, so there is no polling, no sleep, no
// timeout to tune, and — the part that matters operationally — it is impossible
// to miss the signal by arriving late. If `start` runs first, its open of the
// read end blocks instead, and the two rendezvous whichever order they occur in.
// A pipe would not do: the write end would be held by the runtime process,
// which exits after `create`.
//
// The FIFO is opened through /proc/self/fd rather than by path. By the time this
// runs the process has already pivoted into the container root, so the host path
// /run/husk/<id>/exec.fifo no longer resolves. The parent passes an open
// descriptor to the *directory* instead, and a directory fd stays valid across
// pivot_root because it references the inode, not a path. Resolving
// /proc/self/fd/<n>/exec.fifo re-enters that directory from a handle the mount
// namespace change could not invalidate.
//
// The same trick is what CVE-2019-5736 abused in the opposite direction, and
// the reason husk re-execs itself from a sealed memfd; see security.SelfExe.
func awaitStartSignal() error {
	path := fmt.Sprintf("/proc/self/fd/%d/%s", fdExecFifo, FifoName)
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", FifoName, err)
	}
	defer unix.Close(fd)

	// The byte is not data anyone reads for content; writing it is how `start`
	// learns that the init process was still alive at the moment of the
	// rendezvous rather than having died during setup.
	if _, err := unix.Write(fd, []byte{0}); err != nil {
		return fmt.Errorf("signal start: %w", err)
	}
	return nil
}
