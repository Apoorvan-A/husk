package security

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// SealedSelfExe returns a file descriptor holding a private, immutable copy of
// the running husk binary, for the runtime to re-exec as `husk init`.
//
// This exists because of CVE-2019-5736, which broke every runc-based runtime in
// 2019 and is the sharpest illustration of why /proc is a two-way door.
//
// The attack: the runtime execs itself via /proc/self/exe to enter the
// container. A malicious image replaces the binary that will be run — typically
// by making /bin/sh a symlink to /proc/self/exe — so that when the runtime's
// init process execs the entry point, it re-executes the *runtime binary from
// inside the container's mount namespace*. A process already inside the
// container then opens /proc/<pid>/exe of that freshly exec'd process, which is
// a writable handle to the runtime binary on the host, and overwrites it. The
// next container start runs the attacker's code as root on the host.
//
// The fix is not to stop using /proc/self/exe — it is to make the thing behind
// it unwritable. A memfd is an anonymous file that lives only in memory and has
// no filesystem path, so a container cannot reach it by any route. Sealing it
// with F_SEAL_WRITE makes it immutable for every holder of the descriptor,
// including the kernel's own writeback path, and F_SEAL_SEAL makes the sealing
// itself irreversible. Even if a container recovers a handle to it, there is
// nothing to overwrite.
//
// The cost is one copy of the binary in memory per container start, which for a
// static Go binary is a few megabytes and is freed as soon as exec completes.
func SealedSelfExe() (*os.File, error) {
	src, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, fmt.Errorf("open self: %w", err)
	}
	defer src.Close()

	// MFD_ALLOW_SEALING is required at creation: a memfd created without it can
	// never be sealed, and there is no way to add the property afterwards.
	fd, err := unix.MemfdCreate("husk-init", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	dst := os.NewFile(uintptr(fd), "husk-init")

	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return nil, fmt.Errorf("copy self into memfd: %w", err)
	}

	// F_SEAL_SHRINK and F_SEAL_GROW close the obvious flanking moves: an
	// attacker who cannot modify bytes could otherwise truncate the file to
	// nothing or append to it.
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(dst.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		dst.Close()
		return nil, fmt.Errorf("seal memfd: %w", err)
	}
	return dst, nil
}
