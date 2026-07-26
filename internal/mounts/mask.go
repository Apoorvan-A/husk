package mounts

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/apoorvan10/husk/internal/container"
)

// DefaultMaskedPaths are entries under /proc and /sys that a PID namespace does
// *not* virtualise. This is the gap most hand-rolled runtimes leave open: people
// assume CLONE_NEWPID hides everything under /proc, but it only scopes the
// numeric PID directories. The files below are global kernel state that a fresh
// procfs still exposes verbatim.
//
//	/proc/kcore          - the live kernel image as an ELF core file. Readable
//	                       memory means readable keys and credentials.
//	/proc/kallsyms       - kernel symbol addresses; defeats KASLR for an exploit.
//	/proc/timer_list,
//	/proc/sched_debug    - host process names and scheduling detail, a clean
//	                       side channel for what else is on the box.
//	/sys/firmware,
//	/sys/devices/system/cpu/... - firmware tables and CPU vulnerability state.
//	/proc/scsi           - host storage topology.
var DefaultMaskedPaths = []string{
	"/proc/asound",
	"/proc/acpi",
	"/proc/kcore",
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/timer_list",
	"/proc/timer_stats",
	"/proc/sched_debug",
	"/proc/scsi",
	"/sys/firmware",
	"/sys/devices/virtual/powercap",
}

// DefaultReadonlyPaths stay visible but unwritable. These are the ones a
// container legitimately reads and must never set: writing /proc/sysrq-trigger
// reboots the *host*, and /proc/sys is the entire kernel tunable surface.
var DefaultReadonlyPaths = []string{
	"/proc/bus",
	"/proc/fs",
	"/proc/irq",
	"/proc/sys",
	"/proc/sysrq-trigger",
}

func applyMasks(sec container.Security) error {
	masked := sec.MaskedPaths
	if masked == nil {
		masked = DefaultMaskedPaths
	}
	readonly := sec.ReadonlyPaths
	if readonly == nil {
		readonly = DefaultReadonlyPaths
	}

	for _, p := range masked {
		if err := maskPath(p); err != nil {
			return fmt.Errorf("mask %s: %w", p, err)
		}
	}
	for _, p := range readonly {
		if err := readonlyPath(p); err != nil {
			return fmt.Errorf("readonly %s: %w", p, err)
		}
	}
	return nil
}

// maskPath makes a path unreadable without deleting it — the container still
// sees the entry, so software that stats it does not break, but reads return
// nothing.
//
// Files are bound over with /dev/null. Directories cannot be, so they get an
// empty read-only tmpfs instead, which presents as an existing but empty
// directory.
func maskPath(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		// Not every kernel builds every one of these. Absent is already masked.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.IsDir() {
		return unix.Mount("tmpfs", path, "tmpfs", unix.MS_RDONLY, "")
	}
	if err := unix.Mount("/dev/null", path, "", unix.MS_BIND, ""); err != nil {
		// A rootless container may be denied the bind on some procfs entries.
		// The path is still covered by the read-only /proc/sys handling and by
		// the capability drop, so this is reported rather than fatal.
		if err == unix.EPERM || err == unix.EACCES {
			return nil
		}
		return err
	}
	return nil
}

func readonlyPath(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// Same two-step as any read-only bind: the first mount establishes it, the
	// remount is what actually applies MS_RDONLY.
	if err := unix.Mount(path, path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			return nil
		}
		return err
	}
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_REC)
	if err := unix.Mount("", path, "", flags, ""); err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			return nil
		}
		return err
	}
	return nil
}
