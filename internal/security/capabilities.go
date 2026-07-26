package security

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// A thread carries five capability sets and they answer five different
// questions. Confusing them is the usual source of "I dropped the capability and
// it still worked":
//
//	Effective   - what the kernel checks *right now* on a privileged operation.
//	Permitted   - the ceiling the thread may raise Effective to. Removing a
//	              capability from Permitted is irreversible for that thread.
//	Inheritable - what survives execve into a file with matching file
//	              capabilities. On its own it grants nothing.
//	Bounding    - a per-thread ceiling on Permitted that can only ever shrink,
//	              is inherited by every descendant, and cannot be raised even by
//	              a process that regains full privileges. This is the one that
//	              actually contains a container.
//	Ambient     - the modern fix for a real gap: without it, a non-root process
//	              execve-ing a normal (non-setuid, no-file-caps) binary loses
//	              every capability, so there was no way to run an unprivileged
//	              helper that keeps, say, CAP_NET_BIND_SERVICE. Ambient
//	              capabilities survive that execve. A capability may only be
//	              raised into Ambient if it is in both Permitted and Inheritable,
//	              and it is dropped automatically the moment it leaves either.
//
// Dropping from Effective alone is close to worthless: the process can raise it
// straight back from Permitted. Dropping from Bounding is what makes it stick.

// DefaultCapabilities is the set husk retains. It is Docker's default profile
// minus two entries, both deliberate:
//
//	CAP_NET_RAW    - allows raw and packet sockets, which means ARP spoofing and
//	                 traffic interception against every other container on the
//	                 same bridge. ping needs it; that is a poor trade, and modern
//	                 distributions ship ping with file capabilities anyway.
//	CAP_SYS_CHROOT - lets a process call chroot(2) again. pivot_root already
//	                 makes the host root unreachable so this is not an escape,
//	                 but nothing legitimate in a container image needs it.
//
// Notably absent from Docker's list too, and worth being able to say why:
// CAP_SYS_ADMIN (mount, pivot_root, and roughly forty other operations — it is
// the reason people call it "the new root"), CAP_SYS_BOOT (reboot(2) reboots the
// *host*; there is no namespace for that), CAP_SYS_MODULE (loading a kernel
// module is a total escape by construction, since the module runs in the one
// kernel everyone shares), and CAP_SYS_PTRACE (ptrace across a PID namespace
// boundary into a more privileged process).
var DefaultCapabilities = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FSETID",
	"CAP_FOWNER",
	"CAP_MKNOD",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETFCAP",
	"CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE",
	"CAP_KILL",
	"CAP_AUDIT_WRITE",
}

var capabilityByName = map[string]uintptr{
	"CAP_CHOWN":              unix.CAP_CHOWN,
	"CAP_DAC_OVERRIDE":       unix.CAP_DAC_OVERRIDE,
	"CAP_DAC_READ_SEARCH":    unix.CAP_DAC_READ_SEARCH,
	"CAP_FOWNER":             unix.CAP_FOWNER,
	"CAP_FSETID":             unix.CAP_FSETID,
	"CAP_KILL":               unix.CAP_KILL,
	"CAP_SETGID":             unix.CAP_SETGID,
	"CAP_SETUID":             unix.CAP_SETUID,
	"CAP_SETPCAP":            unix.CAP_SETPCAP,
	"CAP_LINUX_IMMUTABLE":    unix.CAP_LINUX_IMMUTABLE,
	"CAP_NET_BIND_SERVICE":   unix.CAP_NET_BIND_SERVICE,
	"CAP_NET_BROADCAST":      unix.CAP_NET_BROADCAST,
	"CAP_NET_ADMIN":          unix.CAP_NET_ADMIN,
	"CAP_NET_RAW":            unix.CAP_NET_RAW,
	"CAP_IPC_LOCK":           unix.CAP_IPC_LOCK,
	"CAP_IPC_OWNER":          unix.CAP_IPC_OWNER,
	"CAP_SYS_MODULE":         unix.CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":          unix.CAP_SYS_RAWIO,
	"CAP_SYS_CHROOT":         unix.CAP_SYS_CHROOT,
	"CAP_SYS_PTRACE":         unix.CAP_SYS_PTRACE,
	"CAP_SYS_PACCT":          unix.CAP_SYS_PACCT,
	"CAP_SYS_ADMIN":          unix.CAP_SYS_ADMIN,
	"CAP_SYS_BOOT":           unix.CAP_SYS_BOOT,
	"CAP_SYS_NICE":           unix.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":       unix.CAP_SYS_RESOURCE,
	"CAP_SYS_TIME":           unix.CAP_SYS_TIME,
	"CAP_SYS_TTY_CONFIG":     unix.CAP_SYS_TTY_CONFIG,
	"CAP_MKNOD":              unix.CAP_MKNOD,
	"CAP_LEASE":              unix.CAP_LEASE,
	"CAP_AUDIT_WRITE":        unix.CAP_AUDIT_WRITE,
	"CAP_AUDIT_CONTROL":      unix.CAP_AUDIT_CONTROL,
	"CAP_SETFCAP":            unix.CAP_SETFCAP,
	"CAP_MAC_OVERRIDE":       unix.CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":          unix.CAP_MAC_ADMIN,
	"CAP_SYSLOG":             unix.CAP_SYSLOG,
	"CAP_WAKE_ALARM":         unix.CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":      unix.CAP_BLOCK_SUSPEND,
	"CAP_AUDIT_READ":         unix.CAP_AUDIT_READ,
	"CAP_PERFMON":            unix.CAP_PERFMON,
	"CAP_BPF":                unix.CAP_BPF,
	"CAP_CHECKPOINT_RESTORE": unix.CAP_CHECKPOINT_RESTORE,
}

// LookupCapability resolves a name, tolerating both "CAP_NET_RAW" and "net_raw".
func LookupCapability(name string) (uintptr, bool) {
	n := strings.ToUpper(strings.TrimSpace(name))
	if !strings.HasPrefix(n, "CAP_") {
		n = "CAP_" + n
	}
	v, ok := capabilityByName[n]
	return v, ok
}

// lastCap reads the highest capability this kernel knows about. Hardcoding a
// constant would silently skip capabilities added in newer kernels, leaving them
// in the bounding set of a container that was supposed to have been stripped.
func lastCap() (uintptr, error) {
	var last uintptr = 40 // conservative floor if procfs is unavailable
	data, err := readSmallFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return last, nil
	}
	var v uintptr
	if _, err := fmt.Sscanf(strings.TrimSpace(data), "%d", &v); err != nil {
		return last, nil
	}
	return v, nil
}

// DropCapabilities reduces every capability set to keep.
//
// The order below is forced by the fact that each step removes the privilege
// needed for the next:
//
//  1. Clear Ambient. It must go first: a capability cannot be dropped from
//     Permitted while it is still Ambient, because the kernel would then be
//     holding an ambient capability with no permitted backing.
//  2. Shrink Bounding. PR_CAPBSET_DROP needs CAP_SETPCAP, which we still have
//     because step 3 has not run yet. Doing this after the capset would fail.
//  3. capset Effective/Permitted/Inheritable to keep. This is where CAP_SETPCAP
//     itself usually goes away.
//  4. Raise Ambient for keep, so the set survives the execve into the user's
//     command. Without this step the whole exercise is pointless for a rootless
//     container: execve of an ordinary binary by a non-root uid clears
//     Permitted entirely.
func DropCapabilities(keep []string) error {
	wanted := map[uintptr]bool{}
	for _, name := range keep {
		c, ok := LookupCapability(name)
		if !ok {
			return fmt.Errorf("unknown capability %q", name)
		}
		wanted[c] = true
	}

	// Step 1.
	if _, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT,
		unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); errno != 0 && errno != unix.EINVAL {
		return fmt.Errorf("clear ambient set: %w", errno)
	}

	last, err := lastCap()
	if err != nil {
		return err
	}

	// Step 2.
	for c := uintptr(0); c <= last; c++ {
		if wanted[c] {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0); err != nil {
			// EINVAL means this kernel has no such capability number; EPERM
			// means it was already outside our bounding set, which is the
			// desired end state anyway.
			if err == unix.EINVAL || err == unix.EPERM {
				continue
			}
			return fmt.Errorf("drop bounding capability %d: %w", c, err)
		}
	}

	// Step 3. Capabilities are a 64-bit mask split across two 32-bit words in
	// the v3 API; index 0 holds capabilities 0-31 and index 1 holds 32-63.
	var mask [2]uint32
	for c := range wanted {
		mask[c>>5] |= 1 << (c & 31)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	data := [2]unix.CapUserData{
		{Effective: mask[0], Permitted: mask[0], Inheritable: mask[0]},
		{Effective: mask[1], Permitted: mask[1], Inheritable: mask[1]},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	// Step 4.
	for c := range wanted {
		if _, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT,
			unix.PR_CAP_AMBIENT_RAISE, c, 0, 0, 0); errno != 0 {
			// A capability outside the bounding set cannot be made ambient.
			// That is consistent, not an error.
			if errno == unix.EPERM || errno == unix.EINVAL {
				continue
			}
			return fmt.Errorf("raise ambient capability %d: %w", c, errno)
		}
	}
	return nil
}
