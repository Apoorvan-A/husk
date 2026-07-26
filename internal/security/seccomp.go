package security

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This file assembles a seccomp-BPF program by hand rather than linking
// libseccomp. Two reasons, both practical: libseccomp needs cgo, which would
// cost the static binary that lets husk exec inside a foreign rootfs with no
// loader present; and the filter is the part of the security model most worth
// being able to read instruction by instruction.
//
// The filter is a classic-BPF program the kernel runs on every syscall entry,
// in the kernel, before the syscall executes. It sees one input struct and
// returns one 32-bit action:
//
//	struct seccomp_data {
//	    int   nr;                    // offset  0 - syscall number
//	    __u32 arch;                  // offset  4 - AUDIT_ARCH_* of the caller
//	    __u64 instruction_pointer;   // offset  8
//	    __u64 args[6];               // offset 16
//	};
//
// It cannot dereference pointers, which is not a limitation but the entire
// safety property: a filter that followed args[0] to inspect a path string would
// be racing userspace, which can rewrite that memory between the check and the
// syscall. That TOCTOU is why seccomp does not do path filtering and why
// arguments are only ever compared as scalars.

// classic-BPF opcode components, from linux/bpf_common.h. Composed rather than
// written as magic numbers so the instructions below read like the C macros.
const (
	bpfLD  = 0x00
	bpfJMP = 0x05
	bpfRET = 0x06

	bpfW   = 0x00
	bpfABS = 0x20

	bpfJEQ = 0x10
	bpfJGE = 0x30

	bpfK = 0x00

	opLoadWord  = bpfLD | bpfW | bpfABS // load a 32-bit word from seccomp_data
	opJumpEqual = bpfJMP | bpfJEQ | bpfK
	opJumpGE    = bpfJMP | bpfJGE | bpfK
	opReturn    = bpfRET | bpfK
)

// Offsets into seccomp_data.
const (
	offsetSyscallNr = 0
	offsetArch      = 4
)

// seccomp(2) actions. The high bits encode precedence: when several filters are
// installed the kernel takes the numerically lowest result, so KILL always wins
// over ALLOW no matter which filter produced it.
const (
	retKillProcess = 0x80000000 // kill the whole thread group
	retErrno       = 0x00050000 // return -errno, process continues
	retAllow       = 0x7fff0000
)

// seccomp(2) itself. Using the syscall rather than prctl(PR_SET_SECCOMP) is
// required for the TSYNC flag; see Install.
const (
	seccompSetModeFilter = 1
	seccompFlagTSync     = 1
)

// x32 is a third ABI on x86-64: 64-bit registers, 32-bit pointers, and its own
// syscall numbers offset by this bit. A filter that only checks numbers without
// checking the ABI can be bypassed by issuing the x32 variant of a blocked call,
// because number 2 means open() in x86-64 and something else entirely in i386.
const x32SyscallBit = 0x40000000

// Denied is one entry in the policy. Keeping the name alongside the number makes
// the generated filter auditable and lets the docs quote it directly.
type Denied struct {
	Name string
	Nr   int
}

// DefaultDenied is a subset of Docker's default-denied profile, chosen so every
// entry has a reason that can be stated in one line rather than to maximise the
// count.
var DefaultDenied = []Denied{
	// The kernel keyring is not namespaced. A container can read, and poison,
	// keys belonging to the host and to every other container.
	{"keyctl", unix.SYS_KEYCTL},
	{"add_key", unix.SYS_ADD_KEY},
	{"request_key", unix.SYS_REQUEST_KEY},

	// Filesystem manipulation. Blocking mount(2) alone is the classic mistake:
	// Linux 5.2 introduced an entirely separate mount API, and fsopen/fsmount
	// reach the same functionality without ever calling mount.
	{"mount", unix.SYS_MOUNT},
	{"umount2", unix.SYS_UMOUNT2},
	{"pivot_root", unix.SYS_PIVOT_ROOT},
	{"chroot", unix.SYS_CHROOT},
	{"fsopen", unix.SYS_FSOPEN},
	{"fsconfig", unix.SYS_FSCONFIG},
	{"fsmount", unix.SYS_FSMOUNT},
	{"fspick", unix.SYS_FSPICK},
	{"move_mount", unix.SYS_MOVE_MOUNT},
	{"open_tree", unix.SYS_OPEN_TREE},

	// The Shocker escape: open_by_handle_at resolves a file handle with no
	// reference to any path, so it walks straight past the container root to any
	// inode on the underlying filesystem whose handle can be guessed or brute
	// forced. There is no mount-namespace defence against it; the capability
	// check (CAP_DAC_READ_SEARCH) and this filter are the defence.
	{"open_by_handle_at", unix.SYS_OPEN_BY_HANDLE_AT},
	{"name_to_handle_at", unix.SYS_NAME_TO_HANDLE_AT},

	// Host lifecycle. There is no namespace for "reboot"; the syscall reboots
	// the machine every container on the box is sharing.
	{"reboot", unix.SYS_REBOOT},
	{"kexec_load", unix.SYS_KEXEC_LOAD},
	{"kexec_file_load", unix.SYS_KEXEC_FILE_LOAD},

	// Loading a module is a complete escape by construction: the module runs in
	// the single kernel that every container and the host share.
	{"init_module", unix.SYS_INIT_MODULE},
	{"finit_module", unix.SYS_FINIT_MODULE},
	{"delete_module", unix.SYS_DELETE_MODULE},

	// eBPF and perf both give a container a programmable window into kernel
	// internals, and both have a long history of privilege-escalation CVEs.
	{"bpf", unix.SYS_BPF},
	{"perf_event_open", unix.SYS_PERF_EVENT_OPEN},

	// Cross-process inspection. ptrace scoped to a PID namespace is still enough
	// to attach to a more privileged process that shares it, and process_vm_readv
	// reads another process's address space with no ptrace stop at all.
	{"ptrace", unix.SYS_PTRACE},
	{"process_vm_readv", unix.SYS_PROCESS_VM_READV},
	{"process_vm_writev", unix.SYS_PROCESS_VM_WRITEV},

	// Namespace manipulation from inside. A container that can unshare a new
	// user namespace gets a fresh full capability set in it, which is the first
	// step of most published escape chains.
	{"setns", unix.SYS_SETNS},
	{"unshare", unix.SYS_UNSHARE},

	// Global kernel state with no namespace at all.
	{"acct", unix.SYS_ACCT},
	{"quotactl", unix.SYS_QUOTACTL},
	{"swapon", unix.SYS_SWAPON},
	{"swapoff", unix.SYS_SWAPOFF},
	{"syslog", unix.SYS_SYSLOG},
	{"sethostname", unix.SYS_SETHOSTNAME},
	{"setdomainname", unix.SYS_SETDOMAINNAME},

	// The clock is shared. A container that can move it breaks certificate
	// validation and scheduling for the whole host. (Time namespaces exist as of
	// 5.6 but only virtualise the monotonic and boottime offsets, not the
	// wall clock.)
	{"settimeofday", unix.SYS_SETTIMEOFDAY},
	{"clock_settime", unix.SYS_CLOCK_SETTIME},
	{"clock_adjtime", unix.SYS_CLOCK_ADJTIME},
	{"adjtimex", unix.SYS_ADJTIMEX},

	// Direct hardware access from userspace.
	{"ioperm", unix.SYS_IOPERM},
	{"iopl", unix.SYS_IOPL},

	// userfaultfd lets userspace stall a kernel page fault at a moment of its
	// choosing, which converts a great many hard-to-hit kernel races into
	// reliable exploits.
	{"userfaultfd", unix.SYS_USERFAULTFD},

	// NUMA placement primitives, historically a source of memory-corruption
	// bugs and of no use to a container that does not control its own placement.
	{"move_pages", unix.SYS_MOVE_PAGES},
	{"mbind", unix.SYS_MBIND},
	{"migrate_pages", unix.SYS_MIGRATE_PAGES},
	{"set_mempolicy", unix.SYS_SET_MEMPOLICY},

	// Obsolete interfaces retained for ABI compatibility and never audited to
	// modern standards.
	{"uselib", unix.SYS_USELIB},
	{"lookup_dcookie", unix.SYS_LOOKUP_DCOOKIE},
	{"vhangup", unix.SYS_VHANGUP},
	{"modify_ldt", unix.SYS_MODIFY_LDT},
}

// Program is an assembled filter, kept separate from installation so tests can
// inspect and disassemble it without needing to be inside a container.
type Program struct {
	Instructions []unix.SockFilter
	Denied       []Denied
	Action       uint32
}

// BuildFilter assembles the program. Layout:
//
//	00  ld  [4]                     ; seccomp_data.arch
//	01  jeq AUDIT_ARCH_X86_64 ? +1 : kill
//	02  ret KILL                    ; wrong ABI - fail closed, never allow
//	03  ld  [0]                     ; seccomp_data.nr
//	04  jge 0x40000000 ? kill : +1  ; x32 variant of any call
//	05  ret KILL
//	06  jeq <denied[0]> ? deny : +1
//	..  ...one comparison per denied syscall...
//	N   ret ALLOW
//	N+1 deny: ret <action>
//
// The two fail-closed checks come first and are not negotiable. Checking the
// architecture before the syscall number is what stops the oldest seccomp bypass
// there is: syscall numbers are per-ABI, so on a kernel that accepts i386 or x32
// entry points the same number denotes a different call, and a number-only
// filter can be walked straight through by switching ABI.
//
// Denials are linear comparisons because classic BPF has no jump table and its
// jump offsets are a single unsigned byte. That byte is also the hard limit on
// how long this list may get: the first comparison must be able to jump all the
// way to the deny block, so the policy cannot exceed 255 entries without being
// restructured into a binary search. libseccomp generates that binary search;
// at this size the linear form is faster to read and the cost is a handful of
// kernel instructions per syscall.
func BuildFilter(denied []Denied, action uint32) (*Program, error) {
	if len(denied) > 250 {
		return nil, fmt.Errorf("policy of %d syscalls exceeds the 8-bit BPF jump range", len(denied))
	}

	prog := []unix.SockFilter{
		{Code: opLoadWord, K: offsetArch},
		// jt=1 skips the kill and continues; jf=0 falls through to it.
		{Code: opJumpEqual, Jt: 1, Jf: 0, K: nativeArch},
		{Code: opReturn, K: retKillProcess},

		{Code: opLoadWord, K: offsetSyscallNr},
		// Anything at or above the x32 bit is an x32 syscall. jt=0 falls into
		// the kill, jf=1 skips it.
		{Code: opJumpGE, Jt: 0, Jf: 1, K: x32SyscallBit},
		{Code: opReturn, K: retKillProcess},
	}

	// Each comparison jumps forward to the deny instruction, which sits one past
	// the allow. Offsets are computed from the end so adding entries cannot
	// silently break them.
	for i, d := range denied {
		remaining := len(denied) - i - 1
		prog = append(prog, unix.SockFilter{
			Code: opJumpEqual,
			Jt:   uint8(remaining + 1), // over the rest of the comparisons, over allow
			Jf:   0,
			K:    uint32(d.Nr),
		})
	}

	prog = append(prog,
		unix.SockFilter{Code: opReturn, K: retAllow},
		unix.SockFilter{Code: opReturn, K: action},
	)

	return &Program{Instructions: prog, Denied: denied, Action: action}, nil
}

// ActionErrno denies with the given errno, letting the caller see a normal
// syscall failure. ActionKill terminates the whole thread group.
func ActionErrno(errno unix.Errno) uint32 { return retErrno | (uint32(errno) & 0x0000ffff) }
func ActionKill() uint32                  { return retKillProcess }

// Install loads the filter into the kernel.
//
// Two flags-level details matter more than the filter contents.
//
// no_new_privs must already be set. Installing a filter is otherwise restricted
// to CAP_SYS_ADMIN, for a sound reason: a filter that blocks, say, getuid()
// could confuse a setuid binary into misbehaving, so an unprivileged process is
// only trusted to filter itself once it has promised it can never gain
// privileges through execve. That promise is exactly PR_SET_NO_NEW_PRIVS, it is
// irreversible, and it is inherited by every child.
//
// SECCOMP_FILTER_FLAG_TSYNC is what makes this correct in Go specifically. A
// seccomp filter is a property of a *thread*, not a process, and the Go runtime
// has already started several threads by the time any Go code runs. Installing
// via prctl would filter only whichever thread the goroutine happened to be on,
// leaving the rest unfiltered — and the scheduler is free to move the goroutine
// to one of them mid-function. TSYNC applies the filter to every thread in the
// group atomically, or fails without installing anything. This is the single
// most common way a hand-rolled Go seccomp implementation ends up silently doing
// nothing.
func (p *Program) Install() error {
	if len(p.Instructions) == 0 {
		return fmt.Errorf("empty filter")
	}
	fprog := unix.SockFprog{
		Len:    uint16(len(p.Instructions)),
		Filter: &p.Instructions[0],
	}
	_, _, errno := unix.RawSyscall(
		unix.SYS_SECCOMP,
		seccompSetModeFilter,
		seccompFlagTSync,
		uintptr(unsafe.Pointer(&fprog)),
	)
	if errno != 0 {
		// A non-zero return with TSYNC is the tid of the thread that could not
		// be synchronised, surfaced as an errno by the raw syscall wrapper.
		return fmt.Errorf("seccomp(SET_MODE_FILTER, TSYNC): %w", errno)
	}
	return nil
}

// SetNoNewPrivs is separated out because the ordering it enforces is easy to get
// wrong and impossible to detect afterwards: a filter installed by a privileged
// process without this set still works, so the bug only appears when the runtime
// is later used rootless.
func SetNoNewPrivs() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	return nil
}
