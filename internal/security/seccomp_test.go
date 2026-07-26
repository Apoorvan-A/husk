package security

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The filter is assembled by hand, so the structural invariants that make it
// correct are worth checking without needing a container. A jump offset that is
// off by one produces a filter the kernel loads happily and that allows a
// syscall it was supposed to deny.

func TestFilterChecksArchitectureBeforeSyscallNumber(t *testing.T) {
	prog, err := BuildFilter(DefaultDenied, ActionErrno(unix.EPERM))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ins := prog.Instructions

	// Syscall numbers are per-ABI: number 2 is open() on x86-64 and something
	// else on i386. A filter that compares numbers without first pinning the
	// architecture can be walked straight through by entering the kernel via a
	// different ABI, which is the oldest seccomp bypass there is.
	if ins[0].Code != opLoadWord || ins[0].K != offsetArch {
		t.Errorf("instruction 0 must load seccomp_data.arch (offset %d), got code=%#x k=%d",
			offsetArch, ins[0].Code, ins[0].K)
	}
	if ins[1].Code != opJumpEqual || ins[1].K != nativeArch {
		t.Errorf("instruction 1 must compare against the native arch %#x, got %#x", nativeArch, ins[1].K)
	}
	// A mismatch must fall through to a kill, never to an allow.
	if ins[2].Code != opReturn || ins[2].K != retKillProcess {
		t.Errorf("a foreign architecture must be killed, not allowed; got return %#x", ins[2].K)
	}

	if ins[3].Code != opLoadWord || ins[3].K != offsetSyscallNr {
		t.Errorf("instruction 3 must load seccomp_data.nr, got code=%#x k=%d", ins[3].Code, ins[3].K)
	}
	if ins[4].K != x32SyscallBit {
		t.Errorf("instruction 4 must reject the x32 ABI at %#x, got %#x", x32SyscallBit, ins[4].K)
	}
	if ins[5].Code != opReturn || ins[5].K != retKillProcess {
		t.Errorf("an x32 syscall must be killed, got return %#x", ins[5].K)
	}
}

// Every denial must jump to the deny instruction, and nothing else. An offset
// that lands on the allow return instead silently permits that one syscall.
func TestEveryDenialJumpsToTheDenyInstruction(t *testing.T) {
	action := ActionErrno(unix.EPERM)
	prog, err := BuildFilter(DefaultDenied, action)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ins := prog.Instructions

	const header = 6
	allowIdx := len(ins) - 2
	denyIdx := len(ins) - 1

	if ins[allowIdx].Code != opReturn || ins[allowIdx].K != retAllow {
		t.Fatalf("expected an allow return at %d, got code=%#x k=%#x", allowIdx, ins[allowIdx].Code, ins[allowIdx].K)
	}
	if ins[denyIdx].Code != opReturn || ins[denyIdx].K != action {
		t.Fatalf("expected the deny return at %d, got code=%#x k=%#x", denyIdx, ins[denyIdx].Code, ins[denyIdx].K)
	}

	for i, d := range DefaultDenied {
		pc := header + i
		target := pc + 1 + int(ins[pc].Jt)
		if target != denyIdx {
			t.Errorf("%s (instruction %d) jumps to %d, want the deny instruction at %d",
				d.Name, pc, target, denyIdx)
		}
		if ins[pc].K != uint32(d.Nr) {
			t.Errorf("%s compares against %d, want syscall %d", d.Name, ins[pc].K, d.Nr)
		}
		// jf=0 means "fall through to the next comparison", which is what makes
		// the chain work. A non-zero jf would skip comparisons.
		if ins[pc].Jf != 0 {
			t.Errorf("%s has jf=%d, want 0 so the chain continues", d.Name, ins[pc].Jf)
		}
	}
}

// Classic BPF jump offsets are a single unsigned byte, so a policy long enough
// to push the deny instruction more than 255 slots away silently produces
// garbage. The builder must refuse rather than emit it.
func TestOversizedPolicyIsRejected(t *testing.T) {
	huge := make([]Denied, 300)
	for i := range huge {
		huge[i] = Denied{Name: "synthetic", Nr: i}
	}
	if _, err := BuildFilter(huge, ActionErrno(unix.EPERM)); err == nil {
		t.Error("a 300-entry policy exceeds the 8-bit jump range and must be rejected")
	}
}

// The offsets must stay valid as the policy grows, which is the property most
// likely to break when someone adds a syscall to the deny list.
func TestOffsetsHoldAtEveryPolicySize(t *testing.T) {
	for _, size := range []int{1, 2, 17, 100, 250} {
		policy := make([]Denied, size)
		for i := range policy {
			policy[i] = Denied{Name: "synthetic", Nr: 1000 + i}
		}
		prog, err := BuildFilter(policy, ActionKill())
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		denyIdx := len(prog.Instructions) - 1
		for i := 0; i < size; i++ {
			pc := 6 + i
			if target := pc + 1 + int(prog.Instructions[pc].Jt); target != denyIdx {
				t.Errorf("size %d, entry %d: jumps to %d, want %d", size, i, target, denyIdx)
			}
		}
	}
}

func TestActionEncoding(t *testing.T) {
	// SECCOMP_RET_ERRNO carries the errno in its low 16 bits.
	if got := ActionErrno(unix.EPERM); got != retErrno|uint32(unix.EPERM) {
		t.Errorf("ActionErrno(EPERM) = %#x, want %#x", got, retErrno|uint32(unix.EPERM))
	}
	if got := ActionKill(); got != retKillProcess {
		t.Errorf("ActionKill() = %#x, want %#x", got, retKillProcess)
	}
}

// The deny list is the security policy, so entries disappearing is a regression
// worth failing on rather than noticing later.
func TestPolicyCoversTheEscapeCriticalSyscalls(t *testing.T) {
	present := map[string]bool{}
	for _, d := range DefaultDenied {
		present[d.Name] = true
	}
	for _, required := range []string{
		"mount", "pivot_root", "chroot", // filesystem manipulation
		"fsopen", "fsmount", "move_mount", // the 5.2 mount API, easy to miss
		"open_by_handle_at",           // the Shocker escape
		"init_module", "finit_module", // a module escapes by construction
		"reboot",           // no namespace exists for this
		"setns", "unshare", // fresh capabilities in a new user namespace
		"bpf", "perf_event_open",
		"keyctl", "add_key", // the keyring is not namespaced
		"ptrace",
	} {
		if !present[required] {
			t.Errorf("%s is no longer in the default deny list", required)
		}
	}
}
