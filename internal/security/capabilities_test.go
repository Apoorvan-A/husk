package security

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The default set is a security decision, so a change to it should require
// changing this test too.
func TestDefaultCapabilitiesExcludeTheDangerousOnes(t *testing.T) {
	kept := map[string]bool{}
	for _, c := range DefaultCapabilities {
		kept[c] = true
	}

	for _, c := range []struct{ name, why string }{
		{"CAP_SYS_ADMIN", "mount, pivot_root and ~40 other operations; it is effectively root"},
		{"CAP_SYS_BOOT", "reboot(2) reboots the host; there is no namespace for it"},
		{"CAP_SYS_MODULE", "loading a module is a total escape by construction"},
		{"CAP_SYS_PTRACE", "attaching to a more privileged process across the namespace boundary"},
		{"CAP_SYS_RAWIO", "direct hardware access from userspace"},
		{"CAP_NET_RAW", "raw sockets allow ARP spoofing against every container on the bridge"},
		{"CAP_SYS_CHROOT", "nothing in a container image legitimately calls chroot"},
		{"CAP_DAC_READ_SEARCH", "bypasses read permission checks and enables open_by_handle_at"},
		{"CAP_SYS_TIME", "the clock is shared with the host"},
		{"CAP_BPF", "loading eBPF programs into the shared kernel"},
	} {
		if kept[c.name] {
			t.Errorf("%s is in the default set but should not be: %s", c.name, c.why)
		}
	}
}

func TestLookupCapabilityAcceptsBothSpellings(t *testing.T) {
	for _, spelling := range []string{"CAP_NET_RAW", "net_raw", "NET_RAW", " cap_net_raw "} {
		got, ok := LookupCapability(spelling)
		if !ok {
			t.Errorf("LookupCapability(%q) failed", spelling)
			continue
		}
		if got != unix.CAP_NET_RAW {
			t.Errorf("LookupCapability(%q) = %d, want %d", spelling, got, unix.CAP_NET_RAW)
		}
	}

	if _, ok := LookupCapability("CAP_NOT_A_REAL_CAPABILITY"); ok {
		t.Error("an unknown capability name must not resolve; a typo in a policy should be an error")
	}
}

// Every name in the default set has to resolve, or DropCapabilities fails at
// container start with a name it cannot look up.
func TestDefaultCapabilitiesAllResolve(t *testing.T) {
	for _, name := range DefaultCapabilities {
		if _, ok := LookupCapability(name); !ok {
			t.Errorf("default capability %q does not resolve", name)
		}
	}
}

func TestCapabilityTableIsWellFormed(t *testing.T) {
	seen := map[uintptr]string{}
	for name, value := range capabilityByName {
		if !strings.HasPrefix(name, "CAP_") {
			t.Errorf("capability name %q is missing the CAP_ prefix", name)
		}
		if other, dup := seen[value]; dup {
			t.Errorf("capabilities %q and %q both map to %d", name, other, value)
		}
		seen[value] = name
	}
}
