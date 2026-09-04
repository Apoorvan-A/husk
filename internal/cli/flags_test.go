package cli

import (
	"testing"

	"github.com/Apoorvan-A/husk/internal/security"
)

func TestParseMemoryUsesBinaryMultiples(t *testing.T) {
	// Binary, not decimal. The kernel reports memory.current in bytes, so a
	// "256M" limit set as 256,000,000 reads back as 244 MiB and looks like a
	// bug in the runtime rather than in the parser.
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"1024", 1024},
		{"1K", 1 << 10},
		{"64k", 64 << 10},
		{"256M", 256 << 20},
		{"256m", 256 << 20},
		{"2G", 2 << 30},
	} {
		got, err := parseMemory(tc.in)
		if err != nil {
			t.Errorf("parseMemory(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseMemory(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	if _, err := parseMemory("banana"); err == nil {
		t.Error("parseMemory should reject a non-numeric value")
	}
}

// memory.swap.max needs three distinct states and zero is a meaningful value,
// so a plain int64 cannot express them.
func TestParseSwapDistinguishesUnsetFromZero(t *testing.T) {
	got, err := parseSwap("")
	if err != nil || got != nil {
		t.Errorf(`parseSwap("") = %v, %v; want nil, nil so the default applies`, got, err)
	}

	got, err = parseSwap("0")
	if err != nil {
		t.Fatalf("parseSwap(\"0\"): %v", err)
	}
	if got == nil || *got != 0 {
		t.Errorf(`parseSwap("0") = %v; want a pointer to 0, distinct from unset`, got)
	}

	for _, in := range []string{"max", "MAX", "-1"} {
		got, err := parseSwap(in)
		if err != nil {
			t.Fatalf("parseSwap(%q): %v", in, err)
		}
		if got == nil || *got != -1 {
			t.Errorf("parseSwap(%q) = %v; want a pointer to -1 for unlimited", in, got)
		}
	}
}

func TestParsePorts(t *testing.T) {
	got, err := parsePorts([]string{"8080:80", "5353:53/udp"})
	if err != nil {
		t.Fatalf("parsePorts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d mappings, want 2", len(got))
	}
	if got[0].HostPort != 8080 || got[0].ContainerPort != 80 || got[0].Protocol != "tcp" {
		t.Errorf("first mapping = %+v", got[0])
	}
	if got[1].Protocol != "udp" {
		t.Errorf("second mapping protocol = %q, want udp", got[1].Protocol)
	}

	for _, bad := range []string{"8080", "notaport:80", "8080:notaport"} {
		if _, err := parsePorts([]string{bad}); err == nil {
			t.Errorf("parsePorts(%q) should have failed", bad)
		}
	}
}

func TestResolveCapabilities(t *testing.T) {
	base := []string{"CAP_CHOWN", "CAP_SETUID"}

	got := resolveCapabilities(base, []string{"net_raw"}, []string{"CAP_SETUID"})
	set := map[string]bool{}
	for _, c := range got {
		set[c] = true
	}

	if !set["CAP_CHOWN"] {
		t.Error("CAP_CHOWN should have been retained")
	}
	if !set["CAP_NET_RAW"] {
		t.Error("-cap-add net_raw should have normalised to CAP_NET_RAW and been added")
	}
	if set["CAP_SETUID"] {
		t.Error("-cap-drop CAP_SETUID should have removed it")
	}

	// A drop must win over an add of the same capability, since the safer
	// outcome is the correct one to pick when a caller asks for both.
	got = resolveCapabilities(base, []string{"CAP_NET_RAW"}, []string{"CAP_NET_RAW"})
	for _, c := range got {
		if c == "CAP_NET_RAW" {
			t.Error("-cap-drop should take precedence over -cap-add for the same capability")
		}
	}
}

func TestNewIDIsUniqueAndInterfaceSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newID()
		if seen[id] {
			t.Fatalf("newID produced a duplicate after %d draws: %q", i, id)
		}
		seen[id] = true

		// The id is truncated into a network interface name, which the kernel
		// caps at 15 characters. Anything non-alphanumeric would also be
		// rejected there.
		if len(id) < 8 {
			t.Fatalf("id %q is too short to stay unique after truncation to 8 characters", id)
		}
		for _, r := range id {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				t.Fatalf("id %q contains %q, which is not valid in an interface name", id, r)
			}
		}
	}
}

func TestDefaultCapabilitySetIsUsableAsAResolveBase(t *testing.T) {
	got := resolveCapabilities(security.DefaultCapabilities, nil, nil)
	if len(got) != len(security.DefaultCapabilities) {
		t.Errorf("resolving with no changes returned %d capabilities, want %d",
			len(got), len(security.DefaultCapabilities))
	}
}
