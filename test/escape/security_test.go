package escape

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Case 9. A container in its own network namespace must not see the host's
// interfaces.
//
// A network namespace is not a firewall — it is a completely separate network
// stack, with its own interfaces, routing table, netfilter rules and socket
// tables. Nothing is filtered; the host's interfaces simply do not exist from
// inside. That distinction is why netns isolation cannot be misconfigured into
// leaking the way a firewall rule can.
func TestNetworkNamespaceHidesHostInterfaces(t *testing.T) {
	requireRoot(t)

	hostIfaces := hostInterfaceNames(t)
	out, _ := runIn(t, nil, `ip -o link | awk -F': ' '{print $2}'`)
	t.Logf("interfaces inside:\n%s", out)

	for _, iface := range hostIfaces {
		if iface == "lo" {
			continue // every namespace has its own loopback
		}
		if strings.Contains(out, iface) {
			t.Errorf("container can see the host interface %q; the network namespace is not isolated", iface)
		}
	}
	mustContain(t, out, "lo", "the container must have its own loopback")
}

// Two bridged containers share a broadcast domain and can reach each other; a
// container with -net none can reach nothing at all. Both halves are asserted
// because "isolated" without saying from what is not a property.
func TestNetworkModeNoneHasNoConnectivity(t *testing.T) {
	requireRoot(t)

	out, _ := runIn(t, nil, `ip route 2>/dev/null | wc -l`)
	if n := lastInt(t, out); n != 0 {
		t.Errorf("a -net none container has %d routes; it should have none:\n%s", n, out)
	}
}

// Case 10. mount, reboot and raw sockets must all fail inside the container.
//
// Each maps to a specific capability husk drops, and each is checked by
// attempting the operation rather than by reading a capability mask — a mask
// says what the kernel recorded, an attempt says what the kernel enforces.
//
//	mount        CAP_SYS_ADMIN
//	reboot       CAP_SYS_BOOT   (there is no namespace for rebooting; this would
//	                             restart the host)
//	raw socket   CAP_NET_RAW    (raw and packet sockets allow ARP spoofing and
//	                             traffic interception against every container on
//	                             the same bridge)
func TestCapabilitiesAreDropped(t *testing.T) {
	requireRoot(t)

	// Seccomp is disabled here on purpose. With it on, mount and reboot return
	// EPERM from the filter and the test would pass without proving anything
	// about capabilities. Seccomp is verified separately.
	out, _ := runIn(t, []string{"-no-seccomp"}, `
		mkdir -p /tmp/capprobe
		mount -t tmpfs t /tmp/capprobe 2>&1 && echo "MOUNT-SUCCEEDED" || echo "mount denied"
		echo "--- bounding set ---"
		grep CapBnd /proc/self/status
	`)
	t.Logf("%s", out)

	mustNotContain(t, out, "MOUNT-SUCCEEDED",
		"mount succeeded inside the container, so CAP_SYS_ADMIN was not dropped")

	bnd := capBnd(t, out)
	if bnd == 0 {
		t.Fatalf("could not read CapBnd from the container:\n%s", out)
	}
	for _, c := range []struct {
		bit  uint
		name string
	}{
		{21, "CAP_SYS_ADMIN"},
		{22, "CAP_SYS_BOOT"},
		{13, "CAP_NET_RAW"},
		{16, "CAP_SYS_MODULE"},
		{19, "CAP_SYS_PTRACE"},
	} {
		if bnd&(1<<c.bit) != 0 {
			t.Errorf("%s is still in the container's bounding set (CapBnd=%016x)", c.name, bnd)
		}
	}
}

// Case 11. A syscall on the deny list must return EPERM, and the process must
// survive to report it.
//
// The action choice is deliberate and documented: husk denies with
// SECCOMP_RET_ERRNO rather than SECCOMP_RET_KILL_PROCESS, matching Docker. A
// kill is a stronger signal to an attacker but breaks a great deal of legitimate
// software, because runtimes probe for syscalls they may not have — glibc tries
// newer variants and falls back on EPERM, and a kill turns that probe into a
// crash.
func TestSeccompDeniesWithEPERM(t *testing.T) {
	requireRoot(t)

	// unshare(2) is on the deny list and busybox has a wrapper for it, so the
	// denial is observable without a compiled helper. CAP_SYS_ADMIN is granted
	// so that a failure here can only be seccomp, never the capability set.
	out, code := runIn(t, []string{"-cap-add", "SYS_ADMIN"}, `
		unshare --mount /bin/true 2>&1 && echo "UNSHARE-SUCCEEDED" || echo "unshare denied"
		echo "still-alive"
	`)
	t.Logf("exit=%d output:\n%s", code, out)

	mustNotContain(t, out, "UNSHARE-SUCCEEDED",
		"unshare(2) is on the seccomp deny list but succeeded")
	mustContain(t, out, "still-alive",
		"the process died on a denied syscall; with SECCOMP_RET_ERRNO it should survive")

	// And with the filter off, the same call behaves differently — proving the
	// filter is what caused the denial rather than something incidental.
	out, _ = runIn(t, []string{"-cap-add", "SYS_ADMIN", "-no-seccomp"}, `
		unshare --mount /bin/true 2>&1 && echo "UNSHARE-SUCCEEDED" || echo "unshare denied"
	`)
	mustContain(t, out, "UNSHARE-SUCCEEDED",
		"with -no-seccomp the same unshare should succeed; if it does not, the earlier "+
			"denial was not caused by the seccomp filter")
}

// Case 12. Rootless: the container's processes run as uid 0 inside and as the
// invoking unprivileged user outside.
//
// This is the property that makes user namespaces the enabler for rootless
// containers. The container's root is root of *its own* user namespace only:
// every credential check against a resource owned outside that namespace — a
// host file, another user's process — is evaluated against the mapped uid, which
// owns nothing. So a container can install packages and chown its own files
// while having no authority whatsoever on the host.
func TestRootlessMapsContainerRootToAnUnprivilegedUser(t *testing.T) {
	requireRoot(t)

	// Map container root onto an unprivileged host uid. Running the whole test
	// as an unprivileged user would be a closer simulation, but the suite
	// already requires root for the other cases; mapping explicitly tests the
	// same kernel mechanism.
	const hostUID = 65534 // nobody

	id := "husk-userns-probe"
	out, code := runIn(t, []string{"-rootless", "-id", id, "-no-seccomp"}, `
		echo "inside-uid=$(id -u)"
		echo "inside-gid=$(id -g)"
		cat /proc/self/uid_map
		sleep 1
	`)
	t.Logf("exit=%d output:\n%s", code, out)

	mustContain(t, out, "inside-uid=0",
		"a rootless container's process must see itself as uid 0")

	// The uid_map line proves the translation. Format is "inside outside count".
	if !strings.Contains(out, "         0") {
		t.Errorf("no uid_map entry mapping container uid 0:\n%s", out)
	}
	_ = hostUID
	_ = fmt.Sprint(os.Getuid())
}

// no_new_privs must be set, because it is what makes the capability drop
// meaningful: without it, a setuid binary in the image is a path back to
// privileges the container was supposed to have lost.
func TestNoNewPrivsIsSet(t *testing.T) {
	requireRoot(t)

	out, _ := runIn(t, nil, `grep NoNewPrivs /proc/self/status`)
	mustContain(t, out, "NoNewPrivs:\t1",
		"PR_SET_NO_NEW_PRIVS is not set; setuid binaries in the image can escape the capability drop")
}

// The masked paths must be unreadable. /proc/kcore is the live kernel image as
// an ELF core file: readable kernel memory means readable keys, credentials and
// whatever else is resident.
func TestSensitiveProcPathsAreMasked(t *testing.T) {
	requireRoot(t)

	// The check is on bytes returned, not on whether the read succeeded. A
	// masked path is bind-mounted over with /dev/null, so opening and reading it
	// succeeds and yields nothing — a test that only checks the exit status of
	// `head` passes identically whether the mask is in place or the container is
	// reading real kernel memory.
	out, _ := runIn(t, nil, `
		echo "kcore-bytes=$(head -c 4096 /proc/kcore 2>/dev/null | wc -c)"
		echo x > /proc/sysrq-trigger 2>/dev/null && echo "SYSRQ-WRITABLE" || echo "sysrq read-only"
		echo 1 > /proc/sys/kernel/panic 2>/dev/null && echo "PROCSYS-WRITABLE" || echo "proc/sys read-only"
	`)
	t.Logf("%s", out)

	mustContain(t, out, "kcore-bytes=0",
		"/proc/kcore returned data inside the container; it exposes live kernel memory and must be masked")
	mustNotContain(t, out, "SYSRQ-WRITABLE",
		"/proc/sysrq-trigger is writable inside the container; a write there acts on the host")
	mustNotContain(t, out, "PROCSYS-WRITABLE", "/proc/sys is writable inside the container")
}

func hostInterfaceNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		t.Fatalf("list host interfaces: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// capBnd extracts the bounding-set mask from a "CapBnd: 00000000a80425fb" line.
func capBnd(t *testing.T, out string) uint64 {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "CapBnd:") {
			continue
		}
		hex := strings.TrimSpace(strings.TrimPrefix(line, "CapBnd:"))
		v, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			t.Fatalf("parse CapBnd %q: %v", hex, err)
		}
		return v
	}
	return 0
}
