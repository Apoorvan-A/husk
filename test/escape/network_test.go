package escape

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Egress: a container on the bridge must resolve DNS and reach the internet,
// which exercises the whole path at once — veth into the netns, the bridge as
// gateway, a default route, MASQUERADE for the private source address, and a
// generated /etc/resolv.conf.
//
// The private 10.66.0.x source is unroutable on the internet, so without the
// masquerade a reply would have nowhere to return to. That is the specific thing
// this proves.
func TestBridgeEgressReachesTheInternet(t *testing.T) {
	requireRoot(t)
	if !internetAvailable() {
		t.Skip("no outbound connectivity from the host")
	}
	_, rootfs := setup(t)

	out, code := run(t, "run", "-rootfs", rootfs, "-net", "bridge", "/bin/sh", "-c", `
		echo "addr=$(ip -4 -o addr show eth0 | awk '{print $4}')"
		echo "route=$(ip route | grep default)"
		wget -q -T 10 -O- http://example.com >/dev/null 2>&1 && echo "EGRESS-OK" || echo "EGRESS-FAILED"
	`)
	t.Logf("exit=%d\n%s", code, out)

	mustContain(t, out, "addr=10.66.0.", "the container did not receive an address from the bridge subnet")
	mustContain(t, out, "default via 10.66.0.1", "the container has no default route through the bridge")
	mustContain(t, out, "EGRESS-OK",
		"the container could not reach the internet; DNS, the default route or the MASQUERADE rule is missing")
}

// A published port must be reachable from the host, and the whole netfilter
// arrangement must be removed again when the container goes away.
//
// Both directions are checked. Loopback and a real host address take different
// paths through netfilter — loopback traffic never traverses PREROUTING and
// needs route_localnet plus a masquerade to work at all — and it is entirely
// possible to have one working while the other silently times out.
func TestPublishedPortIsReachableAndCleanedUp(t *testing.T) {
	requireRoot(t)
	_, rootfs := setup(t)

	const (
		id       = "husk-publish-probe"
		hostPort = 18099
	)
	_, _ = run(t, "delete", "-force", id)

	bin, _ := setup(t)
	server := exec.Command(bin, "run", "-rootfs", rootfs, "-net", "bridge",
		"-id", id, "-p", fmt.Sprintf("%d:8080", hostPort), "/probe", "serve", "8080")
	if err := server.Start(); err != nil {
		t.Fatalf("start container: %v", err)
	}
	t.Cleanup(func() {
		_, _ = run(t, "kill", "-all", id, "KILL")
		_, _ = run(t, "delete", "-force", id)
		_ = server.Wait()
	})

	body, err := getWithRetry(fmt.Sprintf("http://127.0.0.1:%d/", hostPort), 15*time.Second)
	if err != nil {
		t.Fatalf("published port unreachable via loopback: %v", err)
	}
	mustContain(t, body, "husk-probe", "unexpected response from the container")
	t.Logf("loopback: %s", strings.TrimSpace(body))

	if hostIP := primaryHostIP(); hostIP != "" {
		body, err := getWithRetry(fmt.Sprintf("http://%s:%d/", hostIP, hostPort), 10*time.Second)
		if err != nil {
			t.Errorf("published port unreachable via the host address %s: %v\n"+
				"loopback worked, so the DNAT is installed but forwarding to the container is "+
				"being dropped in the FORWARD chain", hostIP, err)
		} else {
			t.Logf("host address: %s", strings.TrimSpace(body))
		}
	}

	// Teardown must remove the veth, the lease and the rules. A runtime that
	// leaks any of them degrades the host a little on every container start,
	// which is the kind of fault that only shows up after a thousand of them.
	_, _ = run(t, "kill", "-all", id, "KILL")
	_, _ = run(t, "delete", "-force", id)

	if n := countLines(t, "iptables", "-t", "nat", "-S", "HUSK-DNAT"); n > 1 {
		t.Errorf("DNAT rules survived container deletion:\n%s",
			commandOutput(t, "iptables", "-t", "nat", "-S", "HUSK-DNAT"))
	}
	if out := commandOutput(t, "ip", "-o", "link", "show", "type", "veth"); strings.Contains(out, "hveth") {
		t.Errorf("veth interfaces survived container deletion:\n%s", out)
	}
}

func getWithRetry(url string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return string(body), nil
	}
	return "", lastErr
}

func internetAvailable() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://example.com")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// primaryHostIP returns the address the host uses for its default route, which
// is the one an external client would connect to.
func primaryHostIP() string {
	out, err := exec.Command("sh", "-c",
		`ip -4 route get 1.1.1.1 2>/dev/null | grep -o 'src [0-9.]*' | awk '{print $2}'`).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func commandOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
}

func countLines(t *testing.T, name string, args ...string) int {
	t.Helper()
	out := strings.TrimSpace(commandOutput(t, name, args...))
	if out == "" {
		return 0
	}
	return len(strings.Split(out, "\n"))
}
