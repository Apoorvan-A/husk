package network

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/apoorvan10/husk/internal/container"
)

// husk installs its rules into its own chains rather than appending directly to
// the built-in ones. Two reasons, both operational: a jump to a private chain
// can be removed in one command no matter how many rules accumulated inside it,
// and rules in a private chain are unambiguously husk's, so teardown can never
// delete something Docker or the host firewall put there.
const (
	chainNAT     = "HUSK-POSTROUTING"
	chainDNAT    = "HUSK-DNAT"
	chainForward = "HUSK-FORWARD"
)

// applyRules installs egress NAT, forwarding permission, and any published
// ports.
//
// Shelling out to iptables rather than speaking netfilter over netlink is a
// deliberate choice and the same one Docker makes. The kernel-side interface for
// the legacy tables is not a stable API, the rule encoding is intricate, and the
// nft-vs-legacy backend split means the wrong one silently writes rules the host
// never consults. The iptables binary resolves all of that, and the cost is
// exec'ing a process at container start.
func (m *Manager) applyRules(id, containerIP string, ports []container.PortMapping) error {
	if err := m.ensureChains(); err != nil {
		return err
	}

	// Egress masquerade: rewrite the source of anything leaving the bridge
	// subnet for elsewhere to the host's own address.
	//
	// This is required because the container's 10.66.0.x address is private and
	// unroutable on the internet — a reply would have nowhere to go. MASQUERADE
	// is SNAT that picks the outbound interface's current address at translation
	// time rather than a fixed one, which is what makes it correct on a host
	// whose address can change (DHCP, a laptop moving between networks).
	//
	// The "! -o husk0" is load-bearing: without it, container-to-container
	// traffic on the same bridge would also be NATed, so containers would see
	// each other's traffic as coming from the gateway and lose the source
	// address entirely.
	if err := iptables("-t", "nat", "-C", chainNAT,
		"-s", m.CIDR, "!", "-o", m.Bridge, "-j", "MASQUERADE"); err != nil {
		if err := iptables("-t", "nat", "-A", chainNAT,
			"-s", m.CIDR, "!", "-o", m.Bridge, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("install masquerade rule: %w", err)
		}
	}

	// Many hosts default the FORWARD policy to DROP. Traffic between the bridge
	// and the outside world is forwarded, not delivered locally, so without
	// these it is dropped after the routing decision and the symptom is an
	// egress path that ARPs correctly and then times out.
	forwardRules := [][]string{
		{"-i", m.Bridge, "!", "-o", m.Bridge, "-j", "ACCEPT"},
		// Return traffic only. Allowing arbitrary inbound would expose every
		// container port to the network; RELATED,ESTABLISHED lets replies back
		// without opening anything.
		{"-o", m.Bridge, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		// Container to container across the same bridge.
		{"-i", m.Bridge, "-o", m.Bridge, "-j", "ACCEPT"},
	}
	for _, r := range forwardRules {
		args := append([]string{"-C", chainForward}, r...)
		if err := iptables(args...); err != nil {
			args[0] = "-A"
			if err := iptables(args...); err != nil {
				return fmt.Errorf("install forward rule: %w", err)
			}
		}
	}

	if len(ports) > 0 {
		if err := m.enableLocalhostPublishing(); err != nil {
			return err
		}
	}
	for _, p := range ports {
		if err := m.publishPort(id, containerIP, p); err != nil {
			return err
		}
	}
	return nil
}

// enableLocalhostPublishing makes `curl localhost:PORT` work for a published
// port, which needs two things beyond the DNAT rule itself.
//
// route_localnet. After the DNAT rewrites the destination to 10.66.0.x, the
// packet still carries a source address of 127.0.0.1 and now has to leave via
// the bridge. The kernel's martian-source check normally drops exactly that:
// loopback addresses are not permitted to appear on a real interface, because on
// any other day such a packet is spoofed. Setting route_localnet on the bridge
// tells the kernel to make an exception there. Docker sets the same flag for the
// same reason.
//
// A masquerade for loopback-sourced traffic. Even once the request arrives, the
// container's reply is addressed to 127.0.0.1, which inside its own namespace
// means the container itself — so the reply never comes back. Rewriting the
// source to the bridge address gives the container something routable to answer.
func (m *Manager) enableLocalhostPublishing() error {
	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", m.Bridge)
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable route_localnet on %s: %w", m.Bridge, err)
	}

	rule := []string{"-t", "nat", "-A", chainNAT,
		"-s", "127.0.0.0/8", "-d", m.CIDR, "-j", "MASQUERADE"}
	check := append([]string{}, rule...)
	check[2] = "-C"
	if err := iptables(check...); err != nil {
		if err := iptables(rule...); err != nil {
			return fmt.Errorf("install loopback masquerade: %w", err)
		}
	}
	return nil
}

// publishPort implements -p HOSTPORT:CONTAINERPORT.
//
// What actually happens at the netfilter level, which is worth being precise
// about because "port forwarding" hides three separate mechanisms:
//
//  1. A DNAT rule in nat/PREROUTING rewrites the *destination* of an incoming
//     packet from hostaddr:hostport to containerip:containerport. PREROUTING is
//     before the routing decision, which is essential — the kernel has to make
//     that decision using the rewritten address, or it would deliver the packet
//     locally instead of forwarding it to the bridge.
//
//  2. conntrack records the translation. The reply travelling back out is
//     rewritten automatically by the reverse of the same tuple, which is why
//     there is no second rule for the return path. This is also why DNAT only
//     needs to match the first packet of a flow: everything after it is handled
//     by the conntrack entry, at a fraction of the cost.
//
//  3. A second DNAT rule in nat/OUTPUT covers traffic the host originates to
//     itself. OUTPUT-generated packets never traverse PREROUTING, so without
//     this rule `curl localhost:8080` from the host fails while the same request
//     from another machine succeeds — a genuinely confusing failure mode.
func (m *Manager) publishPort(id, containerIP string, p container.PortMapping) error {
	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}
	dest := addrPort(containerIP, p.ContainerPort)

	if err := ensureRule("nat", chainDNAT,
		"-p", proto, "--dport", strconv.Itoa(p.HostPort),
		"-j", "DNAT", "--to-destination", dest,
		"-m", "comment", "--comment", "husk:"+id); err != nil {
		return fmt.Errorf("publish port %d: %w", p.HostPort, err)
	}

	// Traffic arriving from off-box is *forwarded* to the container rather than
	// delivered locally, so it is subject to the FORWARD chain — and the
	// general forward rules only admit RELATED,ESTABLISHED in that direction. A
	// new inbound connection to a published port would be dropped after the
	// DNAT had already rewritten it, which presents as a port that works from
	// the host and times out from anywhere else.
	//
	// The rule is written against the post-DNAT destination, because FORWARD is
	// traversed after nat/PREROUTING has already rewritten the packet.
	if err := ensureRule("filter", chainForward,
		"-d", containerIP, "-p", proto, "--dport", strconv.Itoa(p.ContainerPort),
		"-o", m.Bridge, "-j", "ACCEPT",
		"-m", "comment", "--comment", "husk:"+id); err != nil {
		return fmt.Errorf("allow forwarding to published port %d: %w", p.ContainerPort, err)
	}
	return nil
}

// ensureRule appends a rule unless an identical one already exists. iptables has
// no upsert, so -C is the only way to keep container restarts from stacking
// duplicate rules until the chain is thousands of entries long.
func ensureRule(table, chain string, rule ...string) error {
	check := append([]string{"-t", table, "-C", chain}, rule...)
	if err := iptables(check...); err == nil {
		return nil
	}
	add := append([]string{"-t", table, "-A", chain}, rule...)
	return iptables(add...)
}

// removeRules deletes the per-container rules. The lease has to be read before
// anything else here, because the container's address is part of the rule text
// and releasing the lease first would make the rules unmatchable — a leak that
// only shows up as a slowly growing nat table.
func (m *Manager) removeRules(id string, ports []container.PortMapping) error {
	ip := m.IPAM.mustLease(id)
	if ip == "" {
		return nil
	}
	for _, p := range ports {
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		_ = iptables("-t", "nat", "-D", chainDNAT, "-p", proto,
			"--dport", strconv.Itoa(p.HostPort), "-j", "DNAT",
			"--to-destination", addrPort(ip, p.ContainerPort),
			"-m", "comment", "--comment", "husk:"+id)

		_ = iptables("-t", "filter", "-D", chainForward,
			"-d", ip, "-p", proto, "--dport", strconv.Itoa(p.ContainerPort),
			"-o", m.Bridge, "-j", "ACCEPT",
			"-m", "comment", "--comment", "husk:"+id)
	}
	// The masquerade and general forward rules are shared by every container and
	// stay in place; they are removed only by an explicit network teardown.
	return nil
}

// ensureChains creates husk's chains and the jumps into them, idempotently.
func (m *Manager) ensureChains() error {
	type chainSpec struct {
		table  string
		name   string
		parent string
	}
	specs := []chainSpec{
		{"nat", chainNAT, "POSTROUTING"},
		{"nat", chainDNAT, "PREROUTING"},
		{"filter", chainForward, "FORWARD"},
	}

	for _, s := range specs {
		// -N fails with "chain already exists"; that is the steady state, not an
		// error worth surfacing.
		_ = iptables("-t", s.table, "-N", s.name)

		if err := iptables("-t", s.table, "-C", s.parent, "-j", s.name); err != nil {
			// Insert at the head rather than append. Appending puts husk's rules
			// after a host firewall's terminal DROP, where they are never
			// evaluated.
			if err := iptables("-t", s.table, "-I", s.parent, "1", "-j", s.name); err != nil {
				return fmt.Errorf("link chain %s into %s: %w", s.name, s.parent, err)
			}
		}
	}

	// The host reaching a published port on its own loopback needs the DNAT
	// chain consulted on locally-generated traffic too.
	if err := iptables("-t", "nat", "-C", "OUTPUT", "-j", chainDNAT); err != nil {
		_ = iptables("-t", "nat", "-I", "OUTPUT", "1", "-j", chainDNAT)
	}
	return nil
}

func iptables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func addrPort(ip string, port int) string { return ip + ":" + strconv.Itoa(port) }

func (a *IPAM) mustLease(containerID string) string {
	if ip, ok := a.leaseOf(containerID); ok {
		return ip.String()
	}
	return ""
}
