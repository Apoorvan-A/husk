package network

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/apoorvan10/husk/internal/container"
)

// Defaults for the container network. 10.66.0.0/24 is inside RFC 1918 space and
// far enough from the ranges Docker and libvirt claim by default to avoid a
// collision on a developer machine that runs all three.
const (
	BridgeName  = "husk0"
	BridgeCIDR  = "10.66.0.1/24"
	DefaultMTU  = 1500
	ContainerIf = "eth0"

	// Interface names are capped by IFNAMSIZ, which is 16 *including* the
	// terminating NUL — so 15 usable characters. Exceeding it does not produce a
	// helpful message: netlink rejects the request with ERANGE, surfacing as
	// "numerical result out of range", which says nothing about names.
	//
	// Both ends of the pair have to fit, so the id suffix is sized against the
	// longer prefix.
	ifNameMax = 15

	hostIfPrefix = "hveth"  // + 8 id chars = 13
	peerIfPrefix = "hvpeer" // + 8 id chars = 14
	idInIfName   = 8
)

// Manager owns the host half of container networking: the bridge, one veth pair
// per container, and the netfilter rules that let traffic in and out.
type Manager struct {
	Bridge string
	CIDR   string
	IPAM   *IPAM
}

func NewManager(stateRoot string) *Manager {
	return &Manager{Bridge: BridgeName, CIDR: BridgeCIDR, IPAM: NewIPAM(stateRoot, BridgeCIDR)}
}

// EnsureBridge creates the bridge if it does not exist and makes sure the host
// is willing to route for it.
//
// A Linux bridge is a software layer-2 switch. Interfaces enslaved to it form
// one broadcast domain, which is what lets containers on the same bridge reach
// each other directly by MAC. Giving the bridge itself an IP address turns it
// into the containers' default gateway as well, so the same device serves both
// roles.
func (m *Manager) EnsureBridge() error {
	if link, err := netlink.LinkByName(m.Bridge); err == nil {
		return netlink.LinkSetUp(link)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = m.Bridge
	br := &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(br); err != nil {
		return fmt.Errorf("create bridge %s: %w", m.Bridge, err)
	}

	addr, err := netlink.ParseAddr(m.CIDR)
	if err != nil {
		return fmt.Errorf("parse bridge address: %w", err)
	}
	if err := netlink.AddrAdd(br, addr); err != nil {
		return fmt.Errorf("assign %s to %s: %w", m.CIDR, m.Bridge, err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		return fmt.Errorf("bring up %s: %w", m.Bridge, err)
	}

	// Without ip_forward the kernel drops any packet whose destination is not a
	// local address, so containers can reach the host and nothing beyond it.
	// This is the single most common reason a hand-built container network has
	// working ARP and no connectivity.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	return nil
}

// Attach builds the container's connectivity and returns the config the child
// needs to finish the job from inside its netns.
//
// A veth pair is a virtual ethernet cable: two interfaces, permanently
// connected, where everything transmitted on one is received on the other. That
// is the only reason it is useful here — a network namespace is otherwise
// completely sealed, with no shared medium to bridge to. One end stays on the
// host and is enslaved to the bridge; the other is moved into the container's
// namespace, at which point it disappears from the host entirely.
func (m *Manager) Attach(id string, pid int, ports []container.PortMapping) (container.Network, error) {
	var cfg container.Network

	if err := m.EnsureBridge(); err != nil {
		return cfg, err
	}

	ip, err := m.IPAM.Allocate(id)
	if err != nil {
		return cfg, err
	}

	hostIf, peerIf := interfaceNames(id)
	if len(hostIf) > ifNameMax || len(peerIf) > ifNameMax {
		m.IPAM.Release(id)
		return cfg, fmt.Errorf("interface names %q/%q exceed the %d-character kernel limit",
			hostIf, peerIf, ifNameMax)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = hostIf
	attrs.MTU = DefaultMTU
	veth := &netlink.Veth{LinkAttrs: attrs, PeerName: peerIf}

	if err := netlink.LinkAdd(veth); err != nil {
		m.IPAM.Release(id)
		return cfg, fmt.Errorf("create veth pair: %w", err)
	}

	cleanup := func() {
		if l, err := netlink.LinkByName(hostIf); err == nil {
			_ = netlink.LinkDel(l)
		}
		m.IPAM.Release(id)
	}

	br, err := netlink.LinkByName(m.Bridge)
	if err != nil {
		cleanup()
		return cfg, fmt.Errorf("find bridge: %w", err)
	}
	hostLink, err := netlink.LinkByName(hostIf)
	if err != nil {
		cleanup()
		return cfg, err
	}
	if err := netlink.LinkSetMaster(hostLink, br); err != nil {
		cleanup()
		return cfg, fmt.Errorf("enslave %s to %s: %w", hostIf, m.Bridge, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		cleanup()
		return cfg, fmt.Errorf("bring up %s: %w", hostIf, err)
	}

	// Move the peer into the container's network namespace, addressed by the
	// child's PID. This is the one operation that crosses the namespace boundary
	// and it can only be done from outside: the container has no way to reach
	// into the host's namespace and pull an interface across, which is exactly
	// the property that makes it safe.
	peer, err := netlink.LinkByName(veth.PeerName)
	if err != nil {
		cleanup()
		return cfg, err
	}
	if err := netlink.LinkSetNsPid(peer, pid); err != nil {
		cleanup()
		return cfg, fmt.Errorf("move %s into netns of pid %d: %w", veth.PeerName, pid, err)
	}

	gateway, _, err := net.ParseCIDR(m.CIDR)
	if err != nil {
		cleanup()
		return cfg, err
	}

	if err := m.applyRules(id, ip.String(), ports); err != nil {
		cleanup()
		return cfg, err
	}

	prefixLen, _ := m.IPAM.subnet.Mask.Size()
	cfg = container.Network{
		Mode:      "bridge",
		PeerName:  veth.PeerName,
		IfaceName: ContainerIf,
		IP:        fmt.Sprintf("%s/%d", ip, prefixLen),
		Gateway:   gateway.String(),
		MTU:       DefaultMTU,
		Ports:     ports,
	}
	cfg.DNS = hostResolvers()
	return cfg, nil
}

// Detach tears down everything Attach built.
//
// Deleting the host end of a veth pair destroys the peer as well, wherever it
// lives — so a container whose namespace is already gone leaves nothing behind.
// Namespaces are refcounted, and the kernel frees a netns once the last process
// in it exits, taking any remaining interfaces with it. That leaves the
// netfilter rules and the IP lease as the only genuinely leakable resources,
// which is why they are removed explicitly.
func (m *Manager) Detach(id string, ports []container.PortMapping) error {
	var errs []string

	if err := m.removeRules(id, ports); err != nil {
		errs = append(errs, err.Error())
	}
	hostIf, _ := interfaceNames(id)
	if link, err := netlink.LinkByName(hostIf); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			errs = append(errs, fmt.Sprintf("delete veth: %v", err))
		}
	}
	if err := m.IPAM.Release(id); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return fmt.Errorf("network teardown: %s", strings.Join(errs, "; "))
	}
	return nil
}

// interfaceNames derives the two ends of the veth pair from a container id.
// Truncation is safe against collisions in practice because ids are random hex
// and the names only have to be unique among concurrently running containers.
func interfaceNames(id string) (host, peer string) {
	s := id
	if len(s) > idInIfName {
		s = s[:idInIfName]
	}
	return hostIfPrefix + s, peerIfPrefix + s
}

// hostResolvers reuses the host's nameservers, skipping the systemd-resolved
// stub at 127.0.0.53. A loopback address means something different inside the
// container's netns — it means the container itself — so copying it across gives
// a resolver pointing at nothing.
func hostResolvers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil && !ip.IsLoopback() {
			out = append(out, fields[1])
		}
	}
	return out
}
