// Package network wires a container into the host's network. It has two halves
// that run in different processes and different namespaces: host.go executes in
// the runtime process and owns the bridge, the veth pair and the netfilter
// rules; container.go executes inside `husk init` after the peer interface has
// been moved in, and owns only what is visible from within the netns.
package network

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/apoorvan10/husk/internal/container"
)

// ConfigureInside brings up the container's interfaces. It runs in the child
// because netlink operations act on the caller's network namespace, and there is
// no way to address "some other namespace" in the rtnetlink protocol — you have
// to be in it.
func ConfigureInside(cfg container.Network) error {
	// Loopback is down by default in a fresh netns. Anything that binds to
	// 127.0.0.1 — which includes a surprising amount of software that has no
	// interest in networking at all — fails until it is up.
	if err := bringUp("lo"); err != nil {
		return fmt.Errorf("loopback: %w", err)
	}

	if cfg.Mode != "bridge" || cfg.IfaceName == "" {
		return nil
	}

	// The veth peer arrives carrying the name the host gave it. Renaming happens
	// here, inside the namespace, and requires the link to be down — the kernel
	// refuses to rename a running interface because in-flight packets already
	// reference it.
	link, err := netlink.LinkByName(cfg.PeerName)
	if err != nil {
		return fmt.Errorf("find %s in netns: %w", cfg.PeerName, err)
	}
	if cfg.PeerName != cfg.IfaceName {
		if err := netlink.LinkSetName(link, cfg.IfaceName); err != nil {
			return fmt.Errorf("rename %s to %s: %w", cfg.PeerName, cfg.IfaceName, err)
		}
		if link, err = netlink.LinkByName(cfg.IfaceName); err != nil {
			return fmt.Errorf("find %s after rename: %w", cfg.IfaceName, err)
		}
	}

	addr, err := netlink.ParseAddr(cfg.IP)
	if err != nil {
		return fmt.Errorf("parse address %q: %w", cfg.IP, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("assign %s: %w", cfg.IP, err)
	}

	// The link must be up before a route through it will install; the kernel
	// rejects a route whose nexthop is on a down interface with ENETUNREACH.
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", cfg.IfaceName, err)
	}

	if cfg.Gateway != "" {
		gw := net.ParseIP(cfg.Gateway)
		if gw == nil {
			return fmt.Errorf("invalid gateway %q", cfg.Gateway)
		}
		// Default route via the bridge's address on the host side. The bridge is
		// the container's first hop for everything, including traffic to the
		// host itself.
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        gw,
			Dst:       nil, // nil Dst is 0.0.0.0/0
		}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("default route via %s: %w", cfg.Gateway, err)
		}
	}

	return writeResolvConf(cfg.DNS)
}

func bringUp(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// writeResolvConf gives the container a resolver. This is written from inside,
// after the pivot, because /etc/resolv.conf must land in the container's
// filesystem — writing it into the rootfs directory from the host would leak
// into every container sharing that image layer.
func writeResolvConf(servers []string) error {
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "8.8.8.8"}
	}
	var b strings.Builder
	for _, s := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	if err := os.MkdirAll(filepath.Dir("/etc/resolv.conf"), 0o755); err != nil {
		return err
	}
	// A read-only rootfs legitimately cannot take this; the container is
	// expected to have been given a resolv.conf by other means.
	if err := os.WriteFile("/etc/resolv.conf", []byte(b.String()), 0o644); err != nil {
		if os.IsPermission(err) {
			return nil
		}
		return fmt.Errorf("write resolv.conf: %w", err)
	}
	return nil
}
