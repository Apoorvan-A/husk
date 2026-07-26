package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// IPAM hands out addresses from the bridge subnet.
//
// The allocation table is a directory of files named after the address, one per
// lease, holding the owning container id. That looks primitive next to a
// database, and it buys the one property that actually matters here: creating a
// file with O_CREAT|O_EXCL is atomic in the kernel, so two `husk run` commands
// racing for the same address cannot both win. There is no lock to forget to
// take and no daemon to be the arbiter — which is the point, since husk does not
// have one.
type IPAM struct {
	dir    string
	subnet *net.IPNet
	base   net.IP
}

func NewIPAM(stateRoot, cidr string) *IPAM {
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return &IPAM{dir: filepath.Join(stateRoot, "ipam")}
	}
	return &IPAM{
		dir:    filepath.Join(stateRoot, "ipam"),
		subnet: subnet,
		base:   ip,
	}
}

// Allocate leases the lowest free address in the subnet.
//
// The scan starts at .2 because .1 is the bridge, and stops before the broadcast
// address. Linear scanning is O(n) in the subnet size, which for a /24 is 254
// stat calls in the worst case and is not worth optimising; a runtime managing
// thousands of containers would keep an index, and would also have outgrown a
// single flat subnet.
func (a *IPAM) Allocate(containerID string) (net.IP, error) {
	if a.subnet == nil {
		return nil, fmt.Errorf("no subnet configured")
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ipam dir: %w", err)
	}

	// Reuse an existing lease if this container already holds one, so a restart
	// keeps its address instead of leaking the old lease.
	if ip, ok := a.leaseOf(containerID); ok {
		return ip, nil
	}

	network := binary.BigEndian.Uint32(a.subnet.IP.To4())
	ones, bits := a.subnet.Mask.Size()
	size := uint32(1) << uint(bits-ones)

	for offset := uint32(2); offset < size-1; offset++ {
		candidate := make(net.IP, 4)
		binary.BigEndian.PutUint32(candidate, network+offset)

		// O_EXCL is the whole synchronisation mechanism: the kernel guarantees
		// exactly one creator, so the winner has the lease and the loser gets
		// EEXIST and moves on.
		f, err := os.OpenFile(a.leasePath(candidate), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("claim %s: %w", candidate, err)
		}
		_, werr := f.WriteString(containerID)
		f.Close()
		if werr != nil {
			os.Remove(a.leasePath(candidate))
			return nil, werr
		}
		return candidate, nil
	}
	return nil, fmt.Errorf("no free addresses in %s", a.subnet)
}

// Release drops a container's lease. Called on teardown; a leaked lease costs
// one address until the next reboot clears the tmpfs.
func (a *IPAM) Release(containerID string) error {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		path := filepath.Join(a.dir, e.Name())
		owner, err := os.ReadFile(path)
		if err != nil || string(owner) != containerID {
			continue
		}
		return os.Remove(path)
	}
	return nil
}

func (a *IPAM) leaseOf(containerID string) (net.IP, bool) {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		owner, err := os.ReadFile(filepath.Join(a.dir, e.Name()))
		if err != nil || string(owner) != containerID {
			continue
		}
		if ip := net.ParseIP(e.Name()); ip != nil {
			return ip, true
		}
	}
	return nil, false
}

func (a *IPAM) leasePath(ip net.IP) string { return filepath.Join(a.dir, ip.String()) }
