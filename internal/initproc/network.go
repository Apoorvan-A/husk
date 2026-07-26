package initproc

import (
	"github.com/apoorvan10/husk/internal/container"
	"github.com/apoorvan10/husk/internal/network"
)

func configureNetwork(cfg *container.Config) error {
	if !cfg.Namespaces.Net {
		// Sharing the host's network namespace: the interfaces are already up
		// and configured, and touching them would reconfigure the host.
		return nil
	}
	return network.ConfigureInside(cfg.Network)
}
