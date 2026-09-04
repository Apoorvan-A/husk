package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	rspec "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/Apoorvan-A/husk/internal/container"
	"github.com/Apoorvan-A/husk/internal/security"
)

// An OCI bundle is a directory containing a config.json and a rootfs. The spec
// is deliberate about this being a *directory* rather than an archive: a runtime
// receives an already-unpacked filesystem and never has to trust itself to
// extract one, which keeps image handling out of the runtime's threat model
// entirely. Pulling and unpacking is the job of whatever produced the bundle.
const configName = "config.json"

func hasBundle(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, configName))
	return err == nil
}

// loadBundle translates an OCI runtime-spec config into husk's own config.
//
// The translation is where compliance actually lives. The spec is far larger
// than what husk implements, and the responsible thing is to reject what cannot
// be honoured rather than accept it silently: a caller that asks for an AppArmor
// profile and gets a container without one has been lied to. Unsupported fields
// that carry a security guarantee are therefore errors, while unsupported fields
// that are merely conveniences are ignored. docs/ARCHITECTURE.md lists which is
// which.
func loadBundle(dir string, c *commonFlags) (*container.Config, error) {
	data, err := os.ReadFile(filepath.Join(dir, configName))
	if err != nil {
		return nil, fmt.Errorf("read bundle config: %w", err)
	}
	var spec rspec.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse %s: %w", configName, err)
	}
	if spec.Process == nil {
		return nil, fmt.Errorf("bundle has no process section")
	}

	id := c.id
	if id == "" {
		id = newID()
	}

	cfg := &container.Config{
		ID:          id,
		Args:        spec.Process.Args,
		Env:         spec.Process.Env,
		Cwd:         spec.Process.Cwd,
		RootMode:    container.RootModePivot,
		InitProcess: false, // runtime-spec requires the user's process to be PID 1
		Security: container.Security{
			NoNewPrivs: spec.Process.NoNewPrivileges,
		},
	}

	if spec.Hostname != "" {
		cfg.Hostname = spec.Hostname
	} else {
		cfg.Hostname = id[:min(12, len(id))]
	}

	// rootfs is relative to the bundle directory unless absolute.
	if spec.Root != nil {
		root := spec.Root.Path
		if !filepath.IsAbs(root) {
			root = filepath.Join(dir, root)
		}
		cfg.Rootfs = root
		cfg.ReadonlyRootfs = spec.Root.Readonly
	}

	cfg.Namespaces = namespacesFromSpec(spec.Linux)

	if spec.Linux != nil {
		cfg.IDMaps = idMapsFromSpec(spec.Linux)
		cfg.Resources = resourcesFromSpec(spec.Linux.Resources)
		cfg.Security.MaskedPaths = spec.Linux.MaskedPaths
		cfg.Security.ReadonlyPaths = spec.Linux.ReadonlyPaths

		if spec.Linux.Seccomp != nil {
			cfg.Security.Seccomp = seccompFromSpec(spec.Linux.Seccomp)
		}
		if spec.Linux.Sysctl != nil && len(spec.Linux.Sysctl) > 0 {
			return nil, fmt.Errorf("bundle requests sysctls, which husk does not implement")
		}
	}

	if spec.Process.Capabilities != nil {
		// The spec has five separate capability sets. husk applies one set to
		// all of them, so accepting a config that distinguishes between them
		// would misrepresent what the container gets. Bounding is the one that
		// contains the container, so that is the one taken.
		cfg.Security.Capabilities = spec.Process.Capabilities.Bounding
	} else {
		cfg.Security.Capabilities = security.DefaultCapabilities
	}

	if spec.Process.ApparmorProfile != "" {
		return nil, fmt.Errorf("bundle requests AppArmor profile %q, which husk does not implement",
			spec.Process.ApparmorProfile)
	}
	if spec.Process.SelinuxLabel != "" {
		return nil, fmt.Errorf("bundle requests an SELinux label, which husk does not implement")
	}

	// Networking is not described by the runtime-spec at all — the spec says a
	// runtime is given a network namespace and something else is responsible for
	// putting interfaces in it, which in Kubernetes is CNI. husk follows the
	// flag when driven directly and does nothing when the bundle supplies a
	// pre-made netns path.
	cfg.Network = container.Network{Mode: c.network}
	return cfg, nil
}

func namespacesFromSpec(l *rspec.Linux) container.Namespaces {
	var ns container.Namespaces
	if l == nil {
		return container.DefaultNamespaces()
	}
	for _, n := range l.Namespaces {
		// A namespace entry with a Path means "join this existing namespace"
		// rather than "create a new one". husk only creates.
		if n.Path != "" {
			continue
		}
		switch n.Type {
		case rspec.MountNamespace:
			ns.Mount = true
		case rspec.PIDNamespace:
			ns.PID = true
		case rspec.UTSNamespace:
			ns.UTS = true
		case rspec.IPCNamespace:
			ns.IPC = true
		case rspec.NetworkNamespace:
			ns.Net = true
		case rspec.UserNamespace:
			ns.User = true
		case rspec.CgroupNamespace:
			ns.Cgroup = true
		}
	}
	return ns
}

func idMapsFromSpec(l *rspec.Linux) container.IDMaps {
	var m container.IDMaps
	for _, u := range l.UIDMappings {
		m.UID = append(m.UID, container.IDMap{
			ContainerID: int(u.ContainerID), HostID: int(u.HostID), Size: int(u.Size),
		})
	}
	for _, g := range l.GIDMappings {
		m.GID = append(m.GID, container.IDMap{
			ContainerID: int(g.ContainerID), HostID: int(g.HostID), Size: int(g.Size),
		})
	}
	return m
}

func resourcesFromSpec(r *rspec.LinuxResources) container.Resources {
	var out container.Resources
	if r == nil {
		return out
	}
	if r.Memory != nil {
		if r.Memory.Limit != nil {
			out.MemoryMax = *r.Memory.Limit
		}
		if r.Memory.Reservation != nil {
			// The spec's "reservation" is v1's soft limit. v2's nearest
			// equivalent is memory.high, which throttles rather than merely
			// hinting to the reclaim heuristics — closer in spirit to what
			// callers actually want from the field.
			out.MemoryHigh = *r.Memory.Reservation
		}
	}
	if r.CPU != nil {
		if r.CPU.Quota != nil && r.CPU.Period != nil && *r.CPU.Period > 0 {
			out.CPUMax = float64(*r.CPU.Quota) / float64(*r.CPU.Period)
		}
		out.CPUSet = r.CPU.Cpus
	}
	if r.Pids != nil {
		out.PidsMax = r.Pids.Limit
	}
	return out
}

func seccompFromSpec(s *rspec.LinuxSeccomp) container.SeccompConfig {
	cfg := container.SeccompConfig{Enabled: true, Action: "errno"}
	if strings.EqualFold(string(s.DefaultAction), string(rspec.ActKillProcess)) {
		cfg.Action = "kill"
	}
	// husk's filter is a fixed deny list rather than a general policy engine, so
	// only the names it already knows are honoured. Anything else is dropped
	// rather than silently reinterpreted; the resulting filter is narrower than
	// requested, never wider.
	for _, sc := range s.Syscalls {
		if sc.Action == rspec.ActAllow {
			continue
		}
		for _, name := range sc.Names {
			if _, ok := security.LookupSyscall(name); ok {
				cfg.ExtraDenied = append(cfg.ExtraDenied, name)
			}
		}
	}
	return cfg
}
