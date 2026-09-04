package cli

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/Apoorvan-A/husk/internal/container"
)

// commonFlags are the options shared by `run` and `create`.
type commonFlags struct {
	id        string
	hostname  string
	memory    string
	memHigh   string
	memSwap   string
	cpus      float64
	pids      int64
	ioMax     string
	cpuSet    string
	ports     stringList
	env       stringList
	rootfs    string
	image     string
	cwd       string
	readonly  bool
	network   string
	rootless  bool
	noSeccomp bool
	capsAdd   stringList
	capsDrop  stringList
	rootMode  string
	stateRoot string
	dataRoot  string
	cgParent  string
	initShim  bool
	detach    bool
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "container id (generated when omitted)")
	fs.StringVar(&c.hostname, "hostname", "", "hostname inside the container (defaults to the id)")
	fs.StringVar(&c.memory, "memory", "", "memory.max, e.g. 256M or 1G")
	fs.StringVar(&c.memHigh, "memory-high", "", "memory.high throttling threshold")
	fs.StringVar(&c.memSwap, "memory-swap", "",
		"memory.swap.max, or \"max\" for unlimited. Defaults to 0 whenever -memory is set, because "+
			"memory.max does not bound a container that can swap")
	fs.Float64Var(&c.cpus, "cpus", 0, "cpu.max quota in CPUs, e.g. 0.5")
	fs.Int64Var(&c.pids, "pids", 0, "pids.max")
	fs.StringVar(&c.ioMax, "io-max", "", "io.max, e.g. \"8:0 rbps=1048576\"")
	fs.StringVar(&c.cpuSet, "cpuset", "", "cpuset.cpus, e.g. 0-3")
	fs.Var(&c.ports, "p", "publish a port as HOST:CONTAINER[/proto] (repeatable)")
	fs.Var(&c.env, "e", "environment variable KEY=VALUE (repeatable)")
	fs.StringVar(&c.rootfs, "rootfs", "", "use a directory as the root filesystem, bypassing the image store")
	fs.StringVar(&c.image, "image", "", "image name from the local store")
	fs.StringVar(&c.cwd, "workdir", "/", "working directory inside the container")
	fs.BoolVar(&c.readonly, "read-only", false, "mount the container root read-only")
	fs.StringVar(&c.network, "net", "bridge", "network mode: bridge | none | host")
	fs.BoolVar(&c.rootless, "rootless", false, "run in a user namespace, mapping container root to the caller")
	fs.BoolVar(&c.noSeccomp, "no-seccomp", false, "disable the seccomp filter")
	fs.Var(&c.capsAdd, "cap-add", "retain an additional capability (repeatable)")
	fs.Var(&c.capsDrop, "cap-drop", "drop a capability from the default set (repeatable)")
	fs.StringVar(&c.rootMode, "root-mode", "pivot",
		"how to enter the container root: pivot | chroot. chroot is escapable and exists only for the escape test suite")
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	fs.StringVar(&c.dataRoot, "data-root", "", "image and layer store (default /var/lib/husk)")
	fs.StringVar(&c.cgParent, "cgroup-parent", "", "cgroup to create containers under, relative to the unified root")
	fs.BoolVar(&c.initShim, "init", true, "keep husk as PID 1 to reap zombies and forward signals")
}

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// parseMemory accepts the suffixes people actually type. Values are binary
// multiples, matching what the kernel reports back in memory.current — using
// decimal ones would make a "256M" limit read back as 244M and look like a bug.
func parseMemory(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.TrimSpace(s)
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "K"), strings.HasSuffix(s, "k"):
		mult, s = 1<<10, s[:len(s)-1]
	case strings.HasSuffix(s, "M"), strings.HasSuffix(s, "m"):
		mult, s = 1<<20, s[:len(s)-1]
	case strings.HasSuffix(s, "G"), strings.HasSuffix(s, "g"):
		mult, s = 1<<30, s[:len(s)-1]
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory value: %w", err)
	}
	return v * mult, nil
}

// parseSwap distinguishes the three states memory.swap.max needs: unset (nil,
// meaning apply husk's default), unlimited ("max"), and a byte count. A plain
// int64 could not express all three, since zero is a meaningful value here.
func parseSwap(s string) (*int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if strings.EqualFold(s, "max") || s == "-1" {
		unlimited := int64(-1)
		return &unlimited, nil
	}
	v, err := parseMemory(s)
	if err != nil {
		return nil, fmt.Errorf("memory-swap: %w", err)
	}
	return &v, nil
}

// parsePorts turns "8080:80" or "8080:80/udp" into mappings.
func parsePorts(specs []string) ([]container.PortMapping, error) {
	var out []container.PortMapping
	for _, spec := range specs {
		proto := "tcp"
		if s, p, ok := strings.Cut(spec, "/"); ok {
			spec, proto = s, p
		}
		hostStr, ctrStr, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf("port %q must be HOST:CONTAINER", spec)
		}
		host, err := strconv.Atoi(hostStr)
		if err != nil {
			return nil, fmt.Errorf("port %q: invalid host port", spec)
		}
		ctr, err := strconv.Atoi(ctrStr)
		if err != nil {
			return nil, fmt.Errorf("port %q: invalid container port", spec)
		}
		out = append(out, container.PortMapping{HostPort: host, ContainerPort: ctr, Protocol: proto})
	}
	return out, nil
}

// resolveCapabilities applies -cap-add and -cap-drop to the default set.
func resolveCapabilities(defaults, add, drop []string) []string {
	keep := map[string]bool{}
	for _, c := range defaults {
		keep[normaliseCap(c)] = true
	}
	for _, c := range add {
		keep[normaliseCap(c)] = true
	}
	for _, c := range drop {
		delete(keep, normaliseCap(c))
	}
	out := make([]string, 0, len(keep))
	for c := range keep {
		out = append(out, c)
	}
	return out
}

func normaliseCap(name string) string {
	n := strings.ToUpper(strings.TrimSpace(name))
	if !strings.HasPrefix(n, "CAP_") {
		n = "CAP_" + n
	}
	return n
}

// newID mints a container identifier. Randomness, not a counter: without a
// daemon there is nothing to hold a counter, and two concurrent `husk run`
// invocations must not collide.
func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("husk: no entropy available: %v", err))
	}
	return hex.EncodeToString(b)
}
