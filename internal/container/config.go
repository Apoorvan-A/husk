package container

// Config is the complete description of a container, produced by the CLI (or by
// parsing an OCI config.json) in the runtime process and shipped verbatim across
// the fork boundary to `husk init`.
//
// It is deliberately a plain serialisable struct with no methods that touch the
// host: after the clone(2) the child is in a foreign set of namespaces and, under
// rootless, has no privileges yet. Anything it needs must already be in this
// struct, because it cannot go back and ask.
type Config struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	Args     []string `json:"args"`
	Env      []string `json:"env"`
	Cwd      string   `json:"cwd"`

	// Rootfs is the path the child will make its "/". Under overlayfs this is
	// the merged mountpoint, not any single layer.
	Rootfs string `json:"rootfs"`

	// RootMode selects how the child pivots into Rootfs. The chroot mode exists
	// only so the escape suite can demonstrate the breakout it permits; see
	// mounts.SetupRootChroot.
	RootMode RootMode `json:"rootMode"`

	// ReadonlyRootfs remounts the new / read-only after the pivot, once all the
	// writable submounts (/proc, /sys, /dev) are already in place.
	ReadonlyRootfs bool `json:"readonlyRootfs"`

	Namespaces Namespaces `json:"namespaces"`
	IDMaps     IDMaps     `json:"idMaps"`
	Resources  Resources  `json:"resources"`
	Network    Network    `json:"network"`
	Security   Security   `json:"security"`

	// InitProcess keeps `husk init` resident as PID 1, supervising the user's
	// command instead of execve-ing it away. That costs one process but gains
	// zombie reaping and signal forwarding, which a program written to be a
	// service rather than an init will not do for itself.
	//
	// `husk run` defaults this on, matching `docker run --init`. The OCI
	// create/start path leaves it off, because runtime-spec conformance requires
	// the user's process to *be* PID 1 and to own the container's exit status.
	InitProcess bool `json:"initProcess"`

	// AwaitStart holds the fully-constructed container at the start line until
	// `husk start` opens the exec FIFO. This is the OCI create/start split;
	// `husk run` leaves it false and the workload begins immediately.
	AwaitStart bool `json:"awaitStart"`

	// NoPivot disables the mount setup entirely. Used by unit tests that only
	// want to observe namespace behaviour.
	NoPivot bool `json:"noPivot"`
}

// RootMode selects the mechanism used to enter the container root.
type RootMode string

const (
	// RootModePivot is the real implementation: mount propagation is made
	// private, the rootfs is bind-mounted onto itself so it is a mountpoint,
	// pivot_root(2) swaps it in, and the old root is detached.
	RootModePivot RootMode = "pivot"

	// RootModeChroot is the naive implementation every "container in 100 lines"
	// tutorial stops at. It is escapable by design and retained only as the
	// negative control for test/escape. Never use it for anything real.
	RootModeChroot RootMode = "chroot"
)

// Namespaces records which of the seven namespaces this container gets its own
// copy of. Each maps to a CLONE_NEW* flag passed to clone(2).
type Namespaces struct {
	Mount  bool `json:"mount"`  // CLONE_NEWNS      - mount table
	PID    bool `json:"pid"`    // CLONE_NEWPID     - process ID numbering
	UTS    bool `json:"uts"`    // CLONE_NEWUTS     - hostname / domainname
	IPC    bool `json:"ipc"`    // CLONE_NEWIPC     - SysV IPC, POSIX message queues
	Net    bool `json:"net"`    // CLONE_NEWNET     - network stack
	User   bool `json:"user"`   // CLONE_NEWUSER    - uid/gid mapping, capabilities
	Cgroup bool `json:"cgroup"` // CLONE_NEWCGROUP  - cgroup root for /proc/self/cgroup
}

// DefaultNamespaces is the full set. User namespaces are opt-in because running
// with one changes what the container can do to a bind-mounted host path.
func DefaultNamespaces() Namespaces {
	return Namespaces{Mount: true, PID: true, UTS: true, IPC: true, Net: true, Cgroup: true}
}

// IDMap is one line of /proc/<pid>/uid_map or gid_map: "ContainerID HostID Size".
type IDMap struct {
	ContainerID int `json:"containerID"`
	HostID      int `json:"hostID"`
	Size        int `json:"size"`
}

// IDMaps carries the uid/gid translation tables the parent writes on the child's
// behalf. The child cannot write its own maps when unprivileged: writing uid_map
// requires CAP_SETUID in the *parent* user namespace, which the child no longer
// has once it is inside the new one.
type IDMaps struct {
	UID []IDMap `json:"uid"`
	GID []IDMap `json:"gid"`
}

// Resources are the cgroup v2 limits. Zero means "leave the controller at its
// inherited default" rather than "set it to zero".
type Resources struct {
	MemoryMax  int64   `json:"memoryMax"`  // memory.max, bytes. Hard limit; breach means OOM kill.
	MemoryHigh int64   `json:"memoryHigh"` // memory.high, bytes. Soft limit; breach means reclaim throttling.
	CPUMax     float64 `json:"cpuMax"`     // cpu.max, in CPUs. 0.5 becomes "50000 100000".
	PidsMax    int64   `json:"pidsMax"`    // pids.max. The fork-bomb ceiling.
	IOMax      string  `json:"ioMax"`      // io.max, written through verbatim: "MAJ:MIN rbps=... wbps=..."
	CPUSet     string  `json:"cpuSet"`     // cpuset.cpus, e.g. "0-3"

	// MemorySwapMax is memory.swap.max in bytes: how much swap the container may
	// use. nil means "apply husk's default", which is zero whenever MemoryMax is
	// set.
	//
	// Setting memory.max without also bounding swap does not bound the
	// container. Anonymous memory is reclaimable when there is swap to reclaim
	// it into, so a container that allocates past its limit is quietly paged out
	// instead of being OOM-killed: it keeps running, memory.events records
	// thousands of `max` breaches, no kill ever happens, and the host's disk
	// takes the load. On a machine with swap enabled — which is most of them —
	// a runtime that writes only memory.max has implemented a performance cliff
	// rather than a limit.
	//
	// Note the v1-to-v2 change here, because it is a common source of confusion:
	// v1's memory.memsw.limit_in_bytes was a *combined* memory-plus-swap ceiling,
	// while v2's memory.swap.max counts swap alone and is independent of
	// memory.max.
	MemorySwapMax *int64 `json:"memorySwapMax,omitempty"`
}

// PortMapping is one -p HOSTPORT:CONTAINERPORT rule, realised as a DNAT.
type PortMapping struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"` // tcp | udp
	HostIP        string `json:"hostIP"`
}

// Network describes the container end of the veth pair. The host end, the bridge
// and the netfilter rules are the parent's problem and never appear here.
type Network struct {
	Mode string `json:"mode"` // bridge | none | host

	// Interface config resolved by the parent's IPAM and handed to the child so
	// it can bring the link up from inside the netns.
	//
	// PeerName is what the veth end is called when it arrives in the namespace;
	// IfaceName is what the container should call it. The rename happens in the
	// child because interface names only have to be unique per namespace, and
	// doing it from the host would require re-entering the netns.
	PeerName  string   `json:"peerName"`
	IfaceName string   `json:"ifaceName"`
	IP        string   `json:"ip"` // CIDR, e.g. 10.66.0.4/24
	Gateway   string   `json:"gateway"`
	MTU       int      `json:"mtu"`
	DNS       []string `json:"dns"`

	Ports []PortMapping `json:"ports"`
}

// Security holds the three layers applied immediately before execve, in the only
// order that works: capabilities, then no_new_privs, then seccomp.
type Security struct {
	// Capabilities to retain. Everything else is stripped from the bounding set,
	// which makes the drop irreversible for the process and all its children.
	Capabilities []string `json:"capabilities"`

	// NoNewPrivs sets PR_SET_NO_NEW_PRIVS. Required before an unprivileged
	// process may install a seccomp filter, and it also neuters setuid binaries
	// inside the container.
	NoNewPrivs bool `json:"noNewPrivs"`

	Seccomp SeccompConfig `json:"seccomp"`

	// MaskedPaths are bind-mounted over with /dev/null; ReadonlyPaths get a
	// bind + remount read-only. Both cover the parts of /proc and /sys that
	// namespaces do not virtualise.
	MaskedPaths   []string `json:"maskedPaths"`
	ReadonlyPaths []string `json:"readonlyPaths"`
}

// SeccompConfig selects the syscall filter policy.
type SeccompConfig struct {
	Enabled bool `json:"enabled"`

	// Action taken on a denied syscall. "errno" returns EPERM and lets the
	// process continue; "kill" terminates the thread. Docker defaults to errno
	// for compatibility, which is also the more useful default for a test suite
	// that wants to observe the denial.
	Action string `json:"action"`

	// ExtraDenied is appended to the built-in deny list.
	ExtraDenied []string `json:"extraDenied"`
}
