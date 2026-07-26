// Package cgroups implements resource control against the cgroup v2 unified
// hierarchy.
//
// v1 is not supported and that is deliberate. v1 gave every controller its own
// independent hierarchy, so a process could sit in one place for memory and a
// completely different place for cpu, and there was no way to ask a coherent
// question like "what is this container's total resource usage". Worse, the
// memory controller could not account page cache back to the cgroup that dirtied
// it, so memory and io accounting disagreed about who was responsible for
// writeback. v2 has one tree, every controller attached to it, and consistent
// ownership — which is the whole reason it can do memory.high and io.max
// sensibly at all.
package cgroups

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/apoorvan10/husk/internal/container"
)

// Root is the unified hierarchy mountpoint.
const Root = "/sys/fs/cgroup"

// Controllers husk needs enabled in its subtree.
var requiredControllers = []string{"cpu", "memory", "pids", "io"}

// Manager owns one container's cgroup directory.
type Manager struct {
	// Parent is the cgroup husk's containers are created under, relative to
	// Root. Defaults to "husk".
	Parent string
	ID     string
}

// New returns a manager for a container. parent may be empty for the default.
func New(id, parent string) *Manager {
	if parent == "" {
		parent = "husk"
	}
	return &Manager{Parent: strings.Trim(parent, "/"), ID: id}
}

// Path is the container's own cgroup directory.
func (m *Manager) Path() string { return filepath.Join(Root, m.Parent, m.ID) }

// parentPath is the intermediate cgroup that holds every husk container.
func (m *Manager) parentPath() string { return filepath.Join(Root, m.Parent) }

// Available reports whether the unified hierarchy is mounted. The magic number
// is what distinguishes cgroup2 from the v1 "cgroup" filesystem, which shares
// the mountpoint name and is otherwise easy to mistake for it.
func Available() bool {
	var st unix.Statfs_t
	if err := unix.Statfs(Root, &st); err != nil {
		return false
	}
	return st.Type == unix.CGROUP2_SUPER_MAGIC
}

// Create builds the container's cgroup and enables the controllers it needs.
//
// The delegation dance is the part worth understanding. A controller is not
// simply "on" for a cgroup — it is enabled for a cgroup's *children* by writing
// "+name" to that cgroup's cgroup.subtree_control. So for a process in
// /sys/fs/cgroup/husk/<id> to be subject to the memory controller, memory must
// be in the subtree_control of both the root and of husk. Each level has to
// hand the controller down explicitly, and a level can only hand down what
// appears in its own cgroup.controllers.
//
// The no-internal-processes rule constrains the shape: with one exception for
// the root, a cgroup may not both contain processes and enable controllers for
// its children. The reason is that resource distribution would otherwise be
// ambiguous — the kernel would have to arbitrate between a process and a whole
// subtree competing at the same level, with no defined weighting between them.
// That is why the layout below always has an empty intermediate directory:
//
//	/sys/fs/cgroup/husk/          subtree_control: +cpu +memory +pids +io
//	                              cgroup.procs:    empty (required)
//	/sys/fs/cgroup/husk/<id>/     cgroup.procs:    the container's PIDs
//	                              subtree_control: empty — it is a leaf
func (m *Manager) Create() error {
	if !Available() {
		return fmt.Errorf("cgroup v2 unified hierarchy not mounted at %s", Root)
	}

	if err := os.MkdirAll(m.parentPath(), 0o755); err != nil {
		return fmt.Errorf("create parent cgroup: %w", err)
	}

	// Hand the controllers down from the root to our parent, then from our
	// parent to the container. Each step is only possible if the level above
	// already delegated.
	if err := enableControllers(Root); err != nil {
		return err
	}
	if err := enableControllers(m.parentPath()); err != nil {
		return err
	}

	if err := os.Mkdir(m.Path(), 0o755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create container cgroup: %w", err)
	}
	return nil
}

// enableControllers writes the "+name" additions that a level has available but
// has not yet delegated. Writing a controller that is already enabled is
// harmless; writing one absent from cgroup.controllers returns ENOENT, so the
// available set is intersected first.
//
// On a systemd host the root's subtree_control is systemd's to manage, and
// controllers it has not delegated are simply not available to us. Rather than
// fight it, husk reports which controller is missing and how to delegate it
// properly — see docs/ARCHITECTURE.md on running under a delegated slice.
func enableControllers(dir string) error {
	available, err := readList(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read cgroup.controllers in %s: %w", dir, err)
	}
	enabled, err := readList(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return fmt.Errorf("read cgroup.subtree_control in %s: %w", dir, err)
	}

	have := map[string]bool{}
	for _, c := range available {
		have[c] = true
	}
	already := map[string]bool{}
	for _, c := range enabled {
		already[c] = true
	}

	var missing []string
	for _, c := range requiredControllers {
		if !have[c] {
			missing = append(missing, c)
			continue
		}
		if already[c] {
			continue
		}
		if err := writeFile(filepath.Join(dir, "cgroup.subtree_control"), "+"+c); err != nil {
			// EBUSY here almost always means the no-internal-processes rule:
			// the cgroup already holds processes, so it cannot start
			// distributing resources to children.
			return fmt.Errorf("enable controller %q in %s: %w", c, dir, err)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("controllers %s are not delegated to %s; see docs/ARCHITECTURE.md on cgroup delegation",
			strings.Join(missing, ", "), dir)
	}
	return nil
}

// Apply writes the limits. Every value is optional: an unset field leaves the
// controller at whatever it inherited rather than clamping it to zero.
func (m *Manager) Apply(r container.Resources) error {
	if r.MemoryMax > 0 {
		// memory.max is the hard wall. Allocation past it triggers reclaim, and
		// if reclaim cannot free enough the cgroup OOM killer fires *inside the
		// cgroup* — it picks a victim from the container's processes, not from
		// the host's. That containment is the whole point: an unbounded
		// container degrades itself rather than the machine.
		if err := m.write("memory.max", strconv.FormatInt(r.MemoryMax, 10)); err != nil {
			return err
		}
	}
	// Swap must be bounded alongside memory or memory.max does not hold; see the
	// comment on Resources.MemorySwapMax. Defaulting to zero whenever a memory
	// limit is set makes "-memory 64M" mean what a reader expects it to mean.
	if r.MemorySwapMax != nil {
		if err := m.writeLimit("memory.swap.max", *r.MemorySwapMax); err != nil {
			return err
		}
	} else if r.MemoryMax > 0 {
		if err := m.writeLimit("memory.swap.max", 0); err != nil {
			return err
		}
	}
	if r.MemoryHigh > 0 {
		// memory.high is a different mechanism, not just a smaller number.
		// Crossing it does not kill anything; it puts the allocating process
		// under increasing reclaim pressure and throttles it, so a workload that
		// briefly spikes is slowed rather than destroyed. In production this is
		// the one you actually want as the primary limit, with memory.max as the
		// backstop.
		if err := m.write("memory.high", strconv.FormatInt(r.MemoryHigh, 10)); err != nil {
			return err
		}
	}
	if r.CPUMax > 0 {
		// cpu.max is "QUOTA PERIOD" in microseconds: the cgroup may consume
		// QUOTA microseconds of CPU time in each PERIOD. 0.5 CPUs becomes
		// "50000 100000".
		//
		// The operational consequence is worth stating precisely, because it is
		// a tail-latency problem and not a throughput one: a process that
		// exhausts its quota is *descheduled until the next period boundary*.
		// A thread holding a lock when that happens keeps holding it for the
		// remainder of the period, so p99 latency degrades far out of
		// proportion to the average CPU shortfall. This is why CPU throttling on
		// a latency-sensitive service shows up as sporadic multi-hundred-
		// millisecond stalls rather than uniform slowness.
		const period = 100000
		quota := int64(r.CPUMax * period)
		if err := m.write("cpu.max", fmt.Sprintf("%d %d", quota, period)); err != nil {
			return err
		}
	}
	if r.PidsMax > 0 {
		// The fork-bomb ceiling. Without it a container can exhaust the host's
		// global PID space, at which point nothing on the machine can fork —
		// including the runtime that would clean up the container.
		if err := m.write("pids.max", strconv.FormatInt(r.PidsMax, 10)); err != nil {
			return err
		}
	}
	if r.IOMax != "" {
		if err := m.write("io.max", r.IOMax); err != nil {
			return err
		}
	}
	if r.CPUSet != "" {
		if err := m.write("cpuset.cpus", r.CPUSet); err != nil {
			return err
		}
	}
	return nil
}

// AddProcess moves a PID into the container's cgroup.
//
// Writing to cgroup.procs migrates the whole thread group, which is what a
// container wants; cgroup.threads exists for the thread-granularity case and is
// only usable in the threaded mode of the hierarchy.
//
// The timing is what matters here. This runs after clone but before the child is
// released to exec, so the user's command is subject to the limits from its very
// first instruction. Applying limits after exec leaves a window in which an
// adversarial workload can allocate freely — small, but a memory bomb only needs
// one pass.
func (m *Manager) AddProcess(pid int) error {
	return m.write("cgroup.procs", strconv.Itoa(pid))
}

// Destroy removes the cgroup. A cgroup with live processes cannot be removed —
// rmdir returns EBUSY — so callers must have killed everything first.
func (m *Manager) Destroy() error {
	if err := os.Remove(m.Path()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove cgroup: %w", err)
	}
	return nil
}

// Processes lists the PIDs currently in the cgroup, host-namespace numbered.
func (m *Manager) Processes() ([]int, error) {
	data, err := os.ReadFile(filepath.Join(m.Path(), "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, line := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(line); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// KillAll uses cgroup.kill, added in Linux 5.14, which delivers SIGKILL to every
// process in the subtree atomically. Iterating cgroup.procs and killing PIDs one
// at a time races a forking workload, which can spawn faster than the loop
// reads — a fork bomb is precisely the case where the naive approach never
// terminates.
func (m *Manager) KillAll() error {
	path := filepath.Join(m.Path(), "cgroup.kill")
	if err := writeFile(path, "1"); err != nil {
		if os.IsNotExist(err) {
			return m.killIteratively()
		}
		return err
	}
	return nil
}

func (m *Manager) killIteratively() error {
	pids, err := m.Processes()
	if err != nil {
		return err
	}
	for _, pid := range pids {
		_ = unix.Kill(pid, unix.SIGKILL)
	}
	return nil
}

func (m *Manager) write(name, value string) error {
	return writeFile(filepath.Join(m.Path(), name), value)
}

// writeLimit writes a limit file, translating a negative value to the literal
// "max" the kernel expects for "unlimited". A limit file will not accept -1.
//
// A missing file is tolerated: memory.swap.max does not exist on a kernel built
// without CONFIG_MEMCG_SWAP, and refusing to start a container on such a host
// would be worse than running without a swap limit there.
func (m *Manager) writeLimit(name string, value int64) error {
	text := strconv.FormatInt(value, 10)
	if value < 0 {
		text = "max"
	}
	err := m.write(name, text)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// writeFile writes a cgroup control file. These are not ordinary files: the
// kernel parses each write() as a complete command, so the value must go out in
// a single call and must not be buffered or split. os.WriteFile with O_TRUNC
// would also be wrong for the "+controller" append semantics of
// subtree_control, hence the explicit O_WRONLY open.
func writeFile(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(value); err != nil {
		return fmt.Errorf("write %q to %s: %w", value, path, err)
	}
	return nil
}

func readList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(data)), nil
}
