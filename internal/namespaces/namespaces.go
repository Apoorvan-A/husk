// Package namespaces turns the requested namespace set into clone(2) flags and
// builds the uid/gid translation tables for a user-namespaced child.
package namespaces

import (
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/apoorvan10/husk/internal/container"
)

// CloneFlags maps the requested namespaces onto the CLONE_NEW* bits.
//
// The historical wart worth knowing: the mount namespace flag is CLONE_NEWNS,
// not CLONE_NEWMNT. Mount namespaces landed in Linux 2.4.19 as the first and, at
// the time, only namespace, so they got the generic name. Everything added
// afterwards had to be more specific.
//
// One flag here behaves unlike the others. CLONE_NEWPID does not move the
// calling process into the new PID namespace — it arranges for the *child* to
// be PID 1 in it. It has to work that way: a process's PID is baked into
// structures its parent and any waiters already hold, so renumbering a running
// process would invalidate every one of them. This is why `unshare(CLONE_NEWPID)`
// appears to do nothing until you fork, and why husk always re-execs itself
// rather than unsharing in place.
func CloneFlags(ns container.Namespaces) uintptr {
	var f uintptr
	if ns.Mount {
		f |= unix.CLONE_NEWNS
	}
	if ns.PID {
		f |= unix.CLONE_NEWPID
	}
	if ns.UTS {
		f |= unix.CLONE_NEWUTS
	}
	if ns.IPC {
		f |= unix.CLONE_NEWIPC
	}
	if ns.Net {
		f |= unix.CLONE_NEWNET
	}
	if ns.User {
		f |= unix.CLONE_NEWUSER
	}
	if ns.Cgroup {
		f |= unix.CLONE_NEWCGROUP
	}
	return f
}

// Names lists the enabled namespaces for logging and `husk state`.
func Names(ns container.Namespaces) []string {
	var out []string
	for _, e := range []struct {
		on   bool
		name string
	}{
		{ns.Mount, "mnt"}, {ns.PID, "pid"}, {ns.UTS, "uts"},
		{ns.IPC, "ipc"}, {ns.Net, "net"}, {ns.User, "user"}, {ns.Cgroup, "cgroup"},
	} {
		if e.on {
			out = append(out, e.name)
		}
	}
	return out
}

// SysProcIDMaps converts our maps into the form os/exec understands.
//
// The maps cannot be written by the child. /proc/<pid>/uid_map may only be
// written by a process holding CAP_SETUID in the user namespace that *owns* the
// target one — the parent's — and the child left that namespace the moment
// clone(2) returned. So the parent must write them, and it must do so before the
// child execs, or the container's entry point runs briefly as the overflow uid
// (65534) with no mapping at all.
//
// Handing them to SysProcAttr rather than writing /proc ourselves buys exactly
// that ordering guarantee: the Go runtime's fork helper has the child block on an
// internal pipe immediately after clone, writes the maps from the parent, and
// only then releases the child to exec. Writing them from our own code after
// cmd.Start() returns would be a race we would usually win and occasionally
// lose.
//
// GidMappingsEnableSetgroups is left false on purpose, which makes the runtime
// write "deny" to /proc/<pid>/setgroups before gid_map. That ordering is a
// security requirement, not a formality. Without the gate an unprivileged
// process inside the namespace can call setgroups(2) to *drop* a supplementary
// group — and dropping a group is how you reach a file whose mode denies that
// group but permits others (mode 0604, group-owned by a group you are in). The
// kernel added the gate in 3.19 for precisely this; it is one-way, and writing
// it after gid_map is populated fails with EPERM.
func SysProcIDMaps(maps container.IDMaps) (uid, gid []syscall.SysProcIDMap) {
	for _, m := range maps.UID {
		uid = append(uid, syscall.SysProcIDMap{
			ContainerID: m.ContainerID, HostID: m.HostID, Size: m.Size,
		})
	}
	for _, m := range maps.GID {
		gid = append(gid, syscall.SysProcIDMap{
			ContainerID: m.ContainerID, HostID: m.HostID, Size: m.Size,
		})
	}
	return uid, gid
}

// RootlessMaps builds the identity a rootless container runs under: root inside,
// the invoking user outside. `id` reports uid 0 in the container while `ps -o
// uid` on the host reports the caller's real uid, which is the whole point —
// the container's root has authority over nothing outside its own namespace.
//
// Only the caller's own id is mapped. Mapping a *range*, so the container can
// host more than one user, requires /etc/subuid delegation and the setuid
// helpers newuidmap/newgidmap, because an unprivileged process may only map ids
// it already owns. That boundary is deliberate and recorded in
// docs/SECURITY-MODEL.md.
func RootlessMaps(uid, gid int) container.IDMaps {
	return container.IDMaps{
		UID: []container.IDMap{{ContainerID: 0, HostID: uid, Size: 1}},
		GID: []container.IDMap{{ContainerID: 0, HostID: gid, Size: 1}},
	}
}
