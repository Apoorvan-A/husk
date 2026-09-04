# Security model

What husk isolates, what it does not, and where the edges are.

This document exists because the most useful thing a runtime can tell you is
what it fails to do. Everything below is a limitation of husk specifically; where
a limitation is shared with production runtimes, that is noted, because those
are the ones worth understanding rather than fixing.

## The one-sentence version

A container is a process the kernel has been asked to lie to. Namespaces control
what it can *see*, cgroups control what it can *consume*, and capabilities plus
seccomp control what it can *ask the kernel to do* — but it is still a process on
your kernel, making syscalls into the same code your host runs. There is exactly
one kernel, and every container on the box shares it.

## What husk does isolate

| Surface | Mechanism | Verified by |
|---|---|---|
| Filesystem view | `pivot_root` after `MS_REC\|MS_PRIVATE`, old root detached with `MNT_DETACH` | escape cases 1–2 |
| Process visibility | `CLONE_NEWPID` plus a freshly mounted procfs | case 3 |
| Mount table | private propagation before any mount | case 4 |
| Memory | `memory.max` **and** `memory.swap.max` | case 5 |
| CPU | `cpu.max` quota, throttling observable in `cpu.stat` | case 6 |
| Process count | `pids.max` | case 7 |
| Writes to the image | overlayfs `upperdir` | cases 8–9 |
| Network stack | `CLONE_NEWNET`, veth into the namespace | case 10 |
| Privileged operations | capability bounding-set reduction | case 11 |
| Syscall surface | seccomp-BPF deny list | case 12 |
| Host identity | `CLONE_NEWUSER` with uid/gid maps | case 13 |
| Privilege regain | `PR_SET_NO_NEW_PRIVS` | case 14 |
| Kernel state via procfs | masked and read-only paths | case 15 |
| Hostname, IPC, cgroup view | `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWCGROUP` | — |

## What husk does not isolate

### The kernel itself

This is the whole game, and it is not a husk limitation — it is what a container
*is*.

Every container on a host executes syscalls against one shared kernel. A kernel
vulnerability reachable from an unprivileged syscall is reachable from inside
every container simultaneously, and exploiting it yields ring-0 code execution
that no namespace observes or constrains. Namespaces are bookkeeping in kernel
data structures; code running *in* the kernel edits that bookkeeping freely.

The seccomp filter is the only thing that meaningfully shrinks this surface, and
it shrinks it by perhaps a fifth. Roughly 300 syscalls remain reachable.

The mitigation is not a better runtime. It is a different isolation boundary —
see [`CONTAINER-VS-VM.md`](CONTAINER-VS-VM.md).

### Side channels

Nothing here addresses Spectre, Meltdown, MDS, or their successors. Containers
share physical cores, caches, branch predictors and memory buses. Two containers
on one host can measure each other. Cloud providers schedule mutually distrusting
tenants on separate physical cores for exactly this reason; husk has no notion of
scheduling domains at all.

### Time

There is no time namespace support. A container sees the host's wall clock, and
though `settimeofday` and `clock_settime` are on the seccomp deny list, that only
prevents *writing* it. (Linux 5.6 added time namespaces, but they virtualise only
the monotonic and boot-time offsets, not the wall clock, so even full support
would not hide the real date.)

### The kernel keyring, and other unnamespaced globals

`keyctl`, `add_key` and `request_key` are denied by seccomp because the keyring
is not namespaced. That is a block, not isolation: a container granted those
syscalls would see host keys. The same shape applies to several other subsystems
that predate namespaces.

### Devices

husk provides a fixed set of device nodes — `null`, `zero`, `full`, `random`,
`urandom`, `tty` — and no device cgroup controller. There is no way to grant a
container access to a specific device, and no enforcement preventing one from
using a device node that was already present in its image. `MS_NODEV` on the API
filesystems covers the common case; a device node in the image's own `/dev` on a
`--rootfs` directory is not covered.

### Disk quota

`io.max` bounds throughput, not capacity. A container can fill the filesystem
backing its `upperdir`, which affects every other container sharing that
filesystem and the host. There is no per-container storage quota.

### The runtime process itself

`husk run` runs as root and does far more work as root than a hardened runtime
would. There is no privilege separation between the parts that need `CAP_SYS_ADMIN`
(mounting, `pivot_root`) and the parts that do not (parsing flags, allocating an
IP address).

## Known gaps specific to husk

These are places where husk is weaker than runc, listed so nobody has to discover
them by reading the source.

**PID reuse in state refresh.** `state.Refresh` checks liveness with `kill(pid, 0)`.
Between a container dying and that check, the kernel can recycle its PID onto an
unrelated process, and husk would report the container as running. A robust
runtime pins the identity with a pidfd, or compares the process start time from
`/proc/<pid>/stat`. See `internal/state/state.go`.

**Rootless maps one uid, not a range.** `--rootless` maps container uid 0 to the
caller and nothing else, so the container cannot have more than one user. Mapping
a range needs `/etc/subuid` delegation and the setuid helpers `newuidmap` and
`newgidmap`, which husk does not invoke.

**Rootless is gated by the host's procfs mount policy.** Mounting a fresh
procfs inside a user namespace is subject to the kernel's `mount_too_revealing`
check: if the host's own `/proc` carries locked submounts, the kernel refuses the
mount with `EPERM` even when the user namespace is owned by root. Whether this
triggers depends on the host kernel and its mount table, so `--rootless` works on
many hosts (developer machines, WSL2, most desktop distributions) and is refused
on others with a hardened `/proc`. husk does not work around this; a production
runtime would carry the container's masked-path set into the fresh mount so the
new procfs is never less revealing than the parent's locked mounts.

**Rootless commit loses opaque markers.** Setting `trusted.overlay.*` xattrs
requires `CAP_SYS_ADMIN`, so a layer committed rootlessly silently loses the
markers that record deleted directories. Deleted subtrees reappear when that
layer is used.

**`husk exec` cannot enter a user-namespaced container.** `setns(CLONE_NEWUSER)`
requires a single-threaded caller and the Go runtime is multi-threaded before
`main()` runs. husk reports this rather than failing obscurely. runc solves it
with `nsexec`, a C constructor that runs before the Go runtime initialises.

**No AppArmor, SELinux, or the device cgroup.** An OCI bundle requesting an
AppArmor profile or an SELinux label is *rejected* rather than silently run
without one — accepting it would be a lie about what the container got — but the
protection is simply unavailable.

**Layers are not content-addressed.** Layer ids are timestamps, so identical
layers are stored twice and nothing verifies a layer's integrity.

**Netfilter rules are shared and never garbage-collected.** Per-container DNAT
and FORWARD rules are removed on delete, but the shared MASQUERADE and general
FORWARD rules persist until `make purge`.

**No user-facing seccomp policy language.** The filter is a fixed deny list. An
OCI bundle's seccomp section is honoured only for syscall names husk already
knows; anything else is dropped. The resulting filter is always narrower than
requested, never wider, but it is not what was asked for.

**`husk kill` does not wait.** It sends the signal and returns. There is no
grace period followed by `SIGKILL` the way `docker stop` implements.

## Threat model

**In scope.** A non-malicious workload that misbehaves: leaks memory, spawns
processes without bound, spins on CPU, writes to files it should not, or crashes
in a way that would otherwise take the host with it. husk contains all of these,
and the escape suite proves it.

**Partially in scope.** A workload that actively probes its boundaries using
documented interfaces — trying to `chroot` out, read host processes, mount
things, reach other containers. The escape suite covers these and they are
blocked, but the coverage is a list of known attacks rather than a proof.

**Out of scope.** An attacker with a kernel exploit. Nothing in this repository
is relevant to that case, and no container runtime is.

## If you want the stronger boundary

Run the workload in a VM. A hypervisor's isolation boundary is enforced by
hardware — VT-x/AMD-V trap-and-emulate, EPT/NPT for memory — and the guest talks
to a separate kernel, so a guest kernel compromise gets you a compromised guest
rather than a compromised host. gVisor, Kata Containers and Firecracker exist to
give you that boundary with something closer to container ergonomics;
[`CONTAINER-VS-VM.md`](CONTAINER-VS-VM.md) covers where each sits and what it
costs.
