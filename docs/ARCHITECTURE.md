# Architecture

How husk is put together, and why the pieces are arranged the way they are.

## The shape of the problem

Creating a container requires two processes, because the work splits across a
privilege boundary that runs in both directions.

The **runtime process** can write `/proc/<pid>/uid_map`, create cgroups, and move
a veth interface into another namespace — all things that need privileges in the
*parent* namespace.

The **container process** is the only one that can mount inside its own mount
namespace, set its own hostname, or install its own seccomp filter — all things
that only exist once you are inside.

Neither can do the other's work, so they take turns, and each has to block until
the other is done. Getting the turn-taking wrong is not a hang; it is a security
hole. If the child reaches `execve` before the parent has applied cgroup limits,
the workload runs unconstrained for a window, and a memory bomb only needs one
pass.

## The handshake

```
runtime process                          husk init (child)
───────────────                          ─────────────────
clone(CLONE_NEW*)  ─────────────────────▶ starts, inherits fds 3,4,5[,6]
send StageConfig   ─────────────────────▶ decode config
                   ◀───────────────────── send StageChildBooted
write setgroups/uid_map/gid_map
echo pid > cgroup.procs
create veth, move peer into netns
install netfilter rules
send StageParentReady + network config ─▶ configure interfaces
                                          pivot_root, mount /proc /sys /dev
                                          mask paths
                                          drop capabilities
                                          no_new_privs, seccomp
                   ◀───────────────────── send StageChildJailed
                                          block on exec.fifo (create path only)
                                          execve, or supervise as PID 1
```

Two unidirectional pipes rather than a socketpair, because the child inherits
them as plain numbered descriptors and `os.Pipe` is the simplest thing that
survives `exec`. Descriptor assignment:

| fd | contents |
|---|---|
| 3 | sync pipe, read end |
| 4 | sync pipe, write end |
| 5 | the container's state directory, as an open directory fd |
| 6 | a sealed memfd holding a copy of the husk binary |

The parent must close its duplicates of the child's ends immediately after
`clone`. While it still holds the write end, a dead child never produces EOF on
the read side, so the next `Await` blocks forever instead of reporting the
failure.

## Ordering constraints

Almost every step in the child removes a privilege the next step would have
needed. The sequence is not stylistic.

| Step | Must come before | Because |
|---|---|---|
| `MS_REC\|MS_PRIVATE` on `/` | any mount | a new mount namespace copies the parent's table *including propagation type*; on a systemd host `/` is `MS_SHARED`, so every mount would propagate back to the host. `pivot_root` also returns `EINVAL` outright if the new root's parent is shared. |
| bind rootfs onto itself | `pivot_root` | `pivot_root` requires `new_root` to be a mountpoint, and a freshly extracted rootfs is just a directory. |
| `chdir("/")` | detaching `put_old` | `pivot_root` does not move the caller's cwd; until the `chdir`, the process holds a working directory on the old root, which is a live handle out of the container. |
| detach `put_old` | anything else | the old root is a fully browsable copy of the host filesystem until it goes. |
| mount `/proc` | reading `/proc/self/fd` | the exec FIFO is opened through `/proc/self/fd/5/`, which needs procfs. |
| all mounts | dropping capabilities | `mount` and `pivot_root` need `CAP_SYS_ADMIN`. |
| clear ambient set | shrinking the bounding set | a capability cannot leave `Permitted` while it is still `Ambient`. |
| shrink bounding set | `capset` | `PR_CAPBSET_DROP` needs `CAP_SETPCAP`, which `capset` is about to remove. |
| `capset` | raising ambient | a capability may only become ambient if it is in both `Permitted` and `Inheritable`. |
| `PR_SET_NO_NEW_PRIVS` | installing seccomp | an unprivileged process may only install a filter once it has promised it can never gain privileges through `execve`. |
| seccomp | `execve` | the filter denies several syscalls used during setup. |

## Threading

The init child calls `runtime.LockOSThread()` before anything else and never
releases it.

Capabilities, seccomp filters and the `no_new_privs` latch are properties of a
*thread*, not a process. The Go scheduler may move a goroutine to a different OS
thread at any function call, and if that happens between dropping capabilities
and exec'ing the workload, the exec inherits the credentials of whichever thread
it lands on — which still has the full set.

The failure is silent. The drop returns no error, the code reads correctly, and
the only symptom is `CapBnd` inside a running container. `test/escape`
`TestCapabilitiesAreDropped` exists because this bug was present and passing
review until a test read the value from inside.

The seccomp install avoids the same problem differently, with
`SECCOMP_FILTER_FLAG_TSYNC`, which applies the filter to every thread in the
group atomically. There is no equivalent flag for capabilities.

## The create/start split

The OCI runtime-spec requires that after `create` the container exists — holds
its namespaces, sits in its cgroup, has its network attached — but has not run
its entry point. `start` is a separate invocation, possibly much later, from a
different process.

A FIFO is the synchronisation primitive because of one property nothing else
has: `open(O_WRONLY)` on a FIFO blocks until some other process opens the read
end. The block is done by the kernel, so there is no polling, no timeout to tune,
and — the part that matters operationally — no way to miss the signal by arriving
late. If `start` runs first, *its* open blocks instead, and the two rendezvous in
either order.

A pipe would not work: the write end would be held by the runtime process, which
exits after `create`.

Two implementation details are load-bearing:

**The child opens it through `/proc/self/fd`.** By the time it opens the FIFO the
child has already pivoted, so the host path `/run/husk/<id>/exec.fifo` no longer
resolves. The parent passes an open descriptor to the *directory*, and a
directory fd survives `pivot_root` because it references an inode rather than a
path. `/proc/self/fd/5/exec.fifo` re-enters that directory through a handle the
mount namespace change could not invalidate.

**`husk start` opens with `O_NONBLOCK`.** A blocking `O_RDONLY` open waits for a
writer, and if the init process died during setup there will never be one —
`start` would hang forever with no diagnostic. A non-blocking open returns
immediately and still completes the rendezvous, because the waiting `O_WRONLY`
open unblocks as soon as *any* reader appears. The wait then moves to the read,
where it can be bounded and where the writer's liveness can be checked.

## PR_SET_PDEATHSIG, and where it must not be set

`husk run` sets `Pdeathsig: SIGKILL` on the child, so a container cannot outlive
the runtime process responsible for cleaning up its cgroup, veth pair and
netfilter rules.

`husk create` must not, and this is worth stating because the bug is confusing.
`create` is *supposed* to exit while the container waits on its start FIFO, so
pdeathsig kills the container the instant create succeeds. The symptom is a
container that reports `created`, has a plausible PID, and is already dead —
followed by `husk start` blocking forever on a FIFO whose writer no longer
exists. Both halves look like separate bugs.

A detached container is re-parented to PID 1 when the runtime exits, and its
cleanup becomes the state file's responsibility rather than the kernel's.

There is a second subtlety: pdeathsig fires when the *thread* that cloned the
child exits, not the process. Go retires idle threads, so without
`runtime.LockOSThread` around the fork, a perfectly healthy runtime can lose that
thread and the container dies for no reason.

## Detached stdio

A detached container's stdio must not be the caller's pipes.

The runtime exits while the container keeps running, so whatever the container
holds as stdout outlives the runtime. If that is a pipe belonging to the caller —
which is what any parent capturing output provides — the container holds the
write end open for its entire life, the caller's read never sees EOF, and a
program that only wanted the container id hangs waiting for a container that may
run for days. The deadlock is in the caller, with no error anywhere.

`husk create` therefore redirects to `<state-dir>/output.log`, which severs the
lifetime coupling and makes `husk logs` possible as a side effect.

## cgroup layout and delegation

```
/sys/fs/cgroup/                  subtree_control: +cpu +memory +pids +io
/sys/fs/cgroup/husk/             subtree_control: +cpu +memory +pids +io
                                 cgroup.procs:    empty — required
/sys/fs/cgroup/husk/<id>/        cgroup.procs:    the container's PIDs
                                 subtree_control: empty — it is a leaf
```

A controller is not simply "on" for a cgroup. It is enabled for a cgroup's
*children*, by writing `+name` to that cgroup's `cgroup.subtree_control`. Each
level hands the controller down explicitly, and can only hand down what appears
in its own `cgroup.controllers`.

The empty intermediate directory is required by the **no-internal-processes
rule**: except at the root, a cgroup may not both contain processes and enable
controllers for its children. Resource distribution would otherwise be ambiguous
— the kernel would have to arbitrate between a process and a whole subtree
competing at the same level, with no defined weighting between them.

### Running under systemd

On a systemd host the root's `subtree_control` is systemd's to manage, and
controllers it has not delegated are unavailable. Rather than fight it, place
husk's containers under a properly delegated slice:

```ini
# /etc/systemd/system/husk.slice
[Unit]
Description=husk containers

[Slice]
# Delegation is what makes the subtree writable by something other than systemd.
Delegate=yes
CPUAccounting=yes
MemoryAccounting=yes
IOAccounting=yes
TasksAccounting=yes
```

```bash
sudo systemctl daemon-reload
sudo systemctl start husk.slice
sudo husk run --cgroup-parent husk.slice --image alpine /bin/sh
```

## Storage

```
/var/lib/husk/
├── layers/<layer-id>/           immutable layer content
├── images/<name>                newline-separated layer ids, base layer first
└── containers/<id>/
    ├── upper/                   the container's writable layer
    ├── work/                    overlayfs scratch space
    └── merged/                  the mountpoint the container pivots into
```

`lowerdir` order is significant and counter-intuitive: the **leftmost** entry is
the topmost layer. Reversing it produces a container where an older layer shadows
a newer one, which usually presents as mysteriously stale binaries.

`workdir` must be on the same filesystem as `upperdir`. This is not arbitrary:
copy-up has to be atomic, so overlayfs builds the copied file in `workdir` and
`rename(2)`s it into `upperdir`. `rename` is only atomic within a filesystem, so
a `workdir` on a different mount makes the operation impossible and the kernel
refuses at mount time.

Two behaviours worth being able to describe:

**Copy-up.** Opening a `lowerdir` file for writing does not write to it.
overlayfs copies the whole file into `upperdir` first, then redirects the write.
The first write to a 2 GiB file costs 2 GiB of I/O regardless of how many bytes
are written — the reason database images perform badly on overlayfs and are
normally given a volume instead.

**Whiteouts.** Deleting a `lowerdir` file cannot remove it. overlayfs creates a
character device with major and minor both 0 at that path in `upperdir`, and the
union layer reads that node as "this name is deleted". Deleting a whole directory
uses a different marker: an empty directory in `upperdir` carrying the
`trusted.overlay.opaque="y"` xattr. Setting a `trusted.*` xattr needs
`CAP_SYS_ADMIN`, which is why overlayfs on a filesystem without xattr support
misbehaves silently, and why a rootless `husk commit` loses opaque markers.

## Networking

The host half runs in the runtime process; the container half runs in `husk init`
after the veth peer has been moved in. They are separate files for that reason —
netlink operates on the caller's namespace, and there is no way to address "some
other namespace" in the rtnetlink protocol. You have to be in it.

```
    host                                container netns
    ────                                ────────────────
    husk0 (bridge, 10.66.0.1/24)
      │
      └── hvethXXXXXXXX ══════════════ hvpeerXXXXXXXX → renamed to eth0
                                        10.66.0.N/24
                                        default via 10.66.0.1
```

Interface names are capped by `IFNAMSIZ`, which is 16 *including* the terminating
NUL — 15 usable characters. Exceeding it produces `ERANGE`, surfaced as
"numerical result out of range", which says nothing about names. Both ends must
fit, so the id suffix is sized against the longer prefix.

The rename happens inside the netns because names only have to be unique per
namespace, and the kernel refuses to rename a running interface — in-flight
packets already reference it — so the link must be down at that moment.

### Netfilter

Rules live in husk's own chains rather than appended to the built-ins, so
teardown can never delete something Docker or the host firewall installed.

```
nat/POSTROUTING  → HUSK-POSTROUTING   -s 10.66.0.0/24 ! -o husk0 -j MASQUERADE
                                       -s 127.0.0.0/8 -d 10.66.0.0/24 -j MASQUERADE
nat/PREROUTING   → HUSK-DNAT          -p tcp --dport 8080 -j DNAT --to 10.66.0.N:80
nat/OUTPUT       → HUSK-DNAT          (same chain; locally-generated traffic
                                       never traverses PREROUTING)
filter/FORWARD   → HUSK-FORWARD       -i husk0 ! -o husk0 -j ACCEPT
                                       -o husk0 -m conntrack --ctstate RELATED,ESTABLISHED
                                       -d 10.66.0.N -p tcp --dport 80 -o husk0 -j ACCEPT
```

The jump is *inserted* at position 1 rather than appended, because appending
places husk's rules after a host firewall's terminal DROP where they are never
evaluated.

Three things make a published port work that a bare DNAT rule does not:

1. **The `nat/OUTPUT` jump.** Traffic the host originates to itself never
   traverses PREROUTING, so without it `curl localhost:8080` fails from the host
   while the same request from another machine succeeds.
2. **`route_localnet` on the bridge.** After DNAT the packet still carries a
   source of 127.0.0.1 and now has to leave via the bridge. The martian-source
   check normally drops exactly that.
3. **A per-port FORWARD accept.** Off-box traffic is *forwarded* to the
   container, and the general rules only admit `RELATED,ESTABLISHED` in that
   direction — a new inbound connection would be dropped after DNAT had already
   rewritten it. The rule is written against the post-DNAT destination, because
   FORWARD runs after `nat/PREROUTING`.

Shelling out to `iptables` rather than speaking netlink is deliberate, and the
same choice Docker makes: the kernel interface to the legacy tables is not a
stable API, and the nft-vs-legacy backend split means the wrong one silently
writes rules the host never consults. The cost is measurable — it is essentially
all of the 185 ms gap between husk's no-network and bridge-network start times.

### IPAM

The allocation table is a directory of files named after the address, holding the
owning container id. Primitive, and it buys the one property that matters:
`O_CREAT|O_EXCL` is atomic in the kernel, so two concurrent `husk run` commands
cannot both claim the same address. There is no lock to forget and no daemon to
be the arbiter — which is the point, since husk does not have one.

## Sealed self-exec

husk copies its own binary into a `memfd`, seals it against writes, and execs
that instead of `/proc/self/exe`.

CVE-2019-5736 broke every runc-based runtime in 2019 by attacking exactly this
path. A malicious image makes `/bin/sh` a symlink to `/proc/self/exe`; when the
runtime's init process execs the entry point, it re-executes the *runtime binary*
from inside the container's mount namespace. A process already in the container
then opens `/proc/<pid>/exe` of that new process — a writable handle to the
runtime binary on the host — and overwrites it. The next container start runs the
attacker's code as root on the host.

A memfd is anonymous: it lives only in memory and has no filesystem path, so a
container cannot reach it by any route. `F_SEAL_WRITE` makes it immutable for
every holder of the descriptor, and `F_SEAL_SEAL` makes the sealing irreversible.
`F_SEAL_SHRINK` and `F_SEAL_GROW` close the flanking moves. The cost is one copy
of the binary per container start, freed as soon as exec completes.

## OCI compliance

husk implements `create`, `start`, `state`, `kill` and `delete` against
runtime-spec 1.2.0, and parses `config.json` from a bundle directory.

The translation from spec to husk config is where compliance actually lives, and
the rule is that anything carrying a **security guarantee** husk cannot honour is
an **error**, while anything that is merely a convenience is ignored. A caller
who asks for an AppArmor profile and silently gets a container without one has
been lied to.

Rejected outright:

- `process.apparmorProfile`
- `process.selinuxLabel`
- `linux.sysctl`

Honoured with documented narrowing:

- `linux.seccomp` — only syscall names husk's filter already knows; the result is
  always narrower than requested, never wider
- `process.capabilities` — the spec's five sets are collapsed to one, and
  `bounding` is the one taken, since it is the set that actually contains a
  container
- `linux.resources.memory.reservation` — mapped to `memory.high`, v2's nearest
  equivalent to v1's soft limit

Not implemented: hooks, annotations beyond passthrough, `linux.devices`, the
device cgroup, `linux.rdma`, and joining pre-existing namespaces by path.
Networking is deliberately absent from the spec — a runtime is handed a network
namespace and something else fills it, which in Kubernetes is CNI.
