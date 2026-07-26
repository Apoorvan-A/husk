# husk

A minimal OCI-compatible container runtime, built directly on Linux kernel
primitives — no Docker, no libcontainer, no containerd.

```
husk run --image alpine --memory 256M --cpus 0.5 -p 8080:80 /bin/sh
```

## Scope, stated up front

**This is a learning implementation, not a production runtime. Use runc.**

It exists because "containers are just namespaces and cgroups" is a sentence
that is easy to say and hard to defend, and the only way I found to actually
defend it was to write one. Everything here is real — it creates namespaces,
writes cgroup limits, pivots into an overlayfs root, builds veth pairs, installs
netfilter rules and loads a seccomp filter — but it makes no attempt at the
completeness, the hardening, or the twelve years of edge cases that make runc
trustworthy. [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) is an explicit
list of what it does *not* protect against.

## What it does

| | |
|---|---|
| **Isolation** | 7 namespaces; `pivot_root` with `MS_REC\|MS_PRIVATE` propagation hardening; masked and read-only paths under `/proc` and `/sys` |
| **Resources** | cgroup v2 unified hierarchy — `memory.max`, `memory.high`, `memory.swap.max`, `cpu.max`, `pids.max`, `io.max`, with `memory.events` and `cpu.stat` read back |
| **Storage** | overlayfs copy-on-write roots, layered images, `husk commit` to snapshot a writable layer |
| **Networking** | veth pairs into the container netns, host bridge, IPAM, `MASQUERADE` egress, `DNAT` port publishing |
| **Security** | user namespaces for rootless execution, capability bounding-set reduction, `PR_SET_NO_NEW_PRIVS`, a hand-assembled seccomp-BPF filter (no libseccomp, no cgo) |
| **Lifecycle** | OCI runtime-spec `create`/`start`/`state`/`kill`/`delete`, FIFO-synchronised, state under `/run/husk/<id>` |
| **Observability** | Prometheus `/metrics` read straight from cgroup files, structured JSON lifecycle logs, `husk top` |
| **Tests** | 22 adversarial tests that try to break out of, or defeat the limits on, containers husk built |

## Quick start

Requires Linux ≥ 5.10, cgroup v2 unified hierarchy, and root.

```bash
make build && sudo make install
```

```bash
# Verify the environment is capable
stat -fc %T /sys/fs/cgroup    # must print: cgroup2fs

# Import a rootfs and run something
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz
sudo husk import alpine-minirootfs-3.21.3-x86_64.tar.gz alpine
sudo husk run --image alpine --memory 256M --cpus 0.5 /bin/sh
```

```bash
# The OCI lifecycle, driven by hand
sudo husk create --image alpine --id demo /bin/sh -c 'sleep 60'
sudo husk state demo          # "created" — the entry point has not run yet
sudo husk start demo          # releases it through the exec FIFO
sudo husk exec demo /bin/sh
sudo husk top
sudo husk kill demo TERM
sudo husk delete demo
```

## What happens during `husk run`

The whole point of the project is that this sequence is legible. Each step is a
syscall with a reason, and the ordering is forced — nearly every line removes a
privilege the next line would have needed.

```
husk run --memory 256M --cpus 0.5 -p 8080:80 --image alpine /bin/sh
│
├─ parse flags (or an OCI config.json)
├─ mount the overlayfs root         overlay: lowerdir=<layers>, upperdir, workdir → merged
├─ create the cgroup                mkdir /sys/fs/cgroup/husk/<id>, delegate controllers
├─ mkfifo /run/husk/<id>/exec.fifo  (create/start path only)
├─ copy self into a sealed memfd    memfd_create + F_SEAL_WRITE — see CVE-2019-5736
│
├─ clone(CLONE_NEWNS|NEWPID|NEWUTS|NEWIPC|NEWNET|NEWCGROUP[|NEWUSER])
│    re-execs the sealed copy as `husk init`, with PR_SET_PDEATHSIG=SIGKILL
│
├─ [parent] ─────────────────────── waits for "child booted"
│    ├─ write /proc/<pid>/setgroups = deny, then uid_map, then gid_map
│    ├─ echo <pid> > cgroup.procs           limits apply before the workload starts
│    ├─ ip link add veth / set master husk0 / set netns <pid>
│    ├─ iptables MASQUERADE + DNAT + FORWARD accept
│    └─ signal "parent ready", carrying the allocated address
│
└─ [child = husk init, PID 1 in the new pidns]
     ├─ runtime.LockOSThread()              capabilities and seccomp are per-thread
     ├─ sethostname()
     ├─ mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)     sever propagation to the host
     ├─ mount(rootfs, rootfs, MS_BIND|MS_REC)           make the rootfs a mountpoint
     ├─ pivot_root(rootfs, rootfs/.put_old)
     ├─ chdir("/"); umount2("/.put_old", MNT_DETACH); rmdir
     ├─ mount /proc /sys /dev /dev/pts /dev/shm; device nodes; symlinks
     ├─ mask /proc/kcore etc.; remount /proc/sys read-only
     ├─ configure lo + eth0 + default route; write /etc/resolv.conf
     ├─ PR_CAP_AMBIENT_CLEAR_ALL; PR_CAPBSET_DROP ×N; capset(); raise ambient
     ├─ prctl(PR_SET_NO_NEW_PRIVS, 1)
     ├─ seccomp(SET_MODE_FILTER, TSYNC, &filter)
     ├─ open("/proc/self/fd/5/exec.fifo", O_WRONLY)     blocks until `husk start`
     └─ execve(argv)   — or stay resident as a reaping, signal-forwarding PID 1
```

[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) walks through why each step is
where it is.

## Adversarial test suite

The tests attack containers husk built rather than asserting that particular
functions were called. A test that checks "`pivot_root` was invoked" passes even
when the call happened in the wrong order and achieved nothing.

```bash
sudo make test-escape
```

| # | Attack | Result |
|---|---|---|
| 1 | `chroot` + retained dirfd + `fchdir` + `chdir("..")` breakout | escapes `--root-mode=chroot`, **contained** by `pivot_root` |
| 2 | Double-`chroot` breakout | escapes `--root-mode=chroot`, **contained** by `pivot_root` |
| 3 | Host process visibility via `/proc` | only container PIDs; PID 1 is the entry point |
| 4 | Mount propagation leak into the host mount table | **no leak** |
| 5 | Memory-limit evasion | OOM-killed in-cgroup (exit 137), `memory.events oom_kill` increments, host unaffected |
| 6 | CPU-quota evasion | `cpu.stat nr_throttled` climbs under `cpu.max` |
| 7 | Fork bomb | stopped at `pids.max`, host stays responsive |
| 8 | overlayfs write isolation | writes confined to `upperdir`; image layers untouched |
| 9 | Whiteout on delete | 0:0 char device in `upperdir`, lower layer intact |
| 10 | Host interface visibility | only `lo` inside |
| 11 | Capability checks (`mount`, raw sockets, `CAP_SYS_ADMIN/BOOT/MODULE/PTRACE`) | all denied; `CapBnd` reduced to 12 |
| 12 | Seccomp denial | `unshare(2)` returns `EPERM`, process survives; succeeds again with `--no-seccomp` |
| 13 | UID mapping | root inside, unprivileged uid outside |
| 14 | `no_new_privs` | set |
| 15 | Masked paths | `/proc/kcore` returns 0 bytes, `/proc/sysrq-trigger` and `/proc/sys` read-only |
| 16 | Bridge egress | DNS + outbound HTTP work through `MASQUERADE` |
| 17 | Published port | reachable from loopback *and* a host address; rules and veth removed on delete |
| 18 | create/start split | entry point does not run until `start` |
| 19 | Dead init before `start` | fails with a diagnostic instead of blocking forever |
| 20 | PID 1 reaping | orphaned children do not accumulate as zombies |
| 21 | Unbounded swap | demonstrates that `memory.max` alone does *not* bound a container |

Case 21 is the inverted one. It asserts the *broken* configuration misbehaves,
which is what stops the default that fixes it from being quietly reverted.

## Benchmarks

Measured with `scripts/benchmark.sh` on Linux 6.6.87 (WSL2), 8 cores, 7.6 GiB
RAM, ext4, entry point `/bin/true`, 50 runs after 5 warmups. Run it yourself; the
absolute numbers are dominated by the host.

| | mean ± σ | range |
|---|---|---|
| runc, no network | **42.2 ms ± 24.8** | 15.5 – 119.6 |
| husk, no network | **59.6 ms ± 19.0** | 23.5 – 90.4 |
| husk, bridge networking | **244.4 ms ± 24.8** | 211.1 – 305.2 |

| peak RSS of the runtime process | |
|---|---|
| runc | 12.0 MiB |
| husk | **9.0 MiB** |

runc is about 1.4× faster to cold start, which is the expected and correct
result. The gap is mostly the sealed-memfd copy of the binary on every start
plus Go runtime initialisation in the init child.

The bridge number is the interesting one: networking costs ~185 ms, and almost
all of it is `exec`ing `iptables` several times per container. Docker makes the
same trade for the same reason — the netlink interface to the legacy tables is
not a stable API — and the fix, if this were production, is a persistent netlink
connection to nftables rather than anything about namespaces.

## Design notes worth reading

Four decisions were not obvious and are documented where they live:

- **The seccomp filter is assembled by hand**, one `sock_filter` at a time, with
  no libseccomp. That keeps the binary cgo-free and therefore static, which
  matters because husk `execve`s itself inside a foreign rootfs with no dynamic
  loader. [`internal/security/seccomp.go`](internal/security/seccomp.go)
- **The init child pins itself to one OS thread.** Capabilities and seccomp
  filters are per-*thread*, and the Go scheduler will happily move a goroutine
  between dropping capabilities and exec'ing the workload — producing a
  container that runs with every capability while the drop reports success.
  [`internal/initproc/initproc.go`](internal/initproc/initproc.go)
- **`memory.swap.max` is set to zero alongside `memory.max`.** With swap
  available, anonymous memory is reclaimable, so a container past its limit is
  paged out instead of killed. On a host with swap, a runtime that writes only
  `memory.max` has implemented a performance cliff rather than a limit.
  [`internal/cgroups/v2.go`](internal/cgroups/v2.go)
- **`husk exec` cannot enter a container that has its own user namespace**, and
  says so rather than failing obscurely. `setns(CLONE_NEWUSER)` requires a
  single-threaded caller; the Go runtime is multi-threaded before `main()` runs.
  runc solves this with `nsexec`, a C constructor that runs before the Go runtime
  initialises. [`internal/cli/exec.go`](internal/cli/exec.go)

## Repository layout

```
cmd/husk/            CLI entry point
internal/
  container/         config and state types that cross the fork boundary
  ipc/               parent/child handshake
  spawn/             runtime side of container creation
  initproc/          container side: mounts, PID 1, the start FIFO
  namespaces/        clone flags, uid/gid mapping
  mounts/            pivot_root, API filesystems, masked paths
  cgroups/           cgroup v2 writes and metric reads
  network/           bridge, veth, IPAM, netfilter
  storage/           overlayfs, layers, commit, tarball import
  security/          capabilities, seccomp-BPF, sealed self-exec
  metrics/           Prometheus collector
  state/             on-disk container state
  cli/               subcommands
test/escape/         the adversarial suite
docs/                architecture, security model, container vs VM
scripts/             benchmark and purge
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the pieces fit, and why
  the ordering is what it is
- [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) — what husk isolates, what
  it does not, and the known gaps
- [`docs/CONTAINER-VS-VM.md`](docs/CONTAINER-VS-VM.md) — the kernel-level
  comparison, and where gVisor, Kata and Firecracker sit

## License

MIT. See [LICENSE](LICENSE).
