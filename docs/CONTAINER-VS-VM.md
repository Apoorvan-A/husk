# Containers and virtual machines, at the kernel level

The usual answer to "what's the difference" is that containers are lighter. That
is a consequence, not a mechanism. This is the mechanism.

## The difference in one line

A VM virtualises **hardware** and runs its own kernel on it. A container
virtualises **kernel data structures** and shares the host's kernel.

Everything else follows from that.

## What a hypervisor actually does

A CPU with VT-x or AMD-V has a second execution mode. The hypervisor puts the
guest into it, and the guest then runs its own code on the real CPU at native
speed — but any instruction that would affect machine state outside the guest
traps into the hypervisor instead of executing. Reading a control register,
touching a device port, changing a page table root: each one exits to the host,
which emulates it against virtual hardware and resumes the guest.

Memory is partitioned by hardware. The guest maintains its own page tables
mapping guest-virtual to guest-physical addresses, and a second hardware layer —
Intel's EPT, AMD's NPT — maps guest-physical to host-physical. The guest kernel
cannot address host memory because the address it would have to use does not
exist in its translation. That is a property of the MMU, not of any software
check.

The guest talks to virtual devices, so a guest driver bug is contained to the
device model in the hypervisor rather than reaching the host's real driver.

The boundary is enforced by silicon. Escaping it means finding a bug in the
hypervisor's emulation of some specific hardware interaction — historically the
device models, which is why Firecracker ships almost none.

## What a container actually is

There is no second execution mode and nothing traps. A container is an ordinary
Linux process. `ps` on the host shows it. The scheduler treats it like any other
task. Its syscalls enter the same kernel your host is running, through the same
entry point, into the same code.

What differs is what the kernel tells it. Seven namespaces each virtualise one
kind of global identifier:

| Namespace | What becomes per-container |
|---|---|
| `CLONE_NEWNS` | the mount table |
| `CLONE_NEWPID` | PID numbering |
| `CLONE_NEWUTS` | hostname and domain name |
| `CLONE_NEWIPC` | SysV IPC and POSIX message queues |
| `CLONE_NEWNET` | the entire network stack — interfaces, routes, netfilter, sockets |
| `CLONE_NEWUSER` | uid/gid mapping and capability scope |
| `CLONE_NEWCGROUP` | the cgroup hierarchy root |

Concretely: `task_struct` gains an `nsproxy` pointer, and lookups that used to
consult a global table consult a per-namespace one instead. Asking a process for
its PID walks its PID namespace's `pid` structure. Resolving a path walks its
mount namespace's tree. The process is not sandboxed; it is *given different
answers*.

Resource limits come from a separate mechanism entirely. cgroups do not restrict
visibility at all — they are accounting plus enforcement, charging every page and
every microsecond of CPU to a control group and refusing allocations past a
limit.

The boundary is enforced by bookkeeping. Escaping it means finding a bug in the
kernel that lets you edit the bookkeeping.

## Blast radius

This is the part that matters, and the part most comparisons skip.

**A kernel vulnerability escapes every container on the host, at once.** There is
one kernel. A privilege-escalation bug reachable from an unprivileged syscall is
reachable from inside every container simultaneously, and exploiting it gives
ring-0 execution — at which point namespaces are just data structures the
attacker can rewrite. Dirty COW, Dirty Pipe and the io_uring bugs were all
container escapes for exactly this reason, without anything in the container
runtime being at fault.

**The same vulnerability does not escape a VM.** A guest kernel compromise gets
the attacker root in the guest. Reaching the host means a *second* exploit
against the hypervisor's emulation. Two independent bugs, in two independent
codebases, one of which is orders of magnitude smaller.

The syscall surface makes the asymmetry concrete. A container reaches roughly
350 syscalls; a default seccomp profile blocks around 50, leaving ~300 entry
points into millions of lines of kernel code. A VM guest reaches its own kernel
freely but touches the host only through a virtual device interface — for
Firecracker, five devices and a few dozen distinct operations.

## What each costs

| | Container | VM |
|---|---|---|
| Kernel | shared with the host | its own |
| Startup | milliseconds — it is a `clone` and an `execve` | hundreds of ms to seconds; a kernel must boot |
| Memory overhead | the process's own footprint | tens to hundreds of MiB for the guest kernel and page tables |
| Density per host | thousands | tens to low hundreds |
| Isolation enforced by | kernel data structures | CPU and MMU hardware |
| Escape requires | one kernel bug | a hypervisor bug, usually after a guest kernel bug |
| Guest OS | must be Linux, and the host's kernel version | any, independently versioned |
| Live migration | not really | mature |

The startup difference is not tuning. A container start does no more work than
starting a process, because that is what it is. A VM start boots an operating
system.

## Where each is right

**Containers** when the workload is your own code, you control what runs, the
tenancy boundary is a team rather than a customer, and density or start latency
matters. A CI runner fleet, a microservice deployment, a build farm.

**VMs** when you run code you did not write, when tenants distrust each other,
when a compliance boundary has to be defensible, or when the guest needs a
different kernel. Multi-tenant cloud, anything running customer-supplied code.

Nested is the common real answer: VMs as the tenancy boundary, containers inside
them for density and packaging. That is how essentially every public cloud
Kubernetes offering is built, and the reason is precisely the blast-radius
argument above.

## The middle ground

Three systems exist because "container ergonomics, VM isolation" is worth a lot.
They sit at different points and make different trades.

**gVisor** (Google) puts a userspace kernel in front. Sentry, written in Go,
implements around 260 Linux syscalls itself; the container's syscalls are
intercepted — by ptrace or KVM — and serviced by Sentry rather than by the host
kernel. Sentry itself talks to the host through a heavily restricted seccomp
profile, so the host surface shrinks from ~300 syscalls to ~60.

*Trade:* no hardware boundary and no separate kernel — a Sentry bug is still a
host-kernel-adjacent problem — and syscall-heavy workloads pay 2–3× because
every syscall crosses into userspace and back. Incomplete syscall coverage breaks
some software outright.

**Kata Containers** runs each container, or each pod, inside a real lightweight
VM with its own kernel, under QEMU or Firecracker, presented through the standard
OCI runtime interface. Kubernetes cannot tell the difference; it is a
`RuntimeClass`.

*Trade:* real hardware isolation, at real VM cost — roughly 100 ms of start
latency and 50–130 MiB per VM. Requires nested virtualisation to run inside a
cloud VM, which not every instance type provides.

**Firecracker** (AWS) is a minimal VMM built for this: ~50k lines of Rust against
QEMU's 1.4 million, with only five emulated devices — virtio-net, virtio-block,
virtio-vsock, a serial console and a partial keyboard controller. No BIOS, no
PCI, no USB, no VGA. Boots in about 125 ms with roughly 5 MiB of overhead, and
runs under its own jailer with seccomp and a chroot.

*Trade:* it is a VMM, not a container runtime — you supply the kernel and rootfs
image, and there is no OCI story of its own. It is the substrate under AWS Lambda
and Fargate, and under Kata's Firecracker backend.

Ordered by isolation strength, and simultaneously by overhead:

```
namespaces + seccomp   <   gVisor   <   Firecracker   <   QEMU/KVM
  ~300 host syscalls       ~60          5 devices         full device model
  ~5 ms start              ~50 ms       ~125 ms           ~500 ms+
```

There is no free position on that line. The correct choice is the weakest
boundary that covers your actual threat model, which for most in-house workloads
is plain containers — and for anything running code a stranger wrote, is not.
