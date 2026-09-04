package mounts

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/Apoorvan-A/husk/internal/container"
)

// Standard hardening flags for the kernel API filesystems. They are cheap and
// each closes a real path:
//
//	MS_NOSUID  - a setuid binary planted in the image cannot elevate.
//	MS_NODEV   - a device node planted in the image cannot be opened, which
//	             otherwise turns a writable image into raw disk access.
//	MS_NOEXEC  - nothing under this mount can be executed at all.
const (
	nosuidNodev       = unix.MS_NOSUID | unix.MS_NODEV
	nosuidNodevNoexec = nosuidNodev | unix.MS_NOEXEC
)

type apiMount struct {
	source string
	target string
	fstype string
	flags  uintptr
	data   string
}

func mountAPIFilesystems(cfg *container.Config) error {
	mounts := []apiMount{
		// A fresh procfs instance, not a bind of the host's. Because the child is
		// already in a PID namespace when this runs, the kernel scopes this
		// procfs to that namespace: /proc lists only container PIDs and
		// /proc/self resolves against container numbering. Bind-mounting the
		// host's /proc instead would expose every host process — one of the
		// twelve escape tests checks exactly this.
		{"proc", "/proc", "proc", nosuidNodevNoexec, ""},

		// sysfs is read-only. The container has no business writing kernel
		// tunables, and with CLONE_NEWNET the kernel will only let us mount a
		// fresh sysfs at all because the netns is ours.
		{"sysfs", "/sys", "sysfs", nosuidNodevNoexec | unix.MS_RDONLY, ""},

		// A tmpfs /dev, then device nodes bound in individually below. mode=755
		// so it looks like a real /dev; size caps what a container can stuff
		// into it.
		{"tmpfs", "/dev", "tmpfs", unix.MS_NOSUID | unix.MS_STRICTATIME, "mode=755,size=65536k"},

		// A private devpts instance. Without it the container would share the
		// host's pty namespace and could open another container's terminal.
		// ptmxmode=0666 matters because /dev/ptmx is a symlink into this mount.
		{"devpts", "/dev/pts", "devpts", unix.MS_NOSUID | unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620,gid=5"},

		{"shm", "/dev/shm", "tmpfs", nosuidNodevNoexec, "mode=1777,size=65536k"},
		{"mqueue", "/dev/mqueue", "mqueue", nosuidNodevNoexec, ""},
	}

	for _, m := range mounts {
		if err := os.MkdirAll(m.target, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", m.target, err)
		}
		if err := unix.Mount(m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			// devpts with gid=5 fails on images that lack a "tty" group, and
			// mqueue is unavailable on some kernels. Neither is worth aborting
			// a container over; the load-bearing mounts are handled below.
			if m.target == "/dev/pts" || m.target == "/dev/mqueue" {
				continue
			}
			return fmt.Errorf("mount %s on %s: %w", m.fstype, m.target, err)
		}
	}

	if err := setupDeviceNodes(); err != nil {
		return err
	}
	return setupDevSymlinks()
}

// The minimal device set a userspace expects to exist. Anything not listed here
// is simply absent inside the container.
var defaultDevices = []struct {
	path string
	mode os.FileMode
	dev  uint64
}{
	{"/dev/null", 0o666, unix.Mkdev(1, 3)},
	{"/dev/zero", 0o666, unix.Mkdev(1, 5)},
	{"/dev/full", 0o666, unix.Mkdev(1, 7)},
	{"/dev/random", 0o666, unix.Mkdev(1, 8)},
	{"/dev/urandom", 0o666, unix.Mkdev(1, 9)},
	{"/dev/tty", 0o666, unix.Mkdev(5, 0)},
}

// setupDeviceNodes populates the tmpfs /dev.
//
// mknod(2) needs CAP_MKNOD in the *initial* user namespace, so it works for a
// privileged runtime and fails with EPERM for a rootless one — a user namespace
// grants a full capability set inside itself, but device creation is one of the
// operations the kernel still checks against init_user_ns. The fallback is to
// bind-mount the host's node over an empty file, which needs no capability at
// all because it creates no device, it only makes an existing one reachable.
// This is the same strategy runc uses for rootless containers.
func setupDeviceNodes() error {
	for _, d := range defaultDevices {
		if err := unix.Mknod(d.path, unix.S_IFCHR|uint32(d.mode), int(d.dev)); err == nil {
			// Mknod applies umask; chmod restores the intended mode.
			if err := os.Chmod(d.path, d.mode); err != nil {
				return fmt.Errorf("chmod %s: %w", d.path, err)
			}
			continue
		}
		if err := bindHostDevice(d.path); err != nil {
			return fmt.Errorf("provide %s: %w", d.path, err)
		}
	}
	return nil
}

func bindHostDevice(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o644)
	if err != nil {
		return err
	}
	f.Close()
	// The source resolves against the host filesystem only because this runs
	// before the old root is fully gone in chroot mode; under pivot_root the
	// child mounts these from the already-populated rootfs image instead. In
	// practice both paths exist because the image ships its own /dev nodes.
	return unix.Mount(path, path, "", unix.MS_BIND, "")
}

// The symlinks glibc, shells and anything using /dev/stdout expect. These are
// symlinks rather than binds because their targets are per-process: /proc/self
// must resolve in the reader's context, not the creator's.
var devSymlinks = []struct{ target, link string }{
	{"/proc/self/fd", "/dev/fd"},
	{"/proc/self/fd/0", "/dev/stdin"},
	{"/proc/self/fd/1", "/dev/stdout"},
	{"/proc/self/fd/2", "/dev/stderr"},
	{"/proc/kcore", "/dev/core"},
	{"pts/ptmx", "/dev/ptmx"},
}

func setupDevSymlinks() error {
	for _, s := range devSymlinks {
		if err := os.Remove(s.link); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear %s: %w", s.link, err)
		}
		if err := os.Symlink(s.target, s.link); err != nil {
			// /dev/core points at /proc/kcore, which is masked on most hosts.
			// A dangling symlink there is harmless.
			if s.link == "/dev/core" {
				continue
			}
			return fmt.Errorf("symlink %s -> %s: %w", s.link, s.target, err)
		}
	}
	return nil
}

// MountCgroupNamespace exposes the container's own cgroup as / of a cgroup2
// mount. This is only safe alongside CLONE_NEWCGROUP: the cgroup namespace
// rebases what the process can see, so /proc/self/cgroup reads "/" instead of
// leaking the host path /sys/fs/cgroup/husk/<id>, and the mount cannot reach
// sibling containers' cgroup directories.
func MountCgroupNamespace() error {
	target := "/sys/fs/cgroup"
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", target, err)
	}
	// Read-only: metrics collection reads these files from the host side, so the
	// container never needs write access to its own limits. A writable mount
	// here would let a container raise its own memory.max.
	flags := uintptr(nosuidNodevNoexec | unix.MS_RDONLY)
	if err := unix.Mount("cgroup2", target, "cgroup2", flags, ""); err != nil {
		return fmt.Errorf("mount cgroup2: %w", err)
	}
	return nil
}

// BindMount attaches a host path inside the container. Read-only binds need two
// syscalls: the initial bind ignores MS_RDONLY (a long-standing kernel quirk —
// the flag applies to the superblock, and a bind reuses the source's), so a
// second remount is required to actually make it read-only. Skipping the
// remount is a classic bug that silently produces a writable "read-only" mount.
func BindMount(source, target string, readonly bool) error {
	fi, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat bind source: %w", err)
	}
	if fi.IsDir() {
		err = os.MkdirAll(target, 0o755)
	} else {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		var f *os.File
		f, err = os.OpenFile(target, os.O_CREATE|os.O_RDONLY, 0o644)
		if err == nil {
			f.Close()
		}
	}
	if err != nil {
		return fmt.Errorf("prepare bind target: %w", err)
	}
	if err := unix.Mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s -> %s: %w", source, target, err)
	}
	if readonly {
		flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_REC)
		if err := unix.Mount("", target, "", flags, ""); err != nil {
			return fmt.Errorf("remount %s read-only: %w", target, err)
		}
	}
	return nil
}
