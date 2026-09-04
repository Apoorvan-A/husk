// Package mounts builds the container's filesystem view from inside its mount
// namespace: it severs mount propagation to the host, swaps the root, populates
// the kernel API filesystems, and masks the parts of /proc and /sys that
// namespaces do not virtualise.
//
// Everything here runs in the child, after clone(2) and before execve(2). None
// of it can be done by the parent, because a mount namespace is only writable
// from within.
package mounts

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/Apoorvan-A/husk/internal/container"
)

const putOld = ".put_old"

// SetupRoot enters the container root using the configured mechanism.
func SetupRoot(cfg *container.Config) error {
	switch cfg.RootMode {
	case container.RootModeChroot:
		return SetupRootChroot(cfg)
	case container.RootModePivot, "":
		return SetupRootPivot(cfg)
	default:
		return fmt.Errorf("unknown root mode %q", cfg.RootMode)
	}
}

// SetupRootPivot is the real implementation.
//
// The sequence is four syscalls and every one of them is load-bearing:
//
//  1. mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)
//
//     A new mount namespace is a *copy* of the parent's mount table, not an
//     empty one, and the copied mounts keep their propagation type. On any
//     systemd host / is MS_SHARED, which means the copy stays in the same peer
//     group as the host's. Every mount and unmount we perform below would
//     propagate straight back out: /proc would show up in the host's
//     /proc/self/mountinfo, and detaching put_old could tear down host mounts.
//     Turning the tree MS_PRIVATE recursively cuts those links. pivot_root(2)
//     also refuses outright — EINVAL — if the new root's parent mount is
//     shared, so this is both a correctness and a security step.
//
//  2. mount(rootfs, rootfs, NULL, MS_BIND|MS_REC, NULL)
//
//     pivot_root requires new_root to be a mountpoint. A freshly extracted
//     rootfs directory is just a directory on the host filesystem, so we bind
//     it onto itself to manufacture one. This is not a trick, it is the
//     documented way to promote a directory to a mount.
//
//  3. pivot_root(rootfs, rootfs/.put_old)
//
//     Moves the *root of the mount namespace* to put_old and installs rootfs in
//     its place. Unlike chroot this changes the mount tree itself rather than
//     one process's idea of "/", which is precisely why it cannot be walked out
//     of: after step 4 the old root has no path and no mount to reach it by.
//
//  4. umount2("/.put_old", MNT_DETACH)
//
//     The old root is still mounted under the new one and would otherwise be a
//     fully browsable copy of the host filesystem. MNT_DETACH does a lazy
//     unmount, which succeeds even though descendants are still busy, and the
//     subtree disappears from the namespace as soon as the last reference goes.
func SetupRootPivot(cfg *container.Config) error {
	// Step 1: sever propagation before touching anything else.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / rprivate: %w", err)
	}

	root, err := filepath.Abs(cfg.Rootfs)
	if err != nil {
		return fmt.Errorf("resolve rootfs: %w", err)
	}

	// Step 2: promote the rootfs directory to a mountpoint. MS_REC carries any
	// submounts already present (overlayfs layers, bind-mounted volumes).
	if err := unix.Mount(root, root, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind rootfs onto itself: %w", err)
	}

	// put_old must live *inside* new_root — the kernel enforces that new_root is
	// a prefix of put_old, so the old tree ends up reachable only through the
	// new one, and therefore removable by unmounting inside it.
	oldRoot := filepath.Join(root, putOld)
	if err := os.MkdirAll(oldRoot, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", putOld, err)
	}

	// Step 3.
	if err := unix.PivotRoot(root, oldRoot); err != nil {
		return fmt.Errorf("pivot_root(%s, %s): %w", root, oldRoot, err)
	}

	// pivot_root does not move the calling process's cwd. Until we chdir the
	// process still has a working directory on the old root, which is itself a
	// live handle out of the container — the exact thing chroot escapes exploit.
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir to new root: %w", err)
	}

	// Step 4: detach before mounting anything else, so the window in which the
	// host filesystem is visible from inside is as short as possible.
	if err := unix.Unmount("/"+putOld, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach %s: %w", putOld, err)
	}
	if err := os.Remove("/" + putOld); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", putOld, err)
	}

	if err := mountAPIFilesystems(cfg); err != nil {
		return err
	}
	if err := applyMasks(cfg.Security); err != nil {
		return err
	}

	// Read-only root is applied last: the API filesystems mounted above are
	// separate mounts and keep their own writability, so a read-only / still
	// leaves a working /proc, /sys/fs/cgroup and /dev.
	if cfg.ReadonlyRootfs {
		if err := unix.Mount("", "/", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("remount / read-only: %w", err)
		}
	}
	return nil
}

// SetupRootChroot is the naive implementation, kept as the negative control for
// the escape suite. It is escapable and must never be selected for real use.
//
// chroot(2) only rewrites one field in the calling process's fs_struct: root.
// It does not touch the mount namespace, and critically it does not force the
// process's *cwd* inside the new root. The classic escape follows directly:
//
//	fd = open(".", O_RDONLY)   // a directory handle outside the new root
//	chroot("subdir")           // root moves down; fd still points outside
//	fchdir(fd)                 // cwd is now outside the root
//	chdir("../../../..")       // walk up; the kernel's ".."-clamping only
//	chroot(".")                // triggers when cwd is inside the root
//
// The kernel does clamp ".." at the root — but only for paths resolved from
// inside it. Once fchdir puts the cwd outside, the clamp never applies and each
// ".." climbs a real directory until it reaches the true filesystem root.
//
// This function deliberately calls chdir before chroot, which is the *correct*
// use of chroot and closes the trivial case. It remains escapable anyway,
// because any process that retains CAP_SYS_CHROOT can simply chroot a second
// time to re-open the hole. That is the point: chroot is not a security
// boundary, and no amount of careful use makes it one.
func SetupRootChroot(cfg *container.Config) error {
	root, err := filepath.Abs(cfg.Rootfs)
	if err != nil {
		return fmt.Errorf("resolve rootfs: %w", err)
	}
	if err := unix.Chdir(root); err != nil {
		return fmt.Errorf("chdir rootfs: %w", err)
	}
	if err := unix.Chroot(root); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}
	// Mount /proc even here, so the M1-vs-M2 comparison isolates the root
	// mechanism rather than confounding it with a missing procfs.
	return mountAPIFilesystems(cfg)
}
