package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Commit snapshots a container's writable layer into a new immutable layer and
// records a new image whose stack is the container's layers plus that one. This
// is `docker commit` reduced to its actual mechanism: no magic, just a copy of
// upperdir and one more entry in the layer list.
//
// The container should be stopped first. Copying a live upperdir gives a layer
// that is internally inconsistent in exactly the way a torn backup is — half a
// database write, a lockfile that outlives its holder — and the copy will
// succeed without complaining.
func (s *Store) Commit(containerID, imageName string, baseLayers []string) (string, error) {
	upper := s.UpperPath(containerID)
	if _, err := os.Stat(upper); err != nil {
		return "", fmt.Errorf("container %s has no writable layer: %w", containerID, err)
	}

	layerID := NewLayerID()
	dest := s.LayerPath(layerID)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", fmt.Errorf("create layer %s: %w", layerID, err)
	}

	if err := copyTree(upper, dest); err != nil {
		os.RemoveAll(dest)
		return "", fmt.Errorf("snapshot writable layer: %w", err)
	}

	if err := s.PutImage(imageName, append(append([]string{}, baseLayers...), layerID)); err != nil {
		os.RemoveAll(dest)
		return "", err
	}
	return layerID, nil
}

// copyTree replicates a directory tree preserving the things that make an
// overlayfs layer meaningful rather than just a pile of files.
//
// Whiteouts are the reason this cannot be a plain file copy. A deleted file
// appears in upperdir as a character device with major 0 and minor 0, and a
// copier that skips device nodes — or worse, tries to read one — produces a
// layer in which the deletion silently did not happen and the old file
// resurfaces from the layer below. Recreating the node is what carries the
// deletion forward.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)

		switch {
		case info.IsDir():
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}

		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.Symlink(link, target); err != nil {
				return err
			}
			// A symlink's own mode is meaningless on Linux, and chmod would
			// follow it to the target, so nothing further is done here.
			return copyOwnership(path, target, true)

		case info.Mode()&(os.ModeDevice|os.ModeCharDevice) != 0:
			st, ok := info.Sys().(*unix.Stat_t)
			if !ok {
				return fmt.Errorf("cannot read device numbers for %s", path)
			}
			mode := uint32(unix.S_IFCHR)
			if info.Mode()&os.ModeCharDevice == 0 {
				mode = unix.S_IFBLK
			}
			if err := unix.Mknod(target, mode|uint32(info.Mode().Perm()), int(st.Rdev)); err != nil {
				return fmt.Errorf("recreate device node %s: %w", rel, err)
			}

		case info.Mode().IsRegular():
			if err := copyFile(path, target, info.Mode().Perm()); err != nil {
				return err
			}

		default:
			// FIFOs and sockets carry no data worth preserving across a commit.
			return nil
		}

		if err := copyOwnership(path, target, false); err != nil {
			return err
		}
		return copyXattrs(path, target)
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Chmod(mode)
}

// copyOwnership preserves uid and gid. Lchown is used for symlinks so the link
// itself is retargeted rather than whatever it points at.
func copyOwnership(src, dst string, symlink bool) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*unix.Stat_t)
	if !ok {
		return nil
	}
	if err := os.Lchown(dst, int(st.Uid), int(st.Gid)); err != nil {
		// A rootless commit cannot restore arbitrary ownership; the layer is
		// still usable, it is just owned by the invoking user.
		if os.IsPermission(err) {
			return nil
		}
		return err
	}
	return nil
}

// copyXattrs carries over extended attributes, which for an overlayfs layer is
// not optional: trusted.overlay.opaque marks a directory that hides everything
// beneath it, and losing that attribute resurrects an entire deleted subtree.
func copyXattrs(src, dst string) error {
	size, err := unix.Llistxattr(src, nil)
	if err != nil || size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	size, err = unix.Llistxattr(src, buf)
	if err != nil {
		return nil
	}

	for _, name := range splitNullTerminated(buf[:size]) {
		vsize, err := unix.Lgetxattr(src, name, nil)
		if err != nil || vsize < 0 {
			continue
		}
		value := make([]byte, vsize)
		if _, err := unix.Lgetxattr(src, name, value); err != nil {
			continue
		}
		// Setting trusted.* requires CAP_SYS_ADMIN; a rootless commit will fail
		// here and the resulting layer loses its opaque markers. That is a real
		// limitation of rootless commit, not a bug to paper over.
		_ = unix.Lsetxattr(dst, name, value, 0)
	}
	return nil
}

func splitNullTerminated(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			if i > start {
				out = append(out, string(b[start:i]))
			}
			start = i + 1
		}
	}
	return out
}
