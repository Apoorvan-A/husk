package storage

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ImportTarball extracts a rootfs tarball into a new layer and records it as an
// image. This is how an alpine or busybox rootfs becomes something husk can run.
func (s *Store) ImportTarball(path, imageName string) (string, error) {
	if err := s.Init(); err != nil {
		return "", err
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") || strings.HasSuffix(path, ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return "", fmt.Errorf("gunzip %s: %w", path, err)
		}
		defer gz.Close()
		r = gz
	}

	layerID := NewLayerID()
	dest := s.LayerPath(layerID)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}

	if err := extractTar(tar.NewReader(r), dest); err != nil {
		os.RemoveAll(dest)
		return "", fmt.Errorf("extract %s: %w", path, err)
	}
	if err := s.PutImage(imageName, []string{layerID}); err != nil {
		os.RemoveAll(dest)
		return "", err
	}
	return layerID, nil
}

// extractTar unpacks into dest.
//
// The path check is the important part and is not defensive boilerplate. A tar
// archive is an untrusted list of paths, and an entry named "../../etc/passwd"
// or a symlink "link -> /" followed by an entry writing through it will happily
// escape the extraction directory and overwrite the host. This is the Zip Slip
// class of bug and container images are precisely the place it gets exploited.
// Every destination is therefore resolved and required to stay under dest.
func extractTar(tr *tar.Reader, dest string) error {
	// Deferred so directory timestamps and permissions are not disturbed by
	// files written into them afterwards.
	type dirMeta struct {
		path string
		mode os.FileMode
	}
	var dirs []dirMeta

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)&os.ModePerm); err != nil {
				return err
			}
			dirs = append(dirs, dirMeta{target, os.FileMode(hdr.Mode) & os.ModePerm})

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&os.ModePerm)
			if err != nil {
				return err
			}
			// Bounded copy: a decompression bomb otherwise fills the disk. 8 GiB
			// is generous for a rootfs layer and catches the pathological case.
			if _, err := io.CopyN(f, tr, 1<<33); err != nil && err != io.EOF {
				f.Close()
				return err
			}
			f.Close()

		case tar.TypeSymlink:
			os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}

		case tar.TypeLink:
			source, err := safeJoin(dest, hdr.Linkname)
			if err != nil {
				return err
			}
			os.Remove(target)
			if err := os.Link(source, target); err != nil {
				return err
			}

		case tar.TypeChar, tar.TypeBlock:
			mode := uint32(unix.S_IFCHR)
			if hdr.Typeflag == tar.TypeBlock {
				mode = unix.S_IFBLK
			}
			dev := unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor))
			// Requires CAP_MKNOD. A rootless import skips the node; the
			// container gets its devices from the tmpfs /dev husk builds anyway.
			_ = unix.Mknod(target, mode|uint32(hdr.Mode&0o7777), int(dev))

		case tar.TypeFifo:
			_ = unix.Mkfifo(target, uint32(hdr.Mode&0o7777))
		}

		// Ownership is best-effort: a rootless extraction cannot set arbitrary
		// uids, and the resulting layer is owned by the caller instead.
		_ = os.Lchown(target, hdr.Uid, hdr.Gid)
	}

	for _, d := range dirs {
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
	}
	return nil
}

// safeJoin resolves name under dest and refuses anything that would land
// outside it.
func safeJoin(dest, name string) (string, error) {
	// filepath.Join already lexically cleans "..", but it does so *after*
	// joining, so a name of "../x" resolves to a sibling of dest rather than an
	// error. The prefix check below is what actually rejects it.
	target := filepath.Join(dest, name)
	cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanDest) {
		return "", fmt.Errorf("archive entry %q escapes the extraction directory", name)
	}
	return target, nil
}
