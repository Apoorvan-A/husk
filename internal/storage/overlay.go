// Package storage provides copy-on-write container roots using overlayfs.
//
// The alternative — copying an image directory per container — costs the full
// image size in time and disk every time a container starts. overlayfs makes the
// cost proportional to what the container actually writes, which is what makes
// starting a hundred containers from one image practical.
package storage

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultRoot is where husk keeps images, layers and container scratch space. It
// must be on a filesystem that supports extended attributes: overlayfs records
// opaque directories in trusted.overlay.* xattrs, and without them a deleted
// directory reappears from the layer below.
const DefaultRoot = "/var/lib/husk"

// Store is husk's on-disk layout.
//
//	<root>/layers/<layer-id>/        immutable layer content
//	<root>/images/<name>              newline-separated layer ids, base first
//	<root>/containers/<id>/upper      the container's writable layer
//	<root>/containers/<id>/work       overlayfs scratch space
//	<root>/containers/<id>/merged     the mountpoint the container pivots into
type Store struct{ Root string }

func NewStore(root string) *Store {
	if root == "" {
		root = DefaultRoot
	}
	return &Store{Root: root}
}

func (s *Store) layersDir() string     { return filepath.Join(s.Root, "layers") }
func (s *Store) imagesDir() string     { return filepath.Join(s.Root, "images") }
func (s *Store) containersDir() string { return filepath.Join(s.Root, "containers") }

func (s *Store) LayerPath(id string) string    { return filepath.Join(s.layersDir(), id) }
func (s *Store) ImagePath(name string) string  { return filepath.Join(s.imagesDir(), name) }
func (s *Store) ContainerDir(id string) string { return filepath.Join(s.containersDir(), id) }
func (s *Store) MergedPath(id string) string   { return filepath.Join(s.ContainerDir(id), "merged") }
func (s *Store) UpperPath(id string) string    { return filepath.Join(s.ContainerDir(id), "upper") }
func (s *Store) WorkPath(id string) string     { return filepath.Join(s.ContainerDir(id), "work") }

// Init creates the directory skeleton.
func (s *Store) Init() error {
	for _, d := range []string{s.layersDir(), s.imagesDir(), s.containersDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	return nil
}

// Mount assembles a container root and returns the merged path.
//
// The four overlayfs components and why each exists:
//
//	lowerdir  One or more read-only layers, colon-separated. Order is
//	          significant and counter-intuitive: the *leftmost* entry is the
//	          topmost layer. Getting it backwards produces a container where an
//	          older layer's version of a file shadows the newer one, which
//	          usually shows up as mysteriously stale binaries.
//
//	upperdir  The single writable layer. Every modification a container makes
//	          lands here and nowhere else, which is what keeps the image
//	          immutable and shared.
//
//	workdir   Empty scratch space overlayfs needs internally, and it must be on
//	          the same filesystem as upperdir. That is not an arbitrary rule:
//	          copy-up has to be atomic, so overlayfs builds the copied file in
//	          workdir and then rename(2)s it into upperdir. rename is only
//	          atomic within a filesystem, so a workdir on a different mount makes
//	          the whole operation impossible — the kernel returns EXDEV at mount
//	          time rather than let it be attempted.
//
//	merged    The mountpoint presenting the union.
//
// Two behaviours worth being able to describe:
//
// Copy-up. Opening a lowerdir file for writing does not write to it. overlayfs
// copies the entire file into upperdir first, then redirects the write. So the
// first write to a 2 GB file costs 2 GB of I/O regardless of how many bytes are
// written — the reason database images perform badly on overlayfs and are
// normally given a volume instead.
//
// Whiteouts. Deleting a lowerdir file cannot remove it, because lowerdir is
// read-only and shared. Instead overlayfs creates a character device with major
// and minor both 0 at that path in upperdir. The union layer interprets that
// node as "this name is deleted" and hides everything below it. The file is gone
// from the container's view and completely intact on disk. Deleting a whole
// directory uses a different marker: an empty directory in upperdir carrying the
// trusted.overlay.opaque="y" xattr, which hides the entire subtree beneath it —
// and setting a trusted.* xattr requires CAP_SYS_ADMIN, which is why overlayfs
// on a filesystem without xattr support silently misbehaves.
func (s *Store) Mount(containerID string, layers []string) (string, error) {
	if len(layers) == 0 {
		return "", fmt.Errorf("no layers to mount")
	}

	upper := s.UpperPath(containerID)
	work := s.WorkPath(containerID)
	merged := s.MergedPath(containerID)
	for _, d := range []string{upper, work, merged} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", fmt.Errorf("create %s: %w", d, err)
		}
	}

	paths := make([]string, len(layers))
	for i, id := range layers {
		p := s.LayerPath(id)
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("layer %s: %w", id, err)
		}
		paths[i] = p
	}

	opts, err := overlayOptions(paths, upper, work)
	if err != nil {
		return "", err
	}
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		return "", fmt.Errorf("mount overlay on %s (%s): %w", merged, opts, err)
	}
	return merged, nil
}

// overlayOptions builds the mount option string from layer paths given in
// base-first order.
//
// It is separated from Mount so the ordering can be tested without root. The
// ordering is the part worth testing: overlayfs reads lowerdir as topmost-first,
// the opposite of how an image's layers are naturally listed, and getting it
// backwards produces a container where an older layer shadows a newer one — a
// failure that presents as mysteriously stale binaries rather than as an error.
func overlayOptions(layerPaths []string, upper, work string) (string, error) {
	lower := make([]string, 0, len(layerPaths))
	for i := len(layerPaths) - 1; i >= 0; i-- {
		p := layerPaths[i]
		// The option string is colon and comma delimited with no escaping
		// mechanism at all, so a path containing either is simply unmountable.
		if strings.ContainsAny(p, ":,") {
			return "", fmt.Errorf("layer path %q contains a delimiter overlayfs cannot escape", p)
		}
		lower = append(lower, p)
	}
	return fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s",
		strings.Join(lower, ":"), upper, work), nil
}

// Unmount detaches a container's merged view. MNT_DETACH keeps teardown from
// failing when a process still holds a file open under it — the mount goes away
// as soon as the last reference does.
func (s *Store) Unmount(containerID string) error {
	merged := s.MergedPath(containerID)
	if err := unix.Unmount(merged, unix.MNT_DETACH); err != nil {
		if err == unix.EINVAL || os.IsNotExist(err) {
			return nil // not mounted
		}
		return fmt.Errorf("unmount %s: %w", merged, err)
	}
	return nil
}

// Remove deletes a container's scratch space. The upper layer is the container's
// only unique data, so this is the point of no return for anything written
// inside it that was not committed.
func (s *Store) Remove(containerID string) error {
	if err := s.Unmount(containerID); err != nil {
		return err
	}
	if err := os.RemoveAll(s.ContainerDir(containerID)); err != nil {
		return fmt.Errorf("remove container storage: %w", err)
	}
	return nil
}

// ImageLayers reads an image's layer stack, base layer first.
func (s *Store) ImageLayers(name string) ([]string, error) {
	f, err := os.Open(s.ImagePath(name))
	if err != nil {
		return nil, fmt.Errorf("image %q: %w", name, err)
	}
	defer f.Close()

	var layers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			layers = append(layers, l)
		}
	}
	return layers, sc.Err()
}

// PutImage records a layer stack under a name.
func (s *Store) PutImage(name string, layers []string) error {
	if err := os.MkdirAll(s.imagesDir(), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.ImagePath(name), []byte(strings.Join(layers, "\n")+"\n"), 0o644)
}

// ListImages returns the known image names.
func (s *Store) ListImages() ([]string, error) {
	entries, err := os.ReadDir(s.imagesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// NewLayerID mints an identifier for a committed layer. A content hash would be
// better — it would deduplicate identical layers and make the store
// content-addressed the way a real image store is — but hashing a whole layer on
// commit is a cost this implementation does not need to pay to demonstrate the
// mechanism. Recorded as a known limitation rather than hidden.
func NewLayerID() string {
	return fmt.Sprintf("l%d", time.Now().UnixNano())
}
