package escape

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// packRootfs tars the prepared rootfs directory so it can be imported as an
// image. Done with the tar binary rather than husk's importer, for the same
// reason the extraction is: fixtures must not be built by the code under test.
func packRootfs(t *testing.T, rootfs string) string {
	t.Helper()

	out := filepath.Join(cacheDir(), "rootfs-image.tar.gz")
	if exists(out) {
		return out
	}
	// --one-file-system and the explicit excludes keep tar from ever descending
	// into a kernel filesystem that may be mounted inside the shared rootfs
	// fixture. Without this, a stray /proc left mounted in the directory sends
	// tar into /proc/kcore, which reports a multi-terabyte size and never ends —
	// the fixture build hangs instead of failing. An image tarball has no
	// business containing proc/sys/dev contents anyway.
	cmd := exec.Command("tar",
		"--one-file-system",
		"--exclude=./proc/*", "--exclude=./sys/*", "--exclude=./dev/*",
		"-czf", out, "-C", rootfs, ".")
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pack rootfs: %v\n%s", err, o)
	}
	return out
}

func mustRootfs(t *testing.T) string {
	t.Helper()
	_, rootfs := setup(t)
	return rootfs
}

// imageLayers reads the layer stack husk recorded for an image.
func imageLayers(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open("/var/lib/husk/images/" + name)
	if err != nil {
		t.Fatalf("read image %s: %v", name, err)
	}
	defer f.Close()

	var layers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			layers = append(layers, l)
		}
	}
	return layers
}
