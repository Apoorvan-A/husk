package escape

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// rootfsURL is the userland the suite runs its attacks in. Pinned to an exact
// release so a test that starts failing means husk changed, not that upstream
// shipped a different busybox.
const rootfsURL = "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/" +
	"alpine-minirootfs-3.21.3-x86_64.tar.gz"

// cacheDir keeps the downloaded tarball and the extracted rootfs between runs.
// HUSK_TEST_CACHE lets CI point it at a restored cache directory.
func cacheDir() string {
	if d := os.Getenv("HUSK_TEST_CACHE"); d != "" {
		return d
	}
	return "/var/lib/husk-test"
}

func doSetup() (bin, rootfs string, err error) {
	root, err := repoRoot()
	if err != nil {
		return "", "", fmt.Errorf("locate repository root: %w", err)
	}

	cache := cacheDir()
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return "", "", err
	}

	bin = filepath.Join(cache, "husk")
	if err := build(root, "./cmd/husk", bin); err != nil {
		return "", "", err
	}

	rootfs = filepath.Join(cache, "rootfs")
	if err := ensureRootfs(cache, rootfs); err != nil {
		return "", "", err
	}

	// The helpers have to live inside the container's filesystem to be
	// executable from within it. Built with CGO_ENABLED=0 so they need no
	// dynamic loader: the alpine userland is musl-based and would not satisfy a
	// glibc-linked binary.
	for _, h := range []string{"breakout", "probe"} {
		staged := filepath.Join(cache, h)
		if err := build(root, "./test/escape/"+h, staged); err != nil {
			return "", "", err
		}
		if err := copyFile(staged, filepath.Join(rootfs, h), 0o755); err != nil {
			return "", "", err
		}
	}

	// A canary the container must not be able to read. Written at the real
	// filesystem root with content unique to this run, so a test that reports an
	// escape cannot be fooled by a same-named file inside the image — the alpine
	// rootfs ships its own /etc/hostname, which is exactly the trap an obvious
	// canary path falls into.
	if err := os.WriteFile(canaryPath, []byte(canaryToken()), 0o600); err != nil {
		return "", "", fmt.Errorf("write host canary: %w", err)
	}
	return bin, rootfs, nil
}

// canaryPath is at the real root, a location no container rootfs replicates.
const canaryPath = "/husk-escape-canary"

var canaryValue string

func canaryToken() string {
	if canaryValue == "" {
		canaryValue = fmt.Sprintf("husk-canary-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return canaryValue
}

func build(dir, pkg, out string) error {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %w\n%s", pkg, err, output)
	}
	return nil
}

func ensureRootfs(cache, rootfs string) error {
	// A marker file rather than a directory existence check: an interrupted
	// extraction leaves a directory that looks complete and produces confusing
	// failures later.
	marker := filepath.Join(rootfs, ".husk-test-ready")
	if exists(marker) {
		return nil
	}
	if err := os.RemoveAll(rootfs); err != nil {
		return err
	}
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return err
	}

	tarball := filepath.Join(cache, "rootfs.tar.gz")
	if !exists(tarball) {
		if err := download(rootfsURL, tarball); err != nil {
			return err
		}
	}

	// tar rather than husk's own extractor: the suite must not depend on the
	// code under test to build its fixtures.
	cmd := exec.Command("tar", "-xzf", tarball, "-C", rootfs)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("extract rootfs: %w\n%s", err, out)
	}
	return os.WriteFile(marker, []byte("ok\n"), 0o644)
}

func download(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: %s", url, resp.Status)
	}

	tmp := dest + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
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
