// Package escape contains husk's adversarial test suite: tests that try to
// break out of, or defeat the limits on, a container husk built.
//
// The suite is written as attacks rather than assertions about implementation
// details on purpose. A test that checks "pivot_root was called" passes even if
// the call was made in the wrong order and achieved nothing. A test that runs a
// real breakout and requires it to fail is checking the property that actually
// matters.
//
// Every test needs real namespaces, real cgroups and real mounts, so the suite
// runs only as root on Linux and skips otherwise.
package escape

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// testImage is imported once from the rootfs tarball the harness fetches.
	testImage = "husk-test-alpine"

	// defaultTimeout bounds a container run. Several of these tests deliberately
	// provoke fork bombs and OOM kills, and a hang there would wedge CI.
	defaultTimeout = 60 * time.Second
)

var (
	buildOnce sync.Once
	huskBin   string
	rootfsDir string
	buildErr  error
)

// requireRoot skips unless the suite can actually do what it is testing.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("escape suite needs root to create namespaces, cgroups and mounts")
	}
}

// setup builds husk and the breakout helper once per test binary, and prepares a
// rootfs directory containing both an alpine userland and the helper.
//
// The rootfs is a plain directory rather than an overlayfs image because the
// filesystem tests need to reason about exactly what is and is not reachable,
// and a union mount adds a layer of indirection that would make a failure
// ambiguous.
func setup(t *testing.T) (bin, rootfs string) {
	t.Helper()
	requireRoot(t)

	buildOnce.Do(func() {
		huskBin, rootfsDir, buildErr = doSetup()
	})
	if buildErr != nil {
		t.Fatalf("harness setup: %v", buildErr)
	}
	return huskBin, rootfsDir
}

// run executes husk with the given arguments and returns combined output.
func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	bin, _ := setup(t)

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("husk %s timed out after %s\noutput:\n%s",
			strings.Join(args, " "), defaultTimeout, buf.String())
	}

	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("husk %s: %v\noutput:\n%s", strings.Join(args, " "), err, buf.String())
	}
	return buf.String(), code
}

// runIn is the common shape: run a shell snippet inside a container built with
// the given extra flags.
func runIn(t *testing.T, flags []string, script string) (string, int) {
	t.Helper()
	_, rootfs := setup(t)
	args := append([]string{"run", "-rootfs", rootfs, "-net", "none"}, flags...)
	args = append(args, "/bin/sh", "-c", script)
	return run(t, args...)
}

func mustContain(t *testing.T, output, want, why string) {
	t.Helper()
	if !strings.Contains(output, want) {
		t.Errorf("%s\nexpected output to contain %q, got:\n%s", why, want, output)
	}
}

func mustNotContain(t *testing.T, output, unwanted, why string) {
	t.Helper()
	if strings.Contains(output, unwanted) {
		t.Errorf("%s\nexpected output NOT to contain %q, got:\n%s", why, unwanted, output)
	}
}

func hostFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read host %s: %v", path, err)
	}
	return strings.TrimSpace(string(data))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if exists(filepath.Join(dir, "go.mod")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
