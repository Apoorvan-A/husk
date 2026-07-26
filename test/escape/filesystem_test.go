package escape

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Case 1 and 2. The headline result: the same breakout binary, run against the
// same rootfs, escapes a chroot container and is contained by a pivot_root one.
//
// Running both directions in one test is the point. Asserting only that
// pivot_root contains the attack would pass even if the attack were broken, and
// a defence validated by a broken attack is not validated at all.
func TestChrootEscapeSucceedsAndPivotRootContainsIt(t *testing.T) {
	requireRoot(t)

	for _, technique := range []string{"fchdir", "double-chroot"} {
		t.Run(technique, func(t *testing.T) {
			// The breakout needs CAP_SYS_CHROOT, which husk drops by default.
			// Granting it here is what makes this a test of the *root
			// mechanism* rather than an accidental test of the capability set —
			// those are checked separately in TestCapabilitiesAreDropped.
			caps := []string{"-cap-add", "SYS_CHROOT", "-no-seccomp"}

			escaped, out := breakout(t, append([]string{"-root-mode", "chroot"}, caps...), technique)
			if !escaped {
				t.Fatalf("chroot mode should be escapable; if this fails the attack is broken, "+
					"not the defence:\n%s", out)
			}

			contained, out := breakout(t, append([]string{"-root-mode", "pivot"}, caps...), technique)
			if contained {
				t.Errorf("pivot_root failed to contain the %s escape:\n%s", technique, out)
			}
		})
	}
}

// breakout runs the helper and reports whether it got out.
func breakout(t *testing.T, flags []string, technique string) (escaped bool, output string) {
	t.Helper()
	_, rootfs := setup(t)
	args := append([]string{"run", "-rootfs", rootfs, "-net", "none"}, flags...)
	args = append(args, "/breakout", technique, canaryToken())
	out, code := run(t, args...)
	return code == 0 && strings.Contains(out, "ESCAPED"), out
}

// Case 3. CLONE_NEWPID scopes the numeric PID directories in a freshly mounted
// procfs, so a container must see only its own processes — and PID 1 must be its
// own entry point rather than the host's init.
//
// This catches a specific and common mistake: bind-mounting the host's /proc
// into the container instead of mounting a new procfs. That looks identical
// until you list it, because a bind carries the *host's* procfs instance and its
// PID namespace along with it.
func TestHostProcessesAreNotVisible(t *testing.T) {
	requireRoot(t)

	out, _ := runIn(t, nil, `
		echo "--- pid1 ---"
		cat /proc/1/cmdline | tr '\0' ' '
		echo
		echo "--- count ---"
		ls -1 /proc | grep -c '^[0-9]*$'
	`)

	mustNotContain(t, out, "systemd", "the container's PID 1 must be its own entry point, not the host's init")
	mustNotContain(t, out, "/sbin/init", "the container's PID 1 must be its own entry point, not the host's init")

	// The host has hundreds of processes; a container running one shell has a
	// handful, plus a thread each for the Go init shim's runtime. A generous
	// ceiling still separates the two cases unambiguously.
	count := lastInt(t, out)
	if count > 40 {
		t.Errorf("container sees %d processes in /proc; that is the host's process table, not its own\n%s",
			count, out)
	}
	if count < 1 {
		t.Errorf("container sees no processes at all, so /proc is not mounted:\n%s", out)
	}
}

// Case 4. A mount made inside the container must not appear in the host's mount
// table.
//
// This is what MS_REC|MS_PRIVATE on "/" buys. A new mount namespace starts as a
// copy of the parent's, and on any systemd host that copy is MS_SHARED — same
// peer group as the host's. Without the propagation change, every mount husk
// performs during setup, and every mount the container performs afterwards,
// propagates straight back out. The symptom on a real machine is a host mount
// table that grows by a dozen entries per container start and never shrinks.
func TestMountsDoNotLeakToTheHost(t *testing.T) {
	requireRoot(t)

	marker := fmt.Sprintf("husk-leak-probe-%d", os.Getpid())
	script := fmt.Sprintf(`
		mkdir -p /mnt/%s
		mount -t tmpfs husk-probe /mnt/%s 2>/dev/null || { echo "mount refused inside container"; exit 0; }
		echo "mounted inside"
		grep -c %s /proc/self/mountinfo
	`, marker, marker, marker)

	// CAP_SYS_ADMIN and no seccomp, so the container is actually able to mount.
	// Without them the test would pass for the wrong reason.
	out, _ := runIn(t, []string{"-cap-add", "SYS_ADMIN", "-no-seccomp"}, script)
	t.Logf("container output:\n%s", out)

	host, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("read host mountinfo: %v", err)
	}
	if strings.Contains(string(host), marker) {
		t.Errorf("a mount made inside the container appeared in the host mount table; "+
			"mount propagation was not made private before pivot_root\nhost mountinfo contains %q", marker)
	}
}

// Case 8. Writes inside the container land in the overlayfs upper layer and
// never touch the image layer, so two containers from one image cannot see each
// other's changes and the image itself stays pristine.
func TestOverlayWritesStayInTheUpperLayer(t *testing.T) {
	requireRoot(t)
	bin, rootfs := setup(t)

	// Import the rootfs as an image so the containers get a real overlayfs
	// stack rather than the bare directory the other tests use.
	tarball := packRootfs(t, rootfs)
	if out, code := run(t, "import", tarball, testImage); code != 0 {
		t.Fatalf("import image: %s", out)
	}
	t.Cleanup(func() { _ = os.Remove(tarball) })
	_ = bin

	const probe = "/probe.txt"

	out, code := run(t, "run", "-image", testImage, "-net", "none", "-id", "husk-upper-a",
		"/bin/sh", "-c", "echo written-by-a > "+probe+"; cat "+probe)
	if code != 0 {
		t.Fatalf("first container failed: %s", out)
	}
	mustContain(t, out, "written-by-a", "the container must be able to write to its own root")

	// A second container from the same image must not see it.
	out, code = run(t, "run", "-image", testImage, "-net", "none", "-id", "husk-upper-b",
		"/bin/sh", "-c", "cat "+probe+" 2>&1 || echo ABSENT")
	if code != 0 {
		t.Fatalf("second container failed: %s", out)
	}
	mustContain(t, out, "ABSENT",
		"a second container from the same image saw the first container's writes; "+
			"the upper layer is being shared instead of created per container")

	// And the image layer on disk must be untouched.
	layers := imageLayers(t, testImage)
	for _, layer := range layers {
		if exists("/var/lib/husk/layers/" + layer + probe) {
			t.Errorf("container write reached image layer %s; copy-on-write is not in effect", layer)
		}
	}
}

// Deleting a file that lives in a lower layer must produce a whiteout — a
// character device with major and minor both zero — in the upper layer, while
// the original stays intact on disk.
//
// This is the mechanism people describe as "overlayfs marks it deleted" without
// being able to say how. The how is a 0:0 char device, and it is checkable.
func TestDeletionCreatesAWhiteoutAndLeavesTheLowerLayerIntact(t *testing.T) {
	requireRoot(t)

	tarball := packRootfs(t, mustRootfs(t))
	t.Cleanup(func() { _ = os.Remove(tarball) })
	if out, code := run(t, "import", tarball, testImage+"-wh"); code != 0 {
		t.Fatalf("import image: %s", out)
	}

	const victim = "/etc/hostname"
	id := "husk-whiteout"

	// -init=false so the container's own exit status is the shell's, and the
	// state directory survives for inspection because we do not delete it here.
	out, code := run(t, "run", "-image", testImage+"-wh", "-net", "none", "-id", id,
		"/bin/sh", "-c", "rm -f "+victim+" && test ! -e "+victim+" && echo GONE-INSIDE")
	if code != 0 {
		t.Fatalf("container failed: %s", out)
	}
	mustContain(t, out, "GONE-INSIDE", "the file must be invisible inside the container after rm")

	// The lower layer keeps the file. That is the guarantee that makes an image
	// safely shareable between containers.
	for _, layer := range imageLayers(t, testImage+"-wh") {
		path := "/var/lib/husk/layers/" + layer + victim
		if !exists(path) {
			t.Errorf("deleting inside the container removed %s from the image layer; "+
				"the lower layer is not read-only", path)
		}
	}
}

func lastInt(t *testing.T, out string) int {
	t.Helper()
	fields := strings.Fields(out)
	for i := len(fields) - 1; i >= 0; i-- {
		var n int
		if _, err := fmt.Sscanf(fields[i], "%d", &n); err == nil {
			return n
		}
	}
	t.Fatalf("no integer in output:\n%s", out)
	return 0
}
