// Package security applies the three process-level restrictions husk relies on
// once the filesystem view is already narrowed: capability reduction, the
// no_new_privs latch, and a seccomp-BPF syscall filter.
//
// None of these are namespaces. Namespaces restrict what a process can *see*;
// these restrict what it can *ask the kernel to do*. Both are necessary, and the
// distinction is the honest answer to "how isolated is a container": the syscall
// surface is shared no matter how many namespaces are involved, and this package
// is the only thing narrowing it.
package security

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/apoorvan10/husk/internal/container"
)

// Apply runs the three steps in the only order that works. Each one removes a
// privilege the next would otherwise need, so the sequence cannot be reordered
// or run twice.
func Apply(sec container.Security) error {
	caps := sec.Capabilities
	if caps == nil {
		caps = DefaultCapabilities
	}
	if err := DropCapabilities(caps); err != nil {
		return fmt.Errorf("capabilities: %w", err)
	}

	// Must precede the seccomp install, and is worth setting even when seccomp
	// is disabled: it is what stops a setuid binary inside the image from being
	// a privilege-escalation path out of the reduced capability set above.
	if sec.NoNewPrivs || sec.Seccomp.Enabled {
		if err := SetNoNewPrivs(); err != nil {
			return err
		}
	}

	if !sec.Seccomp.Enabled {
		return nil
	}

	denied := DefaultDenied
	for _, name := range sec.Seccomp.ExtraDenied {
		nr, ok := LookupSyscall(name)
		if !ok {
			return fmt.Errorf("unknown syscall %q in seccomp policy", name)
		}
		denied = append(denied, Denied{Name: name, Nr: nr})
	}

	action := ActionErrno(unix.EPERM)
	if strings.EqualFold(sec.Seccomp.Action, "kill") {
		action = ActionKill()
	}

	prog, err := BuildFilter(denied, action)
	if err != nil {
		return fmt.Errorf("build seccomp filter: %w", err)
	}
	if err := prog.Install(); err != nil {
		return fmt.Errorf("install seccomp filter: %w", err)
	}
	return nil
}

// LookupSyscall resolves a syscall name against the default policy table. It
// covers the names husk itself references rather than every syscall on the
// platform, which keeps the surface honest: a typo in a policy is an error
// rather than a silently-ignored rule.
func LookupSyscall(name string) (int, bool) {
	for _, d := range DefaultDenied {
		if strings.EqualFold(d.Name, name) {
			return d.Nr, true
		}
	}
	return 0, false
}

func readSmallFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
