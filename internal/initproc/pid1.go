package initproc

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"golang.org/x/sys/unix"
)

// superviseAsPID1 runs the user's command as a child and stays resident as PID 1
// of the container, doing the two jobs PID 1 is uniquely responsible for.
//
// Reaping. When any process dies its parent must wait() for it, otherwise the
// kernel keeps the exit status and a task_struct around and the process stays in
// the table as a zombie. A process whose parent dies first is re-parented to PID
// 1 *of its PID namespace* — us. A long-lived container whose entry point forks
// and does not reap therefore leaks PIDs until pids.max or the global limit is
// hit, at which point nothing in the container can fork. This is the single most
// common "my container mysteriously stopped working" cause.
//
// Signals. `docker stop` sends SIGTERM and then SIGKILL after a grace period.
// The kernel gives PID 1 a special protection: signals whose disposition is the
// default action are simply *not delivered* to it, so a shell script that never
// installs a SIGTERM handler ignores the polite stop entirely and always eats the
// SIGKILL. Forwarding explicitly from a supervisor that does install handlers is
// what restores graceful shutdown.
func superviseAsPID1(bin string, args, env []string) error {
	// Buffered generously: signals arriving while we are inside the handler must
	// not be dropped, and SIGCHLD can arrive in bursts when a forking workload
	// exits.
	sigs := make(chan os.Signal, 64)
	signal.Notify(sigs)

	cmd := exec.Command(bin, args[1:]...)
	cmd.Path = bin
	cmd.Args = args
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", bin, err)
	}
	child := cmd.Process.Pid

	for s := range sigs {
		sig, ok := s.(unix.Signal)
		if !ok {
			continue
		}
		if sig == unix.SIGCHLD {
			if status, done := reap(child); done {
				return exitWith(status)
			}
			continue
		}
		// SIGKILL and SIGSTOP never reach here — the kernel does not allow them
		// to be caught. Everything else is relayed so the workload decides what
		// it means.
		_ = unix.Kill(child, sig)
	}
	return nil
}

// reap drains every child that has changed state. The loop is mandatory: SIGCHLD
// is not queued, so a single delivery can represent any number of exits, and
// handling only one per signal is how zombie leaks happen in code that looks
// correct.
//
// WNOHANG makes each waitpid non-blocking, so the loop terminates on 0 (children
// exist but none have exited) or ECHILD (none left).
func reap(direct int) (status unix.WaitStatus, directExited bool) {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if err == unix.EINTR {
			continue
		}
		if pid <= 0 || err != nil {
			return status, directExited
		}
		if pid == direct {
			status, directExited = ws, true
		}
	}
}

// exitWith reproduces the child's fate as our own, so the exit status the
// runtime observes is the workload's and not the supervisor's.
func exitWith(ws unix.WaitStatus) error {
	if ws.Signaled() {
		// 128+n is the shell convention for "died from signal n". Re-raising the
		// signal on ourselves would be more faithful, but PID 1 cannot be killed
		// by a signal it has a handler for, so the convention is the honest
		// option here.
		os.Exit(128 + int(ws.Signal()))
	}
	os.Exit(ws.ExitStatus())
	return nil
}
