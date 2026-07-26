package escape

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The OCI create/start split: after `create` the container exists and holds all
// its resources, but the entry point has not run. `start` is what releases it.
//
// The interesting assertion is the negative one. It is easy to build a runtime
// where `create` accidentally starts the workload and `start` is a no-op that
// only updates a status field — every visible symptom is identical unless you
// check that the entry point's side effects have not happened yet.
func TestCreateDoesNotRunTheEntryPointUntilStart(t *testing.T) {
	requireRoot(t)
	_, rootfs := setup(t)

	const id = "husk-lifecycle-probe"
	_, _ = run(t, "delete", "-force", id)

	// The entry point writes a marker into its own writable root. If `create`
	// ran it, the marker exists before `start` is ever called.
	marker := "/started-marker"
	out, code := run(t, "create", "-rootfs", rootfs, "-net", "none", "-id", id,
		"/bin/sh", "-c", "echo yes > "+marker+"; sleep 30")
	if code != 0 {
		t.Fatalf("create failed: %s", out)
	}
	t.Cleanup(func() {
		_, _ = run(t, "kill", "-all", id, "KILL")
		_, _ = run(t, "delete", "-force", id)
	})

	if st := containerState(t, id); st.Status != "created" {
		t.Errorf("after create the status is %q, want \"created\"", st.Status)
	}

	// Give a would-be premature entry point ample time to run.
	time.Sleep(300 * time.Millisecond)
	if exists(rootfs + marker) {
		t.Errorf("the entry point ran during create; the create/start split is not implemented")
	}

	if out, code := run(t, "start", id); code != 0 {
		t.Fatalf("start failed: %s", out)
	}
	if st := containerState(t, id); st.Status != "running" {
		t.Errorf("after start the status is %q, want \"running\"", st.Status)
	}

	if !eventually(2*time.Second, func() bool { return exists(rootfs + marker) }) {
		t.Errorf("the entry point did not run after start")
	}
	_ = exec.Command("rm", "-f", rootfs+marker).Run()
}

// `husk start` must fail with a diagnostic rather than blocking forever when the
// init process is gone.
//
// This is the regression test for a bug that was genuinely nasty in practice:
// with PR_SET_PDEATHSIG left set on the detached path, `husk create` killed its
// own container the instant it exited, and the subsequent `start` blocked
// forever in open(O_WRONLY) on a FIFO whose writer no longer existed. A hang
// with no message is the worst possible presentation of that failure.
func TestStartFailsFastWhenInitIsGone(t *testing.T) {
	requireRoot(t)
	_, rootfs := setup(t)

	const id = "husk-dead-init-probe"
	_, _ = run(t, "delete", "-force", id)

	if out, code := run(t, "create", "-rootfs", rootfs, "-net", "none", "-id", id,
		"/bin/sh", "-c", "sleep 30"); code != 0 {
		t.Fatalf("create failed: %s", out)
	}
	t.Cleanup(func() { _, _ = run(t, "delete", "-force", id) })

	st := containerState(t, id)
	if st.Pid <= 0 {
		t.Fatalf("no pid recorded for the created container")
	}
	// Kill the init process out from under the state file, simulating a crash
	// between create and start.
	if err := exec.Command("kill", "-9", strconv.Itoa(st.Pid)).Run(); err != nil {
		t.Fatalf("kill init: %v", err)
	}
	if !eventually(3*time.Second, func() bool {
		return exec.Command("kill", "-0", strconv.Itoa(st.Pid)).Run() != nil
	}) {
		t.Fatalf("init process did not die")
	}

	// The command is run directly rather than through the harness helper,
	// because that helper calls t.Fatalf and calling it from a non-test
	// goroutine is undefined: runtime.Goexit unwinds the wrong stack and the
	// test hangs instead of failing.
	bin, _ := setup(t)
	type result struct {
		out  string
		code int
	}
	done := make(chan result, 1)
	go func() {
		out, err := exec.Command(bin, "start", id).CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		done <- result{string(out), code}
	}()

	select {
	case r := <-done:
		if r.code == 0 {
			t.Errorf("start reported success against a dead init process:\n%s", r.out)
		}
		t.Logf("start correctly failed: %s", strings.TrimSpace(r.out))
	case <-time.After(30 * time.Second):
		t.Fatalf("start blocked instead of reporting that the init process was gone")
	}
}

// The container's init process is a real PID 1 in its namespace: it must reap
// orphans rather than let them accumulate as zombies.
//
// A container that leaks zombies exhausts pids.max eventually and then cannot
// fork at all, which presents as a workload that mysteriously stops working
// after days of uptime.
func TestPID1ReapsOrphanedChildren(t *testing.T) {
	requireRoot(t)
	_, rootfs := setup(t)

	// Spawn short-lived grandchildren whose parents exit immediately, orphaning
	// them onto PID 1. Then count what is left in state Z.
	out, code := run(t, "run", "-rootfs", rootfs, "-net", "none", "-pids", "128", "/bin/sh", "-c", `
		i=0
		while [ $i -lt 20 ]; do
			( /bin/true & )
			i=$((i+1))
		done
		sleep 1
		echo "zombies=$(ps -eo stat --no-headers 2>/dev/null | grep -c Z || awk '{print 0}')"
		echo "procs=$(ls /proc | grep -c '^[0-9]*$')"
	`)
	t.Logf("exit=%d\n%s", code, out)

	if strings.Contains(out, "zombies=") {
		z := valueAfter(out, "zombies=")
		if z > 2 {
			t.Errorf("%d zombie processes remain; PID 1 is not reaping orphans", z)
		}
	}
}

type ociState struct {
	OCIVersion string `json:"ociVersion"`
	ID         string `json:"id"`
	Status     string `json:"status"`
	Pid        int    `json:"pid"`
	Bundle     string `json:"bundle"`
}

func containerState(t *testing.T, id string) ociState {
	t.Helper()
	out, code := run(t, "state", id)
	if code != 0 {
		t.Fatalf("state %s failed: %s", id, out)
	}
	// The runtime's structured logs go to stderr and are captured alongside
	// stdout, so take the JSON object that parses as a state.
	var st ociState
	if err := json.Unmarshal([]byte(jsonObject(out)), &st); err != nil {
		t.Fatalf("parse state output: %v\n%s", err, out)
	}
	if st.OCIVersion == "" {
		t.Errorf("state output is missing ociVersion, so it does not satisfy the runtime-spec")
	}
	return st
}

// jsonObject extracts the pretty-printed object from mixed output.
func jsonObject(out string) string {
	start := strings.Index(out, "{\n")
	if start < 0 {
		return out
	}
	end := strings.LastIndex(out, "}")
	if end < start {
		return out
	}
	return out[start : end+1]
}

func eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func valueAfter(out, prefix string) int {
	i := strings.Index(out, prefix)
	if i < 0 {
		return -1
	}
	rest := out[i+len(prefix):]
	if j := strings.IndexAny(rest, " \n\t"); j >= 0 {
		rest = rest[:j]
	}
	n := 0
	for _, c := range rest {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
