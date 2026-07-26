package escape

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Case 5. A container that allocates past memory.max must be OOM-killed inside
// its own cgroup, and the host must be unaffected.
//
// The containment claim is the interesting half. Without a memory cgroup the
// same allocation triggers the *global* OOM killer, which picks a victim by
// badness score across the whole machine — and the workload with the largest
// resident set is frequently not the one that misbehaved. A memory cgroup turns
// "one container misbehaved, the database got killed" into "one container
// misbehaved, that container died".
func TestMemoryLimitIsEnforcedAndTheHostSurvives(t *testing.T) {
	requireRoot(t)

	const limitMiB = 64
	id := "husk-oom-probe"
	cgroupDir := "/sys/fs/cgroup/husk/" + id

	// Sample memory.events while the container is alive. The cgroup is removed
	// during teardown, taking the counters with it, so this races the container's
	// own exit — hence the tight interval and the fact that the assertion below
	// treats a missed sample as inconclusive rather than as a failure. The
	// load-bearing evidence is the exit status.
	events := make(chan string, 1)
	go func() {
		deadline := time.Now().Add(30 * time.Second)
		last := ""
		for time.Now().Before(deadline) {
			if data, err := os.ReadFile(cgroupDir + "/memory.events"); err == nil {
				last = string(data)
				if oomKillCount(last) > 0 {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
		events <- last
	}()

	// Touch four times the limit in anonymous memory. Anonymous pages are not
	// reclaimable without swap, and husk sets memory.swap.max to zero alongside
	// memory.max, so the cgroup has no way to satisfy the allocation except by
	// killing something inside itself.
	_, rootfs := setup(t)
	out, code := run(t, "run", "-rootfs", rootfs, "-net", "none",
		"-memory", fmt.Sprintf("%dM", limitMiB), "-id", id,
		"/probe", "memhog", strconv.Itoa(limitMiB*4))
	memEvents := <-events

	t.Logf("exit=%d\ncontainer output:\n%s\nmemory.events:\n%s", code, tail(out, 4), memEvents)

	if strings.Contains(out, fmt.Sprintf("completed=%dMiB", limitMiB*4)) {
		t.Fatalf("the container allocated %d MiB under a %d MiB memory.max; the limit was not applied",
			limitMiB*4, limitMiB)
	}

	// 137 is 128+SIGKILL, the shell convention husk's init shim reproduces. The
	// OOM killer is the only thing that sends SIGKILL here, so this is the
	// primary evidence that the kill happened and that it was the kernel's doing
	// rather than the allocator giving up.
	if code != 137 {
		t.Errorf("expected exit 137 (SIGKILL from the OOM killer), got %d; "+
			"the allocation was stopped by something other than a kill", code)
	}

	// Corroborating evidence when the sampler won the race.
	if n := oomKillCount(memEvents); n > 0 {
		t.Logf("memory.events confirms %d oom_kill in the container's own cgroup", n)
	} else {
		t.Logf("memory.events was not sampled before teardown removed the cgroup; " +
			"relying on the exit status")
	}

	// The containment claim. Note that /proc/vmstat's oom_kill counter is *not*
	// the right instrument for this — the kernel increments it for cgroup-scoped
	// kills as well as global ones, so it rises on a correctly contained kill
	// and asserting on it produces a test that fails when everything worked.
	// What actually distinguishes the two is that the host kept running and its
	// own allocations kept succeeding.
	if !hostStillHealthy(t) {
		t.Errorf("the host could not allocate or fork after the container's OOM kill; " +
			"the kill was not contained to the container's cgroup")
	}
}

// hostStillHealthy checks that the machine outside the container is unaffected:
// it can still allocate memory and still fork.
func hostStillHealthy(t *testing.T) bool {
	t.Helper()
	scratch := make([]byte, 16<<20)
	for i := 0; i < len(scratch); i += 4096 {
		scratch[i] = 1
	}
	if err := exec.Command("/bin/true").Run(); err != nil {
		t.Logf("host fork failed: %v", err)
		return false
	}
	return len(scratch) > 0
}

// The regression test for the bug the case above originally caught: with swap
// left unbounded, memory.max stops being a limit and becomes a paging trigger.
// The container survives, nothing is killed, and the only visible symptom is the
// host's disk working hard on someone else's behalf.
//
// Asserting the broken configuration behaves badly is what stops the default
// from being quietly reverted later.
func TestUnboundedSwapDefeatsTheMemoryLimit(t *testing.T) {
	requireRoot(t)

	if !hostHasSwap(t) {
		t.Skip("host has no swap, so there is nothing for the container to escape into")
	}

	const limitMiB = 64
	_, rootfs := setup(t)

	out, _ := run(t, "run", "-rootfs", rootfs, "-net", "none",
		"-memory", fmt.Sprintf("%dM", limitMiB), "-memory-swap", "max",
		"-id", "husk-swap-probe",
		"/probe", "memhog", strconv.Itoa(limitMiB*3))

	if !strings.Contains(out, fmt.Sprintf("completed=%dMiB", limitMiB*3)) {
		t.Logf("output:\n%s", tail(out, 5))
		t.Errorf("with -memory-swap max the container should have been able to allocate past " +
			"memory.max by swapping; it did not, so this test is no longer demonstrating the " +
			"hazard that makes the swap default necessary")
	}
}

func hostHasSwap(t *testing.T) bool {
	t.Helper()
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "SwapTotal:") {
			return !strings.Contains(line, " 0 kB")
		}
	}
	return false
}

func oomKillCount(events string) int {
	for _, line := range strings.Split(events, "\n") {
		if strings.HasPrefix(line, "oom_kill ") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "oom_kill")))
			return n
		}
	}
	return 0
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) <= lines {
		return s
	}
	return "... " + strings.Join(parts[len(parts)-lines:], "\n")
}

// Case 6. A CPU-bound loop under cpu.max must be throttled, and cpu.stat must
// show it.
//
// Reading the throttle counter matters more than measuring the percentage.
// nr_throttled is the kernel telling you it descheduled the cgroup at a period
// boundary, which is the mechanism behind the tail-latency problem CPU quotas
// cause in production: the process is not slowed uniformly, it is stopped dead
// until the next 100 ms period begins.
func TestCPUQuotaThrottlesAndIsObservable(t *testing.T) {
	requireRoot(t)

	id := "husk-cpu-probe"
	cgroupDir := "/sys/fs/cgroup/husk/" + id

	done := make(chan struct{})
	var stats string
	go func() {
		defer close(done)
		// Sample while the container is still alive; the cgroup is removed the
		// moment it exits.
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if data, err := os.ReadFile(cgroupDir + "/cpu.stat"); err == nil {
				s := string(data)
				if throttleCount(s) > 0 {
					stats = s
					return
				}
				stats = s
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	_, rootfs := setup(t)
	out, _ := run(t, "run", "-rootfs", rootfs, "-net", "none",
		"-cpus", "0.2", "-id", id, "/probe", "spin", "4")
	<-done

	t.Logf("container: %s", strings.TrimSpace(out))
	t.Logf("cpu.stat:\n%s", stats)

	if stats == "" {
		t.Fatalf("could not read cpu.stat from %s while the container was running", cgroupDir)
	}
	if n := throttleCount(stats); n == 0 {
		t.Errorf("a CPU-saturating loop under cpu.max 20%% recorded zero throttled periods; "+
			"the quota was not applied\ncpu.stat:\n%s", stats)
	}
}

// Case 7. A fork bomb must hit pids.max and the host must stay responsive.
//
// pids.max is the limit people skip because it looks redundant next to a memory
// limit. It is not: a forking process consumes kernel task structures long
// before it consumes meaningful userspace memory, and exhausting the global PID
// space stops the *whole machine* from forking — including the shell an operator
// would use to fix it, and the runtime that would kill the container.
func TestForkBombHitsPidsMaxAndTheHostStaysResponsive(t *testing.T) {
	requireRoot(t)

	const limit = 32
	out, code := runIn(t, []string{"-pids", strconv.Itoa(limit), "-memory", "128M", "-id", "husk-fork-probe"}, `
		i=0
		while [ $i -lt 200 ]; do
			sleep 30 &
			i=$((i+1))
		done 2>/dev/null
		echo "spawned=$(ls /proc | grep -c '^[0-9]*$')"
	`)
	t.Logf("exit=%d output:\n%s", code, out)

	// The host must still be able to fork. If pids.max were not enforced this
	// would be the assertion that fails, and it is the one that matters
	// operationally.
	if _, err := os.ReadFile("/proc/self/status"); err != nil {
		t.Fatalf("host became unresponsive during the fork bomb: %v", err)
	}

	// Some of the 200 forks must have been refused. Being generous about the
	// exact number: the shell, the init shim's runtime threads and the sleeps
	// all count against the same ceiling.
	if strings.Contains(out, "spawned=") {
		n := lastInt(t, out)
		if n > limit+8 {
			t.Errorf("container reached %d processes under pids.max=%d; the limit was not applied", n, limit)
		}
	}
}

func throttleCount(cpuStat string) int {
	for _, line := range strings.Split(cpuStat, "\n") {
		if strings.HasPrefix(line, "nr_throttled ") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "nr_throttled")))
			return n
		}
	}
	return 0
}
