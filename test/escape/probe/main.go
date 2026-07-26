// Command probe applies deterministic resource pressure from inside a
// container, so the resource tests measure the kernel's enforcement rather than
// busybox's behaviour.
//
// Shell approximations are unreliable here in a way that quietly weakens a test.
// `dd if=/dev/zero of=/some/file` looks like a memory bomb but writes page cache,
// which the kernel reclaims under pressure instead of OOM-killing anyone — so
// the test passes whether or not memory.max is set. Anonymous memory that is
// actually touched cannot be reclaimed without swap, which is what forces the
// cgroup OOM killer to act.
package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: probe {memhog MiB | spin SECONDS | serve PORT}")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "memhog":
		memhog(arg(2, 256))
	case "spin":
		spin(arg(2, 5))
	case "serve":
		serve(arg(2, 8080))
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", os.Args[1])
		os.Exit(2)
	}
}

func arg(i, def int) int {
	if len(os.Args) <= i {
		return def
	}
	v, err := strconv.Atoi(os.Args[i])
	if err != nil {
		return def
	}
	return v
}

// memhog allocates and touches anonymous memory one mebibyte at a time,
// reporting progress as it goes.
//
// Touching every page is the point. A Go allocation is backed by mmap, and the
// kernel does not charge a mapping to a cgroup until a page is faulted in — so
// allocating a gigabyte and never writing to it costs nothing and triggers
// nothing. Writing one byte per 4 KiB page forces the fault, the charge, and
// eventually the kill.
//
// Progress is printed and flushed per chunk so the test can see how far it got
// before the kill, which is what distinguishes "the limit worked" from "the
// process never allocated anything".
func memhog(mib int) {
	held := make([][]byte, 0, mib)
	const pageSize = 4096

	for i := 0; i < mib; i++ {
		chunk := make([]byte, 1<<20)
		for p := 0; p < len(chunk); p += pageSize {
			chunk[p] = 1
		}
		held = append(held, chunk)

		fmt.Printf("allocated=%dMiB\n", i+1)
		os.Stdout.Sync()
	}

	// Keep the allocation live; a reference the compiler cannot discard.
	fmt.Printf("completed=%dMiB\n", len(held))
}

// serve answers HTTP on every interface, so the port-publishing test measures
// the DNAT datapath rather than a busybox nc invocation.
//
// Binding 0.0.0.0 rather than a specific address matters: a DNAT'd packet
// arrives with the container's bridge address as its destination, not localhost,
// so a server bound only to 127.0.0.1 is unreachable from outside no matter how
// correct the netfilter rules are. That mismatch is one of the most common
// reasons a published port appears not to work.
func serve(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host, _ := os.Hostname()
		fmt.Fprintf(w, "husk-probe hostname=%s remote=%s\n", host, r.RemoteAddr)
	})

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	fmt.Printf("listening on %s\n", addr)
	os.Stdout.Sync()

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

// spin burns CPU in a tight loop for the given duration, so cpu.max has
// something to throttle.
func spin(seconds int) {
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	iterations := 0
	for time.Now().Before(deadline) {
		// Enough arithmetic between clock reads that the loop is CPU-bound
		// rather than dominated by the time syscall.
		for i := 0; i < 100000; i++ {
			iterations++
		}
	}
	fmt.Printf("iterations=%d\n", iterations)
}
