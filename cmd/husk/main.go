// Command husk is a minimal OCI-compatible container runtime built directly on
// Linux kernel primitives.
//
// This is a learning implementation. It is not a production runtime and makes no
// attempt to be one — use runc. See docs/SECURITY-MODEL.md for what it does and
// does not isolate against.
package main

import (
	"fmt"
	"os"

	"github.com/Apoorvan-A/husk/internal/cli"
)

func main() {
	if err := cli.Main(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "husk: %v\n", err)
		os.Exit(1)
	}
}
