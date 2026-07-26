// Package cli parses arguments and dispatches subcommands. It deliberately uses
// only the standard library's flag package: a runtime whose whole point is to
// have no hidden machinery should not pull in a CLI framework to print a usage
// string.
package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/apoorvan10/husk/internal/initproc"
)

const usage = `husk — a minimal OCI-compatible container runtime

Usage:
  husk <command> [flags] [arguments]

Container commands:
  run        create and immediately start a container
  exec       run an additional process inside a running container
  ps         list containers
  logs       print the captured output of a detached container
  top        live per-container resource usage from cgroup files

Image commands:
  import     extract a rootfs tarball into the local image store
  images     list images in the local store
  commit     snapshot a container's writable layer as a new image layer

OCI runtime lifecycle:
  create     construct a container from a bundle but do not start it
  start      release a created container to run its entry point
  state      print a container's OCI state as JSON
  kill       send a signal to a container's init process
  delete     remove a stopped container and its resources

Other:
  metrics    serve Prometheus metrics for all running containers
  version    print version information

Run "husk <command> -h" for the flags of a single command.
`

// Main dispatches. The error it returns is printed by the caller and becomes a
// non-zero exit status.
func Main(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("no command given")
	}

	cmd, rest := args[0], args[1:]

	switch cmd {
	// init is the container side of the fork. It is not part of the public
	// interface and is only ever exec'd by the runtime itself; the environment
	// marker is what distinguishes a real re-exec from someone typing it.
	case "init":
		if os.Getenv("HUSK_INIT") != "1" {
			return fmt.Errorf("init is used internally by husk and cannot be invoked directly")
		}
		return initproc.Run()

	case "run":
		return runCommand(rest)
	case "exec":
		return execCommand(rest)
	case "ps":
		return psCommand(rest)
	case "logs":
		return logsCommand(rest)
	case "top":
		return topCommand(rest)
	case "commit":
		return commitCommand(rest)
	case "import":
		return importCommand(rest)
	case "images":
		return imagesCommand(rest)

	case "create":
		return createCommand(rest)
	case "start":
		return startCommand(rest)
	case "state":
		return stateCommand(rest)
	case "kill":
		return killCommand(rest)
	case "delete":
		return deleteCommand(rest)

	case "metrics":
		return metricsCommand(rest)
	case "version":
		return versionCommand()

	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 8, 3, ' ', 0)
}
