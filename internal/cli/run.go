package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Apoorvan-A/husk/internal/cgroups"
	"github.com/Apoorvan-A/husk/internal/container"
	"github.com/Apoorvan-A/husk/internal/hlog"
	"github.com/Apoorvan-A/husk/internal/network"
	"github.com/Apoorvan-A/husk/internal/security"
	"github.com/Apoorvan-A/husk/internal/spawn"
	"github.com/Apoorvan-A/husk/internal/state"
	"github.com/Apoorvan-A/husk/internal/storage"
)

// env bundles the three stores every command needs, so a command body does not
// have to thread four root paths through every call.
type env struct {
	states  *state.Store
	storage *storage.Store
	network *network.Manager
}

func newEnv(c *commonFlags) *env {
	states := state.NewStore(c.stateRoot)
	return &env{
		states:  states,
		storage: storage.NewStore(c.dataRoot),
		network: network.NewManager(states.Root),
	}
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var c commonFlags
	c.register(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: husk run [flags] COMMAND [ARG...]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		fs.Usage()
		return fmt.Errorf("no command given")
	}
	return launch(&c, cmdArgs, false)
}

func createCommand(args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	var c commonFlags
	bundle := fs.String("bundle", ".", "path to an OCI bundle containing config.json")
	c.register(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: husk create [flags] [COMMAND ARG...]\n\n"+
			"With -bundle, the command and all resource settings come from the bundle's config.json.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// An OCI bundle supplies everything; the flags are only used when husk is
	// driven directly rather than by a spec-compliant caller.
	if hasBundle(*bundle) {
		cfg, err := loadBundle(*bundle, &c)
		if err != nil {
			return err
		}
		return launchConfig(&c, cfg, *bundle, true)
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		fs.Usage()
		return fmt.Errorf("no command given and no bundle found")
	}
	return launch(&c, cmdArgs, true)
}

// launch builds a config from flags and hands off to launchConfig.
func launch(c *commonFlags, cmdArgs []string, awaitStart bool) error {
	cfg, err := buildConfig(c, cmdArgs)
	if err != nil {
		return err
	}
	return launchConfig(c, cfg, "", awaitStart)
}

func buildConfig(c *commonFlags, cmdArgs []string) (*container.Config, error) {
	id := c.id
	if id == "" {
		id = newID()
	}
	hostname := c.hostname
	if hostname == "" {
		hostname = id[:min(12, len(id))]
	}

	memMax, err := parseMemory(c.memory)
	if err != nil {
		return nil, err
	}
	memHigh, err := parseMemory(c.memHigh)
	if err != nil {
		return nil, err
	}
	memSwap, err := parseSwap(c.memSwap)
	if err != nil {
		return nil, err
	}
	ports, err := parsePorts(c.ports)
	if err != nil {
		return nil, err
	}

	rootMode := container.RootMode(c.rootMode)
	if rootMode != container.RootModePivot && rootMode != container.RootModeChroot {
		return nil, fmt.Errorf("root-mode must be pivot or chroot, got %q", c.rootMode)
	}

	ns := container.DefaultNamespaces()
	switch c.network {
	case "bridge", "none":
		// keep CLONE_NEWNET
	case "host":
		// Sharing the host's network namespace removes the isolation entirely:
		// the container can bind host ports, see host interfaces, and reach
		// anything the host can reach on loopback. Supported because it is
		// occasionally the right answer, but never the default.
		ns.Net = false
	default:
		return nil, fmt.Errorf("unknown network mode %q", c.network)
	}
	ns.User = c.rootless

	cfg := &container.Config{
		ID:             id,
		Hostname:       hostname,
		Args:           cmdArgs,
		Env:            c.env,
		Cwd:            c.cwd,
		RootMode:       rootMode,
		ReadonlyRootfs: c.readonly,
		Namespaces:     ns,
		InitProcess:    c.initShim,
		Resources: container.Resources{
			MemoryMax:     memMax,
			MemoryHigh:    memHigh,
			MemorySwapMax: memSwap,
			CPUMax:        c.cpus,
			PidsMax:       c.pids,
			IOMax:         c.ioMax,
			CPUSet:        c.cpuSet,
		},
		Network: container.Network{Mode: c.network, Ports: ports},
		Security: container.Security{
			Capabilities: resolveCapabilities(security.DefaultCapabilities, c.capsAdd, c.capsDrop),
			NoNewPrivs:   true,
			Seccomp: container.SeccompConfig{
				Enabled: !c.noSeccomp,
				Action:  "errno",
			},
		},
	}

	if c.rootless {
		cfg.IDMaps = namespacesRootless()
	}
	return cfg, nil
}

// launchConfig performs the full create sequence and, unless awaitStart is set,
// waits for the container to exit.
//
// The teardown discipline matters more than the setup here. Every step below
// allocates a host resource that outlives the process if nobody removes it: a
// cgroup directory, a veth interface, an IP lease, netfilter rules, an overlayfs
// mount. Each is registered for cleanup the moment it is created, so a failure
// halfway through unwinds exactly what was built rather than leaving the host
// dirty.
func launchConfig(c *commonFlags, cfg *container.Config, bundle string, awaitStart bool) error {
	e := newEnv(c)
	cfg.AwaitStart = awaitStart
	started := time.Now()

	if err := e.states.Create(cfg.ID); err != nil {
		return err
	}
	var cleanups []func()
	failed := true
	defer func() {
		if !failed {
			return
		}
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()
	cleanups = append(cleanups, func() { _ = e.states.Remove(cfg.ID) })

	if awaitStart {
		if err := e.states.MakeFifo(cfg.ID); err != nil {
			return err
		}
	}

	layers, err := e.prepareRootfs(c, cfg)
	if err != nil {
		return err
	}
	if cfg.Rootfs != c.rootfs {
		cleanups = append(cleanups, func() { _ = e.storage.Remove(cfg.ID) })
	}

	cg := cgroups.New(cfg.ID, c.cgParent)
	if err := cg.Create(); err != nil {
		return fmt.Errorf("cgroup: %w", err)
	}
	cleanups = append(cleanups, func() { _ = cg.Destroy() })
	if err := cg.Apply(cfg.Resources); err != nil {
		return fmt.Errorf("cgroup limits: %w", err)
	}

	st := &state.State{
		ID:        cfg.ID,
		Status:    state.StatusCreating,
		Bundle:    bundle,
		Created:   time.Now(),
		Config:    cfg,
		Image:     c.image,
		Layers:    layers,
		CgroupDir: cg.Path(),
	}
	if err := e.states.Save(st); err != nil {
		return err
	}

	networkAttached := false
	setup := func(pid int) (container.Network, error) {
		// Cgroup membership before anything else: from this write onward the
		// container's memory and CPU are accounted and capped, and the user's
		// command has not run yet.
		if err := cg.AddProcess(pid); err != nil {
			return container.Network{}, fmt.Errorf("move pid %d into cgroup: %w", pid, err)
		}
		if cfg.Network.Mode != "bridge" || !cfg.Namespaces.Net {
			return cfg.Network, nil
		}
		netCfg, err := e.network.Attach(cfg.ID, pid, cfg.Network.Ports)
		if err != nil {
			return container.Network{}, err
		}
		networkAttached = true
		return netCfg, nil
	}
	cleanups = append(cleanups, func() {
		if networkAttached {
			_ = e.network.Detach(cfg.ID, cfg.Network.Ports)
		}
	})

	stdin, stdout, stderr, closeIO, err := containerIO(e.states.Dir(cfg.ID), awaitStart)
	if err != nil {
		return err
	}
	defer closeIO()

	handle, err := spawn.Start(spawn.Options{
		Config:   cfg,
		Stdin:    stdin,
		Stdout:   stdout,
		Stderr:   stderr,
		StateDir: e.states.Dir(cfg.ID),
		Detached: awaitStart,
		Setup:    setup,
	})
	if err != nil {
		return err
	}

	st.Pid = handle.Pid
	cfg.Network = handle.Network
	st.Status = state.StatusCreated
	if !awaitStart {
		st.Status = state.StatusRunning
	}
	if err := e.states.Save(st); err != nil {
		return err
	}

	hlog.Event("container.create", cfg.ID,
		"pid", handle.Pid,
		"rootfs", cfg.Rootfs,
		"ip", cfg.Network.IP,
		hlog.Duration("setup", time.Since(started)),
	)

	if awaitStart {
		// The container is constructed and blocked on its FIFO. Hand it over to
		// whoever calls `husk start`.
		failed = false
		if err := handle.Detach(); err != nil {
			return err
		}
		fmt.Println(cfg.ID)
		return nil
	}

	failed = false
	code, waitErr := handle.Wait()

	st.Status = state.StatusStopped
	st.ExitCode = code
	_ = e.states.Save(st)

	hlog.Event("container.exit", cfg.ID,
		"exit_code", code,
		hlog.Duration("lifetime", time.Since(started)),
	)

	// Reclaim everything now that the workload is gone. Errors are reported but
	// do not mask the container's own exit status, which is what the caller
	// actually asked for.
	if err := e.teardown(cfg.ID, cfg.Network.Ports, cg, cfg.Rootfs != c.rootfs); err != nil {
		fmt.Fprintf(os.Stderr, "husk: cleanup: %v\n", err)
	}
	_ = e.states.Remove(cfg.ID)

	if waitErr != nil {
		return waitErr
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// LogName is where a detached container's output goes.
const LogName = "output.log"

// containerIO decides where the container's three standard streams point.
//
// A foreground `husk run` passes the caller's own streams straight through, so
// the container behaves like any other command in a pipeline.
//
// A detached `husk create` must not, and the reason is subtle enough to be worth
// stating. The runtime process exits while the container keeps running, so
// whatever the container holds as stdout outlives the runtime. If that is a pipe
// belonging to the caller — which is what any parent capturing output gives us —
// the container keeps the write end open forever, the caller's read never sees
// EOF, and a program that merely wanted the container id hangs indefinitely
// waiting for a container that may run for days. The failure is a deadlock with
// no error, in the caller rather than in husk, and it took a hung test run to
// find.
//
// Redirecting to a file under the container's state directory severs that
// lifetime coupling and has the side benefit of making the output retrievable
// after the fact.
func containerIO(stateDir string, detached bool) (stdin io.Reader, stdout, stderr io.Writer, cleanup func(), err error) {
	if !detached {
		return os.Stdin, os.Stdout, os.Stderr, func() {}, nil
	}

	log, err := os.OpenFile(filepath.Join(stateDir, LogName),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open container log: %w", err)
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		log.Close()
		return nil, nil, nil, nil, err
	}
	return devNull, log, log, func() {
		log.Close()
		devNull.Close()
	}, nil
}

// prepareRootfs resolves the container's root, either a caller-supplied
// directory or an overlayfs stack assembled from an image's layers.
func (e *env) prepareRootfs(c *commonFlags, cfg *container.Config) ([]string, error) {
	if c.rootfs != "" {
		// A bare directory. No copy-on-write, so writes land directly in it and
		// two containers sharing it will interfere. Useful for quick tests and
		// for the escape suite, which needs a predictable root.
		info, err := os.Stat(c.rootfs)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("rootfs %q is not a directory", c.rootfs)
		}
		cfg.Rootfs = c.rootfs
		return nil, nil
	}
	if c.image == "" {
		return nil, fmt.Errorf("one of -image or -rootfs is required")
	}

	if err := e.storage.Init(); err != nil {
		return nil, err
	}
	layers, err := e.storage.ImageLayers(c.image)
	if err != nil {
		return nil, err
	}
	merged, err := e.storage.Mount(cfg.ID, layers)
	if err != nil {
		return nil, err
	}
	cfg.Rootfs = merged
	return layers, nil
}

func (e *env) teardown(id string, ports []container.PortMapping, cg *cgroups.Manager, removeStorage bool) error {
	var problems []string

	if err := e.network.Detach(id, ports); err != nil {
		problems = append(problems, err.Error())
	}
	// Kill anything still in the cgroup before removing it: rmdir on a populated
	// cgroup returns EBUSY, and a container whose init died can leave orphans
	// behind that were re-parented outside the PID namespace's reach.
	_ = cg.KillAll()
	if err := cg.Destroy(); err != nil {
		problems = append(problems, err.Error())
	}
	if removeStorage {
		if err := e.storage.Remove(id); err != nil {
			problems = append(problems, err.Error())
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

func namespacesRootless() container.IDMaps {
	return container.IDMaps{
		UID: []container.IDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GID: []container.IDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
