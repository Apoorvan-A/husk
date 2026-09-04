package cli

import (
	"flag"
	"fmt"

	"github.com/Apoorvan-A/husk/internal/hlog"
	"github.com/Apoorvan-A/husk/internal/state"
)

func commitCommand(args []string) error {
	fs := flag.NewFlagSet("commit", flag.ContinueOnError)
	var c commonFlags
	fs.StringVar(&c.stateRoot, "state-root", "", "runtime state directory (default /run/husk)")
	fs.StringVar(&c.dataRoot, "data-root", "", "image and layer store (default /var/lib/husk)")
	fs.Usage = func() {
		fmt.Println("Usage: husk commit CONTAINER IMAGE")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return fmt.Errorf("need a container and a target image name")
	}
	id, image := fs.Arg(0), fs.Arg(1)

	e := newEnv(&c)
	st, err := e.states.Load(id)
	if err != nil {
		return err
	}
	st.Refresh()
	if st.Status == state.StatusRunning {
		// A commit of a live upperdir captures a torn snapshot: half-written
		// files, lockfiles whose holder is still running. Docker pauses the
		// container for exactly this reason; husk asks the caller to stop it,
		// which is honest about what it does not implement.
		return fmt.Errorf("container %q is running; stop it before committing", id)
	}
	if len(st.Layers) == 0 {
		return fmt.Errorf("container %q was started from a bare rootfs and has no layer stack to extend", id)
	}

	layerID, err := e.storage.Commit(id, image, st.Layers)
	if err != nil {
		return err
	}
	hlog.Event("image.commit", id, "image", image, "layer", layerID)
	fmt.Printf("%s\n", image)
	return nil
}

func importCommand(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	var c commonFlags
	fs.StringVar(&c.dataRoot, "data-root", "", "image and layer store (default /var/lib/husk)")
	fs.Usage = func() {
		fmt.Println("Usage: husk import ROOTFS.tar.gz IMAGE")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return fmt.Errorf("need a tarball and an image name")
	}

	e := newEnv(&c)
	layerID, err := e.storage.ImportTarball(fs.Arg(0), fs.Arg(1))
	if err != nil {
		return err
	}
	hlog.Event("image.import", "", "image", fs.Arg(1), "layer", layerID)
	fmt.Println(fs.Arg(1))
	return nil
}

func imagesCommand(args []string) error {
	fs := flag.NewFlagSet("images", flag.ContinueOnError)
	var c commonFlags
	fs.StringVar(&c.dataRoot, "data-root", "", "image and layer store (default /var/lib/husk)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	e := newEnv(&c)
	names, err := e.storage.ListImages()
	if err != nil {
		return err
	}

	w := newTabWriter()
	fmt.Fprintln(w, "IMAGE\tLAYERS")
	for _, n := range names {
		layers, err := e.storage.ImageLayers(n)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "%s\t%d\n", n, len(layers))
	}
	return w.Flush()
}
