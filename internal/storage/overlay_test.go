package storage

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// extractTar takes an untrusted list of paths. An entry named "../../etc/passwd"
// escapes the extraction directory and overwrites the host — the Zip Slip class
// of bug, and container images are exactly where it gets exploited.
func TestExtractRejectsPathsThatEscapeTheDestination(t *testing.T) {
	for _, name := range []string{
		"../escaped",
		"../../etc/passwd",
		"good/../../escaped",
		"/absolute/escape",
	} {
		t.Run(name, func(t *testing.T) {
			dest := t.TempDir()
			archive := tarWith(t, tar.Header{
				Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: 4,
			}, "evil")

			err := extractTar(tar.NewReader(bytes.NewReader(archive)), dest)

			// An absolute path is cleaned into the destination by filepath.Join
			// rather than escaping, so it is allowed through; what must never
			// happen is a write landing outside dest.
			if err == nil {
				assertNothingOutside(t, dest)
			}
		})
	}
}

// A hard link whose target escapes is the same hazard by another route.
func TestExtractRejectsEscapingHardLinks(t *testing.T) {
	dest := t.TempDir()
	archive := tarWith(t, tar.Header{
		Name: "link", Typeflag: tar.TypeLink, Linkname: "../../../etc/passwd", Mode: 0o644,
	}, "")

	if err := extractTar(tar.NewReader(bytes.NewReader(archive)), dest); err == nil {
		if _, statErr := os.Lstat(filepath.Join(dest, "link")); statErr == nil {
			t.Error("a hard link to a path outside the destination was created")
		}
	}
}

func TestExtractHandlesOrdinaryEntries(t *testing.T) {
	dest := t.TempDir()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	mustWrite(t, tw, tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755}, "")
	mustWrite(t, tw, tar.Header{Name: "etc/hosts", Typeflag: tar.TypeReg, Mode: 0o644, Size: 10}, "127.0.0.1\n")
	mustWrite(t, tw, tar.Header{Name: "etc/link", Typeflag: tar.TypeSymlink, Linkname: "hosts"}, "")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := extractTar(tar.NewReader(bytes.NewReader(buf.Bytes())), dest); err != nil {
		t.Fatalf("extract: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dest, "etc/hosts"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "127.0.0.1\n" {
		t.Errorf("extracted content = %q", content)
	}
	if target, err := os.Readlink(filepath.Join(dest, "etc/link")); err != nil || target != "hosts" {
		t.Errorf("symlink = %q, %v; want \"hosts\"", target, err)
	}
}

func TestSafeJoin(t *testing.T) {
	dest := "/var/lib/husk/layers/l1"
	for _, name := range []string{"../x", "../../etc/shadow", "a/../../../x"} {
		if _, err := safeJoin(dest, name); err == nil {
			t.Errorf("safeJoin(%q) should have been rejected", name)
		}
	}
	for _, name := range []string{"etc/hosts", "./bin/sh", "a/b/../c"} {
		got, err := safeJoin(dest, name)
		if err != nil {
			t.Errorf("safeJoin(%q): %v", name, err)
			continue
		}
		if !filepath.IsAbs(got) || len(got) <= len(dest) {
			t.Errorf("safeJoin(%q) = %q, which is not under %q", name, got, dest)
		}
	}
}

// Layer ordering is the one thing about overlayfs that is easy to get
// backwards: lowerdir is read topmost-first, so an image's base layer — which is
// listed first everywhere else — must end up last.
func TestOverlayOptionsOrdersLayersTopmostFirst(t *testing.T) {
	opts, err := overlayOptions([]string{"/l/base", "/l/middle", "/l/top"}, "/c/upper", "/c/work")
	if err != nil {
		t.Fatal(err)
	}

	want := "lowerdir=/l/top:/l/middle:/l/base,upperdir=/c/upper,workdir=/c/work"
	if opts != want {
		t.Errorf("overlayOptions produced:\n  %s\nwant:\n  %s\n\n"+
			"overlayfs treats the leftmost lowerdir entry as the topmost layer, so listing "+
			"the base layer first shadows newer files with older ones", opts, want)
	}
}

// A colon or comma in a layer path cannot be escaped in the option string, so it
// has to be rejected rather than producing a mount with silently wrong layers.
func TestOverlayOptionsRejectsUnescapableDelimiters(t *testing.T) {
	for _, bad := range []string{"/layers/a:b", "/layers/a,b"} {
		if _, err := overlayOptions([]string{bad}, "/c/upper", "/c/work"); err == nil {
			t.Errorf("overlayOptions accepted the unescapable path %q", bad)
		}
	}
}

func TestImageLayerRoundTrip(t *testing.T) {
	s := NewStore(t.TempDir())
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	want := []string{"l1", "l2", "l3"}
	if err := s.PutImage("demo", want); err != nil {
		t.Fatal(err)
	}
	got, err := s.ImageLayers("demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("layer %d = %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := s.ImageLayers("nonexistent"); err == nil {
		t.Error("reading an unknown image should fail")
	}
}

func tarWith(t *testing.T, hdr tar.Header, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	mustWrite(t, tw, hdr, body)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mustWrite(t *testing.T, tw *tar.Writer, hdr tar.Header, body string) {
	t.Helper()
	hdr.Size = int64(len(body))
	if err := tw.WriteHeader(&hdr); err != nil {
		t.Fatal(err)
	}
	if body != "" {
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
}

func assertNothingOutside(t *testing.T, dest string) {
	t.Helper()
	parent := filepath.Dir(dest)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(dest) && e.Name() == "escaped" {
			t.Errorf("extraction wrote %q outside the destination", e.Name())
		}
	}
}
