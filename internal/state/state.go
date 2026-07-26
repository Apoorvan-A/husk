// Package state persists what the runtime needs to know about a container
// between invocations.
//
// husk has no daemon. `husk create` exits, and the `husk start`, `husk kill` and
// `husk delete` that follow are separate processes with no shared memory. Every
// fact one needs from another lives in a file here.
//
// The directory is under /run rather than /var deliberately: /run is a tmpfs, so
// a reboot clears it. That is the correct behaviour for state describing
// processes and network interfaces that also did not survive the reboot — stale
// entries claiming a container is running would otherwise need reconciling on
// every boot.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/apoorvan10/husk/internal/container"
)

// DefaultRoot is the runtime state directory.
const DefaultRoot = "/run/husk"

// Status values from the OCI runtime-spec lifecycle.
const (
	StatusCreating Status = "creating"
	StatusCreated  Status = "created"
	StatusRunning  Status = "running"
	StatusStopped  Status = "stopped"
)

type Status string

// State is the on-disk record. The first six fields are the OCI runtime-spec
// `state` structure verbatim, so `husk state <id>` output is directly consumable
// by anything that speaks the spec. Everything after them is husk's own
// bookkeeping, kept in the same file rather than a second one so a crash cannot
// leave the two disagreeing.
type State struct {
	OCIVersion  string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      Status            `json:"status"`
	Pid         int               `json:"pid"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations,omitempty"`

	Created   time.Time         `json:"created"`
	Config    *container.Config `json:"config,omitempty"`
	Image     string            `json:"image,omitempty"`
	Layers    []string          `json:"layers,omitempty"`
	CgroupDir string            `json:"cgroupDir,omitempty"`
	ExitCode  int               `json:"exitCode"`
}

// OCIVersion is the runtime-spec revision husk targets.
const OCIVersion = "1.2.0"

// Store is the state directory.
type Store struct{ Root string }

func NewStore(root string) *Store {
	if root == "" {
		root = DefaultRoot
	}
	return &Store{Root: root}
}

func (s *Store) Dir(id string) string  { return filepath.Join(s.Root, id) }
func (s *Store) file(id string) string { return filepath.Join(s.Dir(id), "state.json") }

// FifoPath is the create/start rendezvous point.
func (s *Store) FifoPath(id string) string { return filepath.Join(s.Dir(id), "exec.fifo") }

// Create makes a container's state directory. It fails if one already exists,
// which is what enforces ID uniqueness — using MkdirAll here would silently let
// two containers share a directory and corrupt each other's state.
func (s *Store) Create(id string) error {
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return fmt.Errorf("create state root: %w", err)
	}
	if err := os.Mkdir(s.Dir(id), 0o700); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("container %q already exists", id)
		}
		return fmt.Errorf("create state dir: %w", err)
	}
	return nil
}

// MakeFifo creates the exec FIFO before the container is cloned, so the child
// can open it the moment it is ready. mkfifo, not a regular file: the blocking
// open semantics are the entire mechanism.
func (s *Store) MakeFifo(id string) error {
	path := s.FifoPath(id)
	if err := unix.Mkfifo(path, 0o600); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create exec fifo: %w", err)
	}
	return nil
}

// Save writes the record atomically. A plain write can be interrupted between
// truncation and completion, leaving a zero-length or half-written state.json
// that every subsequent command fails to parse — and since the file is the only
// record of a running container, that failure is unrecoverable. Writing to a
// temporary file and renaming makes the replacement atomic within the directory,
// so a reader sees either the whole old state or the whole new one.
func (s *Store) Save(st *State) error {
	if st.OCIVersion == "" {
		st.OCIVersion = OCIVersion
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := s.Dir(st.ID)
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// fsync before rename: rename is atomic with respect to the directory entry,
	// but without the sync the *contents* may still be in page cache when a
	// power loss hits, leaving a correctly-named empty file.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.file(st.ID))
}

// Load reads a container's record.
func (s *Store) Load(id string) (*State, error) {
	data, err := os.ReadFile(s.file(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("container %q does not exist", id)
		}
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse state for %q: %w", id, err)
	}
	return &st, nil
}

// Remove deletes a container's state directory.
func (s *Store) Remove(id string) error {
	return os.RemoveAll(s.Dir(id))
}

// List returns every container's state, reconciling each against reality first.
func (s *Store) List() ([]*State, error) {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*State
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		st, err := s.Load(e.Name())
		if err != nil {
			continue // a directory mid-creation, or one being torn down
		}
		st.Refresh()
		out = append(out, st)
	}
	return out, nil
}

// Refresh corrects the recorded status against the actual process.
//
// The file says "running" because that is what the last command that touched it
// believed. The container's init process can die at any moment — OOM kill, a
// crash, someone with a terminal — and nothing writes the state file when it
// does, because there is no daemon watching. Every read therefore has to verify.
//
// signal 0 is the check: the kernel performs its usual permission and existence
// checks and delivers nothing. ESRCH means no such process.
//
// The PID-reuse caveat is real and worth stating rather than hiding: between the
// container dying and this check, the kernel could have recycled its PID onto an
// unrelated process, and this would report the container as running. A robust
// runtime pins the identity with a pidfd (or compares the process start time in
// /proc/<pid>/stat) instead. husk uses the simple check and documents the gap.
func (st *State) Refresh() {
	if st.Status != StatusRunning && st.Status != StatusCreated {
		return
	}
	if st.Pid <= 0 {
		st.Status = StatusStopped
		return
	}
	if err := unix.Kill(st.Pid, 0); err != nil {
		st.Status = StatusStopped
	}
}
