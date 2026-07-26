// Package ipc implements the handshake between the runtime process and the
// `husk init` child it clones into new namespaces.
//
// The handshake exists because container setup is split across a privilege
// boundary that runs in both directions. The child is the only process that can
// mount inside its own mount namespace, but it is not the process that can write
// its own uid_map, create its cgroup, or move a veth peer into its netns — those
// need privileges the child gave up the instant clone(2) returned. So the two
// have to take turns, and each side has to block until the other is done.
//
// Getting this wrong is not a hang, it is a security hole: if the child proceeds
// to execve before the parent has applied the cgroup limits, the user's command
// runs unconstrained for a window. The pipe closes that window.
package ipc

import (
	"encoding/json"
	"fmt"
	"os"
)

// Stage names a point in the setup sequence that one side must wait for.
type Stage string

const (
	// StageConfig carries the container config from parent to child. It is the
	// first thing sent, before the child does anything at all.
	StageConfig Stage = "config"

	// StageChildBooted: child is alive and has read its config. Sent by child.
	// The parent needs this before it can write uid_map, because it needs the
	// child's PID and the child must already be in the new user namespace.
	StageChildBooted Stage = "child-booted"

	// StageParentReady: uid/gid maps written, cgroup populated, netns furnished.
	// Sent by parent. Everything the child cannot do for itself is now done.
	StageParentReady Stage = "parent-ready"

	// StageChildJailed: child has pivoted, dropped capabilities and installed
	// seccomp. Sent by child. The parent uses this to know setup succeeded
	// before it reports "created" for the OCI lifecycle.
	StageChildJailed Stage = "child-jailed"

	// StageError: the sender failed. Payload carries the message. Either side
	// may send it, and receiving one aborts the whole startup.
	StageError Stage = "error"
)

type message struct {
	Stage   Stage           `json:"stage"`
	Payload string          `json:"payload,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

// Pipe is one end of a bidirectional handshake channel. Each side holds a read
// file and a write file; the two Pipes are crossed over so one's writer is the
// other's reader.
type Pipe struct {
	r   *os.File
	w   *os.File
	dec *json.Decoder
	enc *json.Encoder
}

// NewPipe wraps an already-open pair of file descriptors.
func NewPipe(r, w *os.File) *Pipe {
	return &Pipe{r: r, w: w, dec: json.NewDecoder(r), enc: json.NewEncoder(w)}
}

// Pair creates a crossed pair of Pipes: parent.w feeds child.r and vice versa.
// Two unidirectional pipes are used rather than a socketpair because the child
// inherits these as plain numbered descriptors and os.Pipe gives us the simplest
// thing that survives exec.
func Pair() (parent *Pipe, child *Pipe, err error) {
	p2cR, p2cW, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("parent-to-child pipe: %w", err)
	}
	c2pR, c2pW, err := os.Pipe()
	if err != nil {
		p2cR.Close()
		p2cW.Close()
		return nil, nil, fmt.Errorf("child-to-parent pipe: %w", err)
	}
	return NewPipe(c2pR, p2cW), NewPipe(p2cR, c2pW), nil
}

// Files returns the two descriptors in the order they should be handed to
// exec.Cmd.ExtraFiles, read end first.
func (p *Pipe) Files() []*os.File { return []*os.File{p.r, p.w} }

// Close releases both ends.
func (p *Pipe) Close() error {
	rerr := p.r.Close()
	werr := p.w.Close()
	if rerr != nil {
		return rerr
	}
	return werr
}

// CloseChildCopies drops the parent's duplicates of the child's descriptors
// after the fork. Without this the parent still holds a writer open on the
// child's read end, so a child that dies never gives the parent an EOF and the
// next Await blocks forever.
func (p *Pipe) CloseChildCopies(child *Pipe) {
	child.r.Close()
	child.w.Close()
}

// Signal announces that this side has reached stage.
func (p *Pipe) Signal(stage Stage) error {
	return p.enc.Encode(message{Stage: stage})
}

// Fail reports an error to the other side, so it can surface a real message
// instead of "the child exited".
func (p *Pipe) Fail(err error) error {
	return p.enc.Encode(message{Stage: StageError, Payload: err.Error()})
}

// SendJSON announces a stage and attaches a serialised body.
func (p *Pipe) SendJSON(stage Stage, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode %q body: %w", stage, err)
	}
	return p.enc.Encode(message{Stage: stage, Body: body})
}

// Await blocks until the other side reports want, and fails fast on anything
// else. An EOF here means the peer died without reporting: for the parent that
// is a crashed child, for the child a crashed runtime.
func (p *Pipe) Await(want Stage) error { return p.AwaitJSON(want, nil) }

// AwaitJSON is Await plus decoding of the attached body into v.
func (p *Pipe) AwaitJSON(want Stage, v any) error {
	var m message
	if err := p.dec.Decode(&m); err != nil {
		return fmt.Errorf("waiting for %q: %w", want, err)
	}
	if m.Stage == StageError {
		return fmt.Errorf("peer failed before %q: %s", want, m.Payload)
	}
	if m.Stage != want {
		return fmt.Errorf("handshake out of order: wanted %q, got %q", want, m.Stage)
	}
	if v != nil {
		if err := json.Unmarshal(m.Body, v); err != nil {
			return fmt.Errorf("decode %q body: %w", want, err)
		}
	}
	return nil
}
