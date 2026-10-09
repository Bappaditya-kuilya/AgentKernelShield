// Package switcher implements the AKS tool-switch socket protocol
// (AKS-SPEC.md §9.2, §8.4, FR-6/FR-7/FR-8).
//
// NOTE on naming: this package lives in directory internal/switch, but the
// package clause is `switcher`, not `switch` — `switch` is a Go keyword and
// cannot be a package name (a PackageName must be an identifier). Importers
// use path ".../internal/switch" and refer to switcher.New, switcher.Server.
package switcher

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
)

// Socket endpoint and permission intent (spec §9.2, §13.4).
const (
	// SocketDir is the socket directory; created mode 0750 (spec §13.4).
	SocketDir = "/run/aks"
	// SocketPath is the JSON-lines socket all switch traffic uses.
	SocketPath = "/run/aks/aks.sock"
	// SocketFileMode is the intent for the socket file: owner+group rw
	// (group `aks`). Applied with chmod after bind because Go inherits the
	// process umask at bind time. Brief wider-mode window before chmod is
	// accepted in v1; the authenticated channel (P1 FR-25) removes it.
	SocketFileMode = 0660
	// SocketDirMode is the intent for the socket directory (spec §13.4).
	SocketDirMode = 0750
	// maxLineBytes bounds one protocol line; larger lines are rejected with
	// bad_request after the line is consumed.
	maxLineBytes = 64 << 10
)

// Protocol operations (spec §9.2).
const (
	OpEnterTool = "enter_tool"
	OpExitTool  = "exit_tool"
)

// Error strings sent in {"ok":false,"error":...} replies. "busy" and the
// ack shapes are mandated by spec §9.2; the rest are v1 extensions.
const (
	ErrTextBusy           = "busy"
	ErrTextCallIDMismatch = "call_id_mismatch"
	ErrTextBadRequest     = "bad_request"
	ErrTextUnknownOp      = "unknown_op"
	ErrTextApplyFailed    = "apply_failed"
)

// Request is one newline-delimited JSON client message.
type Request struct {
	Op     string `json:"op"`
	Tool   string `json:"tool,omitempty"`
	CallID string `json:"call_id,omitempty"`
}

// Response is one newline-delimited JSON server reply.
type Response struct {
	OK      bool   `json:"ok"`
	Profile string `json:"profile,omitempty"`
	Epoch   uint64 `json:"epoch,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Applier applies a resolved (profile, epoch) to the kernel. BPF
// CGROUP_STATE map writes go behind this interface; the kernel wiring is a
// later slice and provides the real implementation.
type Applier interface {
	Apply(profile string, epoch uint64) error
}

// NoopApplier is an Applier that performs no kernel writes and reports
// success. It exists for unit-test wiring and for running the socket server
// before the BPF map writer (later slice) exists. It MUST NOT be used in
// production: with it, the server acks profile switches that enforcement
// never sees. The name is deliberately honest — it does nothing.
type NoopApplier struct{}

// Apply implements Applier by doing nothing and returning nil.
func (NoopApplier) Apply(string, uint64) error { return nil }

// routeRequest handles one protocol line: parse, drive the machine, apply
// to the kernel, build the reply.
//
// Fail-closed ordering: on enter, the machine commits first (so overlap is
// rejected), then Apply runs; if Apply fails, the machine is rolled back to
// baseline via Exit and apply_failed is replied — a switch is never acked
// unless the kernel write succeeded (FR-6: ack after the map update). On
// exit the machine is already at baseline, so an Apply failure needs no
// rollback and still replies apply_failed.
func routeRequest(m *Machine, applier Applier, line []byte) Response {
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return Response{OK: false, Error: ErrTextBadRequest}
	}
	switch req.Op {
	case OpEnterTool:
		profile, epoch, err := m.Enter(req.Tool, req.CallID)
		if err == ErrBusy {
			return Response{OK: false, Error: ErrTextBusy}
		}
		if err := applier.Apply(profile, epoch); err != nil {
			// Roll back to baseline. Enter succeeded, so the stored
			// call_id matches and this Exit cannot mismatch; a rollback
			// error still reports apply-failed either way.
			if _, _, err := m.Exit(req.CallID); err != nil {
				return Response{OK: false, Error: ErrTextApplyFailed}
			}
			return Response{OK: false, Error: ErrTextApplyFailed}
		}
		return Response{OK: true, Profile: profile, Epoch: epoch}
	case OpExitTool:
		profile, epoch, err := m.Exit(req.CallID)
		if err == ErrCallIDMismatch {
			return Response{OK: false, Error: ErrTextCallIDMismatch}
		}
		if err := applier.Apply(profile, epoch); err != nil {
			return Response{OK: false, Error: ErrTextApplyFailed}
		}
		return Response{OK: true, Profile: profile, Epoch: epoch}
	default:
		return Response{OK: false, Error: ErrTextUnknownOp}
	}
}

// Config configures a Server. Zero values select SocketPath, the default
// baseline profile, and NoopApplier.
type Config struct {
	// SocketPath overrides the socket path (tests); "" selects SocketPath.
	SocketPath string
	// Baseline overrides the revert profile; "" selects BaselineProfile.
	Baseline string
	// KnownTools lists policy-declared tool names for per-connection
	// machines; unknown names resolve to RestrictedProfile.
	KnownTools []string
	// Applier writes (profile, epoch) to the kernel; nil selects
	// NoopApplier (non-production; see its doc comment).
	Applier Applier
}

// Server is the Unix-socket JSON-lines switch endpoint (spec §9.2). Each
// connection gets its own Machine (per-connection state); v1 allows one
// tool at a time per connection, overlapping enter_tool replies busy.
type Server struct {
	sockPath string
	baseline string
	known    []string
	applier  Applier
}

// New returns a Server from cfg, filling zero values with defaults.
func New(cfg Config) *Server {
	s := &Server{
		sockPath: cfg.SocketPath,
		baseline: cfg.Baseline,
		known:    cfg.KnownTools,
		applier:  cfg.Applier,
	}
	if s.sockPath == "" {
		s.sockPath = SocketPath
	}
	if s.baseline == "" {
		s.baseline = BaselineProfile
	}
	if s.applier == nil {
		s.applier = NoopApplier{}
	}
	return s
}

// ListenAndServe creates the socket (dir 0750, file 0660 intent), serves
// until ctx is cancelled, then closes the listener and returns. Open
// connections are not waited for: each still reverts to baseline via its
// teardown path when it closes. Peer-credential / cgroup-membership checks
// (SO_PEERCRED, spec §9.2) are P1 FR-25 scope and explicitly absent here.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := os.MkdirAll(SocketDir, SocketDirMode); err != nil {
		return err
	}
	// A stale socket from a crashed daemon would make bind fail; removing
	// it is crash recovery, and the mode/auth posture is re-applied below.
	_ = os.Remove(s.sockPath)
	ln, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return err
	}
	// Enforce the 0660 intent: bind inherits the process umask (typically
	// 022 -> 0755), so chmod after bind. Startup fails if this fails —
	// fail closed rather than serve with wrong permissions.
	if err := os.Chmod(s.sockPath, SocketFileMode); err != nil {
		_ = ln.Close()
		_ = os.Remove(s.sockPath)
		return err
	}
	defer func() { _ = ln.Close() }()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				// Transient accept error (e.g. listener close race):
				// keep serving; a dead listener surfaces on next Accept.
				continue
			}
		}
		go s.handleConn(conn)
	}
}

// handleConn serves one connection: newline-delimited JSON requests get
// newline-delimited JSON replies. A malformed line gets an error reply and
// the connection stays open (one bad line must not kill the session). When
// the connection ends for any reason, the machine reverts to baseline and
// the revert is applied immediately — this is the FR-7 connection-loss path
// (apply error here has no client to report to and is dropped with intent).
func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	m := NewMachine(s.baseline, s.known)
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}
		var resp Response
		if len(line) > maxLineBytes {
			resp = Response{OK: false, Error: ErrTextBadRequest}
		} else {
			resp = routeRequest(m, s.applier, line)
		}
		out, err := json.Marshal(resp)
		if err != nil {
			break
		}
		out = append(out, '\n')
		if _, err := writer.Write(out); err != nil {
			break
		}
		if err := writer.Flush(); err != nil {
			break
		}
	}
	profile, epoch := m.Close()
	_ = s.applier.Apply(profile, epoch)
}
