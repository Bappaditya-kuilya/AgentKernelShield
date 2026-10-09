package switcher

import (
	"errors"
	"sync"
)

// Profile names mandated by AKS-SPEC.md §8.4 / FR-8.
const (
	// BaselineProfile is always in force when no tool call is active.
	BaselineProfile = "baseline"
	// RestrictedProfile applies to unknown tools (FR-8: safe by default).
	RestrictedProfile = "restricted"
)

var (
	// ErrBusy is returned by Enter when a tool call is already active.
	// Spec §8.4, v1: one tool at a time per agent; overlap replies
	// {"ok":false,"error":"busy"} without changing state or epoch.
	ErrBusy = errors.New("busy")
	// ErrCallIDMismatch is returned by Exit when the call_id does not match
	// the active call. State is left unchanged (fail closed).
	ErrCallIDMismatch = errors.New("call_id_mismatch")
)

// Machine is the pure tool-switch state machine: {baseline, active tool,
// epoch}. It performs no syscalls and no I/O, so unit tests cover it fully.
//
// Epoch starts at 0 (baseline, before any switch) and bumps by exactly one
// on every state transition (enter, exit, close-revert). Transitions that
// change nothing (overlap rejected, exit/mismatch, close while idle) leave
// the epoch untouched, so the epoch strictly orders real policy switches.
//
// A Machine is safe for concurrent use; the socket server gives each
// connection its own Machine (per-connection state, spec §9.2).
type Machine struct {
	mu sync.Mutex
	// baseline is the profile to revert to; empty at construction means
	// BaselineProfile.
	baseline string
	// known is the set of tool names declared in policy; anything else
	// resolves to RestrictedProfile.
	known map[string]struct{}
	// activeTool == "" means no tool call is active (baseline in force).
	activeTool    string
	activeCallID  string
	activeProfile string
	epoch         uint64
}

// NewMachine returns a Machine reverting to baseline. An empty baseline
// selects BaselineProfile. knownTools lists policy-declared tool names;
// every other name resolves to RestrictedProfile on Enter.
func NewMachine(baseline string, knownTools []string) *Machine {
	if baseline == "" {
		baseline = BaselineProfile
	}
	known := make(map[string]struct{}, len(knownTools))
	for _, t := range knownTools {
		known[t] = struct{}{}
	}
	return &Machine{baseline: baseline, known: known}
}

// Enter starts a tool call. It returns the effective profile and the new
// epoch. Unknown (and empty) tool names resolve to RestrictedProfile.
// While a call is active, any further Enter fails with ErrBusy and changes
// nothing.
func (m *Machine) Enter(tool, callID string) (profile string, epoch uint64, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTool != "" {
		return "", m.epoch, ErrBusy
	}
	if _, ok := m.known[tool]; ok {
		profile = tool
	} else {
		profile = RestrictedProfile
	}
	m.activeTool = tool
	m.activeCallID = callID
	m.activeProfile = profile
	m.epoch++
	return profile, m.epoch, nil
}

// Exit ends the active tool call and reverts to baseline with a bumped
// epoch. A call_id that does not match the active call fails with
// ErrCallIDMismatch and changes nothing (fail closed). Exit with no active
// call is an idempotent no-op returning baseline and the current epoch.
func (m *Machine) Exit(callID string) (profile string, epoch uint64, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTool == "" {
		return m.baseline, m.epoch, nil
	}
	if callID != m.activeCallID {
		return "", m.epoch, ErrCallIDMismatch
	}
	m.activeTool = ""
	m.activeCallID = ""
	m.activeProfile = ""
	m.epoch++
	return m.baseline, m.epoch, nil
}

// Close reverts to baseline with a bumped epoch. The socket server calls it
// when a connection drops (EOF/error), so a crashed middleware reverts
// within the teardown path, well under the 1 s bound of FR-7. Close while
// idle is a no-op returning baseline and the current epoch.
func (m *Machine) Close() (profile string, epoch uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTool == "" {
		return m.baseline, m.epoch
	}
	m.activeTool = ""
	m.activeCallID = ""
	m.activeProfile = ""
	m.epoch++
	return m.baseline, m.epoch
}

// Snapshot returns the current (active tool, effective profile, epoch).
// An empty tool means baseline is in force.
func (m *Machine) Snapshot() (tool, profile string, epoch uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTool == "" {
		return "", m.baseline, m.epoch
	}
	return m.activeTool, m.activeProfile, m.epoch
}

// Baseline returns the profile this machine reverts to.
func (m *Machine) Baseline() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.baseline
}

// Epoch returns the current epoch without changing state.
func (m *Machine) Epoch() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epoch
}
