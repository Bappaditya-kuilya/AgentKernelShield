package switcher_test

import (
	"testing"

	switcher "github.com/Bappaditya-kuilya/aks/internal/switch"
	"github.com/stretchr/testify/require"
)

func newTestMachine() *switcher.Machine {
	return switcher.NewMachine("", []string{"read_docs", "write_report"})
}

func TestEnter_AcksProfileAndEpoch(t *testing.T) {
	m := newTestMachine()
	profile, epoch, err := m.Enter("read_docs", "c1")
	require.NoError(t, err)
	require.Equal(t, "read_docs", profile)
	require.Equal(t, uint64(1), epoch)

	tool, active, snapEpoch := m.Snapshot()
	require.Equal(t, "read_docs", tool)
	require.Equal(t, "read_docs", active)
	require.Equal(t, uint64(1), snapEpoch)
}

func TestExit_RevertsToBaselineAndBumpsEpoch(t *testing.T) {
	m := newTestMachine()
	_, enterEpoch, err := m.Enter("read_docs", "c1")
	require.NoError(t, err)

	profile, exitEpoch, err := m.Exit("c1")
	require.NoError(t, err)
	require.Equal(t, switcher.BaselineProfile, profile)
	require.Equal(t, enterEpoch+1, exitEpoch)

	tool, active, _ := m.Snapshot()
	require.Equal(t, "", tool)
	require.Equal(t, switcher.BaselineProfile, active)
}

func TestEnter_OverlapReturnsBusy(t *testing.T) {
	m := newTestMachine()
	_, epoch1, err := m.Enter("read_docs", "c1")
	require.NoError(t, err)

	profile, epoch, err := m.Enter("write_report", "c2")
	require.ErrorIs(t, err, switcher.ErrBusy)
	require.Equal(t, "", profile)
	// Rejected overlap changes neither state nor epoch.
	require.Equal(t, epoch1, epoch)
	require.Equal(t, epoch1, m.Epoch())
	tool, active, _ := m.Snapshot()
	require.Equal(t, "read_docs", tool)
	require.Equal(t, "read_docs", active)

	// The first call still exits cleanly afterwards.
	base, epoch2, err := m.Exit("c1")
	require.NoError(t, err)
	require.Equal(t, switcher.BaselineProfile, base)
	require.Equal(t, epoch1+1, epoch2)
}

func TestEnter_UnknownToolGetsRestricted(t *testing.T) {
	m := newTestMachine()
	profile, epoch, err := m.Enter("mystery_tool", "c9")
	require.NoError(t, err)
	require.Equal(t, switcher.RestrictedProfile, profile)
	require.Equal(t, uint64(1), epoch)

	tool, active, _ := m.Snapshot()
	require.Equal(t, "mystery_tool", tool)
	require.Equal(t, switcher.RestrictedProfile, active)

	base, epoch2, err := m.Exit("c9")
	require.NoError(t, err)
	require.Equal(t, switcher.BaselineProfile, base)
	require.Equal(t, uint64(2), epoch2)
}

func TestClose_RevertsToBaseline(t *testing.T) {
	m := newTestMachine()
	_, enterEpoch, err := m.Enter("write_report", "c1")
	require.NoError(t, err)

	profile, closeEpoch := m.Close()
	require.Equal(t, switcher.BaselineProfile, profile)
	require.Equal(t, enterEpoch+1, closeEpoch)

	// Idle close is a no-op: baseline, epoch untouched.
	profile2, epoch2 := m.Close()
	require.Equal(t, switcher.BaselineProfile, profile2)
	require.Equal(t, closeEpoch, epoch2)

	tool, active, _ := m.Snapshot()
	require.Equal(t, "", tool)
	require.Equal(t, switcher.BaselineProfile, active)
}

func TestRapidEnterExitSequence(t *testing.T) {
	m := newTestMachine()
	const rounds = 100
	tools := []string{"read_docs", "write_report", "unknown_tool"}
	var wantEpoch uint64
	for i := 0; i < rounds; i++ {
		tool := tools[i%len(tools)]
		wantProfile := tool
		if tool == "unknown_tool" {
			wantProfile = switcher.RestrictedProfile
		}
		profile, epoch, err := m.Enter(tool, "c")
		require.NoError(t, err)
		require.Equal(t, wantProfile, profile)
		wantEpoch++
		require.Equal(t, wantEpoch, epoch)

		base, epoch, err := m.Exit("c")
		require.NoError(t, err)
		require.Equal(t, switcher.BaselineProfile, base)
		wantEpoch++
		require.Equal(t, wantEpoch, epoch)
	}
	require.Equal(t, uint64(2*rounds), m.Epoch())
}

func TestExit_CallIDMismatchLeavesState(t *testing.T) {
	m := newTestMachine()
	_, epoch1, err := m.Enter("read_docs", "c1")
	require.NoError(t, err)

	profile, epoch, err := m.Exit("wrong-id")
	require.ErrorIs(t, err, switcher.ErrCallIDMismatch)
	require.Equal(t, "", profile)
	require.Equal(t, epoch1, epoch)

	// Still active; the right call_id exits normally.
	tool, _, _ := m.Snapshot()
	require.Equal(t, "read_docs", tool)
	base, epoch2, err := m.Exit("c1")
	require.NoError(t, err)
	require.Equal(t, switcher.BaselineProfile, base)
	require.Equal(t, epoch1+1, epoch2)
}

func TestExit_IdleIsNoop(t *testing.T) {
	m := newTestMachine()
	profile, epoch, err := m.Exit("c1")
	require.NoError(t, err)
	require.Equal(t, switcher.BaselineProfile, profile)
	require.Equal(t, uint64(0), epoch)
}
