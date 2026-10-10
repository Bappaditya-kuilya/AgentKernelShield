package switcher_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

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

func TestRapidEnterExitLoop_EpochsStrictlyIncrease(t *testing.T) {
	m := newTestMachine()
	const rounds = 200
	var prev uint64
	for i := 0; i < rounds; i++ {
		profile, enterEpoch, err := m.Enter("read_docs", "c-race")
		require.NoError(t, err)
		require.Equal(t, "read_docs", profile)
		require.Equal(t, prev+1, enterEpoch, "enter epoch must strictly increase (round %d)", i)
		prev = enterEpoch

		base, exitEpoch, err := m.Exit("c-race")
		require.NoError(t, err)
		require.Equal(t, switcher.BaselineProfile, base)
		require.Equal(t, prev+1, exitEpoch, "exit epoch must strictly increase (round %d)", i)
		prev = exitEpoch
	}
	require.Equal(t, uint64(2*rounds), prev)
	require.Equal(t, uint64(2*rounds), m.Epoch())

	tool, active, epoch := m.Snapshot()
	require.Equal(t, "", tool)
	require.Equal(t, switcher.BaselineProfile, active)
	require.Equal(t, uint64(2*rounds), epoch)
}

func TestConcurrentOverlappingEnter_SingleWinner(t *testing.T) {
	m := newTestMachine()
	const n = 16
	type enterResult struct {
		callID string
		epoch  uint64
		err    error
	}
	start := make(chan struct{})
	resCh := make(chan enterResult, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			callID := fmt.Sprintf("c-%d", idx)
			_, epoch, err := m.Enter("read_docs", callID)
			resCh <- enterResult{callID: callID, epoch: epoch, err: err}
		}(i)
	}
	close(start)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("deadlock: concurrent Enter did not finish")
	}
	close(resCh)

	var winners []enterResult
	busy := 0
	for r := range resCh {
		if r.err == nil {
			winners = append(winners, r)
		} else {
			require.ErrorIs(t, r.err, switcher.ErrBusy)
			busy++
		}
	}
	require.Len(t, winners, 1, "exactly one overlapping Enter must win")
	require.Equal(t, n-1, busy)
	require.Equal(t, uint64(1), winners[0].epoch)
	require.Equal(t, uint64(1), m.Epoch())

	// State is consistent: winner holds the machine, rejected overlap
	// changed nothing.
	tool, active, epoch := m.Snapshot()
	require.Equal(t, "read_docs", tool)
	require.Equal(t, "read_docs", active)
	require.Equal(t, uint64(1), epoch)

	// Winner still exits cleanly afterwards.
	base, exitEpoch, err := m.Exit(winners[0].callID)
	require.NoError(t, err)
	require.Equal(t, switcher.BaselineProfile, base)
	require.Equal(t, uint64(2), exitEpoch)
}

func TestConcurrentEnterCloseRace_ValidFinalState(t *testing.T) {
	const rounds = 100
	for i := 0; i < rounds; i++ {
		m := newTestMachine()
		start := make(chan struct{})
		type enterOut struct {
			epoch uint64
			err   error
		}
		enterRes := make(chan enterOut, 1)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, epoch, err := m.Enter("read_docs", "c-race")
			enterRes <- enterOut{epoch: epoch, err: err}
		}()
		go func() {
			defer wg.Done()
			<-start
			_, _ = m.Close()
		}()
		close(start)

		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("deadlock in Enter/Close race (round %d)", i)
		}

		// Enter races only an idle no-op or a post-enter revert, so from a
		// fresh machine it must always succeed with epoch 1.
		res := <-enterRes
		require.NoError(t, res.err, "round %d: Enter must win vs Close", i)
		require.Equal(t, uint64(1), res.epoch, "round %d: Enter bumps 0->1", i)

		// Settle: exactly one of the racy Close and this Close reverts,
		// the other is an idle no-op — either interleaving lands idle at
		// epoch 2 (one Enter bump + one Close bump).
		profile, settleEpoch := m.Close()
		require.Equal(t, switcher.BaselineProfile, profile)
		require.Equal(t, uint64(2), settleEpoch, "round %d: settle lands epoch 2", i)
		tool, active, epoch := m.Snapshot()
		require.Equal(t, "", tool, "round %d: machine must revert to baseline", i)
		require.Equal(t, switcher.BaselineProfile, active, "round %d", i)
		require.Equal(t, uint64(2), epoch, "round %d: one enter + one revert bump", i)
	}
}
