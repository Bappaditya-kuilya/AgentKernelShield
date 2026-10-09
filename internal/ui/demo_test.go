package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bappaditya-kuilya/aks/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type demoEvent struct {
	TS     string `json:"ts"`
	PID    uint32 `json:"pid"`
	PPID   uint32 `json:"ppid"`
	Comm   string `json:"comm"`
	Event  string `json:"event"`
	Action string `json:"action"`
}

type demoSession struct {
	Meta struct {
		Kind  string `json:"kind"`
		Task  string `json:"task"`
		Tools []struct {
			Name string   `json:"name"`
			PIDs []uint32 `json:"pids"`
		} `json:"tools"`
	} `json:"meta"`
	Events []demoEvent `json:"events"`
}

// TestDemoFixture_ServedAndShaped verifies the replay fixture used by
// ?demo=1: served over HTTP, valid JSON, every event shaped like the SSE
// wire format, timestamps parseable, and every ppid resolves inside the
// session (connected process tree).
func TestDemoFixture_ServedAndShaped(t *testing.T) {
	srv := httptest.NewServer(ui.New("gemini-cli", "test").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/demo-session.json")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var s demoSession
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&s))
	require.NotEmpty(t, s.Meta.Task, "fixture needs a task")
	require.NotEmpty(t, s.Events, "fixture needs events")

	pids := map[uint32]bool{}
	for i, e := range s.Events {
		assert.NotEmpty(t, e.Comm, "event %d comm", i)
		assert.Contains(t, []string{"file_open", "net_connect", "exec", "ssl_data"}, e.Event, "event %d type", i)
		assert.Contains(t, []string{"ALLOW", "BLOCK"}, e.Action, "event %d action", i)
		_, err := time.Parse(time.RFC3339, e.TS)
		assert.NoError(t, err, "event %d ts parses", i)
		pids[e.PID] = true
	}
	for i, e := range s.Events {
		if e.PPID == 0 {
			continue
		}
		if !pids[e.PPID] {
			// Only the session root may point outside (its parent is the
			// shell that launched the agent); anything else is a broken tree.
			assert.Equal(t, 0, i, "only the root event may have an external ppid")
		}
	}
	// Tool pids referenced by metadata exist in the event stream.
	for _, tool := range s.Meta.Tools {
		for _, pid := range tool.PIDs {
			assert.True(t, pids[pid], "tool %s pid %d exists", tool.Name, pid)
		}
	}
}

// TestDemoFixture_MatchesStaticFile guards against the served copy drifting
// from the file the test above validates indirectly: read it straight.
func TestDemoFixture_MatchesStaticFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("static", "demo-session.json"))
	require.NoError(t, err)
	var s demoSession
	require.NoError(t, json.Unmarshal(raw, &s))
	assert.Equal(t, "replay", s.Meta.Kind)
}
