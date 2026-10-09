package switcher

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type recApply struct {
	profile string
	epoch   uint64
}

type recApplier struct{ ch chan recApply }

func (r *recApplier) Apply(p string, e uint64) error { r.ch <- recApply{p, e}; return nil }

// NOTE: Server only listens on a Unix socket (server.go:178-217) and
// ListenAndServe hardcodes MkdirAll(SocketDir=/run/aks) (server.go:179),
// which fails without root — so tests drive handleConn over net.Pipe
// (in-process, no network). Busy is per-connection (server.go:143-146:
// each conn gets its own Machine), so overlap is tested on one conn.
type client struct {
	c net.Conn
	r *bufio.Reader
}

func servePipe(t *testing.T, ap *recApplier) *client {
	t.Helper()
	c, srv := net.Pipe()
	go New(Config{KnownTools: []string{"read_docs"}, Applier: ap}).handleConn(srv)
	t.Cleanup(func() { _ = c.Close() })
	return &client{c: c, r: bufio.NewReader(c)}
}

func (cl *client) req(t *testing.T, r Request) Response {
	t.Helper()
	b, err := json.Marshal(r)
	require.NoError(t, err)
	_, err = cl.c.Write(append(b, '\n'))
	require.NoError(t, err)
	line, err := cl.r.ReadBytes('\n')
	require.NoError(t, err)
	var resp Response
	require.NoError(t, json.Unmarshal(line, &resp))
	return resp
}

func TestEnterTool_AckLatency(t *testing.T) {
	ap := &recApplier{ch: make(chan recApply, 4)}
	cl := servePipe(t, ap)
	start := time.Now()
	resp := cl.req(t, Request{Op: OpEnterTool, Tool: "read_docs", CallID: "c1"})
	lat := time.Since(start)
	t.Logf("enter_tool ack latency=%s", lat)
	require.True(t, resp.OK)
	require.Equal(t, "read_docs", resp.Profile)
	require.Equal(t, uint64(1), resp.Epoch)
	require.Less(t, lat, 10*time.Millisecond)
}

func TestOverlappingEnter_Busy(t *testing.T) {
	ap := &recApplier{ch: make(chan recApply, 4)}
	cl := servePipe(t, ap)
	require.True(t, cl.req(t, Request{Op: OpEnterTool, Tool: "read_docs", CallID: "c1"}).OK)
	busy := cl.req(t, Request{Op: OpEnterTool, Tool: "read_docs", CallID: "c2"})
	require.False(t, busy.OK)
	require.Equal(t, ErrTextBusy, busy.Error)
	exit := cl.req(t, Request{Op: OpExitTool, CallID: "c1"})
	require.True(t, exit.OK)
	require.Equal(t, BaselineProfile, exit.Profile)
}

func TestCrashConn_RevertsBaselineWithin1s(t *testing.T) {
	ap := &recApplier{ch: make(chan recApply, 4)}
	cl := servePipe(t, ap)
	require.True(t, cl.req(t, Request{Op: OpEnterTool, Tool: "read_docs", CallID: "c1"}).OK)
	require.Equal(t, recApply{"read_docs", 1}, <-ap.ch)
	_ = cl.c.Close() // abrupt close, no exit_tool (FR-7 path: handleConn teardown, server.go:253-254)
	select {
	case got := <-ap.ch:
		require.Equal(t, recApply{BaselineProfile, 2}, got)
	case <-time.After(time.Second):
		t.Fatal("no baseline revert Apply within 1s of connection loss")
	}
}
