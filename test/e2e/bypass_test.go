//go:build linux && integration

// Package e2e — bypass suite (Phase 7). Evasion vectors against the
// current hooks: shebang/symlink indirection, execveat, interpreter -c
// flags, and fork-storm lineage stress.
//
// Run with (VM, root, BPF LSM — never in unprivileged containers):
//
//	sudo go test -tags integration -v -run TestBypass ./test/e2e/
//
// Requires the same setup as e2e_test.go: ollama profile, aks.bpf.o.
// Reuses requireRoot, parseAuditLog, filterByAction, assertContainsPath.
// Exec-path assertions use suffix matching (my own helper below) because
// bpf_d_path returns the canonical path (/bin → /usr/bin on Ubuntu).

package e2e

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Bappaditya-kuilya/aks/internal/audit"
	"github.com/Bappaditya-kuilya/aks/internal/detector"
	"github.com/Bappaditya-kuilya/aks/internal/loader"
	"github.com/Bappaditya-kuilya/aks/internal/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBypassVectorsBlocked runs the evasive target and requires every
// vector to be denied (G1 slice; hardlink/memfd/unix-socket omitted by
// design — see bypass_target/main.go header).
func TestBypassVectorsBlocked(t *testing.T) {
	requireRoot(t)

	build := exec.Command("go", "build", "-tags", "linux", "-o", "bypass_target/bypass_target", "./bypass_target")
	build.Dir = "."
	require.NoError(t, build.Run(), "bypass target must build")
	defer os.Remove("bypass_target/bypass_target")

	p, err := profiles.LoadFile(profilePath)
	require.NoError(t, err)
	l, err := loader.Load(p, bpfObjPath, "")
	require.NoError(t, err)
	defer l.Close()

	var auditBuf bytes.Buffer
	log := audit.New(&auditBuf)
	det := detector.New(p)

	// Seed the reactive denylist the way the daemon would (8.8.8.8 is not
	// used here, but keep parity with TestJailbreakEscape setup).
	require.NoError(t, l.BlockIP(net.ParseIP("8.8.8.8")))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			e, err := l.ReadEvent()
			if err != nil {
				return
			}
			dec := det.Evaluate(e)
			log.Log(dec)
		}
	}()

	cmd := exec.Command("./bypass_target/bypass_target")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	t.Logf("bypass target output:\n%s", out)
	require.NoError(t, err, "exit 0 = all vectors blocked; 1 = table miss; 3 = execveat miss")

	time.Sleep(200 * time.Millisecond)
	_ = l.Close()
	<-done

	entries := parseAuditLog(t, auditBuf.Bytes())
	blocked := filterByAction(entries, "BLOCK")

	// File vectors all resolve to /etc/shadow: shebang cat, symlink,
	// 32 fork children (ringbuf holds all of them).
	assertContainsPath(t, blocked, "/etc/shadow")
	assert.GreaterOrEqual(t, countPath(blocked, "/etc/shadow"), 32,
		"fork-storm children must each produce a BLOCK")

	// Exec vectors: shebang interpreter (canonical path ends in sh),
	// bash -c + execveat (/bin/bash), python3 -c.
	assertExecSuffix(t, blocked, "sh")
	assertExecSuffix(t, blocked, "bash")
	assertExecSuffix(t, blocked, "python3")
}

// assertExecSuffix requires a BLOCK exec event whose path ends with substr.
// Suffix matching avoids guessing /bin → /usr/bin canonicalization.
func assertExecSuffix(t *testing.T, entries []auditEntry, substr string) {
	t.Helper()
	for _, e := range entries {
		ev, _ := e["event"].(string)
		path, _ := e["path"].(string)
		if ev == "exec" && strings.HasSuffix(path, substr) {
			return
		}
	}
	t.Fatalf("expected BLOCK exec event with path suffix %q", substr)
}

// countPath counts BLOCK entries for an exact file path.
func countPath(entries []auditEntry, path string) int {
	n := 0
	for _, e := range entries {
		if p, _ := e["path"].(string); p == path {
			n++
		}
	}
	return n
}
