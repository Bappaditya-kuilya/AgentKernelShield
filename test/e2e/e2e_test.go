//go:build linux && integration

// Package e2e contains the Jailbreak Escape Test — aks's MVP correctness test.
//
// Run with:
//
//	sudo go test -tags integration -v ./test/e2e/
//
// Requires:
//   - Linux kernel 5.7+ with CONFIG_BPF_LSM=y and lsm=bpf in boot params
//   - Root privileges (eBPF program loading)
//   - Ollama profile at ../../profiles/ollama.yaml
//   - aks.bpf.o at ../../bpf/aks.bpf.o (built by `make bpf`)

package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Bappaditya-kuilya/aks/internal/audit"
	"github.com/Bappaditya-kuilya/aks/internal/detector"
	"github.com/Bappaditya-kuilya/aks/internal/loader"
	"github.com/Bappaditya-kuilya/aks/internal/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	profilePath = "../../profiles/ollama.yaml"
	bpfObjPath  = "../../bpf/aks.bpf.o"
	targetBin   = "./target/target"
)

// TestJailbreakEscape is the primary MVP correctness test.
//
// It:
//  1. Builds the synthetic "rogue AI process" binary (test/e2e/target)
//  2. Loads aks's eBPF programs with the Ollama profile
//  3. Runs the rogue binary under aks's watch
//  4. Asserts every escape attempt returns EPERM (exit 0 from target)
//  5. Asserts the audit log captured all 4 BLOCK events
func TestJailbreakEscape(t *testing.T) {
	requireRoot(t)

	// ── Step 1: build the target binary ──────────────────────────────────────
	t.Log("building target binary...")
	build := exec.Command("go", "build", "-tags", "linux", "-o", targetBin, "./target")
	build.Dir = "."
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build target: %s", out)
	defer os.Remove(targetBin)

	// ── Step 2: load aks ───────────────────────────────────────────────────
	t.Log("loading aks eBPF programs...")
	p, err := profiles.LoadFile(profilePath)
	require.NoError(t, err)

	l, err := loader.Load(p, bpfObjPath, "")
	require.NoError(t, err, "loader.Load: ensure kernel has CONFIG_BPF_LSM=y and lsm=bpf")
	defer l.Close()

	det := detector.New(p)
	var auditBuf bytes.Buffer
	log := audit.New(&auditBuf)

	// Pre-block the known-bad IP so the BPF LSM hook returns EPERM synchronously.
	// The production daemon does this at runtime via BlockIP after reading ring
	// buffer events; in the e2e test we simulate that the daemon already acted.
	require.NoError(t, l.BlockIP(net.ParseIP("8.8.8.8")))

	// ── Step 3: drain ring buffer in background ───────────────────────────────
	done := make(chan struct{})
	var blockCount int
	go func() {
		defer close(done)
		for {
			e, err := l.ReadEvent()
			if err != nil {
				return
			}
			dec := det.Evaluate(e)
			log.Log(dec)
			if dec.Action == detector.Block {
				blockCount++
			}
		}
	}()

	// ── Step 4: run the rogue binary ─────────────────────────────────────────
	t.Log("running rogue target binary...")
	cmd := exec.Command(targetBin)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	require.NoError(t, err, "target exited non-zero: at least one escape succeeded — aks missed a block")

	// Give ring buffer a moment to flush
	time.Sleep(200 * time.Millisecond)
	_ = l.Close()
	<-done

	// ── Step 5: assert audit log ──────────────────────────────────────────────
	t.Log("verifying audit log...")
	auditLines := parseAuditLog(t, auditBuf.Bytes())

	blocked := filterByAction(auditLines, "BLOCK")
	assert.GreaterOrEqual(t, len(blocked), 4,
		"expected at least 4 BLOCK events (passwd, shadow, connect, exec), got %d\nfull log:\n%s",
		len(blocked), auditBuf.String())

	assertContainsPath(t, blocked, "/etc/passwd")
	assertContainsPath(t, blocked, "/etc/shadow")
	assertContainsDest(t, blocked, "8.8.8.8")
	assertContainsExec(t, blocked, "/bin/bash")

	t.Logf("audit log:\n%s", auditBuf.String())
}

// TestAllowedOperationsUnblocked verifies that normal Ollama file access
// works correctly alongside aks (no false positives).
func TestAllowedOperationsUnblocked(t *testing.T) {
	requireRoot(t)

	p, err := profiles.LoadFile(profilePath)
	require.NoError(t, err)

	l, err := loader.Load(p, bpfObjPath, "")
	require.NoError(t, err)
	defer l.Close()

	// Create a temp file in the Ollama blob path
	blobDir := fmt.Sprintf("/tmp/ollama_test_%d", os.Getpid())
	require.NoError(t, os.MkdirAll(blobDir, 0755))
	defer os.RemoveAll(blobDir)

	blobFile := blobDir + "/sha256-testblob"
	require.NoError(t, os.WriteFile(blobFile, []byte("fake model blob"), 0644))

	// Open it — should succeed (allowed by profile)
	f, err := os.Open(blobFile)
	assert.NoError(t, err, "expected allowed path to be readable under aks")
	if f != nil {
		f.Close()
	}
}

// TestKill9Survival verifies fail-closed pinning (Phase 5, FR-10/G3).
//
// Requires (VM only — never runs in containers/CI without BPF LSM):
//   - Linux kernel 5.7+ with CONFIG_BPF_LSM=y and lsm=bpf in boot params
//   - Root privileges (eBPF load + bpffs access)
//   - bpffs mounted at /sys/fs/bpf; loader pins maps at /sys/fs/bpf/aks
//   - aks.bpf.o at ../../bpf/aks.bpf.o (built by `make bpf`)
//   - loader.Detach keeps pins (enforcement continues); loader.Release
//     clears the pin dir (invoked via `aks stop [--release]`)
//
// Flow:
//  1. Build + start `aks watch` daemon in the background
//  2. kill -9 the daemon
//  3. Assert /etc/shadow open is still denied (fail-closed) and pins exist
//  4. Run `aks stop --release`, assert the pin dir is empty
func TestKill9Survival(t *testing.T) {
	requireRoot(t)

	const pinDir = "/sys/fs/bpf/aks"

	// ── Step 1: build the aks binary ─────────────────────────────────────────
	aksBin := fmt.Sprintf("/tmp/aks_e2e_%d", os.Getpid())
	build := exec.Command("go", "build", "-tags", "linux", "-o", aksBin, "../../cmd/aks")
	build.Dir = "."
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build aks: %s", out)
	defer os.Remove(aksBin)
	// Leave the VM clean even on failure.
	defer func() { _ = exec.Command(aksBin, "stop", "--release").Run() }()

	// ── Step 2: start `aks watch` in the background ──────────────────────────
	daemon := exec.Command(aksBin, "watch",
		"--profile", profilePath,
		"--bpf-obj", bpfObjPath)
	daemon.Dir = "."
	stdout, err := daemon.StdoutPipe()
	require.NoError(t, err)
	daemon.Stderr = os.Stderr
	require.NoError(t, daemon.Start())
	defer func() { _ = daemon.Process.Kill() }()

	// Wait until the daemon reports it is watching (or time out).
	ready := make(chan struct{})
	go func() {
		defer close(ready)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "watching") {
				return
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		_ = daemon.Process.Kill()
		t.Fatal("timed out waiting for aks watch to become ready")
	}

	// ── Step 3: kill -9 the daemon ───────────────────────────────────────────
	require.NoError(t, daemon.Process.Signal(syscall.SIGKILL))
	_ = daemon.Wait()
	time.Sleep(500 * time.Millisecond)

	// ── Step 4: enforcement must survive ─────────────────────────────────────
	entries, err := os.ReadDir(pinDir)
	require.NoError(t, err, "pin dir %q unreadable after kill -9", pinDir)
	assert.NotEmpty(t, entries, "expected pins under %q after kill -9", pinDir)

	_, openErr := os.Open("/etc/shadow")
	require.Error(t, openErr, "expected /etc/shadow open denied after kill -9 (fail-closed)")
	assert.True(t, errors.Is(openErr, syscall.EPERM) || os.IsPermission(openErr),
		"expected EPERM opening /etc/shadow, got: %v", openErr)

	// ── Step 5: full release empties the pin dir ─────────────────────────────
	release := exec.Command(aksBin, "stop", "--release")
	release.Dir = "."
	relOut, err := release.CombinedOutput()
	require.NoError(t, err, "aks stop --release: %s", relOut)

	entries, err = os.ReadDir(pinDir)
	if err != nil && os.IsNotExist(err) {
		return // dir removed counts as empty
	}
	require.NoError(t, err)
	assert.Empty(t, entries, "expected pin dir %q empty after --release", pinDir)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("e2e tests require root (eBPF LSM loading)")
	}
}

type auditEntry map[string]any

func parseAuditLog(t *testing.T, data []byte) []auditEntry {
	t.Helper()
	var entries []auditEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e auditEntry
		require.NoError(t, json.Unmarshal(line, &e))
		entries = append(entries, e)
	}
	return entries
}

func filterByAction(entries []auditEntry, action string) []auditEntry {
	var out []auditEntry
	for _, e := range entries {
		if e["action"] == action {
			out = append(out, e)
		}
	}
	return out
}

func assertContainsPath(t *testing.T, entries []auditEntry, path string) {
	t.Helper()
	for _, e := range entries {
		if e["path"] == path {
			return
		}
	}
	t.Errorf("audit log has no BLOCK entry for path %q", path)
}

func assertContainsDest(t *testing.T, entries []auditEntry, ip string) {
	t.Helper()
	for _, e := range entries {
		if e["dest_ip"] == ip {
			return
		}
	}
	t.Errorf("audit log has no BLOCK entry for dest_ip %q", ip)
}

func assertContainsExec(t *testing.T, entries []auditEntry, path string) {
	t.Helper()
	for _, e := range entries {
		if e["event"] == "exec" && e["path"] == path {
			return
		}
	}
	t.Errorf("audit log has no BLOCK exec entry for path %q", path)
}
