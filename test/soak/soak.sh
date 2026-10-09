#!/bin/bash
# Soak: long-run stability + ringbuf pressure (checklist §7).
# VM-ONLY: needs a kernel with BPF LSM + root. Never run in containers.
#
# Phase (b) drives normal ollama activity and fails on any BLOCK attributed
# to agent comms ("false denies"). Phase (c) hammers opens and fails if a
# known-deny probe is ever allowed. Phase (d) reports ringbuf drops.
# Usage: [DURATION=60] ./test/soak/soak.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
SCRIPT_LIB="$REPO_ROOT/test/lib/common.sh"
. "$SCRIPT_LIB"

DURATION="${DURATION:-1800}"
LOG="/tmp/aks-soak-audit.jsonl"
FAIL=0

require_root || exit 1

# Never run soak concurrently with another watch/e2e/bench: both share the
# pinned maps under /sys/fs/bpf/aks (last-writer-wins), which invalidates
# the run.
guard_concurrent || exit 1
ensure_built || exit 1

# ── (a) start watch ──────────────────────────────────────────────────────
rm -f "$LOG"
start_watch "$LOG" --profile "$REPO_ROOT/profiles/ollama.yaml" --bpf-obj "$REPO_ROOT/bpf/aks.bpf.o" || exit 1
WATCH_PID=$STARTED_PID
trap 'kill $WATCH_PID 2>/dev/null || true' EXIT
echo "aks attached — PID $WATCH_PID, log $LOG"

# BLOCKs attributed to agent comms (ollama.yaml allowed_commands).
agent_blocks() {
  python3 - "$LOG" <<'EOF'
import json, sys
comms = {"ollama", "ollama-runner", "llama-runner"}
n = 0
for line in open(sys.argv[1], errors="replace"):
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if r.get("action") == "BLOCK" and r.get("comm") in comms:
        n += 1
print(n)
EOF
}

# ── (b) normal activity: fail on any false deny ──────────────────────────
echo "=== normal activity (${DURATION}s) ==="
if ! command -v ollama >/dev/null; then
  echo "warning: ollama not found, skipping activity drive (phase b unattested)"
else
  END=$((SECONDS + DURATION))
  i=0
  while [ "$SECONDS" -lt "$END" ]; do
    i=$((i + 1))
    ollama run qwen2.5:0.5b "Soak prompt $i: reply in five words or less." >/dev/null 2>&1
    sleep 2
  done
fi
BLOCKS=$(agent_blocks)
echo "agent-attributed BLOCKs: $BLOCKS"
if [ "$BLOCKS" -gt 0 ]; then
  echo "FAIL: false denies during normal activity"
  FAIL=1
fi

# ── (c) ringbuf pressure + known-deny probe ──────────────────────────────
echo "=== ringbuf pressure (200x open burst + deny probe) ==="
PROBE_OK=1
for _ in $(seq 1 200); do
  cat /etc/hosts >/dev/null 2>&1
  if cat /etc/shadow >/dev/null 2>&1; then PROBE_OK=0; fi
done
if [ "$PROBE_OK" -eq 0 ]; then
  echo "FAIL: deny probe (cat /etc/shadow) was allowed at least once"
  FAIL=1
else
  echo "deny probe blocked every time"
fi

# ── (d) COUNTERS drop check ──────────────────────────────────────────────
echo "=== COUNTERS drop check ==="
kill "$WATCH_PID" 2>/dev/null || true
trap - EXIT
wait "$WATCH_PID" 2>/dev/null || true
PIN=/sys/fs/bpf/aks/counters
if [ ! -e "$PIN" ]; then
  echo "SKIP: no pinned counters map at $PIN (loader has no Go handle for it)"
elif ! command -v bpftool >/dev/null; then
  echo "SKIP: bpftool not found, cannot dump $PIN"
else
  DROPS=$(bpftool -j map dump pinned "$PIN" | python3 -c '
import json, sys
tot = sum(sum(e["values"]) for e in json.load(sys.stdin) if e["key"] in (2, 6, 10))
print(tot)')
  echo "ringbuf-drop total (keys 2,6,10): $DROPS"
  if [ "$DROPS" -gt 0 ]; then
    echo "drops observed under pressure ($DROPS)"
  elif [ "$PROBE_OK" -eq 0 ]; then
    echo "FAIL: deny probe was allowed at least once and no drops recorded"
    FAIL=1
  else
    echo "SKIP: drops total 0 with all probe denies landed — 200 opens cannot fill 16MB ringbuf (pressure below overflow threshold)"
  fi
fi

# ── summary ──────────────────────────────────────────────────────────────
echo "=== soak summary ==="
if [ "$FAIL" -eq 0 ]; then
  echo "PASS: soak clean — full log $LOG"
else
  echo "FAIL: soak found problems — full log $LOG"
fi
exit "$FAIL"
