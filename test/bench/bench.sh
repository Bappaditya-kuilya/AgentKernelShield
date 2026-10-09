#!/bin/bash
# Microbenchmark: enforcement overhead (Phase 7, spec G4 target <5%).
# VM-ONLY: needs a kernel with BPF LSM + root. Never run in containers.
#
# Compares exec/open/connect latency WITHOUT aks vs WITH `aks watch`.
# Usage: ./test/bench/bench.sh [--quick]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
SCRIPT_LIB="$REPO_ROOT/test/lib/common.sh"
. "$SCRIPT_LIB"

if ! command -v hyperfine >/dev/null; then
  echo "installing hyperfine..."
  sudo apt-get install -y hyperfine
fi

require_root || exit 1

if ! command -v clang >/dev/null; then
  echo "install BPF toolchain: sudo apt install -y clang llvm libbpf-dev" >&2
  exit 1
fi

RUNS=50
[ "${1:-}" = "--quick" ] && RUNS=10

echo "=== baseline (no aks) ==="
hyperfine --warmup 3 --min-runs "${RUNS:-10}" --export-json /tmp/bench_base.json \
  '/bin/true' \
  'cat /etc/hosts >/dev/null' \
  'python3 -c "pass"'

echo "=== with aks watch (bench profile) ==="
# NOTE: must use profiles/bench.yaml, NOT an agent profile. ollama.yaml has
# no entry_comm, which means watch-all + default-deny: the detector then
# BLOCKs the bench workloads themselves (/bin/true exec via allowed_commands,
# /etc/ld.so.cache open via default-deny) and the LSM hook inline-denies
# `python3 -c` via the expanded /usr/bin/python3.* denylist. bench.yaml sets
# entry_comm to a process that never runs, so hooks stay attached while every
# workload takes the unwatched allow fast-path — that cost is what we measure.
# Also: never run e2e and bench concurrently; both share the pinned maps
# under /sys/fs/bpf/aks (last-writer-wins), which invalidates the numbers.
guard_concurrent || exit 1
ensure_built || exit 1
start_watch "" --bpf-obj "$REPO_ROOT/bpf/aks.bpf.o" --profile "$REPO_ROOT/profiles/bench.yaml" || exit 1
WATCH_PID=$STARTED_PID
hyperfine --warmup 3 --min-runs "${RUNS:-10}" --export-json /tmp/bench_aks.json \
  '/bin/true' \
  'cat /etc/hosts >/dev/null' \
  'python3 -c "pass"'
stop_watch "$WATCH_PID"

echo "=== per-hook cost (bpf_stats) ==="
if command -v bpftool >/dev/null; then
  sysctl -w kernel.bpf_stats_enabled=1
  start_watch "" --bpf-obj "$REPO_ROOT/bpf/aks.bpf.o" --profile "$REPO_ROOT/profiles/bench.yaml" || exit 1
  STAT_PID=$STARTED_PID
  for _ in $(seq 1 1500); do /bin/true; done
  bpftool prog show | grep -E 'aks_|run_time_ns|avg_runtime' | tee /tmp/bench_hook_cost.txt
  stop_watch "$STAT_PID"
  sysctl -w kernel.bpf_stats_enabled=0
  echo "hook cost saved to /tmp/bench_hook_cost.txt"
else
  echo "warning: bpftool not found, skipping per-hook cost" >&2
fi

echo "=== deltas (publish the slower direction, never cherry-pick) ==="
python3 - <<'EOF'
import json
base = {r["command"]: r["mean"] for r in json.load(open("/tmp/bench_base.json"))["results"]}
aks = {r["command"]: r["mean"] for r in json.load(open("/tmp/bench_aks.json"))["results"]}
for cmd, b in base.items():
    a = aks[cmd]
    print(f"{cmd}: base={b*1e3:.3f}ms aks={a*1e3:.3f}ms delta={(a-b)/b*100:+.1f}%")
EOF
echo "also record: bpf_stats hook cost (kernel.bpf_stats_enabled=1, bpftool prog show)"
