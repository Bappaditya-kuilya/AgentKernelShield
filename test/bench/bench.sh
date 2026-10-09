#!/bin/bash
# Microbenchmark: enforcement overhead (Phase 7, spec G4 target <5%).
# VM-ONLY: needs a kernel with BPF LSM + root. Never run in containers.
#
# Compares exec/open/connect latency WITHOUT aks vs WITH `aks watch`.
# Usage: ./test/bench/bench.sh [--quick]
set -uo pipefail

cd "$(dirname "$0")/../.."

if ! command -v hyperfine >/dev/null; then
  echo "installing hyperfine..."
  sudo apt-get install -y hyperfine
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (eBPF load)" >&2
  exit 1
fi

RUNS=50
[ "${1:-}" = "--quick" ] && RUNS=10

echo "=== baseline (no aks) ==="
hyperfine --runs "$RUNS" --export-json /tmp/bench_base.json \
  '/bin/true' \
  'cat /etc/hosts >/dev/null' \
  'python3 -c "pass"'

echo "=== with aks watch (ollama profile) ==="
make bpf build >/dev/null
./aks watch --profile ./profiles/ollama.yaml & WATCH_PID=$!
sleep 2
hyperfine --runs "$RUNS" --export-json /tmp/bench_aks.json \
  '/bin/true' \
  'cat /etc/hosts >/dev/null' \
  'python3 -c "pass"'
kill "$WATCH_PID"

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
