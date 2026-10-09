#!/bin/bash
# Shared guards for test/bench/bench.sh and test/soak/soak.sh.
# Sourced via: . "$REPO_ROOT/test/lib/common.sh"  (REPO_ROOT must be set first)
# VM-ONLY helpers: need a kernel with BPF LSM + root.

# Exit 1 unless root (eBPF load).
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (eBPF load)" >&2
    return 1
  fi
}

# Exit 1 if another watch/e2e is running (shared /sys/fs/bpf/aks pins).
guard_concurrent() {
  if pgrep -f 'aks watch|e2e\.test' >/dev/null 2>&1; then
    echo "another aks watch or e2e.test is running (shared /sys/fs/bpf/aks pins) — stop it first" >&2
    return 1
  fi
}

# Rebuild unless go is missing and ./aks is newer than the sources.
ensure_built() {
  if ! command -v go >/dev/null; then
    if [ -x ./aks ] && ! find cmd internal -name '*.go' -newer ./aks | grep -q .; then
      echo "go not found, using existing ./aks"
    else
      echo "go not found — install Go 1.22+ or add it to PATH and retry" >&2
      return 1
    fi
  else
    make bpf build >/dev/null
  fi
}

# start_watch <log> <aks watch args...>: background aks watch (appending to
# <log> when non-empty), fail if it dies within 2s. Sets $STARTED_PID and
# echoes it; return 1 on startup failure.
start_watch() {
  local log="$1"
  shift
  if [ -n "$log" ]; then
    ./aks watch "$@" >>"$log" 2>&1 & STARTED_PID=$!
  else
    ./aks watch "$@" & STARTED_PID=$!
  fi
  sleep 2
  if ! kill -0 "$STARTED_PID" 2>/dev/null; then
    if [ -n "$log" ] && [ -f "$log" ]; then
      echo "aks failed to start. Check $log"
      cat "$log"
    else
      echo "aks watch failed to start (PID $STARTED_PID)" >&2
    fi
    return 1
  fi
  echo "$STARTED_PID"
}

# stop_watch <pid>: kill -0-guarded kill + wait (no-op for empty/dead pid).
stop_watch() {
  local pid="${1:-}"
  [ -z "$pid" ] && return 0
  if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; fi
  wait "$pid" 2>/dev/null || true
}
