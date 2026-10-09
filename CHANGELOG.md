# Changelog

## Unreleased
- Detector (pure-Go, unit-verified here): `Exec` routes through `MatchCommand`
  (deny → command → path → default); unknown event types deny under
  deny-default instead of unconditional allow (`internal/detector/`).
- Kernel `bpf/lsm.c` (written, VM verification pending): fail-closed
  `bpf_d_path`/scratch failures, `COUNTERS` deny/drop counts (FR-9), prior-LSM
  verdict discipline (FR-11), `blocked_ipv6` denylist mirror with v6
  connect events (`dest_ip6`/`is_ipv6`).
- Loader (Go decode verified here, map load pending VM): `decodeEvent`
  handles `dest_ip6`/`is_ipv6`; `BlockIP` routes v6 to `blocked_ipv6`.
- Tests: detector exec/unknown-type pins, loader v6 decode vectors
  (non-palindrome `2001:db8::1234`, `::1` via wire path). New `test/e2e`
  bypass suite (shebang, symlink, execveat, `-c` flags, fork-storm) and
  `test/bench/bench.sh` skeleton — both VM-only, not yet run.
- UI: Agent tab (task timeline + process tree over live SSE) with `?demo=1`
  replay of a scripted Gemini session (`demo-session.json`, shape-tested).
- Dead-code pass (unit-verified here): removed `Verdict.String`,
  `Event.String` (+tests), `Loader.Release` (linux+stub), UI `state.events`
  store + `tableContainer` id, Makefile `generate` PHONY, `MAX_ARGV_LEN`,
  stale personal path in `test-gemini.yaml` (README recipe now uses denied
  `/tmp/secret.txt`). Kept: `SSLReadArgs` (FD lifecycle), `Version`
  (schema gate), `Description` (strict-decode compat), `EVENT_SSL_DATA` /
  paddings (ABI/reserved). C edits unverified (no clang here).

## Rollback
- Release: `aks stop --release` (unpins maps, unloads LSM).
- Stuck pin: `rm -rf /sys/fs/bpf/aks` then reload.
- No-boot: pick recovery GRUB entry without `lsm=bpf`.
