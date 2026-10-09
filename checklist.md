# VM + Release Checklist — what "successful build" means, with numbers

Run everything below on the enforcement VM (Ubuntu 24.04, kernel 5.7+,
`CONFIG_BPF_LSM=y`, `lsm=bpf`, root). Nothing here runs in unprivileged
containers. Each gate lists the exact command, the passing score, and where
the score comes from.

## 0. Host prerequisites

- [ ] `cat /sys/kernel/security/lsm | grep bpf` → contains `bpf`
- [ ] `ls /sys/kernel/btf/vmlinux` exists (CO-RE + verifier need BTF)
- [ ] `go version` → 1.24+, `clang --version`, `bpftool --version` (v7.4.0+), `hyperfine --version`
- [ ] Recovery GRUB entry WITHOUT `lsm=bpf` exists (spec §16.1)

## 1. Unit (pure Go, also runs anywhere)

- [ ] `gofmt -l internal/ test/ cmd/` → empty
- [ ] `go vet ./internal/... ./cmd/...` → exit 0
- [ ] `go vet -tags integration ./test/e2e/...` → exit 0
- [ ] `go test -race -count=1 ./internal/...` → 7/7 packages ok
      (audit, detector, events, loader, profiles, switch, ui)
- [ ] `cd middleware/python && python3 -m unittest` → 5/5 ok
- [ ] `go build ./...` → exit 0

## 2. BPF build + verifier

- [ ] `make bpf` → exit 0, produces `bpf/aks.bpf.o`
- [ ] Verifier log clean on the release kernel AND one second kernel
      (compat matrix: Ubuntu 24.04 current + 1 other). Any `rejected` = fail.
- [ ] `grep -rn "return 0" bpf/lsm.c` → every hit has a trailing allow comment
- [ ] `clang-format --dry-run --Werror bpf/probe.c bpf/lsm.c bpf/headers/common.h` → exit 0

## 3. e2e enforcement (`sudo go test -tags integration -v -count=1 ./test/e2e/`)

- [ ] `TestJailbreakEscape` → ≥4 BLOCK events (`/etc/passwd`, `/etc/shadow`,
      `8.8.8.8:443`, `/bin/bash` exec) — G1 slice
- [ ] `TestAllowedOperationsUnblocked` → allow-blob readable (0 false positives)
- [ ] `TestKill9Survival` → pins survive `kill -9`, `/etc/shadow` still EPERM;
      `stop --release` empties `/sys/fs/bpf/aks` — G3 proof
- [ ] MANUAL (UNVERIFIED — no e2e coverage; `aks_file_open` in bpf/lsm.c
      has no read/write flag check, so current code denies both): `cat
      /etc/shadow` → expect EPERM + BLOCK event; `echo x | tee -a
      /etc/shadow` → expect EPERM + BLOCK event; confirm both in audit log
- [ ] MANUAL (UNVERIFIED — no e2e coverage; BPF `blocked_ipv6` denylist in
      bpf/lsm.c + Go `MatchIP` allowlist in internal/profiles): connect to
      denied v6 host → expect BLOCK + event; `curl -g http://[::1]/` →
      expect ALLOW; confirm both in audit log (Phase 4)

## 4. Bypass suite (`sudo go test -tags integration -run TestBypass ./test/e2e/`)

- [ ] Shebang, symlink, execveat, `python -c`, `bash -c`, 32× fork-storm →
      100% denied, exit 0 (G1). Any ALLOWED = fail, file an issue.
- [ ] Known gaps stay documented, not silently passing: hardlink,
      memfd+fexecve (need `(dev,ino)` redesign), unix-socket (allowed by
      design), io_uring (follow-up).

## 5. Tool switching (Phase 6 gates)

- [ ] Profile switch acked before tool start; ack <10 ms on localhost
- [ ] Unknown tool → `restricted` profile (fs read_only)
- [ ] Middleware crash mid-tool → baseline restored <1 s
- [ ] Overlapping `enter_tool` → `busy`, no state corruption

## 6. Benchmark (G4: <5% overhead) — `test/bench/bench.sh`

Why <5%: an empty BPF LSM hook already costs ~4% on hot syscalls
(lsm-perf `file_permission` measurements, Paul Renauld; static-call
follow-ups gain ~2-3% on UnixBench syscall overhead — LWN 974057). Our
hooks add map lookups + `bpf_d_path` on top, so <5% end-to-end on
exec/open/connect is the bar that proves the policy check is cheap
relative to the unavoidable hook cost.
Method (hyperfine docs + stability literature):
- [ ] `--warmup 3`, `--min-runs 10` (hyperfine defaults; 30 reps is the
      practical minimum for stable claims — Stanojevic et al.)
- [ ] Same host, same governor, idle machine; report mean ± stddev, never
      a single run; publish the slower direction, never cherry-pick
- [ ] `hyperfine` delta on `/bin/true`, `cat /etc/hosts`, `python3 -c pass`
      (watch vs no-watch) → **each < +5%**
- [ ] Per-hook cost: `sysctl -w kernel.bpf_stats_enabled=1`, workload,
      `bpftool prog show` → `run_time_ns / run_cnt` per `aks_*` program
      (note: stats collection itself adds ~20ns/run — eBPF Summit 2020,
      Bryce Kahle; disable with `sysctl -w kernel.bpf_stats_enabled=0`
      after measuring). Sanity bound: mean hook runtime in the low
      hundreds of ns; anything in µs means a map/d_path problem.

## 7. Soak (FR-14, G2)

- [ ] Demo agent 30 min on baseline → **0 false denies**
- [ ] Ringbuf-pressure run → denies still happen AND `COUNTERS` drop
      counter increments with matching deny events (FR-9)

## 8. Release (spec §15)

- [ ] CI green (build, fmt, clippy-equivalent `vet`, unit, deny, audit)
- [ ] Integration + bypass + race suites pass, logs attached
- [ ] Benchmark rerun, numbers pasted into README
- [ ] Verifier passes on target kernels, log attached
- [ ] CHANGELOG updated; rollback note accurate (`stop --release` + unpin
      + recovery GRUB)
- [ ] Tag `vX.Y.Z` (signed) + binary + SHA256 + SBOM; smoke test on clean
      VM (install → `aks run` → blocked `curl`)
- [ ] `git log` clean of banned attribution (spec §20.3 hook + CI scan)

## 9. Scorecard (fill on the VM)

| Gate | Result | Log |
|---|---|---|
| unit 7/7 + middleware 5/5 | | |
| verifier (2 kernels) | | |
| e2e 4-vector + allow-blob | | |
| kill-9 survival | | |
| read-vs-write | | |
| v6 deny + ::1 allow | | |
| bypass 6 vectors | | |
| switch ack/revert/busy | | |
| bench <5% + hook ns | | |
| soak 0 false denies | | |
| release checklist | | |

Rollback triggers: any false-deny bricking the demo agent, any in-scope
bypass succeeding, verifier reject on a supported kernel.
