# VM Checklist — fastest path to proven green, in dependency order

Do the gates in order. Each gate unblocks the next; stop at the first red.
Nothing here runs in unprivileged containers. Prerequisite: the bounded-glob
fix must be on main first (`grep -n GlobWalk internal/loader/loader_linux.go`
non-empty) — without it §3 hangs 10 minutes in `/**/` expansion.

## 0. Host (2 min)

- [ ] `cat /sys/kernel/security/lsm | grep bpf`
- [ ] `ls /sys/kernel/btf/vmlinux`
- [ ] `go version` ≥1.24, `clang`, `bpftool` ≥7.4, `hyperfine` present
- [ ] Recovery GRUB entry without `lsm=bpf`

## 1. Unit + build (3 min, also runs anywhere)

- [ ] `gofmt -l internal/ test/ cmd/` → empty
- [ ] `go vet ./internal/... ./cmd/...` + `go vet -tags integration ./test/e2e/` → 0
- [ ] `go test -race -count=1 ./internal/...` → 7/7 ok
- [ ] `cd middleware/python && python3 -m unittest` → 5/5 ok
- [ ] `go build ./...` → 0
- [ ] `make bpf` → `bpf/aks.bpf.o` built; verifier clean on 2 kernels;
      `clang-format --dry-run --Werror bpf/probe.c bpf/lsm.c bpf/headers/common.h` → 0

## 2. e2e (one 15-min run covers §2–§4)

- [ ] `sudo go test -tags integration -v -count=1 ./test/e2e/` →
      `TestJailbreakEscape` (4 BLOCKs), allow-blob readable, bypass 6/6 denied.
      Any ALLOWED = file an issue.
- [ ] EXPECTED-FAIL (do not chase): `TestKill9Survival` step 4 asserts EPERM
      after `kill -9`, but links are deliberately unpinned (plan Will-NOT) so
      enforcement stops with the daemon. Pins-exist half passes; EPERM half
      needs link pinning (future) or a test rework to assert pins only.
- [ ] MANUAL, no tests exist: read-vs-write (`file_open` has no write-flag
      check — both denied today) and v6 deny/`::1` allow. Run by hand, confirm
      in audit log, paste output into the scorecard.

## 3. Switch (unit-proven; no socket server binary exists yet)

- [ ] Covered by unit tests only: ack shape, `busy` overlap, crash revert,
      `<10ms` ack / `<1s` revert (net.Pipe harness). No `aks` subcommand serves
      `/run/aks/aks.sock`, so there is no VM socket gate to run. Do not invent one.

## 4. Bench + soak (same VM session as §2)

- [ ] `test/bench/bench.sh` → each workload delta < +5% (G4). Publish the
      slower direction. Per-hook ns via `bpf_stats_enabled=1` + `bpftool prog
      show` (disable after; collection costs ~20ns/run).
- [ ] `test/soak/soak.sh` → 0 false denies; drops SKIP-when-0 is correct
      (200 opens cannot fill 16MB ringbuf).
- [ ] No 30-min demo-agent script exists; soak.sh + `demo/run_demo.sh`
      scenarios are the soak suite. Do not claim a 30-min run without writing it.

## 5. Release (spec §15)

- [ ] CI + integration green, logs attached; benchmark numbers pasted into README
- [ ] CHANGELOG + rollback note accurate; `git log` attribution clean
- [ ] Tag `vX.Y.Z` (signed) + binary + SHA256 + SBOM; clean-VM smoke test
      (`install` → `aks watch` → blocked `curl`). Note: CLI is `watch`,
      not `run`.

## Scorecard

| Gate | Result | Log |
|---|---|---|
| unit/build/verifier | | |
| e2e + bypass | | |
| kill-9 (pins half) | | |
| manual read-write + v6 | | |
| bench + soak | | |
| release | | |

Rollback triggers: false-deny bricking the demo, any in-scope bypass allowed,
verifier reject on a supported kernel.
