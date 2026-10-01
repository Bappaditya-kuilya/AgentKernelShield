# AKS Plan — vigil → aks (read-only review, no code changed)

> Swarm: 5 parallel read-only agents. Zero edits to source. This file is the only write.
> Decisions locked: wipe fresh git, full rename vigil→aks, strip all prior mentions, new GitHub repo.

## 1. What it is

**vigil:** eBPF runtime guard for AI agents. `tracepoints` observe, `LSM` blocks (`file_open`, `socket_connect`, `bprm_check`), Go daemon decides.
**Stack:** Go 1.24 + C/eBPF (`cilium/ebpf`, `cobra`), `bpf/vigil.bpf.o` via `clang+bpftool`, UI SSE `:7394`.
**Run:** `vigil watch --framework <ollama|claude-code|gemini-cli> [--profile --bpf-obj /usr/lib/vigil/vigil.bpf.o --ui --port 7394]`, `vigil profile list`.
**Flow:** kernel ringbuf 16MB → `loader.drainRingbuf` → `detector.Evaluate` → `audit JSONL` + `ui broadcast` + reactive `BlockIP()`.

## 2. AKS-SPEC drift (have vs gap)

| Area | Have (file:line) | Drift |
|---|---|---|
| Identity FR-1 | `bpf/probe.c:40-55`, `bpf/lsm.c:47-60` `watched_pids+entry_comm`, lineage `probe.c:95-168`, seed `loader_linux.go:321-350` | No cgroup, no `CGROUP_STATE`, no `aks run`. PID tree races on reuse |
| Exec FR-2 | `lsm.c:167-192` path denylist, `profile.go:105-139` glob/basename | No `(dev,ino)` `EXEC_ALLOW`. Symlink/replaced-binary TOCTOU |
| FS FR-3 | `lsm.c:80-124` exact-path block only | No `FS_MODE`, no `FMODE_WRITE` check, no `read_only` mode |
| Net FR-4 | `profile.go:120-127` CIDR `MatchIP`, `lsm.c:128-163` `blocked_ipv4` denylist, `main.go:96-98` reactive `BlockIP` | Inverted: kernel denylist empty at load, allow in Go after connect. No `ip:port`, no hostname→IP, `AF_INET`-only `:135-136` |
| Policy FR-5 | `profiles/loader.go:11-29` yaml+CIDR compile | No `version/baseline/tools/restricted`, no line+reason validator |
| Switch FR-6/7 | — | No `/run/aks/aks.sock`, no `enter_tool/exit_tool`, no `ack(epoch)`, no `busy`, no revert |
| Unknown FR-8 | `profile.go:99-101` `default_policy` | No `restricted`. Unknown → static default, not `read_only` |
| Ringbuf FR-9 | `probe.c:16-19` 16MB, `loader_linux.go:181-210` drain | No `COUNTERS` drop count. Reserve-fail silent (`probe.c:74-75`) or deny-without-event (`lsm.c:109-111`) |
| Pinned FR-10 | `loader_linux.go:62-64,247-299,424-464` in-mem links, `Close()` detaches | No `pin/bpffs` hits. `kill -9` = fail-open, opposite G3 |
| Prior verdict FR-11 | `lsm.c:81,130,168` single-arg `BPF_PROG`, `return 0/-1` | No `int ret` param, never honored. Can flip prior deny to allow |
| CLI FR-12 | `main.go:24-48` `watch` + `profile list`, SSE UI `ui/server.go:42-55` | No `run/policy check/status/tui/stop --release/learn`. Web UI violates spec non-goal (wanted ratatui) |
| Middleware FR-13 | — | No `middleware/python/`, zero `.py` files |
| Baseline FR-14 | `Allowed*` only | No `baseline:{exec,net,fs}` runtime set, no 30-min soak |
| Stack §7 | `go.mod` Go+cilium+cobra, C BPF | Spec Rust+Aya+tokio+clap+ratatui. Layout `bpf/cmd/internal/profiles/test` vs `aks-ebpf/aks-common/aks/middleware/tests/{bypass,race,bench}/docs/adr` |
| License | `LICENSE` Apache-2.0, BPF `"GPL"` `lsm.c:12` | Spec dual MIT/GPL + choice statement. Actual GPL-only kernel, Apache-only userspace |

## 3. Migration: vigil → aks (wipe + full rename + strip-all + new repo)

**Surface: 251 lines, 325 occurrences** (`vigil` 262, `Vigil` 9, `VIGIL` 10, `VectorInstitute` 44). Repro: `grep -rn "vigil\|Vigil\|VIGIL\|VectorInstitute" --exclude-dir=.git .`

| Group | Hits | Action |
|---|---|---|
| Go module+imports | `go.mod:1`, `cmd/vigil/main.go:8-12`, `internal/*`, `test/e2e/*:28-31` | `github.com/VectorInstitute/vigil` → `github.com/<you>/aks`, `go fmt ./...` |
| Dir+binary | `cmd/vigil/`, `Makefile:19`, `ci.yml:72`, `release.yml:67,70`, `main.go:20,42,61-62,78,80,85` | `git mv cmd/vigil cmd/aks`, `BINARY:=aks`, cobra `Use: aks`, log `aks:` |
| BPF obj | `Makefile:6`, `integration.yml:63,69,87`, `release.yml:64,77,117,136`, `main.go:42`, `run_demo.sh:36,38`, `e2e_test.go:13,38`, `install.sh:40,44,74-75,83`, symbols `lsm.c:81,129,168` ↔ `loader_linux.go:51-53` | `bpf/aks.bpf.o`, `bpftool gen object bpf/aks.bpf.o`, `--bpf-obj /usr/lib/aks/aks.bpf.o`, rename `vigil_*`→`aks_*` in C+Go together |
| Install paths | `.gitignore:2`, `install.sh:13-14,44,83,95,104`, `run_demo.sh:25`, `docs/index.html:307`, `main.tf:71-72,78,211,213` | `/usr/local/bin/aks`, `/usr/lib/aks/`, `/usr/lib/aks/aks.bpf.o`, `/var/lib/aks-system-ready`, `/aks` |
| Tarballs | `release.yml:75-76,81-82,129,134-135`, `install.sh:72,78-79`, `integration.yml:68,87,232-233`, `Makefile:4`, `run_demo.sh:41`, `main.tf:80` | `aks-<TAG>-linux-amd64.tar.gz`, `aks-linux-*`, `aks-bpf`, `/tmp/aks-*.gz/log` |
| Env `VIGIL_*` | `run_demo.sh:23-24,94,98-99,104,110` | `AKS_BIN`, `AKS_PID` |
| Docs | `index.html:6,221,227,246,301,311-312,324,327,330,333,340,379,451,453-454`, `architecture.html:6,516,602,667-670`, `ui/static/index.html:6,447` | Titles, `github.com/<you>/aks`, `cd aks`, `sudo aks watch`, keep `:7394` unless changed |
| Coder | `coder/README:1,3,7,21,30,50,53-54,56`, `cloudbuild.yaml:8,12`, `variables.tf:38,57,59,62`, `main.tf:28,53,61,63,66-67,71-73,75,77-78,80-81,84,87-89,128,131-132,172,211,213`, `tfvars.example:7,11-12` | Image `.../aks/workspace:latest`, `aks_repo`, `repo_name=aks`, `slug=aks-ui`, `push aks-demo` |
| Profiles prose | `claude-code.yaml:6,9,70`, `gemini-cli.yaml:7`, `profile.go:41` | `AKS enforces…`, `aks uses…`, `aks will log…` |
| Spec refs (strip per your call) | `AKS-SPEC.md:120,125,281,349,572,586` | Replace with `prior eBPF work`. Note: violates `AKS-SPEC.md:125` credit rule — keep local copy for license cover |
| Misc logs | `README:13`, `logo.svg:3`, `install.sh:24`, `loader_linux.go:10`, `server.go:4`, `scenarios/*:11`, `e2e:18` | Mechanical `sed`, eyeball `logo.svg` text |

**Steps (2–3h):**
1. `[Setup]` `rm -rf .git; git init; gh repo create aks --private; git add -A; git commit -m "chore: import vigil baseline"` — verify: `git log` 1 commit, `gh repo view` ok
2. `[Core]` Module+imports+`cmd/vigil→cmd/aks` — verify: `go build ./...`
3. `[Core]` BPF obj+symbols+install paths+tarballs+env — verify: `make bpf && make build`, `grep -ri vigil` only spec-allowed
4. `[Integration]` Docs/coder/demo/profiles/spec-strip — verify: `grep -rni "vectorinstitute\|vigil" --exclude-dir=.git .` zero
5. `[Verify]` `make test-unit && make lint && make build` + push + CI green — verify: all pass

## 4. Must-build (11–18h, order 3→1→2)

### Fix 3 — prior verdict + FMODE_WRITE (2–4h, do first)
- Touch: `bpf/lsm.c:80-211` → `BPF_PROG(..., int ret)` + `if (ret) return ret;`, `BPF_CORE_READ(file,f_mode) & FMODE_WRITE` gate; `common.h:10-13` add `FMODE_READ/WRITE` defines (mirror `AF_INET` precedent); `test/e2e/target/main.go` read-vs-write case.
- Risks: BTF prototype change rejects on old kernel/cilium; `f_mode` needs `BPF_CORE_READ`; `FMODE_WRITE=0x2` local define; ringbuf-full currently denies — decide `return ret` to avoid self-DoS.
- Verify: `make bpf`, `cat` allowed + `echo >>` denied on blocked path, `TestJailbreakEscape` updated to attempt writes, full `make test-unit`.

### Fix 1 — CGROUP_STATE + launcher (4–6h)
- Touch: `common.h` struct, `probe.c:50-55` authoritative map, `lsm.c:47-52` `__weak` mirror + `bpf_get_current_cgroup_id()` in 3 hooks, `loader_linux.go:30-59,212-244,424-464` `CgroupState` populate/cleanup, new `aks run` (`mkdir -p /sys/fs/cgroup/...`, pass ID).
- Risks: needs cgroupv2 + root, `EEXIST/EROFS` under systemd, `HASH<u64,u8>` vs `ARRAY`, shared-map `__type` must match or `LoadAndAssign` fails.
- Verify: in-cgroup blocked / out-of-cgroup allowed, old e2e still passes with empty map, `bpftool map dump` ID matches `/proc/self/cgroup`.

### Fix 2 — pinning fail-closed (5–8h, highest uncertainty)
- Touch: `loader_linux.go:89` → `CollectionOptions{Maps:{PinPath:/sys/fs/bpf/aks}}` + `EEXIST` reuse, split `Detach()` vs `Release()/UnpinAll()`, `main.go:24-48` add `stop [--release]`, `loader_stub.go` stub, `e2e_test.go:66-68` crash test.
- Risks: tracepoint link pin asymmetric (likely maps-pinned + links-reattached — decide explicitly), stale `blocked_ipv4/watched_pids` on reuse needs idempotent `populateMaps`, `/sys/fs/bpf` unmounted in CI, `closeOnce/doneCh/wg` race on double close.
- Verify: `watch &; kill -9; watch` still denies `/etc/shadow`, `stop` keeps pins, `stop --release` empties `/sys/fs/bpf/aks`.

## 5. Test/release gaps blocking aks claims

- **Now green:** 6 pkgs unit (~60 tests), e2e 4-vector (`passwd/shadow/8.8.8.8/bash`) + allow-blob, CI lint/unit/build, QEMU e2e with `lsm=bpf`.
- **Gaps:** `go.mod 1.24` vs CI `1.22` (bump first); no `SECURITY.md/CHANGELOG.md/docs/adr/threat-model`; release tarball amd64-only, no SBOM/SHA/sign/verifier-log/rollback; bypass 4/≈12 (missing memfd+fexecve, shebang, symlink, hardlink, bind, execveat, io_uring, unix-socket, `python -c`, `bash -c`, fork storm, UDP/DNS, read_only-write, open-fd); zero race/bench (`hyperfine/bpf_stats`)/soak/fuzz; no `kill -9` survival, ack-latency, compat matrix.
- **Commands:** `make test-unit`, `go test ./internal/... -race -count=1 -coverprofile=cover.out`, `make lint`, `make bpf`, `bpftool prog show`, `sudo go test -tags integration -v -count=1 ./test/e2e/`, `cat /sys/kernel/security/lsm`.

## 6. Totals + sequence

- Migration **2–3h** → must-build **11–18h** → gaps (bypass+bench+docs) **1–2w** if chasing full spec.
- Order: migration → `go 1.24` CI bump → Fix 3 → Fix 1 → Fix 2 → e2e+verifier log → docs/release hardening.
- Rollback: fresh repo, so `git log` + `stop --release` + `rm -rf /sys/fs/bpf/aks`, recovery GRUB entry without `lsm=bpf`.

---
*Next: approve this plan, then `writing-plans` breaks the approved slice into executable steps. No implementation until you say go.*
