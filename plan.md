# AKS Build Plan — how to build (plan only, nothing executed here)

> Orchestrated 2026-10-09 via skill-router (Planning) + ponytail + make-plan.
> Research: 3 parallel read-only subagents (repo audit, system requirements, test gates).
> Rule: **nothing in this file runs in the current container** — kernel/LSM work happens on the VM in §0.
> Ponytail filter applied: each phase says what it will NOT build.

## 0. System requirements (run here: nowhere — build host + VM)

### 0a. Build host (local or CI — no kernel needed)
- Go 1.24 (`go.mod:3`; CI still pins 1.22 — Phase 1 fixes the skew), `make`
- `clang` (`-g -O2 -target bpf -D__TARGET_ARCH_x86/arm64`), `llvm`, `bpftool` (v7.4.0 fallback),
  `linux-headers-$(uname -r)`, `libbpf-dev`, `build-essential`, `libelf-dev`, `zlib1g-dev`
- Lint: `golangci-lint`, `clang-format`, `go vet`, `gofmt`
- Release (linux only): `GOOS=linux GOARCH=amd64/arm64`

### 0b. Enforcement VM (all kernel work — NOT this container)
- Ubuntu 24.04 LTS (22.04 for the Coder template), x86_64 or aarch64
- Kernel 5.7+ (release floor 5.15), `CONFIG_BPF_LSM=y`, BTF at `/sys/kernel/btf/vmlinux`
- Boot param `lsm=bpf` (or `lsm=<existing>,bpf`): edit `GRUB_CMDLINE_LINUX`, `update-grub`, reboot.
  Keep a recovery GRUB entry **without** `lsm=bpf`. Verify: `cat /sys/kernel/security/lsm | grep bpf`
- cgroup v2 at `/sys/fs/cgroup`, root for load/attach (`sudo aks watch`, `sudo go test -tags integration`)
- Agent runs non-root + `no_new_privs`, no `CAP_BPF`. `aksd` root under systemd `ProtectSystem=strict`
- GitHub runners lack BPF LSM → e2e runs in nested QEMU-KVM micro-VM (`linux-image-generic`, `lsm=bpf`)

### 0c. Why not here
This container: kernel `6.8.0-1066-aws` but **no** `/sys/kernel/security/lsm` (no securityfs, host cmdline
unfixable from inside), **no** `go`/`clang`/`bpftool`, **no** built `aks` binary or `bpf/aks.bpf.o`.
Has BTF + cgroup2 — enough for unit tests only, once a Go toolchain exists.

## Phase 0. Documentation discovery (done — allowed patterns)

- BPF↔Go contract: maps/progs `events, ssl_events, ssl_read_args, blocked_paths, blocked_ipv4,
  entry_comm, watched_pids` and `trace_openat/execve/connect, trace_exec/fork/exit_lineage,
  aks_file_open/socket_connect/bprm_check` (`bpf/lsm.c:16-60`, `bpf/probe.c:15-55`,
  `internal/loader/loader_linux.go:30-59`). Copy these names verbatim — never invent.
- Event wire format: hardcoded byte slices in `loader_linux.go:505-531,546-569` must match
  `bpf/headers/common.h:34-49`. Any struct change updates both decoders + tests.
- Test contracts: `test/e2e/e2e_test.go:50-125` (4 BLOCK vectors), `:129-153` (allow-blob);
  `internal/profiles/profile_test.go`, `internal/detector/detector_test.go`, `internal/ui/server_test.go`.
- Spec gates: `AKS-SPEC.md:14` (test pyramid), `:19.1` (Day 0–4 milestones), `:15` (release checklist).

## Phase 1. Toolchain + hygiene (local, ~1h) — do first, cheapest wins
- [x] Bump CI Go 1.22→1.24 (match `go.mod:3`) — done in `ci.yml` ×3, `integration.yml`, `release.yml`
- [x] C sources as `Makefile:22` prereqs so `make bpf` rebuilds on edit — done
- [x] CLI-vs-disk skew resolved by drop (ponytail): `vllm`/`llamacpp` removed from `--framework` help +
  `profile list` (`cmd/aks/main.go:40,116-121`) — done, no new yamls
- [x] `scripts/checkpoint-1.sh` gate (gofmt, vet, lint, clang-format, `go test -race`) + `checkpoints/` gitignored —
  written, reviewer-fixed, `bash -n` clean (not executed: no Go toolchain here)
- [ ] Gate execution: `bash scripts/checkpoint-1.sh` green on capable host/CI + log attached
- [ ] Commit Phase 1 as one commit (held: tree contains another session's detector edits — exclude them)
- Copy from: existing `profiles/ollama.yaml` for new yamls; `Makefile:22-35` recipe already correct.
- Will NOT: touch enforcement semantics; add deps; restructure layout.

## Phase 2. Enforcement truthfulness (VM, ~3h) — PARTIAL 2026-10-09: pure-Go slice done, loader/VM slice open
- What: make kernel match userspace verdicts. Expand `denied_paths` globs to concrete inodes at load
  (userspace `populateMaps`, reuse `doublestar` from `profiles/profile.go:141-148`) instead of writing
  literal `**` keys into the exact-match map (`loader_linux.go:213-222`, `lsm.c:103,190`).
  Wire `allowed_commands`: route exec through `MatchCommand` or delete the dead list + its tests
  (`detector.go:47-53`, `profile_test.go:236-255`). Unknown event types → deny under deny-default,
  not unconditional Allow (`detector.go:58-59`).
  - [x] `allowed_commands` wired CONSERVATIVE: exec → `MatchCommand` deny → Block, else fall through to
    path verdict (`detector.go:evaluateExec`). Decided 2026-10-09 over the additive variant (basename-Allow
    was spoofable by an attacker-planted `ollama`-named binary). Adds denies only, never allows.
  - [x] Unknown event types deny under deny-default (`detector.go` default → `defaultDecision`, both defaults pinned).
  - [x] `denied_paths` glob→concrete expansion in `populateMaps` (`loader_linux.go:expandDeniedPaths`,
    `filepath.Glob` + `doublestar.FilepathGlob`; no-match → stderr warning, no key). Code + temp-dir unit tests
    written 2026-10-09; EXECUTION PENDING on a Go host (no toolchain in this container).
- Tests: unit (glob expansion table, unknown-type under both defaults) + e2e extend:
  `~/.ssh`-style glob target blocked, non-allowlisted exec denied, allow-blob still passes.
  - [x] Unknown-type under both defaults + exec command pins (`detector_test.go`) — EXECUTED 2026-10-09: `go test -race ./internal/...` green.
  - [x] Glob expansion table (`loader_linux_test.go`, 4 temp-dir cases) — EXECUTED 2026-10-09: green in the same run.
  - [x] Bounded `**` walk (2026-10-09, corrected same day): CI hung 10 min in
    `FilepathGlob` on `/**/.aws/**` (whole shared host root, followed
    symlinks). First attempt (`GlobWalk` + SkipDir) was PROVABLY WRONG —
    library source shows its callback fires for matches only, so it cannot
    prune unmatched subtrees; its MapFS tests passed vacuously. Real fix:
    `filepath.WalkDir` from the literal-prefix root (true pruning, Lstat so
    symlinks never descend, unreadable dirs skipped) + top-level
    /proc|/sys|/dev skip + process-lifetime memo (daemon loads once; e2e
    loads same profile 3×). 5 temp-dir regression tests green here.
    VM run is the judge; if still slow, next step is per-pattern budget,
    not wider skips.
  - [ ] e2e extend + VM run — OPEN, needs VM.
- Checkpoint (VM): `make bpf && sudo go test -tags integration -v -count=1 ./test/e2e/` green;
  `bpftool map dump` shows expanded inode keys, zero `*` keys. — OPEN.
- Will NOT: prefix-trie matching (P1 FR-20); `(dev,ino)` exec allowlist redesign — glob expansion only.

## Phase 3. Fail-open/closed consistency (VM, ~2-4h) — WRITTEN 2026-10-09, UNVERIFIED (no clang/LSM/root here; VM must compile + test)
- What: every BPF branch has one honest verdict. Honor prior LSM verdict (confirm hook signatures take
  no `ret` arg — `lsm.c:81,130,168` match kernel prototypes, so this means ordering/cooperation, not a
  new param). Decide ringbuf-full policy explicitly: deny+`COUNTERS` drop increment (spec FR-9) —
  never deny-without-event (`lsm.c:109-111,147-149,196-198`). `bpf_d_path`/scratch failures must deny
  under deny-default, not `return 0` (`lsm.c:88-89,92-94,175-176,179-181`).
  - [x] FR-11 by ordering: signatures unchanged (kernel prototypes take no `ret`); `return 0` kept only for not-ours/denylist-miss, each commented; top-of-file contract comment (`lsm.c:4-7`).
  - [x] `COUNTERS` per-CPU array added (`lsm.c:66-76`, key space `HOOK_*`/`CTR_*` in `common.h`); `count()` helper; DROP bumped on reserve-fail, DENY on every emitted deny. ALLOW deliberately uncounted (hot-path overhead, G4).
  - [x] `deny_with_path()` helper: `bpf_d_path`/scratch failures deny with best-effort event (pathless on resolution fail) — 4 sites (file_open ×2, bprm ×2).
  - [x] No deny-without-event left: all 3 reserve-fail sites deny + bump DROP.
  - [x] Every `return 0` justified in a trailing comment (final-verification grep ready).
  - [ ] VM verify: `make bpf` (verifier log), e2e read-vs-write (`cat` allow / `echo >>` deny), ringbuf-pressure (deny + DROP increments), `bpftool map dump counters` — OPEN, needs VM.
  - Blind-write risks for VM to confirm: BPF stack with inlined helper (~256B path + small scalars); `__u32→__u8` event_type truncation; `counters` map load alongside loader; no userspace COUNTERS reader yet.
- Tests: e2e read-vs-write case on blocked path (`cat` allowed, `echo >>` denied);
  ringbuf-pressure test asserts deny + drop counter increments. — OPEN, needs VM.
- Checkpoint (VM): e2e green + `COUNTERS` shows drops with matching deny events; no silent branch left
  (grep `return 0` in `lsm.c` — each hit has a comment justifying allow). — OPEN.
- Will NOT: `file_permission` hook (P1 FR-21); self-DoS tuning beyond the counter.

## Phase 4. IPv6 (VM, ~2h) — PARTIAL 2026-10-09: full denylist mirror written; Go slice verified, kernel/VM slice open
- What: close the `AF_INET`-only hole (`lsm.c:135-136`). Minimal option: explicit deny+event for
  `AF_INET6` under deny-default (2 lines, no new map). Full option: `blocked_ipv6` map + v6 decode
  (`loader_linux.go:521-529` ignores `dest_ip6`/`is_ipv6`) + `BlockIP` v6 (`loader_linux.go:468-472`).
  Fix the vacuous `::1` test (`detector_test.go:74-83` uses a synthetic event real code can't produce).
  - Decision: FULL mirror (minimal deny-all-v6 would kill ::1 loopback at kernel, contradicting the checkpoint; undetectable here).
  - [x] Kernel: `blocked_ipv6` HASH map (`char[16]` key, `IPV6_LEN` in `common.h`) + AF_INET6 branch in `aks_socket_connect` (denylist lookup, v6 event with `dest_ip6`/`is_ipv6`/port, DROP/DENY counters). Non-IP families still allow with comment. — WRITTEN BLIND, needs `make bpf`.
  - [x] Loader (write-only): `objects.BlockedIPv6`, `Close()`, `BlockIP` routes v4→`blocked_ipv4` / v6→`blocked_ipv6` with nil-map guard; `decodeEvent` decodes `dest_ip6`/`is_ipv6` (verbatim copy, no endian conversion). Behavior change: `BlockIP` v6 now blocks instead of erroring (`cmd/aks/main.go:97`, `e2e_test.go:77` v4 path unchanged).
  - [x] Go verified HERE: `TestDecodeEvent_ipv6` (2001:db8::1234 non-palindrome, RED→GREEN) + `TestDecodeEvent_ipv6Loopback` (::1 via real wire path — resolves the vacuous-test complaint); `go test -race ./internal/...` 6/6 green, gofmt/vet clean.
  - [ ] VM verify: `make bpf` verifier log, e2e v6 connect vector (denied host → BLOCK + event), `::1` loopback → ALLOW via real path — OPEN, needs VM.
  - Blind-write risks for VM: `bpf_probe_read_kernel` of `sin6_addr`; `char[16]` map key vs cilium `[16]byte`; old `.o` without `blocked_ipv6` → `BlockIP` v6 errors until rebuild (nil guard).
- Tests: unit (v6 decode vectors incl. non-palindrome IPs — the `8.8.8.8` palindrome masks endian bugs);
  e2e v6 connect vector.
  - [x] Unit v6 decode vectors done (see above).
  - [ ] e2e v6 connect vector — OPEN, needs VM.
- Checkpoint (VM): v6 connect to denied host → BLOCK + event; `::1` loopback → ALLOW via real path. — OPEN.
- Will NOT: UDP/DNS control (P1 FR-26); resolver pinning.

## Phase 5. Fail-closed pinning (VM, 5-8h, highest uncertainty)
- [x] `CollectionOptions{Maps:{PinPath:/sys/fs/bpf/aks}}` + `EEXIST` reuse via `MapReplacements`
  (`loader:loadObjects`/`loadWithPinnedReuse`); `PinByName` required for cilium/ebpf v0.21.0 — code written, uncompiled here
- [x] `Detach()` (keep pins) vs `Release()`/`UnpinAll()` (clear `/sys/fs/bpf/aks`); `Close()` aliases `Detach`;
  stubs added for non-Linux — code written, uncompiled here
- [x] `aks stop` (pins stay) + `aks stop --release` (unpin); plain stop is a no-op reporting the invariant,
  `--release` calls package-level `loader.UnpinAll()` (fixed 2026-10-09: `Detach`/`Release` are Loader methods,
  not package funcs — the first `stop` draft called non-existent package funcs)
- [x] `populateMaps` idempotency contract documented (all `Put`/UpdateAny; stale `blocked_ipv4` preserved fail-closed)
- [x] `TestKill9Survival` in `test/e2e` (kill -9 → pins exist + `/etc/shadow` EPERM → `--release` → empty) — written, VM-only
- [ ] Checkpoint (VM): survival test green + `ls /sys/fs/bpf/aks` non-empty after kill, empty after release
- [ ] Compile gate: `gofmt`/`go vet`/`go build ./...` on a Go host ( slices A+B were parallel — interface mismatch caught + fixed by reading, not compiling)
- Will NOT: pinning tracepoint links (decided: maps-pinned + links-reattached); timer leases.

## Phase 6. Tool switching + policy schema (VM, ~1w, biggest slice)
- [x] Schema: `version/baseline/tools/restricted` + effective-set helpers (`EffectiveExec/Net/FS/DenyFiles`);
  legacy yamls load unchanged (all legacy keys present in struct — verified by grep); `DefaultDeny` prefers
  `default`, falls back to `default_policy`
- [x] Validator: strict decode (`KnownFields`) + `line N: reason` errors (bad fs/net/exec/deny_files/name/version);
  `aks policy check <file>` (exit 0 + `ok`, else non-zero) — code written, unrun
- [x] Switch server: NEW `internal/switch/` (`package switcher` — `switch` is a Go keyword): pure `Machine`
  (enter/exit/busy/unknown→restricted/close-revert, epoch per transition) + socket server
  (`/run/aks/aks.sock` 0660, `apply_failed` rollback, `NoopApplier` honest stub) + state tests — written, unrun
- [x] Middleware: `middleware/python/aks_client.py` (stdlib only, `enter_tool`/`exit_tool`/`tool_call` with
  `finally`-exit) + `unittest` + mock tests — written, unrun (`python3 -m unittest` on capable host)
- [x] BPF `CGROUP_STATE` map + per-hook lookup (missing → fall through unchanged, verdict logic untouched) +
  event tail `{profile_id, epoch}` (append-only 320→328B, old decoder safe) + `SeedCgroupState` helper —
  code written, unverifiable here (blind-write risks noted: `bpf_get_current_cgroup_id` on 5.15 floor,
  verifier, old-pin `Compatible` fail until `--release`)
- [ ] Gates (all need capable hosts): `go build ./...` + `go test -race ./internal/...` + `python3 -m unittest`;
  VM switch suite (ack <10ms, revert <1s); 30-min soak, 0 false denies
- Will NOT: annotation compiler (P1 FR-24); authenticated channel (P1 FR-25); concurrent-tool cgroups (P2).
- Will NOT: annotation compiler (P1 FR-24); authenticated channel (P1 FR-25, note T7 residual);
  concurrent-tool child cgroups (P2); `aks learn` (P1 FR-23).

## Phase 7. Bypass + race + bench + release (VM + local, ~1w) — PARTIAL 2026-10-09: written, VM runs open
- What: bypass suite — memfd+fexecve, shebang, symlink, hardlink, bind-mount, `execveat`, io_uring
  connect, unix-socket connect, `python -c`, `bash -c`, fork-storm → 100% denied (G1).
  Race: switch during fork-storm, rapid enter/exit, overlapping `enter_tool`. Bench: `hyperfine`
  exec/open/connect delta <5% + `bpf_stats`. Release: CHANGELOG, SBOM+SHA, signed tag, verifier log,
  README benchmark, rollback note (`stop --release` + unpin + recovery GRUB).
  - [x] Bypass suite written: `test/e2e/bypass_test.go` (same package, reuses
    `requireRoot`/`parseAuditLog`/`filterByAction`, suffix-match exec asserts
    to dodge /bin→/usr/bin canonicalization) + `test/e2e/bypass_target/main.go`
    (shebang, symlink, `python -c`, `bash -c`, 32× fork-storm, execveat-last
    via raw trap amd64=322/arm64=281 with arch guard; exit 0/1/3 unambiguous).
    Compile-checked here (`gofmt` clean, `go vet -tags integration` clean).
  - [x] Deliberate omissions with in-file rationale: hardlink + memfd+fexecve
    (invisible to exact-path maps — need the Will-NOT `(dev,ino)` redesign),
    unix-socket (allowed for non-IP families by Phase 4 design), io_uring
    (VM follow-up), bind-mount (d_path still yields the denied path — low value).
  - [x] Bench skeleton: `test/bench/bench.sh` (`bash -n` clean, VM-run).
  - [x] Release docs: `CHANGELOG.md` (new, Unreleased factual only),
    `docs/rollback.md` (honest: no `stop --release` exists, kill = fail-open
    until Phase 5, GRUB recovery). No workflow edits, no SBOM/SHA/sign (release-time).
  - [ ] VM runs: `sudo go test -tags integration -run TestBypass ./test/e2e/`,
    `test/bench/bench.sh`, e2e green — OPEN, needs root/VM. Never run here.
  - [ ] Tool-switch races (fork-storm switch, rapid enter/exit, overlapping
    `enter_tool`) — socket server now exists (`internal/switch/`), race tests
    not yet written; VM run open.
- Checkpoint: release checklist `AKS-SPEC.md:15` all boxes + VM logs attached to the release. — OPEN.
- Will NOT: fuzzing infra beyond a smoke run (P1); second-kernel matrix beyond one extra kernel;
  K8s operator, Landlock fallback, signed policies (all P2).

## Final verification (all phases)
- `grep -rn "return 0" bpf/lsm.c` — every allow-branch commented.
- `grep -rn '\*' <(bpftool map dump)` — no literal glob keys in kernel maps.
- `make test-unit && make lint && make build` + VM e2e + bypass + soak — all green, logs attached.
- Anti-pattern sweep: no invented map/prog names (diff against §Phase 0 contract); no new deps
  without deleting one; no `Co-authored-by: claude` trailers (spec §20.3 hook + CI scan).

## Totals + order
- Phase 1 (local, 1h) → 2 → 3 → 4 (VM, ~7h) → 5 (VM, 5-8h) → 6 (VM, 1w) → 7 (1w).
- Cut order if time runs short: 7-docs polish → 6-middleware extras → 4-full-option (take minimal deny).
  Never cut: deny-path tests, threat-model updates, prior-art credit.
- Rollback per phase: `git revert` + `aks stop --release` + `rm -rf /sys/fs/bpf/aks`; host recovery
  via GRUB entry without `lsm=bpf`.

---
## Appendix: prior review (vigil → aks, kept verbatim history)

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
