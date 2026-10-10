# AKS threat model (grounded in THIS tree)

Source: `AKS-SPEC.md` §13 (`AKS-SPEC.md:351-395`). Spec text is the
authority for intent; the "Status in THIS tree" column is verified
against the files cited — no invented facts. Known-gap reports are
out of scope as vulnerabilities per `SECURITY.md:33-41`; they are
tracked in `plan.md` / `checklist.md`.

## 1. Assets and actors (`AKS-SPEC.md:353-361`)

- Assets: host files (keys, tokens, source), network position, the
  enforcement itself (`AKS-SPEC.md:355`).
- Actors: prompt injector (via documents, web, tool output), malicious
  or mislabeled MCP server, curious local user, the agent itself acting
  on bad instructions (`AKS-SPEC.md:356`).
- Trusted: kernel, `aksd`, policy YAML, agent framework and middleware
  code (`AKS-SPEC.md:360`). In THIS tree the daemon is `aks watch`
  (`cmd/aks/main.go:24-48`) plus the `internal/switch` library and
  `middleware/python/aks_client.py` client (neither served by the
  daemon yet — see `checklist.md:38-42`).
- Untrusted: LLM output, tool results, documents, web content, MCP
  server processes and their annotations (`AKS-SPEC.md:361`).

## 2. Trust boundaries

Spec boundary (`AKS-SPEC.md:360-361`): everything above "Trusted" vs
"Untrusted". In THIS tree the boundary is enforced at three LSM hooks
(`bpf/lsm.c:171,232,320`: `aks_file_open`, `aks_socket_connect`,
`aks_bprm_check`), with a userspace detector that only logs
(`cmd/aks/main.go:92-99`: a `Block` decision calls `BlockIP` for
network events, otherwise it is written to the audit log and broadcast
— there is no retroactive deny for exec/file).

## 3. Threats T1–T14 (`AKS-SPEC.md:365-380`)

| # | Threat (spec) | Spec mitigation | Status in THIS tree |
|---|---|---|---|
| T1 | Injected command spawns shell or `curl` | `bprm_check_security` allowlist | DENYLIST, not allowlist. Kernel does exact-path `blocked_paths` lookup, miss allows (`bpf/lsm.c:352-354`). Shells are denylisted only in `profiles/ollama.yaml:21-27`; `profiles/claude-code.yaml` / `profiles/gemini-cli.yaml` have no shell entries. `allowed_commands` is consulted only by the userspace detector (`internal/detector/detector.go:76-84`), which logs but does not deny exec/file retroactively (`cmd/aks/main.go:92-99`). |
| T2 | Exfil via network | `socket_connect` allowlist | DENYLIST in kernel (`blocked_ipv4`/`blocked_ipv6`, miss allows: `bpf/lsm.c:289-291,256-258`), allowlist in userspace detector (`internal/detector/detector.go:86-93`) plus reactive `BlockIP` (`internal/loader/loader_linux.go:734-754`). First contact with an unknown IP is ALLOW+log under `claude-code`/`gemini-cli` (`profiles/claude-code.yaml:65-71`, `profiles/gemini-cli.yaml:65-68` allow `0.0.0.0/0`); BLOCK only after `BlockIP` or under `ollama` (loopback only, `profiles/ollama.yaml:62-65`, deny-default `profiles/ollama.yaml:6`). Spec residuals stand: DNS tunnel over allowed resolver, exfil to an allowed endpoint. |
| T3 | Read secrets (`~/.ssh`) | `deny_files` expanded to inodes | Globs expanded to concrete paths in userspace at load (`internal/loader/loader_linux.go:331-347`), exact-match in kernel (`bpf/lsm.c:203-205`). Unmatched patterns are skipped with a stderr warning — fail-open but visible (`internal/loader/loader_linux.go:376-400`). Files created after load are not covered until reload (no prefix trie; `plan.md:87` Will-NOT cites FR-20). |
| T4 | Write when tool is read-only | `file_open` write-intent deny | ABSENT. `aks_file_open` has no `f_mode` / `FMODE_WRITE` / `FS_MODE` check (`bpf/lsm.c:171-228`; no `FMODE_WRITE`, `f_mode`, `file_permission`, or `ptrace`/`task_kill` hooks exist in `bpf/`). Reads and writes to a denylisted path are both denied; writes to non-denylisted paths are allowed regardless of profile (`checklist.md:34-36`; `plan.md:224`). Fds opened before a switch stay writable (no `file_permission` hook — P1 FR-21). |
| T5 | Agent escapes cgroup | Non-root agent; root-owned cgroup | Cgroup launcher does NOT exist: `cmd/aks/main.go:24-48,106-176` provides `watch` / `profile` / `policy` / `stop` only, no `aks run`. Identity is PID lineage (`watched_pids` + `entry_comm`: `bpf/lsm.c:106-113,179-181`; seeding in `internal/loader/loader_linux.go:562-598`). `cgroup_state` map and `SeedCgroupState` helper exist (`bpf/lsm.c:51-61`; `internal/loader/loader_linux.go:281-323`) but `Load` never calls the seeder ("intentionally NOT called from populateMaps/Load", `internal/loader/loader_linux.go:299-301`); hooks stash state into events only (`bpf/lsm.c:123-135`). |
| T6 | Agent detaches or edits AKS (bpf syscall, bpffs, ptrace, kill) | Non-root, no `CAP_BPF`; P1 `bpf` / `ptrace` / `task_kill` hooks | P1 hooks ABSENT (`bpf/lsm.c` ends at `aks_bprm_check`, `bpf/lsm.c:320-378`; no other `SEC("lsm/…")` hooks). v1 relies on non-root only, exactly the spec residual (`AKS-SPEC.md:372`). |
| T7 | Compromised agent calls `enter_tool` for a looser profile | Profiles limited to YAML; switch audited; P1 authenticated channel | Server is a LIBRARY, not a live endpoint. `internal/switch/server.go:18-34` defines `/run/aks/aks.sock` (dir `0750`, file `0660` intent); `middleware/python/aks_client.py:12,52-55` speaks the protocol — but no `aks` subcommand serves the socket (`cmd/aks/main.go` imports `audit`/`detector`/`loader`/`profiles`/`ui` only; `checklist.md:38-42`: "no socket server binary exists yet"). `SO_PEERCRED` / cgroup-membership checks are explicitly absent (`internal/switch/server.go:173-177`, P1 FR-25). Default `NoopApplier` acks switches without kernel writes and "MUST NOT be used in production" (`internal/switch/server.go:74-82`). Spec residual stands (attacker gets loosest declared profile) plus unauthenticated until FR-25. |
| T8 | Mislabeled MCP annotation widens access | Annotations never widen | None by design: no annotation-to-policy path exists; policy loads from human YAML via `profiles.LoadFile` (`cmd/aks/main.go:56`; schema in `internal/profiles/profile.go:61-96`). No annotation compiler in tree (P1 FR-24, `plan.md:157-159` Will-NOT). |
| T9 | Bypass via `memfd_create` + `fexecve`, shebang, symlink, hardlink, bind mount | LSM sees the resolved file | PARTIAL. `bpf_d_path` sees the resolved path, so shebang / symlink / `execveat` are covered by the bypass suite (`test/e2e/bypass_test.go:35-97`). **Hardlink and `memfd_create`+`fexecve` are invisible to exact-path maps and deliberately omitted** (`test/e2e/bypass_target/main.go:12-14`; `test/e2e/bypass_test.go:35-37`) pending the `(dev,ino)` redesign (spec FR-2; kernel keys are exact path strings, `bpf/lsm.c:25-32`). |
| T10 | `io_uring` ops skip syscall filters | LSM hooks sit on kernel objects | Hooks are LSM (not tracepoints) for enforcement, but the `io_uring` vector is an explicit VM follow-up, omitted from the suite (`test/e2e/bypass_target/main.go:12-14`). Unix-socket connects are allowed by design for non-IP families (`bpf/lsm.c:244-246`; `test/e2e/bypass_target/main.go:12-14`; `SECURITY.md:39-41`). |
| T11 | Daemon crash opens the gate | Pinned links and maps | **MAPS pinned, LINKS unpinned — fail-OPEN on kill.** Maps pin by name under `/sys/fs/bpf/aks` (`internal/loader/loader_linux.go:81-111`); `Detach`/`Close` close every link while keeping pins (`internal/loader/loader_linux.go:671-723`); `kill -9` therefore detaches enforcement (`docs/rollback.md:17-21`). `checklist.md:30-33` expects only the pins-half of `TestKill9Survival` to pass; the EPERM-half needs link pinning (future). Plain `aks stop` is a no-op reporting the invariant; `--release` unpins maps (`cmd/aks/main.go:131-144`; `internal/loader/loader_linux.go:725-732`). |
| T12 | Event log leaks secrets | Log path/ip only, never env or content; log mode 0600 | Event wire format carries timestamps, pids, comm, path / ip / port, profile/epoch only (`internal/loader/loader_linux.go:787-826`; example output `README.md:91-96`). No env or file content is logged. Paths can still be sensitive — the 0600 residual from spec stands; the daemon writes to stdout/file with no mode enforcement observed (`cmd/aks/main.go:50-104`). |
| T13 | Malicious dependency | `cargo-deny`, `cargo-audit`, lockfile, minimal deps | Spec names Rust controls; THIS tree is Go — supply-chain scope is `go.mod` + workflows (`SECURITY.md:31`). Transitive risk remains (spec residual). |
| T14 | Policy tampering on disk | Policy file owned by root, mode 0640 | Policy is a YAML path argument (`cmd/aks/main.go:51-59`); no signing in tree (P2 per spec). Root compromise out of scope (spec residual). |

## 4. Residual gaps that exist in THIS tree (do not file as new vulns)

Per `SECURITY.md:39-41`, the deliberately documented gaps, with primary
evidence:

1. **Unpinned links after `kill -9`** — `internal/loader/loader_linux.go:676-689`
   closes links on `Detach`; `docs/rollback.md:17-21` states fail-OPEN
   until pinning lands; `checklist.md:30-33` gates only the pins-half.
2. **Hardlink / `memfd_create`+`fexecve` invisibility to exact-path maps** —
   `test/e2e/bypass_target/main.go:12-14`,
   `test/e2e/bypass_test.go:35-37`, `SECURITY.md:39-41`; kernel keys are
   exact path strings (`bpf/lsm.c:25-32`).
3. **Unix-socket allow** — non-IP families return 0 / no opinion
   (`bpf/lsm.c:244-246`); allowed by design
   (`test/e2e/bypass_target/main.go:12-14`).
4. **No write-intent check** — `aks_file_open` (`bpf/lsm.c:171-228`) has no
   write-flag gate; both reads and writes to denylisted paths deny, all
   else allows (`checklist.md:34-36`).
