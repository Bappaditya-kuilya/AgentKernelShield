<div align="center">
  <img src="assets/agentkernelshield-logo.svg" width="220" alt="AgentKernelShield emblem"/>
</div>

# aks

eBPF-based runtime security for AI inference workloads.

Aks attaches to AI agent processes (Claude Code, Gemini CLI, Ollama) and enforces a behavioral profile at the kernel level, blocking unexpected file access, network connections, and subprocess spawning before they complete. No code changes required in the target process.

## Prior art

AKS builds on two prior projects. **Aks** (Bappaditya-kuilya) provides kernel-level behavioral profiles for agent processes via BPF LSM with process-tree tracking (Go + C); AKS differs by adding tool-scoped policy switching per MCP tool call, where Aks uses one static profile per agent. **AgentSight** (eunomia-bpf) provides observability linking prompts, model calls, and tool decisions to system effects (Rust, MIT); AKS differs by enforcing policy inline in the kernel, where AgentSight observes without blocking.

## How it works

```mermaid
flowchart LR
    A["AI process<br/>claude / gemini / ollama"] -->|syscalls| B["Linux Kernel<br/>eBPF LSM hooks<br/>file_open / socket_connect / bprm_check"]
    B -->|ringbuf events| C["aks daemon<br/>profile → ALLOW / BLOCK"]
    C -->|JSON + SSE| D["Audit log / SIEM<br/>Web UI :7394"]
```

```
AI process (claude, gemini, ollama, ...)
        │ syscalls
        ▼
Linux Kernel: eBPF LSM hooks (file_open, socket_connect, bprm_check)
        │ ring buffer events
        ▼
aks daemon: evaluates against profile → ALLOW / BLOCK
        │ JSON + real-time UI
        ▼
Audit log / SIEM
```

- **Kernel layer** (`bpf/`): tracepoints observe syscalls; LSM hooks enforce policy inline
- **Process lineage** (`bpf/probe.c`): tracks agent process trees by PID — follows forks and execs so child processes (`node`, `sh`, `git`) are attributed to the correct agent
- **Profiles** (`profiles/`): YAML files defining allowed paths, networks, and commands per framework
- **Detector** (`internal/detector`): evaluates kernel events against the loaded profile
- **Tool switching** (`internal/switch` library, `middleware/python/aks_client.py` client): the `enter_tool`/`exit_tool` protocol over `/run/aks/aks.sock` is implemented and unit-tested, but no `aks` subcommand serves the socket yet — `aks watch` does not open it, so per-tool switching is not live (see Testing below for the VM gates).
- **Audit** (`internal/audit`): one JSON line per decision, stdout or file
- **Web UI** (`internal/ui`): real-time event feed with BLOCK/ALLOW badges, served over SSE

## Tech Stack

| Layer | Tech |
|---|---|
| Daemon | Go 1.24 (`cmd/aks`, `internal/`) |
| eBPF | C (`bpf/probe.c`, `bpf/lsm.c`), `clang` + `bpftool`, CO-RE |
| Loader | `github.com/cilium/ebpf`, ringbuf, LSM attach, uprobes |
| CLI | `github.com/spf13/cobra` |
| Profiles | YAML (`gopkg.in/yaml.v3`), `doublestar` globs, CIDR match |
| Kernel | Linux 5.7+ `CONFIG_BPF_LSM=y`, `lsm=bpf`, BTF `/sys/kernel/btf/vmlinux` |
| UI / Audit | SSE + embedded static HTML, JSONL to stdout/file |
| Test | `go test -race`, `testify`, QEMU `linux-image-generic` e2e |

## Requirements

- Linux kernel 5.7+ with `CONFIG_BPF_LSM=y`
- Boot param: `lsm=bpf` (add to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`)
- `clang`, `llvm`, `bpftool`, `linux-headers`
- Root privileges to load eBPF programs
- Go 1.24+

## Quick start

```bash
# Install from latest release (Linux amd64/arm64)
curl -fsSL https://github.com/Bappaditya-kuilya/aks/releases/latest/download/install.sh | sudo bash

# Watch an AI agent with the built-in profile
sudo aks watch --framework gemini-cli

# With real-time web UI at http://localhost:7394
sudo aks watch --framework claude-code --ui

# Use a custom profile
sudo aks watch --profile /path/to/custom.yaml

# List available profiles
aks profile list

# Validate a policy file (strict schema, line+reason errors)
aks policy check ./profiles/ollama.yaml

# Stop: plain `stop` keeps pins (fail-closed, enforcement continues); `--release` unpins maps.
# Killing `aks watch` detaches links instead — fail-OPEN until link pinning lands. See docs/rollback.md.
sudo aks stop [--release]
```

## Output

```json
{"ts":"2026-01-01T00:00:00Z","pid":1234,"comm":"gemini","event":"file_open","path":"/etc/passwd","action":"BLOCK","reason":"matches denied path pattern"}
{"ts":"2026-01-01T00:00:01Z","pid":1234,"comm":"node","event":"net_connect","dest_ip":"1.2.3.4","dest_port":443,"action":"ALLOW","reason":"default policy: allow — destination network not in allowlist"}
```

## Process lineage tracking

AI agents spawn many child processes (`node`, `sh`, `python3`, `git`, ...) that share comm names with unrelated system processes. Without lineage tracking, aks would either miss agent children or produce noise from VS Code, SSH daemons, and cron jobs with the same comm.

Aks solves this with BPF process lineage tracking:

1. `entry_comm` in the profile names the agent's root process (e.g. `gemini`)
2. A `sched_process_exec` tracepoint detects when that process starts and adds its PID to `watched_pids`
3. A `sched_process_fork` tracepoint propagates membership to all descendants
4. A `sched_process_exit` tracepoint removes PIDs when processes exit (prevents PID reuse false positives)
5. Observation tracepoints only emit events for PIDs in `watched_pids`

Result: aks sees exactly the agent's process tree — nothing more.

```yaml
# profiles/gemini-cli.yaml
entry_comm: gemini   # root process to track
```

## Profiles

| Profile | Entry process | Status |
|---|---|---|
| `ollama` | `ollama` | Available |
| `claude-code` | `claude` | Available |
| `gemini-cli` | `gemini` | Available |

## Testing

```bash
# Unit tests (works on macOS and Linux, no eBPF required)
make test-unit
# = go test ./internal/... -race -count=1

# Integration / e2e test (Linux + root, requires BPF LSM enabled)
make test-integration
# = make bpf + sudo go test -tags integration ./test/e2e/

# Bypass suite: evasion vectors (VM-only, same requirements as e2e)
# sudo go test -tags integration -run TestBypass ./test/e2e/

# Middleware unit tests (no root needed)
# cd middleware/python && python3 -m unittest

# Full enforcement gates (VM only: Ubuntu 24.04, lsm=bpf, root)
# sudo go test -tags integration -v -count=1 ./test/e2e/
# sudo go test -tags integration -run TestBypass ./test/e2e/
# ./test/bench/bench.sh
```

How to test blocking manually (no agent needed):

```bash
make bpf && make build
echo demo-secret > /tmp/secret.txt
sudo ./aks watch --profile ./test-gemini.yaml --bpf-obj bpf/aks.bpf.o > /tmp/aks-gemini.jsonl &
# in another shell (unwatched, should succeed):
cat /tmp/secret.txt
# via watched tree — run through gemini CLI:
# > read @/tmp/secret.txt   # expect BLOCK file_open /tmp/secret.txt + EPERM
grep BLOCK /tmp/aks-gemini.jsonl
```

## Security

Found an enforcement bypass or fail-open bug? Please report it privately via
[GitHub Security Advisories](https://github.com/Bappaditya-kuilya/AgentKernelShield/security/advisories/new)
— see [SECURITY.md](SECURITY.md) for scope and disclosure. Do not open a public issue for vulnerabilities.

## Demo

See [`coder/`](coder/) for a Coder workspace template that provisions a Ubuntu VM with aks, Claude Code, and Gemini CLI, and runs live jailbreak blocking scenarios.
