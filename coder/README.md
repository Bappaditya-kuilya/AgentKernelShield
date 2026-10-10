# aks — Coder workspace template

Provisions a Ubuntu 22.04 GCP VM that runs the aks workspace Docker image, with Claude Code and Gemini CLI pre-installed. The Coder agent startup script clones the aks repo, builds the eBPF programs, and installs profiles on each workspace start.

## Why Ubuntu (not Container-Optimized OS)?

aks's BPF LSM hooks (`lsm/file_open`, `lsm/bprm_check`, `lsm/socket_connect`) require `lsm=bpf` in the host kernel boot parameters. Container-Optimized OS does not support custom GRUB parameters. A plain Ubuntu 22.04 VM is used instead; the workspace container runs `--privileged` so it can load eBPF programs into the host kernel.

The first workspace start triggers a one-time reboot to activate `lsm=bpf`. Subsequent starts skip the reboot.

## Build and push the workspace image

```bash
# From the repo root
gcloud builds submit \
  --config coder/docker/cloudbuild.yaml \
  --substitutions _PROJECT=coderd \
  .
```

The image is pushed to `us-central1-docker.pkg.dev/coderd/aks/workspace:latest`.

## Deploy the Coder template

```bash
cd coder/coder-template
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — set project, container_image, service_account_email
terraform init
coder templates push aks-demo --directory .
```

## Demo

Once the workspace is running, open a terminal:

```bash
# Run all three jailbreak scenarios under the claude-code profile
sudo ./demo/run_demo.sh --profile claude-code

# Or the gemini-cli profile
sudo ./demo/run_demo.sh --profile gemini-cli
```

Scenarios (profile-specific — `claude-code`/`gemini-cli` are `default_policy: allow`):
- **Credential theft** — `open(/etc/shadow)`, `~/.ssh/id_rsa`, `~/.aws/credentials` → BLOCK (in `denied_paths` for all three profiles)
- **Shell escape** — BLOCK only under `ollama` (shells in `denied_paths`); under `claude-code`/`gemini-cli` `execve(/bin/bash)` is not denylisted and `python3` is allowlisted → ALLOW + logged
- **Network exfiltration** — first connection ALLOW + logged under `claude-code`/`gemini-cli` (`0.0.0.0/0` allowed); BLOCK only after `BlockIP` adds the IP, or under `ollama` (deny-default)

## Running real agents under aks

```bash
# Terminal 1: start aks
sudo aks watch --profile profiles/claude-code.yaml

# Terminal 2: run Claude Code normally — aks streams every file/network event
claude
```

## Profiles

| Profile | Description |
|---|---|
| `ollama` | Ollama LLM inference server |
| `claude-code` | Claude Code AI coding agent |
| `gemini-cli` | Gemini CLI AI coding agent |
