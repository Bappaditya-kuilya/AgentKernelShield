# Contributing to aks

## Prerequisites

- Go 1.24+ (`go version`)
- For BPF builds: `clang`, `llvm`, `bpftool` (v7.4+), `linux-headers`, BTF at
  `/sys/kernel/btf/vmlinux` (Linux only)
- For enforcement tests: Linux 5.7+ with `CONFIG_BPF_LSM=y`, boot param
  `lsm=bpf`, root, `bpffs` mounted at `/sys/fs/bpf`

## Build, test, lint

```bash
make build            # aks binary (pure Go, portable)
make bpf              # eBPF object (Linux only)
make test-unit         # go test ./internal/... -race (macOS + Linux, no root)
make test-integration  # make bpf + sudo e2e (VM only, needs BPF LSM + root)
make lint              # golangci-lint (Go) + clang-format check (C)
make fmt               # format Go + C in place
```

More gates (all VM-only): bypass suite
(`sudo go test -tags integration -run TestBypass ./test/e2e/`),
`test/bench/bench.sh`, `test/soak/soak.sh`, middleware
(`cd middleware/python && python3 -m unittest`, no root needed).

## Demo UI without a VM

```bash
python3 -m http.server 7395 --directory internal/ui/static
# open http://localhost:7395/?demo=1  (scripted Gemini replay)
```

## Pull requests

- Trunk-based: short branches off `main`, squash merge.
- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Local gate green before pushing: `gofmt`, `go vet`, `go test -race
  ./internal/...`. Every kernel-side change needs a verifier log plus a
  deny test and an allow test from the VM.
- Credits go to human authors only: no AI tool is ever listed as author,
  co-author, or contributor (commits, trailers, docs, release notes).
- Security-sensitive change? Read `docs/threat-model.md` and
  `SECURITY.md` first; report vulnerabilities privately, never in a PR.
