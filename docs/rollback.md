# Rollback

Honest status: the CLI serves `watch`, `profile list`, `policy check`,
and `stop [--release]` (`cmd/aks/main.go`). Maps are pinned by name under
`/sys/fs/bpf/aks` (`internal/loader/loader_linux.go:81-111`); program and
link handles live in memory only — `kill -9` detaches them (fail-OPEN)
while the pins survive.

## Rollback per phase (code)
- `git revert` the phase's commits. No shared history rewrites.

## Stop enforcement on a test host
1. Prefer the CLI: `sudo aks stop` keeps map pins but enforcement stops
   with the daemon (fail-OPEN until link pinning lands);
   `sudo aks stop --release` detaches and unpins everything under
   `/sys/fs/bpf/aks` (`loader.UnpinAll`, `cmd/aks/main.go:131-144`).
2. Fallback: kill the `aks watch` process. `Close()` detaches links and
   closes map FDs (pins stay).
3. WARNING: links live in memory only — `kill -9` detaches them too, which
   is fail-OPEN until link pinning lands (maps pin today; links do not).
   Verify with `sudo bpftool prog show | grep aks` (empty = detached).
4. Remove a stale build: `make clean` (deletes `aks`, `bpf/*.o`).

## Host recovery (bad policy / unusable host)
1. Reboot into the GRUB entry WITHOUT `lsm=bpf` (keep one permanently —
   spec §16.1). Enforcement cannot load there.
2. Delete stale pins (fallback when `aks stop --release` cannot run):
   `sudo rm -rf /sys/fs/bpf/aks`.
3. Fix the profile (`aks policy check <file>` must print `ok`), reboot
   back, re-run the e2e suite before trusting the host.
