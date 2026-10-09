# Rollback

Honest status: there is no `aks stop --release` yet (CLI has `watch` and
`profile list` only), and programs/links are not pinned (Phase 5 open).

## Rollback per phase (code)
- `git revert` the phase's commits. No shared history rewrites.

## Stop enforcement on a test host
1. Kill the `aks watch` process. `Close()` detaches links and closes maps.
2. WARNING: links live in memory only — `kill -9` detaches them too, which
   is fail-OPEN until Phase 5 pinning lands. Verify with
   `sudo bpftool prog show | grep aks` (empty = detached).
3. Remove a stale build: `make clean` (deletes `aks`, `bpf/*.o`).

## Host recovery (bad policy / unusable host)
1. Reboot into the GRUB entry WITHOUT `lsm=bpf` (keep one permanently —
   spec §16.1). Enforcement cannot load there.
2. Delete any pins if Phase 5 has landed: `sudo rm -rf /sys/fs/bpf/aks`.
3. Fix the profile with `aks policy check` semantics in mind (validator
   lands in Phase 6; until then re-read the deny list by hand), reboot
   back, re-run the e2e suite before trusting the host.
