# Security Policy

## Supported versions

Security fixes go to `main` and the latest `vX.Y.Z` release. Older tags are
unsupported — upgrade first, then report if the issue reproduces.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** (preferred — no email needed):

https://github.com/Bappaditya-kuilya/AgentKernelShield/security/advisories/new

Include: what you did, what you expected (which threat-model item it breaks,
see below), the profile and hook involved, kernel version, and logs.
A minimal reproducer (commands, not screenshots) gets the fastest response.

## Scope

This project is a Linux LSM enforcement engine. In scope:

- Enforcement bypass: prompt-injected commands, exfiltration, or file access
  that the loaded policy should deny but does not (threats T1–T11 in
  `docs/threat-model.md`: exec allowlist, network allowlist, `deny_files`,
  read-only mode, cgroup escape, fail-open paths, memfd/symlink/TOCTOU
  vectors, ring-buffer loss without counting).
- Policy validation flaws: a policy that loads but enforces something
  materially different from what the YAML says.
- Fail-open bugs: daemon crash, kill, or error paths that lift enforcement
  (G3) outside the documented link-pinning limitation.
- Supply-chain issues in pinned dependencies (`go.mod`, workflows).

Out of scope (documented limits, not vulnerabilities):

- Attackers with root or a compromised kernel (no LSM survives that).
- Prompt-injection detection/classification (out of scope by design).
- Social engineering, physical access, upstream kernel/Cilium CVEs
  (report those upstream).
- The deliberately documented gaps: unpinned links after `kill -9`,
  hardlink/memfd invisibility to exact-path maps, unix-socket allow,
  io_uring follow-up — these are tracked in `docs/threat-model.md`, not reports.

## Disclosure

Coordinated disclosure: please give us time to fix before going public;
90 days is the norm. We will credit reporters in the release notes unless
you ask to stay anonymous. There is no paid bounty.

## What happens after you report

1. We confirm receipt and reproduce on the enforcement VM (gates in
   README Testing).
2. Fix lands on `main` with a regression test; backported to the supported
   release if affected.
3. Advisory published with CVE request where appropriate; credit as agreed.
