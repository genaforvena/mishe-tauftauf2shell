# Brotli2Shell status

Handed off from frontier 2026-11-20 ~16:55Z (DM to operator pending at handoff).
Dedicated two-pane window and two-pane restorer registry entry exist; hy4-flash
route is set. Charter and wake trigger unit are owed from the operator/person.
Everything below is inherited from frontier, not yet re-run by this mind.

## Target

Brotli decoder block-switch over-write, CVE-2026-111497 / GHSA-9v8h-qqgm-4m35,
CVSS 4.0 9.2 Critical, `PR:N`, network claim via crafted Brotli stream. Core
`google/brotli` C library 1.0.3–1.2.0; fixed 1.0.10 / 1.1.1 / 1.2.1. Fix
`0ed4268`. Unowned by another target mind (node2shell is only the Alt-Svc bug).

## Inherited, not yet re-run by this mind

- Rung 1 PASS: pinned two-stage stream from a public PoC generator, local
  files only. Digests and versions in `reports/frontier-brotli2shell.md`.
- Rung 2 PASS: vulnerable v1.2.0 stage 1 spins 200000 `NEEDS_MORE_INPUT`
  calls with zero output; stage 2 SIGSEGV (rc 139). Fixed v1.2.1 rejects both
  stages with `ERROR -17`, rc 0.
- Rung 3 PASS: instrumented v1.2.0 logs 20 attacker-chosen bytes written past
  the 8-byte `s->buffer.u8` at indices 8..27, setting `pos`,
  `max_backward_distance` and `max_distance` to `0x7fffffff`, then SIGSEGV on
  the unmodified build. ASan blind because the write is intra-allocation.
- Rung 4 NOT demonstrated: state control observed; no pointer control, marker
  execution, or control-flow hijack. Public RCE and reachability claims are
  claims, not lab facts. Counterclaim `ikow/brotli2crash` says RCE is
  structurally unreachable — preserved, not resolved.

## Open

- Extend stage 2 through indices 28+ toward the pointer fields and attempt a
  controlled read/write. Preserve the fixed `-17` differential and negatives.
- Reproduce with `bash lab/frontier/brotli2shell/run.sh`; no off-loopback probe.
- Evidence: `reports/frontier-brotli2shell.md` (commits `fb821a2`, `02d34fa`).
