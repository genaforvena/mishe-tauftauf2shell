# iondtn2shell — status

Admitted 2026-11-21 ~05:28Z by the operator under standing approval #6 on
frontier's `fefc2b7` / `de67924` handoff (brief
`reports/frontier-iondtn2shell.md`). Advisories: GHSA-gmhw-vmwr-wrxh
(maintainer, 2026-11-07, High 7.5
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) and CVE-2026-123999 / VulnCheck
(CVSS v4 8.7, also availability-only). The GHSA "No known CVE" vs VulnCheck
CVE assignment conflict is preserved as a claim. Affected `3.6.2 <= 4.2.0`,
patched `4.2.1-a.2`. Claim: unbounded `strcat` of rendered AMP values past a
1024-byte heap allocation in `ui_str_from_ac()`. Gate: the remote path needs
non-default `-l -r` logging; otherwise only local UI rendering is claimed.
Brief: [frontier-iondtn2shell.md](frontier-iondtn2shell.md). Pins and raw
URLs: `lab/frontier/iondtn2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/iondtn2shell/run.sh <outdir>` — brief records
  26 PASS, `ALL CHECKS PASSED rc 0`, trace SHA-256
  `e9bc1ffffb7ba2bc39b5c3c26cf29a4c1cf0f8f96160a92cc979326f29d38f71`.
- Operator replay ~05:26Z from a clean `git archive HEAD` extraction of
  `d4267283` into two separate absolute output directories: `ALL CHECKS
  PASSED rc 0` in both, canonical trace
  `sha256=e9bc1ffffb7ba2bc39b5c3c26cf29a4c1cf0f8f96160a92cc979326f29d38f71`
  — byte-identical to the brief (the harness printed 27 `PASS` lines including
  `PINNED_SOURCE_BYTES`).
- Rungs 1/2/3 on byte-exact pinned upstream `nm/mgr/nm_mgr_print.c:548-563`
  from release 4.2.0 (`568df887cb9f18aa8ec013b1a566d83215e499ae`, sha256
  `31b9673c…`) and fix 4.2.1-a.2 (`54d4b1f0b647e0cb7dfc558651777a042acf5e38`,
  sha256 `c2abf2d0…`): 18 rendered values of 80 bytes write 1458 bytes into a
  1024-byte `STAKE` region (`overflow=434`); the first byte past the
  allocation changes; ASan reports `heap-buffer-overflow`, `WRITE of size 81`,
  frame `ui_str_from_ac` at pinned line 557. Fix `4b158b6` uses
  `istrlen()`/`istrcat()` capacity checks and returns NULL before overflowing.
- Rung 4 INSTRUMENTED only: token `ION2SHL!` (`494f4e3253484c21`) read back
  byte-exact at chosen write offsets 1024/1088/1152/1280/1408; patched build
  returns NULL (`puterr=1`), leaves the neighbour unchanged and never reaches
  the token (`FIXED_NO_WRITE`). Chosen-byte control is in the harness
  allocator's adjacent region — scaffolding, not target behaviour.
- UNKNOWN: live `nm_mgr`, loopback UDP CLA/AMP reachability, `-l -r` path,
  AMP wire bytes, interactive UI, real heap adjacency, useful-pointer control
  and execution. No security impact beyond the claimed availability crash is
  demonstrated.

Cheapest next rung: build 4.2.0 `nm_mgr` under ASan, start it loopback-only
with `-l -r`, send a deeply nested AMP report whose rendered value list
exceeds 1 KiB, capture the real ASan frame at pinned line 557 and the wire
bytes that produced it; then measure what the real allocator places after the
1024-byte region and whether a useful pointer is reachable.
