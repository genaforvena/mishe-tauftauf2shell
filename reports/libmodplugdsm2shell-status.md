# libmodplugdsm2shell — admitted status (195th, 2026-11-27)

Staged by frontier from CVE-2026-111270 / GHSA-rxvf-jg5h-5fv5 (CWE-787, CVSS
6.9 v4.0, affected `0` through `0.8.9.1`). Vulnerable source commit
`d1b97ed0020bc620a059d3675d1854b40bd2608d` (no affected release tag found);
fixed `v0.8.9.2` commit `a52647673746f5ba944bf3cc09be8ccb51cc9db5`; fix
`b824d9b32a1aa8b9145bbd53cbb73179ccc95acd`. The two-pane window 203 is live on
the inner socket and registered as one of 204 unique window names.

`ReadDSM()` writes `PatternSize[nPat]` at raw `load_dsm.cpp:138` and
`Patterns[nPat]` at `:139` without checking `MAX_PATTERNS` (240). A 241-chunk
DSM file makes clang UBSan report `index 240 out of bounds` for `WORD[240]` and
`MODCOMMAND *[240]` at those raw lines; the plain vulnerable build changes
adjacent `Order[0..1]` from `ff ff` to `40 00`. Fixed pin and 240-chunk controls
are clean under both sanitizer and plain builds.

Registered grade at handoff: **R1 — / R2 ✓ / R3 ✓ / R4 — / R5 —**.
R3 is UBSan array-bounds plus a state differential, NOT an ASan redzone report:
ASan with field padding did not detect the intra-object write (negative
preserved). R4 is not claimed: overwritten bytes are allocator-derived pointer
bytes, with no chosen-offset readback, consumer, pointer dereference or command.
No DSM wire path, daemon, remote input or side effect was exercised.

`sh build-all.sh && sh run-all.sh`: PASS=11 FAIL=0, rc 0. Runner SHA-256
`508c6dd08eb7d736a546cd886b1335913cd42d2e7757349385850ecb6bfcddb4`. ADMITTED
01:2xZ under standing #6 as the 195th declared target mind; staged two-pane
window 203 adopted as-is (panes %412/%413, dead=0, one registry entry, 204/204
unique names, no duplicate CVE/GHSA or sink lane).

Clean-archive replay from commit `8b3db561` (runs/, source checkouts, build
directories and binaries removed): runner sha matched, `sh build-all.sh` rc 0
`BUILD_OK`, unmodified `sh run-all.sh` rc 0 PASS=11 FAIL=0. Frontier's own clean
replay from `b5f5e260` is recorded in the commit history; the operator and W302
each replayed the `8b3db561` archive independently.
Witness W302 (`.mishe-tauftauf/artifacts/witness-w302-libmodplug/detail.md`)
ESTABLISHED AS LABELED, no grade change and NO r5: 2/2 tarball pins and 2/2
sink pins OK, five fresh plain vulnerable runs identical, fixed and 240-chunk
controls clean, ASan field-padding intra-object negative confirmed. No
chosen-byte readback, pointer control, wire/request path or command.
R4 stays NOT CLAIMED; the charter's next #7 experiment is a real local
libmodplug consumer with attacker-influenced allocations and a chosen-byte
readback, still on loopback only.
Brief: `reports/frontier-libmodplugdsm2shell.md`. Harness provenance:
`lab/frontier/libmodplugdsm2shell/PROVENANCE.md`.
