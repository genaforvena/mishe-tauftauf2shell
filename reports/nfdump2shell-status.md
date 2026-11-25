# nfdump2shell — admitted status (2026-11-25 21:4xZ)

**ADMITTED by operator at 21:4xZ under standing #6 as the 152nd declared
target mind.** Staging evidence from frontier W234 is preserved below. The
live two-pane window 160 (created 21:26Z, panes `%322`/`%323`) was adopted, not
duplicated. The hy4-flash route, resolver keys and generated wake units were
NOT added: `.mishe-tauftauf/operator/standing-approvals.md:47-51` reserves
engine-config changes, systemd units and the full-flag sync to the person.
`check-omp-only.py` stays RED for `nfdump2shell: no route` (153 declared roles)
and the 21:29/21:34Z doctor runs list twelve missing unit files. The
`failed-m2shell-doctor-service` RED was dispositioned to the person and
re-observed GREEN at 21:42Z on that basis, not because the units exist. Grade
unchanged: rung 3 pinned verbatim / rung 4 PARTIAL, no r5, witness UNKNOWN.

Brief: reports/frontier-nfdump2shell.md
Evidence: lab/frontier/nfdump2shell/PROVENANCE.md

Claim: `GHSA-gpgq-hv9x-7mqj` (public GHSA endpoint returned HTTP 404; no
CVE/CVSS claimed). Upstream fix commit
`32b9cbe7f17e099d59fc5eac71c84c6c6f051fa5`, parent
`8a00543aa5c7b25b7d3f7642fdf306fd9979f237`. A V3 record with a truncated
EXgenericFlow element passes `VerifyV3Record()` and reaches the
`genericFlow->msecReceived = msecReceived` store past the element.

Local result: pinned verbatim `VerifyV3Record()`, `GetExtension()`/
`ScanExtensions()` and `Process_nfd()`; GCC+Clang ASan heap `WRITE of size
8`, 0 bytes after a 48-byte region. Fixed build rejects the short element;
safe-full and no-element inputs clean in both builds. Plain build:
`EXPECTED_BYTES=9b50351f49010000`, `CANARY_AFTER=9b50351f49010000`.
run-all.sh: 10 PASS / 0 FAIL.

Grade: rung 3 pinned verbatim / rung 4 PARTIAL packet-chosen offset with
harness-chosen written value. No adjacent object, pointer, wire, command or
rung 5.

Next: the person runs the exact full-flag sync from `docs/runtime-pin.md`, then
the witness replays the labeled grade; after activation, build the pinned
`nfcapd` loopback receive path and test the live heap neighborhood plus the
ICMP `srcPort`/`dstPort` file-chosen byte path.
