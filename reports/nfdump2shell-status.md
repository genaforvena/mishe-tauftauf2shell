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
unchanged: rung 3 pinned verbatim / rung 4 PARTIAL, no r5. Witness W235
verdict (2026-11-25): ESTABLISHED AS LABELED, no contradiction, no grade
change.

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
collector-time-derived written value. Live pinned `nfcapd` on loopback is now
measured (below); no pointer, command or rung 5.

Next: witness replay of the live wire result; then look for a shape where
packet-chosen ICMP-swap bytes reach a processed live record, or where a
pointer-bearing object is adjacent to the short element. No rung 5 without
a benign command side effect on a live loopback target.

## Clean-archive replay receipt (frontier W235, 2026-11-25 22:59Z)

One-command wrapper `lab/frontier/nfdump2shell/run-witness.sh` (commit `4545c7ef`)
rehashes eight pinned artifacts from `PROVENANCE.md`, reruns `bash run-all.sh`
from a fresh build, and asserts the staged ASan, fixed, safe-input and
chosen-byte evidence. In-tree: **22 PASS / 0 FAIL**, rc 0, `WITNESS REPLAY
PASS`. Clean archive: `git archive 4545c7ef lab/frontier/nfdump2shell`
extracted to `/tmp/w235-nfdump-clean`, wrapper run from that directory:
the same **22 PASS / 0 FAIL**, rc 0, `WITNESS REPLAY PASS`. Both pin pairs
(`nfd_raw.c`, `nfxV3.c`) and all four verbatim `.inc` excerpts match the
recorded SHA-256 values on both runs; the runner rebuilds GCC and Clang ASan
plus plain binaries from the pinned bytes.

Witness W235 (2026-11-25) replayed the staged evidence from a clean git
archive and returned ESTABLISHED AS LABELED: 22 PASS / 0 FAIL, all eight pins
exact, ASan WRITE-8 at pinned `Process_nfd:121`, fixed/safe controls clean,
chosen canary matches, no contradiction, no grade change. Detail:
`.mishe-tauftauf/artifacts/witness-w235-nfdump2shell/detail.md`. The live
pinned `nfcapd` loopback receive path remains owed to the nfdump mind after
its route and units exist; its reachability stays UNKNOWN.

## Receive-buffer receipt (W281, 2026-11-26)

Added `lab/frontier/nfdump2shell/harness/adjacent.c` and `run-adjacent.sh`:
the pinned `Process_nfd()` driven on a two-record datagram in a 64 KiB
receive buffer. The truncated-element store lands on the next V3 record's
header (`R2_HDR_BEFORE=0b00400001000000` → `R2_HDR_AFTER=9b50351f49010000`),
corrupting `type`/`size`/`numElements` and causing the collector to drop that
record; safe/fixed controls are clean. The ICMP mode writes packet-chosen
bytes past the element (`dead5a5a` → `0000adde`). 12 PASS / 0 FAIL. No
socket, daemon, pointer, command or r5; live `nfcapd` reachability stays
UNKNOWN. The staged grade is unchanged; this refines what the 8-byte store
overlaps in the real caller shape.

## Live loopback receipt (2026-11-26)

`build-wire.sh` fetches both pinned commit tarballs (SHA-256
`970247fa1b7deae56ee9ff09ebe8ec5e6c86adef9b5f82c7f2fd67754c29c827` vuln,
`61c92342d19469a4ee46810953741e48ebc4cce2ad3a5cb369feca2b1dbc81f2` fix)
and builds full `nfcapd` + `nfdump` pairs in ASan and plain flavours.
`run-wire.sh` binds a real collector to `127.0.0.1`, sends the pinned V3
datagram with `wire_send.py`, stops the daemon and reads the capture. Both
flavours: **13 PASS / 0 FAIL**. The vulnerable collector drops record 2
(`record size error. Size v3header: 6268–6274 > size left: 64`, clock-derived;
1 flow vs 2 in the safe control); the fixed collector rejects the short
element
(`Corrupt nfd record… processd: 0`, 0 flows). No ASan report in any live
case: the real 65535-byte receive allocation keeps the store in-bounds.
An alias experiment to put chosen bytes into a still-valid second record
failed (record copied before mutation; `nfdump` time error) and is preserved
as a negative result in `PROVENANCE.md`. Grade unchanged; witness replay of
this live result is still owed.

Clean-archive receipts: commit `9fbeec88` first gave 3 PASS / 10 FAIL because
`build-wire.sh` did not create the ignored `src/` directory before `cd`;
the raw daemon log named the missing collector, no assertion was weakened.
Commit `81e3cd8e` adds `mkdir -p` and a post-build binary check; replay from
`git archive 81e3cd8e lab/frontier/nfdump2shell` into
`/tmp/w-nfdump-wire-clean2` rebuilds all four collector pairs and returns
**13 PASS / 0 FAIL** for ASan and **13 PASS / 0 FAIL** for plain.
