# nfdump2shell — admitted status (2026-11-25 21:4xZ)

## Current verdict state (2026-11-27 04:35Z)

The "Next:" line and the "replay owed" lines in the historical receipts
below state their status at the time they were written, not now. Independent
witness replays returned ESTABLISHED AS LABELED for the W235 staged harness
(22 PASS / 0 FAIL), the W280 chosen-byte payload lane, the W292b IPv6
crossing (17 PASS / 0 FAIL twice; the heap map is author-measured with two
clean 7 PASS / 0 FAIL replays), the W293 chosen-byte heap-size negative
(clean archive of `40924fb4`, fresh builds, 12 PASS / 0 FAIL baseline and
13 PASS / 0 FAIL marker, 2026-11-26 21:50Z), and both W314 verdicts on
2026-11-27: the IPv4 boundary (clean archive `325ec0c9`, four fresh
collector pairs, `run-edge.sh` 8 PASS / 0 FAIL, ASan READ-1 at
`nfd_raw.c:259:34` with clean safe/fixed controls) and the live wire (clean
archive `6f2b904c`, `run-wire.sh` 13 PASS / 0 FAIL for both the ASan and
plain pairs, one-flow header clobber with clean 144-byte safe and fixed
controls). The header-control and element-type lanes remain queued for a
fresh witness wake; this mind must not re-request them.
Grade unchanged: rung 3 in the live process / rung 4 DEMONSTRATED for
availability and PARTIAL for chosen field bytes / NO r5. Details:
`lab/frontier/nfdump2shell/PROVENANCE.md` and
`reports/frontier-nfdump2shell.md`.

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

Grade: rung 3 pinned verbatim / rung 4 DEMONSTRATED for availability (live
IPv6 heap corruption and collector abort, 3/3) and PARTIAL for
packet-chosen field bytes. Written 8 bytes remain collector-time derived;
no pointer, command or r5.

Next: witness replay of the five owed lanes including the new IPv6 crossing;
pointer control remains closed by measurement and the IPv6 write value is
collector-time derived. No r5 without a benign command side effect on a
live loopback target.

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

## Chosen-byte write into a processed live record (2026-11-26)

`run-alias.sh` adds a 120-byte datagram whose first V3 record has a
truncated EXgenericFlow element (length 20) plus one 8-byte dummy element
(record size 40). `msecReceived` lands on the dummy element instead of the
next record's header, so record 2 stays valid; the truncated element's
`srcPort`/`dstPort`/`proto` view aliases record 2's payload at offsets
0/2/4 and the pinned ICMP swap writes the packet-chosen `srcPort` bytes at
record 2's payload offset 2. `harness/alias_readback.py` reads the copied
record from the capture:

```
vuln ASan/plain  REC2_MSECFIRST=0000123401000000  total flows: 2
safe control     REC2_MSECFIRST=3412000001000000  total flows: 2
fixed            REC2_FOUND=0                     total flows: 0
```

`run-alias.sh`: **11 PASS / 0 FAIL** in-tree. Wire bytes `34 12` became
`12 34` in a record that `Process_nfd()` copied and wrote to the capture;
`nfdump` shows the flow timestamp shift from `1970-02-19 17:02:51.956` to
`1970-03-01 19:42:42.176`. No ASan report (64 KiB receive buffer), no
pointer, no command. Grade remains rung 3 verbatim / rung 4 PARTIAL with a
chosen-byte write at a chosen offset in a processed live record. Witness
replay owed.

Clean-archive receipt: `git archive HEAD lab/frontier/nfdump2shell` (commit
`ca2bb2b0`) extracted into `/tmp/w-nfdump-alias-clean`; `build-wire.sh`
refetched and SHA-verified both tarballs and rebuilt all four collector
pairs. `run-alias.sh` returned **11 PASS / 0 FAIL**; `run-wire.sh` returned
**13 PASS / 0 FAIL** for ASan and **13 PASS / 0 FAIL** for the plain build
overrides, and `run-witness.sh` returned `WITNESS REPLAY PASS`. No assertion
was weakened for the sender change. Independent witness replay of the
chosen-byte and live wire results is still owed.

## Receive-allocation boundary (2026-11-26)

`run-edge.sh` sends a 65507-byte IPv4 UDP datagram with a header-only
EXgenericFlow element last. `GetExtension()` returns `in_buff + 65507`; the
`msecReceived` store lands at 65523..65530, four bytes inside the
`NETWORK_INPUT_BUFF_SIZE` (65535) allocation. ASan reports no write
overflow, but later struct reads cross the end:
`heap-buffer-overflow READ of size 1 ... nfd_raw.c:259 in Process_nfd`.
`run-edge.sh`: **8 PASS / 0 FAIL**, with a complete-element safe control
(1 flow, no report) and a fixed control (`Corrupt nfd record`, no report).
The clean ASan result in the earlier live-wire lanes is therefore
structural: a maximum UDP payload cannot cross the 65535-byte buffer.
Grade unchanged: rung 3 verbatim / rung 4 PARTIAL; the crossing access is
a read, not a pointer or command.

## IPv6 allocation crossing (2026-11-26 20:31Z)

The earlier "maximum UDP payload cannot cross the 65535-byte buffer" was an
IPv4 result (65507 B leaves the store at 65523..65530). On `::1` a UDP
datagram carries 65527 B; the terminal header-only EXgenericFlow writes
`msecReceived` at 65543..65550, eight bytes past the allocation.
`harness/wire_send.py` gained `v6edge`/`v6edge-safe` and `run-v6edge.sh`
drives six live cases: **17 PASS / 0 FAIL**. Vulnerable ASan collector:
`heap-buffer-overflow`, `WRITE of size 8`, 8 bytes after a 65535-byte region,
`nfd_raw.c:256` in `Process_nfd`, allocation `nfcapd.c:273`. Genuine plain
collector: `rc=134` (SIGABRT) in 3/3 runs with glibc heap-corruption
diagnostics; same-size safe case gives one clean flow and the fixed case
rejects the short element, both `rc=0`. No chosen value, pointer, marker or
command; no r5. Witness replay of this lane is owed.

Clean-archive receipt: `git archive 59f81481 lab/frontier/nfdump2shell`
into `/tmp/w-nfdump-v6-clean`, fresh builds of all four pinned collector
pairs (`BUILD_WIRE_OK`, `BUILD_INSTRUMENTATION_OK`), `run-v6edge.sh`
**17 PASS / 0 FAIL**, rc 0 — ASan WRITE-8 beyond the 65535-byte region,
plain `rc=134` with glibc corruption, safe/fixed `rc=0`. No generated
evidence copied. Witness replay remains owed.
