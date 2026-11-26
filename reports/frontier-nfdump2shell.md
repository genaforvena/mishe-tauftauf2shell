# Frontier brief: nfdump nfcapd truncated EXgenericFlow heap write — GHSA-gpgq-hv9x-7mqj

Status: **STAGED 2026-11-25 by frontier W234**, awaiting operator admission
and witness replay. Rung 3 pinned verbatim function; rung 4 PARTIAL (a
harness-chosen 64-bit value written at an attacker-chosen offset past a
truncated extension). No adjacent-object target, pointer control, socket,
command execution or rung 5. Witness W235 verdict (2026-11-25): ESTABLISHED
AS LABELED, no contradiction, no grade change; live `nfcapd` loopback
reachability stays UNKNOWN. See `reports/nfdump2shell-status.md`.

## Claim and scope

- The identifier `GHSA-gpgq-hv9x-7mqj` comes from this plant's scout/wall.
  Both `https://github.com/advisories/GHSA-gpgq-hv9x-7mqj` and
  `https://api.github.com/advisories/GHSA-gpgq-hv9x-7mqj` returned HTTP 404
  on 2026-11-25; **no CVE id or CVSS is claimed**. The verified ground truth
  is the upstream fix commit and its diff.
- Project: `phaag/nfdump`, `nfcapd` data path `src/netflow/nfd_raw.c`,
  `Process_nfd()`; verification gate `src/libnffile/nfxV3.c`,
  `VerifyV3Record()`. Fix commit
  `32b9cbe7f17e099d59fc5eac71c84c6c6f051fa5` (2026-11-25 13:26 +0100,
  "Security patch: nfdump nfcapd heap out-of-bounds write in Process_nfd
  via truncated EXgenericFlow extension / Additional code hardening"),
  parent `8a00543aa5c7b25b7d3f7642fdf306fd9979f237`. No tagged fixed
  release was found; the pin is the commit pair.
- Claimed primitive: a network-facing packet record whose EXgenericFlow
  element is shorter than the fixed struct size passes record verification
  and reaches the `msecReceived` store. The network boundary is a claim from
  the advisory identifier and the code path; no live socket is exercised in
  this staged evidence.

## Pins and source-bound mechanism

- Vulnerable pin: parent `8a00543a`; fixed pin: `32b9cbe7`. Verbatim
  functions and SHA-256 manifest are in `lab/frontier/nfdump2shell/pins/`
  and `PROVENANCE.md`.
- Vulnerable `VerifyV3Record()` checks only `length > rlen`, `type <
  MAXEXTENSIONS` and that the elements consume the record exactly. It never
  checks `length >= extensionTable[type].size`. A 20-byte element of type
  `EXgenericFlowID` (4-byte element header + 16 bytes of `msecFirst`/
  `msecLast`) therefore verifies as a complete 32-byte V3 record.
- Vulnerable `GetExtension()` returns `elementHeader + sizeof(elementHeader_t)`
  for that element. Back in `Process_nfd()`, after the record is copied and
  an EXipReceived extension is appended to the copy, the store
  `genericFlow->msecReceived = msecReceived` writes 8 bytes at payload
  offset 16 — exactly 0..8 bytes past the declared element and record.
- The fix adds `length < sizeof(elementHeader_t)` and
  `length < extensionTable[type].size` checks to `VerifyV3Record()`, tightens
  `MapRecordHandle()` bounds, and replaces `GetExtension()` with a single
  `ScanExtensions()` pass over the verified copy. The short element is
  rejected before any store.
- `EXgenericFlowSize` is 52, `offsetof(msecReceived)` is 16, the record
  header is 12 bytes and `nfd_header_t` is 16 bytes (measured in the
  pinned header build). The attack packet is 48 bytes.

## Local evidence

`bash lab/frontier/nfdump2shell/run-all.sh`: **10 PASS / 0 FAIL**.

- GCC ASan: `heap-buffer-overflow`, `WRITE of size 8`, 0 bytes after a
  48-byte region, stack `#0 Process_nfd (process-parent.inc:121)`
  `#1 main (driver.c:214)`. Clang ASan reports the same write.
- Fixed ASan build: `Process_nfd: Corrupt nfd record: expected 1 records,
  processd: 0`, no ASan report.
- Full 52-byte EXgenericFlow and no-element records are clean in both
  vulnerable and fixed builds.
- Plain vulnerable build with a 16-byte trailing canary region:
  `EXPECTED_BYTES=9b50351f49010000`, `CANARY_AFTER=9b50351f49010000` —
  the harness-chosen `msecReceived` (from `fs.received`,
  `tv_sec=0x54415554`, `tv_usec=123000`) landed at element end. The fixed
  plain build leaves the canary at `5a5a5a5a5a5a5a5a`.
- Harness copies the pinned headers, both `VerifyV3Record()` bodies, and
  both `Process_nfd()`/`GetExtension()`/`ScanExtensions()` bodies verbatim;
  exporter/cache/output-block/stat helpers are stand-ins. No full daemon is
  built. Exact hashes and raw logs are in `PROVENANCE.md`.

### Receive-buffer shape (W281)

`harness/adjacent.c` + `run-adjacent.sh` drive the same verbatim pins on a
two-record datagram held in a 64 KiB buffer — the real caller shape. The
truncated-element store at `STORE_OFF=48` is exactly the next record's
header (`R2_OFF=48`): `R2_HDR_BEFORE=0b00400001000000` becomes
`R2_HDR_AFTER=9b50351f49010000` (`type=20635, size=7989, numElements=329`)
and pinned `Process_nfd()` drops the second record. Safe input and the fixed
build leave the header intact. `MODE=icmp` shows the pinned ICMP swap
writing packet-chosen bytes past the element (`P2_BYTES_BEFORE=dead5a5a...`
→ `P2_BYTES_AFTER=0000adde...`). `run-adjacent.sh`: 12 PASS / 0 FAIL.
ASan does not fire in this shape: the store stays inside the buffer, so the
48-byte-allocation ASan report and the live-header corruption are two
views of the same store, neither a wire input nor a command. See
`lab/frontier/nfdump2shell/PROVENANCE.md`.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE of size 8 in the
  verbatim pinned `Process_nfd()` path, with fixed and safe-input controls.
- **Rung 4 PARTIAL:** the element length (hence the write offset) is
  packet-controlled and the written 64-bit value is chosen in the harness;
  it is observed in the trailing canary region of a live plain process.
  The value is collector-time-derived, not attacker-chosen, and no adjacent
  object or pointer is targeted.
- **Not rung 5:** no live `nfcapd` process, no loopback socket, no attacker
  control of the written value, no pointer hijack, no benign command or
  observed side effect.

Cheapest next experiment: build the pinned `nfcapd` receive path on
loopback, send the 48-byte packet to the listening collector and check
whether the 8-byte write lands in a live heap object; measure what field
`msecReceived` overlaps and whether the ICMP `srcPort`/`dstPort` swap in the
same pin yields file-chosen bytes past a shorter element. Only then consider
pointer-bearing adjacency. Preserve the no-wire/no-command ceiling until
measured.

## Duplicate check

`reports/frontier-*.md` and the wall's do-not-duplicate list were checked
before provisioning; the only prior nfdump mention is the W233 FCEUX brief
proposing this candidate. No nfdump lab, window or admitted target exists.
