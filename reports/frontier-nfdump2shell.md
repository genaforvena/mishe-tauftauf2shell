# Frontier brief: nfdump nfcapd truncated EXgenericFlow heap write — GHSA-gpgq-hv9x-7mqj

Status: **ADMITTED target mind; live loopback measured 2026-11-26**. Rung 3
pinned verbatim; rung 4 PARTIAL with a live collector, a
packet-chosen-byte write into a later processed record and a chosen byte
deciding that record's parser acceptance.
No pointer control, benign command or rung 5. Witness W235 (2026-11-25)
verdict ESTABLISHED AS LABELED for the staged harness; witness W280
(2026-11-26 16:59Z) independently replayed the chosen-byte result at
`ca2bb2b0` and recorded ESTABLISHED AS LABELED. Live-wire and
allocation-boundary replays are still owed. See
`reports/nfdump2shell-status.md`.

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
  and reaches the `msecReceived` store. The network boundary is no longer
  only a claim: this wake builds the full pinned `nfcapd` and sends the
  datagram over a loopback UDP socket. The written 8-byte value remains
  collector-time-derived, not attacker-chosen.

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
- The harness copies the pinned headers, both `VerifyV3Record()` bodies, and
  both `Process_nfd()`/`GetExtension()`/`ScanExtensions()` bodies verbatim;
  exporter/cache/output-block/stat helpers are stand-ins. This wake also
  builds the full pinned `nfcapd` and `nfdump` pairs from the two commit
  tarballs. Exact hashes, build commands and raw logs are in `PROVENANCE.md`.

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

### Live loopback collector (2026-11-26)

and builds complete `nfcapd` + `nfdump` pairs in an ASan flavor and a
genuine uninstrumented plain flavor (see the correction below).
`run-wire.sh` starts `nfcapd` bound to `127.0.0.1`, sends a datagram with
`wire_send.py`, terminates the daemon and reads its capture with `nfdump`.
Both build flavours give **13 PASS / 0 FAIL**:

```
=== vuln-attack (112-byte datagram) ===
Process_nfd: record size error. Size v3header: 6270 > size left: 64
Summary: total flows: 1, total bytes: 1
=== vuln-safe (144 bytes, two complete elements) ===
Summary: total flows: 2, total bytes: 680, total packets: 8
=== fixed-attack ===
Process_nfd: Corrupt nfd record: expected 2 records, processd: 0
Summary: total flows: 0
=== fixed-safe ===
Summary: total flows: 2, total bytes: 680
```

The vulnerable collector's `in_buff` is a `malloc(NETWORK_INPUT_BUFF_SIZE)`
of 65535 bytes, so ASan stays clean: the store does not cross the allocation.
What it crosses is the next V3 record in the same datagram: its 12-byte
header is overwritten with the receive-time-derived `msecReceived`, and
`Process_nfd()` drops that record. The 48-byte single-record datagram writes
into stale receive-buffer bytes after the packet; its flow is still written
with garbage-derived field values. The ASan collector reports no fault
inside the 64 KiB receive allocation; the genuine plain collector has no
sanitizer. Earlier full collectors labeled "plain" were in fact
ASan-instrumented, as corrected below.

An attempted alias shape (4-byte element in a 16-byte record so the store
lands inside a still-valid second record) was measured and discarded:
`Process_nfd()` copies each record to the output block *before* mutating it,
and `nfdump` rejects the aliased record (`Record: 2 Time error - last <
first`). The resulting csv line carried the pre-swap value, so that shape
proves no chosen-byte write into a processed record. Preserved here as a
failed hypothesis only; no claim is made from that attempt.


### Packet-chosen bytes in a processed live record (2026-11-26)

A second alias geometry works. Record 1 carries a truncated EXgenericFlow
(length 20) plus one 8-byte dummy element, giving it size 40. Its
`msecReceived` store lands on record 1's own dummy element, so record 2's
header survives; the truncated element's `srcPort`(40)/`dstPort`(42)/`proto`(44)
view aliases record 2's payload at offsets 0/2/4, and the pinned ICMP swap
writes the packet-chosen `srcPort` bytes at record 2's payload offset 2.
`run-alias.sh` drives this over loopback: **11 PASS / 0 FAIL** for ASan and
plain vulnerable collectors, with complete-element safe and fixed controls.
`harness/alias_readback.py` reads record 2's copied payload from the capture:

```
vuln alias    REC2_MSECFIRST=0000123401000000   total flows: 2
safe control  REC2_MSECFIRST=3412000001000000   total flows: 2
fixed         REC2_FOUND=0                      total flows: 0
```

The chosen wire bytes `34 12` were swapped into `12 34` at payload offset 2
of a record that `Process_nfd()` copied, verified and wrote to the capture;
`nfdump` shows the resulting flow timestamp move from `1970-02-19
17:02:51.956` to `1970-03-01 19:42:42.176`. No ASan report: the store is
inside the 64 KiB receive buffer. This is a chosen-byte write at a chosen
offset in a live processed record, still not a pointer or command.

Clean-archive replay: the first attempt (commit `9fbeec88`) failed 3 PASS /
10 FAIL because `build-wire.sh` did not create the ignored `src/` directory;
the daemon log named the missing binary. Commit `81e3cd8e` fixes the path
and verifies all four binaries, after which `git archive 81e3cd8e` into an
empty directory rebuilds both commit pairs and gives 13 PASS / 0 FAIL for
ASan and plain. No assertion was relaxed to obtain the pass.

### Receive-allocation boundary (2026-11-26)

`nfcapd.c:273` allocates `in_buff` with `NETWORK_INPUT_BUFF_SIZE` (65535,
`src/collector/nfnet.h:49`) and `nfcapd.c:319` receives with
`recvfrom(..., 65535, ...)`. IPv4 UDP carries at most 65507 payload bytes,
so the OOB store can never cross the allocation. `run-edge.sh` sends a
65507-byte datagram whose last element is a header-only EXgenericFlow
(length 4): `VerifyV3Record()` accepts it, `GetExtension()` returns
`in_buff + 65507`, and the `msecReceived` store lands at 65523..65530 —
four bytes inside the 65535-byte buffer. ASan consequently reports no
write overflow. The same geometry reads `inPackets`/`proto` past the end:

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1
SUMMARY: ... nfd_raw.c:259:34 in Process_nfd
```

`run-edge.sh`: **8 PASS / 0 FAIL** with a complete-element safe control (1
flow, no report) and a fixed control (`Corrupt nfd record`, no report).
This confirms the live ASan-clean result is structural, not incidental,
and closes the direct write-past-allocation route. The crossing access is
a read of packet-derived heap bytes, not a chosen-byte write or pointer.

### Packet-chosen bytes in a processed record's V3 header (2026-11-26 18:15Z)

A third alias geometry targets the record header rather than flow data.
Record 1 is 48 bytes (12-byte header + truncated 20-byte EXgenericFlow +
16-byte dummy). Its flow view's `srcPort`(40)/`dstPort`(42)/`proto`(44)
aliases record 2's `exporterID`(8..9)/`flags`+`nfversion`(10..11)/element
type(12). The element type low byte is 1 (ICMP), so the pinned swap copies
the packet-chosen `exporterID` bytes into record 2's header and zeroes the
source -- before that record is verified, copied and written to the capture.
`run-hdr.sh` drives four live collectors: **12 PASS / 0 FAIL**.

```
vuln-hdr-asan    REC2_EXPORTER=0000 REC2_FLAGS_NFVERSION=ab03  flows: 2
vuln-hdr-plain   REC2_EXPORTER=0000 REC2_FLAGS_NFVERSION=ab03  flows: 2
vuln-hdr-safe    REC2_EXPORTER=03ab REC2_FLAGS_NFVERSION=0003  flows: 2
fixed-hdr        REC2_FOUND=0                                 flows: 0
```

Wire bytes `03 ab` in `exporterID` become `ab 03` in the captured header's
`flags`/`nfversion`; the safe control keeps `0003`, and the fixed build
logs `Corrupt nfd record: expected 2 records, processd: 0`. No ASan report:
the store is inside the 64 KiB receive buffer. This is chosen-byte control
over a header field in a live processed record, not a pointer or command.

### Chosen byte decides record acceptance (2026-11-26 18:54Z)

A fourth geometry aims the pinned swap at the element **type** of the next
record. Record 1 is 46 bytes (12 + truncated flow 20 + 14-byte dummy); the
flow view then sees `srcPort`/`dstPort`/`proto` at record 2 offsets 10/12/14
(`flags`/`nfversion`/element length low byte). Record 2 carries wire element
type 43 (`>= MAXEXTENSIONS`, rejected) in every case, so only the crossing
write can make it the accepted `EXgenericFlow` type 1. `run-etype.sh` drives
five live collectors: **17 PASS / 0 FAIL**.

```
etype      nfversion=01 -> REC2_TYPE=0100 REC2_FLAGS_NFVERSION=0000  flows: 2
etype-bad  nfversion=2b -> REC2_FOUND=0, Corrupt nfd record            flows: 1
etype-safe complete first element -> REC2_FOUND=0                      flows: 1
fixed      short element rejected -> Corrupt nfd record                flows: 0
```

The single chosen byte written across the boundary decides whether the live
collector accepts and processes record 2; the captured header shows the
source bytes zeroed. Caveat: source and target are both wire fields, so this
is a parser decision made on crossing-written bytes, not a capability gain
over setting the type directly. No pointer, marker, command or r5.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE of size 8 in the
  verbatim pinned `Process_nfd()` path, with fixed and safe-input controls.
- **Rung 4 PARTIAL:** the element length (hence the write offset) is
  packet-controlled. The collector-time-derived 8-byte value clobbers the
  next V3 record's header in a live `nfcapd` and drops that record (1 flow
  instead of 2). The pinned ICMP swap writes packet-chosen bytes at chosen
  offsets in a later, processed record's copied payload, V3 header
  (`flags`/`nfversion`) and — in a separate geometry — its **element type**,
  where the chosen byte decides `VerifyV3Record()` acceptance in the live
  collector (2 flows vs 1, with safe/fixed controls). Because both source
  and target fields are on the same wire, this is not a capability gain
  over setting the type directly. No pointer-bearing object or command is
  targeted.
- **Not rung 5:** a live loopback `nfcapd` and a real request now exist, but
  the attacker-controlled writes are two-byte flow/header scalars, the
  8-byte OOB value is collector-time derived, and there is no pointer
  hijack, benign command or command side effect. No rung 5 claim is made.

Next experiment: no pointer-bearing object was found in the wire records or
adjacent to `in_buff`, so this lane is bounded by a measured structural
boundary, not by an untested idea. Five alias geometries are resolved:
the first clobbered a header, the second writes chosen bytes to a processed
record's timestamp field, the third to its `flags`/`nfversion` header field,
the fourth to its element type (a parser acceptance decision), and a
2026-11-26 framing attempt aimed the swap at a later record's `size` field
but did not trigger. With a 58-byte first record, the short flow view's
`proto` byte aliases the second record's size low byte (`0x40`), not its
`numElements`, so no ICMP swap ran; the 56-byte layout that does trigger
it draws the would-be chosen bytes from the fixed V3 record type (`0b 00`).
Direct record-size framing remains unproven. Witness replay of the live
wire, allocation-boundary, header-control and element-type lanes is still
owed; the chosen-byte payload replay is ESTABLISHED AS LABELED (W280).

### Build-label correction and pointer boundary (2026-11-26 19:29Z)

Pinned `configure.ac:27-36` appends `-fsanitize=address` under
`--enable-devel` even with empty `CFLAGS`. `build-wire.sh` used that flag
for all four collectors, so the two previously called "plain" were ASan
builds (`__asan_init` present in the built ELF). The script now uses
`--disable-devel` for plain and asserts `__asan_init` present/absent in the
actual ELF, resolving libtool wrappers to `.libs/`. Fresh plain collectors
have no ASan symbols or `libasan`; all live runners pass again with them
(`run-alias.sh` 11/0, `run-etype.sh` 17/0, `run-hdr.sh` 12/0,
`run-wire.sh` plain 13/0, `run-edge.sh` 8/0), and the element-type case
still writes `REC2_TYPE=0100` with two flows. The harness `run-all.sh`
"plain" binaries were always genuinely uninstrumented `gcc` builds; no
grade claim changes.

The pointer-lane question is closed by observation: V3 wire records and
`Process_nfd()`'s extension structs carry no pointers; `FlowSource_t`,
`nffile_t`, exporter entries and the output `dataBlock` are separate
allocations. GDB at live `Process_nfd()` measured `in_buff=0x555555578240`,
`fs=0x5555555882c0`, `nffile=0x555555588f40`, `dataBlock=0x7ffff4e40010`
in the genuine plain build; the chunk after `in_buff` holds the source
ident string, not a pointer. An over-long element can make `GetExtension()`
read past the buffer (`nfd_raw.c:259`), but that is a read. No pointer
overwrite, benign marker or command side effect: grade unchanged.

Clean archive of commit `ceb87a6e` rebuilt all four collectors and returned
17/0 (`run-etype.sh`), 11/0 (`run-alias.sh`), 12/0 (`run-hdr.sh`), 8/0
(`run-edge.sh`) and 13/0 for plain `run-wire.sh`, with
`BUILD_INSTRUMENTATION_OK`. No generated evidence was copied into the
archive.

### Crossing-write bound (2026-11-26 19:47Z)

The 8-byte timestamp store cannot cross the live 65535-byte receive buffer
from any valid UDP datagram: a 65507-byte packet allows an element header
only at `E<=65503`, so the store ends at `E+27<=65530`. The ICMP swap writes
at `E+46..47` only when `proto` at `E+48` is an ICMP byte from the packet;
packet bytes end at 65507, which forces the write target to `<=65504`.
Making the target cross (`E>=65489`) puts the trigger byte at `>=65537`,
past both packet and allocation. GDB at the live plain collector's
`nfd_raw.c:259` with the 65507-byte `edge` datagram measured
`in_buff=0x555555578230`, `in_buff_cnt=65507`, and heap residue
`01 00 00 00 ...` at `in_buff+65528` — a trigger byte there is not
attacker-chosen from the wire. No crossing write, no pointer control; grade
unchanged, NO r5. Detail: `lab/frontier/nfdump2shell/PROVENANCE.md`.

### Framing closure (2026-11-26 20:11Z)

The pinned swap cannot set an accepted record `size` or `numElements`: to
aim `dstPort` at those fields, `srcPort` must alias the adjacent `size` or
record `type`, and the pinned code zeroes `srcPort` after copying. With a
54-byte record1 the live plain collector rejected the otherwise-valid
1281-byte / 261-element record2 (`processd: 1`, `Flows: 1`), while the same
record2 after a complete record1 gave `Flows: 2` and the fixed build gave
`processd: 0` / `Flows: 0`. This closes direct record-size framing as well as
the earlier 58/56-byte attempts; the `exporterID`, flags and element-type
chosen-byte lanes stand. No pointer or command; grade unchanged, NO r5.

## Duplicate check

`reports/frontier-*.md` and the wall's do-not-duplicate list were checked
before provisioning; the only prior nfdump mention is the W233 FCEUX brief
proposing this candidate. No nfdump lab, window or admitted target exists.
