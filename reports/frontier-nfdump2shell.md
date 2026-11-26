# Frontier brief: nfdump nfcapd truncated EXgenericFlow heap write — GHSA-gpgq-hv9x-7mqj

Status: **ADMITTED target mind; live loopback measured 2026-11-26**. Rung 3
pinned verbatim; rung 4 PARTIAL (packet-chosen offset, collector-time-derived
written value) now also demonstrated in the real pinned `nfcapd` on
`127.0.0.1` with vulnerable/fixed/safe controls. No pointer control, benign
command or rung 5. Witness W235 (2026-11-25) verdict ESTABLISHED AS LABELED;
the live collector result is new, un-witnessed evidence awaiting replay.
See `reports/nfdump2shell-status.md`.

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

`build-wire.sh` provisions the two pinned source tarballs (SHA-256 verified)
and builds complete `nfcapd` + `nfdump` pairs with ASan and plain flags.
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
with garbage-derived field values. No ASan report appears in any live case,
plain or ASan.

An attempted alias shape (4-byte element in a 16-byte record so the store
lands inside a still-valid second record) was measured and discarded:
`Process_nfd()` copies each record to the output block *before* mutating it,
and `nfdump` rejects the aliased record (`Record: 2 Time error - last <
first`). The resulting csv line carried the pre-swap value, so it proves no
chosen-byte write into a processed record. Preserved as a negative result;
no claim is made from it.

Clean-archive replay: the first attempt (commit `9fbeec88`) failed 3 PASS /
10 FAIL because `build-wire.sh` did not create the ignored `src/` directory;
the daemon log named the missing binary. Commit `81e3cd8e` fixes the path
and verifies all four binaries, after which `git archive 81e3cd8e` into an
empty directory rebuilds both commit pairs and gives 13 PASS / 0 FAIL for
ASan and plain. No assertion was relaxed to obtain the pass.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE of size 8 in the
  verbatim pinned `Process_nfd()` path, with fixed and safe-input controls.
- **Rung 4 PARTIAL:** the element length (hence the write offset) is
  packet-controlled; the written 64-bit value is collector-time-derived, not
  attacker-chosen. The write is observed in the harness canary, in a
  caller-shaped 64 KiB buffer, and now in a live pinned `nfcapd`: the next
  V3 record's header is clobbered and that record is dropped (1 flow instead
  of 2), with fixed and safe-input controls. No pointer-bearing object is
  targeted and no chosen byte is written into a processed record.
- **Not rung 5:** a live loopback `nfcapd` and a real request now exist, but
  there is no attacker control of the written value, no pointer hijack, no
  benign command and no command side effect. No rung 5 claim is made.

Next experiment: seek a shape where packet-chosen bytes (the ICMP swap)
reach a *processed* live record, or a pointer-bearing object adjacent to the
short element. The attempted alias shape failed for the reason recorded
above; the direct next-record-header overwrite is structurally real but its
value is time-derived. Witness replay of the live result is still owed.

## Duplicate check

`reports/frontier-*.md` and the wall's do-not-duplicate list were checked
before provisioning; the only prior nfdump mention is the W233 FCEUX brief
proposing this candidate. No nfdump lab, window or admitted target exists.
