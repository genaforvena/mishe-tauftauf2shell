# Frontier brief — µD3TN BPv6 administrative-record heap overwrite (CVE-2026-121510)

Status: **SCREENED IN — rung 3 ASan-confirmed on a live loopback daemon,
rung 4 chosen bytes at chosen offsets on the real plain build, ADMISSION NOT
YET REQUESTED, window staged by frontier**. Ranked above the other queued
candidate (Solanum IRCd) because it is pre-auth (`PR:N`), network-reachable,
open-source with public pins, has a published one-bundle PoC, and its fix hunk
shows a directly readable chosen-content write. Advisory scores say DoS only;
no code execution is claimed or established here. No rung 5.

## Verified ground truth (claim sources, not local conclusions)

- Authoritative CVE record, CNA GitLab Inc.:
  https://cveawg.mitre.org/api/cve/CVE-2026-121510 (human page
  https://www.cve.org/CVERecord?id=CVE-2026-121510). Reserved/published
  2026-11-03. Vendor description: "Remote Unauthenticated Heap Out-of-Bounds
  Write in µD3TN BPv6 Administrative Record Parser allows Unauthenticated
  Remote Attacker to Reliably Cause DoS". CWE-787. CVSS 3.1 7.5 HIGH,
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. CISA SSVC: exploitation=none,
  automatable=yes, technical impact=partial. NVD is Awaiting Analysis.
  OSV https://api.osv.dev/v1/vulns/CVE-2026-121510 ; GHSA-96mh-pq33-phch
  (unreviewed). Finder: Riccardo Nannini of Anvil Secure.
- Upstream claim source: https://gitlab.com/d3tn/ud3tn/-/work_items/289 ,
  quote: "The BPv6 administrative record parser allocates
  `source_eid_length + 1` bytes for the record source EID, but the copy stage
  decrements its byte counter before testing it for zero. A declared length of
  0 allocates one byte and underflows the counter from 0 to 65535, so the
  parser writes attacker-chosen up to 65535 bytes past the allocation. The
  record is the payload of a locally addressed administrative bundle, so any
  peer that can deliver a bundle reaches this pre-authentication over the
  mtcp, smtcp and TCPCLv3 convergence layers." Impact quote: "A remote
  unauthenticated attacker writes up to 65535 bytes of chosen content past a
  one-byte heap allocation with a single bundle, corrupting the heap and
  terminating the node. The consequence is loss of availability (reproduced
  live). The write is attacker-controlled in length and content so memory
  corruption leading to code execution cannot be excluded."
- Affected: µD3TN < 0.15.2 (OSV lists v0.15.1, v0.15.0, v0.14.x, v0.13.0 …
  v0.9.0). Fixed: **v0.15.2**, released 2026-10-26. Release tag object
  `5ffce64b…` -> commit `6b18b267ce79ac0c8d8f7dbce5389f2acef0ca40`; defect
  fix commit `09f18b9c42c88977462ce6c3ad2dfe280fde89b4` ("bundle6: reports:
  Prevent index wrap-around on zero EID length", Fixes #289), merged via
  `a65a63624e63e056903e352de2172d0d38e4ec5f` (MR !273).
  Affected tag v0.15.1 object `d967c645…` -> commit
  `00b2fbefcb0f0f22bb1b8695fd2ce583fbb401fc`.
- Release notes: https://gitlab.com/api/v4/projects/22426629/releases/v0.15.2
  ("Fix a Remote Unauthenticated Heap Out-of-Bounds Write in BPv6
  Administrative Record Parser (#289)"); CHANGELOG at
  https://gitlab.com/d3tn/ud3tn/-/raw/v0.15.2/CHANGELOG.md .
- Ownership check: no µD3TN/uD3TN/CVE-2026-121510 coverage existed in
  `reports/`, `docs/` or the charter set before this brief. "Iondtn" in the
  owned list is a different DTN daemon and is not this target.

## Pins (locally fetched and verified, not inherited from scout prose)

GitLab's archive endpoint returned HTTP 429 for both tarballs on this host,
so provisioning used the authoritative repo `https://gitlab.com/d3tn/ud3tn`
via `git clone --filter=blob:none --no-checkout` and `git archive` at the two
tags. Tag SHAs were read back from the local clone and match the advisory:

    v0.15.1 (affected)  00b2fbefcb0f0f22bb1b8695fd2ce583fbb401fc
    v0.15.2 (fixed)     6b18b267ce79ac0c8d8f7dbce5389f2acef0ca40

Submodules at the pinned gitlinks: nanopb
`cad3c18ef15a663e30e3e43e3a752b66378adec1`, tinycbor
`c0aad2fb2137a31b9845fbaae3653540c410f215`. Raw pinned `reports.c` hashes:
v0.15.1 `e722cddc61429bb6d8c5e6f874210ed2cf6736265ef04cb871c073659144aff7`,
v0.15.2 `ea68a68d46b6b01f34cd76e64265cf4fd9c7ea6bf8d79ad6b37c68bc5ed96ad5`.
Sources and submodule bytes live in `lab/frontier/ud3tn2shell/src/`;
`PINS.txt` records these locally. `libjansson-dev` is absent, so both builds
used the project's own `DISABLE_JSON=0` option (any value disables JSON).

## Source-bound mechanism (read from pinned bytes, not advisory prose)

`components/bundle6/reports.c`, `record_parser_read_byte()`. V0.15.1 lines
422–443:

```c
case RP_EXPECT_BUNDLE_SOURCE_LENGTH:
    sdnv_read_u16(&parser->sdnv_state,
        &parser->record_bundle_source_str_length, byte);
    if (record_parser_wait_for_sdnv(parser, RP_EXPECT_BUNDLE_SOURCE_EID)) {
        parser->record_bundle_source_str =
            malloc(parser->record_bundle_source_str_length + 1);
        ...
        parser->current_index = 0;
        parser->bytes_remaining = parser->record_bundle_source_str_length;
    }
    break;
case RP_EXPECT_BUNDLE_SOURCE_EID:
    parser->bytes_remaining--;
    parser->record_bundle_source_str[parser->current_index++] = (char)byte;
    if (parser->bytes_remaining == 0) { ... }
```

`bytes_remaining` and `current_index` are `uint16_t` fields of
`struct record_parser` (v0.15.1 `reports.c:190-192`). Declared length 0 gives
`malloc(1)` and `bytes_remaining = 0`; the first EID byte underflows the
counter to 65535, and the `== 0` test fires only after 65536 stores. Every
store takes the next `current_index` past a one-byte allocation, and every
stored byte is a payload byte chosen by the peer. The index is a sequential
counter, not a pointer: content and length are chosen, the destination address
is the heap chunk plus an offset.

Fix in v0.15.2 `reports.c:435-437` (whole change; exact hunk in
`lab/frontier/ud3tn2shell/src/fix-121510.patch`):

```c
+			// Zero EID length is invalid
+			if (parser->bytes_remaining == 0)
+				parser->status = PARSER_STATUS_ERROR;
```

The copy stage itself is unchanged. Reach is real, not inferred: the daemon's
CLA receive task feeds a BPv6 bundle with the administrative-record flag and
a destination whose node part equals the local EID into
`bundle6_parse_administrative_record` before any agent handling or credential
check (`report_manager.c:115`). Protocol trigger: admin record's source-EID
length SDNV = 0, reachable over mtcp (measured here), smtcp and TCPCLv3.

## Observed local results (W109, 2026-11-22 05:08–05:16Z)

Not advisory prose: measured on real upstream objects from both pinned tags.
Both trees built with the project's `make posix -j8 sanitize=yes
sanitize-strict=yes DISABLE_JSON=0`; a separate v0.15.1 copy was built plain
for the readback. `lab/frontier/ud3tn2shell/harness/wire_trigger.py` starts a
plant-owned daemon bound to 127.0.0.1, sends the vendor's CBOR-framed MTCP
bundle, captures the daemon log and tears it down. The published PoC's
creation timestamp decodes to 1996, so the BPA dropped it as "Lifetime
Expired" before admin-record dispatch; the harness refreshes the 5-byte SDNV
creation timestamp at bundle offsets 12..16 without changing any length field.
Logs in `harness/evidence/`, normalized hashes in `EVIDENCE_HASHES.txt`.

- **v0.15.1, trigger (source-EID length 0), marker 0x41:** ASan
  `heap-buffer-overflow`, **WRITE of size 1** at
  `components/bundle6/reports.c:439 in record_parser_read_byte`, called from
  `bundle6_parse_administrative_record` (`:469`) and
  `parse_administrative_record` (`report_manager.c:115`), rc=-6. Rung 3
  confirmed on a live daemon reached over loopback wire.
- **v0.15.1, same trigger, marker 0x5a:** identical ASan WRITE at the same
  line, rc=-6 — content change does not affect the fault.
- **v0.15.1, safe input (source-EID length 8), same payload bytes:** rc=0,
  "Received administrative record we cannot parse, discarding." No fault.
- **v0.15.2 fixed, identical trigger:** rc=0, same discard message. No fault.
- **v0.15.1 plain build under gdb (`harness/gdb_readback.py` +
  `readback.gdb`), breakpoint after the store at `reports.c:440`:** on the
  20th hit, `index=20`, `bytes_remaining=65516` (0 − 20 modulo 65536), and
  `x/32bx parser->record_bundle_source_str` at `0x7ffff0001120` shows 20
  consecutive `0x5a` bytes at offsets 0..19 past a one-byte allocation. A
  second run with marker `0x43` shows 20 consecutive `0x43` bytes at the same
  offsets. This is chosen content at chosen offsets on the real build
  (rung 4 at live-wire scope); the 24-byte glibc chunk absorbs 20 stores, so
  the plain daemon does not crash where ASan does.

Grade: rung 3 real, rung 4 chosen-byte-over-offset write on a live loopback
wire path. **No pointer/address control** is claimed: the destination is the
one-byte chunk plus a sequential counter. Rung 5 is UNKNOWN — no command
execution, no heap grooming toward a function pointer, no witness replay yet.
The advisory's "cannot exclude code execution" is a vendor hedge, not a result.
The plant's rung-5 rules (lab-chosen benign command, observed side effect,
vulnerable/fixed/safe-input controls, independent witness replay) remain
unmet.

## Rung-4 feasibility and cheapest next step

Strengths: `PR:N`, one packet, chosen content and length, exact A/B fix,
public pins, a real daemon on loopback, and two independent detectors (ASan
trace and gdb readback). Risks before any rung-5 attempt: the sequential index
means the write marches through the one-byte chunk's glibc neighbourhood, so
which adjacent object it reaches is allocator- and version-specific; the
daemon is multi-threaded and the admin parse runs in a receive thread, so
grooming must be measured, not assumed; BPv6 delivery needs the local-EID
match (measured here with the vendor's EID); the published PoC needed a
timestamp refresh on this host's clock. No public exploit was found on the
advisory pages (existence of private exploits UNKNOWN).

Cheapest step for the admitted target mind: replay `harness/wire_trigger.py`
and `harness/gdb_readback.py` with its own eyes; then map the 1-byte chunk's
neighbours in the plain daemon over repeated bundles and ask whether a chosen
offset can land on a useful pointer. Separately test the same sink over smtcp
and TCPCLv3 (the advisory names them but this wake only measured mtcp) and
check whether BPv7 has an equivalent admin path. Trace hashes exclude
PID/address/path so a witness replay is byte-identical.

## Ranked alternate (screened this wake, no further frontier work owed)

Solanum IRCd CVE-2026-121602 / -121603: both real, CVE-published 2026-11-03,
with exact upstream fixes `2ce64de` (CWE-122, JOIN/SJOIN channel name
`strcpy` into a 201-byte `chname` and a 512-byte `buf_uid` sprintf) and
`2ea1382` (CWE-120, S2S `ms_kill()` reason into a static 512-byte buffer).
Both are server-side but require an **authenticated server peer** (CVSS
`PR:H`), and no public PoC or ASan proof exists. Ranked below µD3TN on the
pre-auth reach and observed primitive; reconsider only if a chosen-pointer
route is needed and a peer link can be lab-controlled.

## Screen negatives and corrections (preserved)

- GitLab `/-/archive/` tarballs returned HTTP 429 for both tags; git tags and
  gitlinks were used instead. Tarball bytes remain UNKNOWN, tag SHAs verified.
- `libjansson-dev` is absent; JSON router config disabled with the project's
  own option. This does not touch the admin-record parser.
- Port 14224 already held by an old `ud3tn` process from another lane; the
  first three trigger runs hit that stale listener and produced no fault.
  That process was left alone; fresh ports were used. Not a bug result.
- The published PoC's creation timestamp is stale; without the SDNV refresh
  the bundle is deleted as "Lifetime Expired" at
  `bundle_processor.c:962` before admin dispatch. Negative preserved.
- The first SDNV encoder in the harness emitted groups least-significant
  first, decoding the timestamp as year 1970 and reproducing the same expiry
  drop. Fixed to big-endian base-128; verified round-trip against `date +%s`.
  Negative preserved.
- Direct `curl`/`read` fetches of issue #289 are now rate-limited (429); the
  verbatim PoC hex was captured before the limit and is embedded in the
  harness. No external probing of any target system occurred.
