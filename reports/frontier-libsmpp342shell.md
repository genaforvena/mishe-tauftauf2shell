# frontier-libsmpp342shell — SMPP C-Octet unbounded `strlen` (CVE-2026-75895)

Status: **staged, rung 3 ASan-confirmed in verbatim pinned source (W271,
2026-11-26), independently replayed ESTABLISHED AS LABELED (W279, 2026-11-26)**.
Ranked first of seven new candidates from two read-only advisory sweeps:
one-line always-on fix, small C codebase, direct public API taking a buffer
and explicit length, and a 17-byte deterministic input. Pins, hashes,
refetch commands, negatives and witness detail are in
`lab/frontier/libsmpp342shell/PROVENANCE.md` and below.

## Claim source and scope

- CVE-2026-75895 / GHSA-fpm9-38vr-4gp8, GitHub Advisory Database entry
  https://github.com/advisories/ghsa-fpm9-38vr-4gp8 (unreviewed, published
  2026-09-18, updated 09-30; High 7.5,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`, CWE-125). The advisory
  claims an out-of-bounds heap read from a crafted SMPP PDU with a C-Octet
  string that lacks a terminator; the reported package is "libsmpp35
  0.1.0 through 1.8.0".
- **Version-label caveat, preserved:** the advisory's package/version labels do
  not match the upstream repository that carries the fix. The patch is in
  Osmocom `libsmpp34`, vulnerable tag 1.14.5 and fixed tag 1.14.6. That
  mismatch is a claim discrepancy, not a reproduced fact about any deployed
  package; this brief grades only the pinned `libsmpp34` code.
- Upstream: https://github.com/osmocom/libsmpp34 . Fix commit
  `af0e2912057551dab97bbe26e6a41f18a75f3bbb` ("smpp34_unpack: bound C_OCTET
  scan with strnlen()") changes exactly one line in `src/smpp34_unpack.c`;
  fetched patch text read. `git ls-remote --tags` resolved annotated tags
  1.14.5 `46707ad426764992b1f5e180fba17fbc89b0114b` (peeled commit
  `d6ac32fde99f08b2019a5ca095471456583dc93a`) and 1.14.6
  `77965468429a1abcf20bb48b98adb1f93dab158c` (peeled commit
  `f93991bd19b6715a6e1782711734cfc52760432e`). Raw sources at both peeled
  commits were checked before staging.
- Checked before staging: no brief, charter, manifest row, lab lane, wall
  receipt or screened-out note for libsmpp34/libsmpp35 in this plant; not on
  the wall's do-not-duplicate list. SOES, Mosquitto and RabbitMQC are distinct
  admitted targets and are untouched.

## Source-bound mechanism (pinned bytes)

Read from the verbatim pinned `src/smpp34_unpack.c`:

- `smpp34_unpack()` (`:44`) receives the wire buffer `ptrBuf` and its length
  `ptrLen`; `aux` tracks the cursor and `left` the remaining bytes.
- The `C_OCTET` macro (`:127-130` in 1.14.5) ran
  `lenval = strlen((char*)aux) + 1;` **before** the `if (lenval > left)`
  rejection. The PDU buffer may be exactly `command_length` bytes with no
  trailing NUL, so the scan itself reads past the allocation. The post-hoc
  length check is therefore too late.
- The fix (1.14.6, same line) changes that to
  `lenval = strnlen((char *)aux, left) + 1;`. With no terminator in the
  remaining bytes, `lenval = left + 1`, and the existing check rejects the
  PDU before any copy. No other source line changes.
- `BIND_TRANSMITTER` dispatch includes the verbatim
  `def_frame/bind_transmitter.frame`, whose first field is
  `C_OCTET(instancia, system_id, 16)` — the reachable first C-Octet after the
  16-byte PDU header.

## Local experiment and observed bytes

`lab/frontier/libsmpp342shell/run-all.sh` (sha256
`373fcdc9a182485efc38dbb3b7fa99908a57f80cd4e4977838058be708405637`) extracts
both tagged tarballs, checks tarball and verbatim-source hashes, and compiles
`harness/driver.c` against the **unmodified** upstream `.c` files through the
public `smpp34_unpack()` API. No socket or external target is used. Console
`evidence-run-console.log`: `RESULT PASS=31 FAIL=0 rc 0`.

- Attack input: 17-byte `bind_transmitter` — 16-byte header
  (`command_length=17`, `command_id=2`, `command_status=0`,
  `sequence_number=1`) plus one unterminated `A` at offset 16. Heap buffer
  allocated at exactly 17 bytes.
- GCC 12 ASan: `heap-buffer-overflow`, `READ of size 2`, `0 bytes after
  17-byte region`, frame `smpp34_unpack build/vuln/def_frame/bind_transmitter.frame:1`
  (the `strlen` interceptor inlined through the verbatim macro). Clang 18 ASan
  reports the same overflow and frame. Both exit rc 1.
- Fixed build on the same 17 bytes: rc 0, `rv=-1`,
  `len(system_id):2(Value length exceed buffer length)`, no ASan report; GCC
  and Clang agree. This is the observed rung-2 state failure and fixed
  control.
- Safe control: a complete, valid 31-byte `bind_transmitter` with terminated
  C-Octets parses to `rv=0` in both builds with chosen bytes read back as
  `system_id=sys password=pw address_range=r`, no ASan report.
- Guard-page control: the unterminated byte is placed as the last byte of a
  mapped page followed by `PROT_NONE`; the unmodified plain (non-ASan)
  vulnerable build faults with rc 139. This removes reliance on allocator
  layout for the fault observation.

## Honest grade

Rung 3: ASan-confirmed heap OOB READ in verbatim pinned upstream source, with
a guard-page fault in the plain build. Rung 4 **NOT CLAIMED**: one chosen byte
is supplied at offset 16, but no chosen bytes are observed at chosen offsets,
no pointer/control-flow target is steered, and there is no live wire consumer
or command execution. Rung 5 NOT CLAIMED.

## Cheapest next experiment to move up a rung

Keep the verbatim pinned library and replace the lab driver's buffer with a
local loopback SMPP listener: feed the 17-byte PDU from a client on 127.0.0.1
to a real consumer that calls `smpp34_unpack()` on the received bytes, with
the same fixed and safe controls. If the ASan report follows wire bytes,
record it as a live-loopback read; then try heap grooming so a plain build's
`strlen` crosses into an adjacent allocation filled with chosen bytes and
observe the length actually consumed. A rung-4 claim needs observed chosen
bytes at chosen offsets, not a larger repeated read.

## Independent witness replay (W279, 2026-11-26)

Witness #5652 replayed stage `58f43e61` from a clean archive: runner
`373fcdc9...`, driver `f2d0ceed...` and console `cbd59199...` hashes matched
PROVENANCE. Both tarballs were refetched from the exact PROVENANCE URLs and
sha256-matched (`6a275907...` / `c85f8d09...`). The unmodified `sh run-all.sh`
returned rc 0 with `RESULT PASS=31 FAIL=0`; the fresh console was byte-identical
to the staged console. Fresh raw evidence: GCC and Clang ASan
`heap-buffer-overflow READ of size 2`, 0 bytes after the 17-byte region, frame
`smpp34_unpack build/vuln/def_frame/bind_transmitter.frame:1` in `strlen`,
allocation at `harness/driver.c:52`; the plain build faults on the guard page
with rc 139. The one-line fixed build rejects the same input with `rv=-1`, and
the valid 31-byte PDU parses with `rv=0`, clean under both compilers. Verdict:
**ESTABLISHED AS LABELED**, rung 3 confirmed, no r4/r5, no contradiction.
Evidence: `.mishe-tauftauf/artifacts/witness-w276-libsmpp342shell/`.

## Ranked alternatives from the same sweeps

- bellard/quickjs CVE-2026-88378 / GHSA-jww9-7qmq-6hv5: unsigned LEB128 in
  `bc_get_leb128_int()` becomes a negative bytecode-function count, with an
  exact 21-byte regression input in fix commit `42526037…`; staged as
  quickjsbcode2shell in W271 (window 185), no longer a next candidate.
- musl CVE-2026-107891: `regcomp()` int overflow with a short repetition
  pattern and a one-file patch (`7813e911…`, untagged); needs a regex-parser
  harness, MED.
- Apache Axis2/C CVE-2026-124023: default Guththila parser indexes a
  10-entry event map with a raw byte; staged as axis2guththila2shell in W273
  (window 187).
- libsmpp34 beat all of these on source size, pin availability and the
  direct buffer+length API, not on advisory severity.

## Do-not-duplicate and boundaries

No admitted target or screened lane is reused. All testing is local against
the pinned source; no external system was probed. Admission is the operator's;
wake units and full-flag sync stay with the person. Clean-archive witness
replay completed in W279 with ESTABLISHED AS LABELED (section above).
