# Frontier brief — asn1scc uPER size-field overflow (Asn1scc2Shell)

**Status: new frontier find, brief + harness COMPLETE (2026-11-21 ~13:35Z) —
pending independent witness replay and operator admission.** Rungs 1/2/3 are
ESTABLISHED on the real, verbatim-pinned asn1scc C runtime: rung 3 is the ASan
report, rungs 1/2 run without sanitizers. Rung 4 shows attacker-chosen bytes at
chosen offsets past a 5-byte declared destination through the runtime's own
`BitStream_ReadByteArray`, reached by the ordinary generated uPER
`Payload_Decode()` call. No ASN.1 application, listener, real heap neighbour
object, pointer, control-flow diversion or execution was observed — all stay
UNKNOWN.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-75614 / GHSA-825c-7h77-2jjq. CNA GitHub, Inc.
  (`providerMetadata.shortName = GitHub_M`), published 2026-11-05T16:47:56Z;
  maintainer advisory by usr3-1415, 2026-07-11. CNA record text: "Prior to
  4.7.0.1, `BitStream_DecodeConstraintWholeNumber` in
  `asn1crt/asn1crt_encoding.c` reads enough bits for a constrained integer but
  does not reject values above the declared range when the encoded range is
  not a power of two … a crafted over-range size field can write beyond a
  destination buffer. … This issue is fixed in version 4.7.0.1."
- **Severity**: CNA CVSS 3.1 8.1 HIGH, `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`;
  CWE-129 (improper validation of array index) and CWE-787 (out-of-bounds
  write). GHSA repeats High / 8.1.
- **Versions**: affected `< 4.7.0.1` (CNA); OSV's concrete affected list
  includes the pinned vulnerable tag `4.6.0.17`. Fixed in **released**
  `4.7.0.1` — release API reports `draft=false`, `prerelease=false`,
  published `2026-03-15T19:38:10Z`, with compiler asset
  `asn1scc-bin-4.7.0.1.tar.bz2` (45,728,405 bytes). This is unlike the
  unmerged-PR fixed side of the HnswLib candidate.
- **Fix**: commit `fe6ab763bc60d8a2def4104c15414809b45fffd9` ("Fix 4 security
  vulnerabilities in C runtime (CVE-DRAFT-1..4)"), patch pin in `src/`.
  Maintainer advisory: "Fixed in 4.7.0.1, commit `fe6ab763…` (reject decoded
  values greater than range)."
- **Claimed primitive**: maintainer advisory says a crafted size field (e.g.
  `0b111` = 7 for `SIZE(0..5)`, where 3 bits encode 0..7) makes generated
  variable-size decoders write past the destination; its private PoC reported
  "heap-buffer-overflow WRITE of size 8, 0 bytes after 48-byte region" with a
  7-byte packet. That is a claim; the bytes below are this lab's own build.
- **Pins**: eight SHA-256 pins in `lab/frontier/asn1scc2shell/src/SHA256SUMS`
  including both full release tarballs, the fix patch, the compiler asset and
  the CVE/GHSA/OSV/release records. Full digests and provenance are in
  `lab/frontier/asn1scc2shell/PROVENANCE.md`.

## Source-bound mechanism (raw pinned bytes)

- Vulnerable 4.6.0.17 `asn1crt/asn1crt_encoding.c:801` is
  `BitStream_DecodeConstraintWholeNumber`; `:805` computes
  `range = max - min`, `:816` computes `nRangeBits =
  GetNumberOfBitsForNonNegativeInteger(range)`, and `:819-822` decodes `uv`
  then writes `*v = uv + min` with **no `uv > range` check**. For
  `SIZE(0..5)`, `range = 5`, `nRangeBits = 3`, so wire field `111` yields 7.
- Fixed 4.7.0.1 `asn1crt_encoding.c:821-822` adds `if (uv > range) return
  FALSE;` in the same function (and `:907-908` in
  `BitStream_DecodeConstraintPosWholeNumber`), exactly the patch hunk in the
  pinned `fix-fe6ab763.patch`.
- Generated `schema.c` (pinned 4.7.0.1 compiler, minimal `OCTET STRING
  (SIZE(0..5))` schema) decodes the size at `:56`, assigns `pVal->nCount` at
  `:58`, copies with `BitStream_DecodeOctetString_no_length(..., pVal->arr,
  pVal->nCount)` at `:59`, and only checks `Payload_IsConstraintValid` in the
  return expression at `:61` — after the copy.
- The pinned vulnerable runtime's `BitStream_DecodeOctetString_no_length`
  (`:1420`) forwards to `BitStream_ReadByteArray` (`:1449`); that helper's
  per-byte store is `asn1crt_encoding.c:400`. Both source trees are compiled
  verbatim; no shim performs the write.

## Lab evidence (`lab/frontier/asn1scc2shell/`, `bash run.sh <outdir>`)

12 PASS / 0 FAIL rc 0; two independent five-run groups both
`sha256=e39fec33622f9f10b63c2b0b804fcfa7072ac7b6498d63c2801ec3bd24b7bcd6`.
Clean `git archive 821647e lab/frontier/asn1scc2shell` replay into a fresh
`/tmp` directory gave the same 12 PASS / 0 FAIL rc 0 and the same digest.

- Rung 1: pinned 4.6.0.17 runtime called directly with the hostile 3-bit field
  returns `rt=1 decoded=7` against a declared range 0..5.
- Rung 2: the generated decoder's return is `ok=0 err=1 decoded=7` — the
  constraint check fires only after the oversized length is already in the
  destination field.
- Rung 3: ASan reports `heap-buffer-overflow`, `WRITE of size 1`, `0 bytes
  after 9-byte region`, frames `asn1crt_encoding.c:400` ← `:1449` ←
  generated `schema.c:59`. The 9-byte destination is an exact-size harness
  allocation (`sizeof(int)` + 5-byte array), so no struct padding hides the
  boundary.
- Rung 4: staged readback gives byte-exact
  `arr=5aa55aa55a past +5=a5 +6=5a expected=5aa55aa55aa55a`, and the second
  packet gives `arr=a55aa55aa5 past +5=5a +6=a5 expected=a55aa55aa55aa5` —
  two chosen patterns, not a fixed marker. The two past-end bytes are in
  harness staging, not an identified live neighbour.
- Guard mode places `arr[5]` at a `PROT_NONE` page boundary and faults with
  rc 139 on the first past-end store.
- Controls: fixed 4.7.0.1 runtime returns `rt=0 decoded=0` and is ASan-clean
  on the hostile packet; the generated fixed-side wrapper still returns
  `ok=1 decoded=0` because it overwrites the runtime failure code, but writes
  zero bytes. Benign size 2 is clean on both builds.

## Rung-4 feasibility assessment

Grade: rungs 1/2/3 ESTABLISHED; rung 4 INSTRUMENTED chosen bytes at chosen
offsets. Released fixed version and small C build make this an unusually clean
handoff candidate. Cheapest next experiment: a loopback-only uPER service that
calls the generated decoder on the pinned 4.6.0.17 runtime with ASan and gdb;
send the 8-byte hostile packet, freeze the first past-end bytes with a
watchpoint, and inspect the real heap neighbour before making any pointer or
control-flow claim. No such service, neighbour, pointer or execution exists
yet; those remain UNKNOWN.

## Next-candidate queue (updated 2026-11-21)

- libIEC61850 CVE-2026-49035 / CISA ICSA-26-204-06: released fixed v1.6.2
  (`db35acf6`), unauthenticated MMS Initiate → `maxFileChunkSize` underflow →
  large file copy into a fixed 65,100-byte heap buffer; public PoCs exist but
  need an MMS server and file-staging prerequisites. Rank 1 for the next wake.
- OpenJPEG OSV-2025-219 / GHSA-78g4-xqwv-q3g8: strongest public chosen-value
  write claim, but fix is not in any tagged release and the PoC must be
  regenerated. Rank 2.
- wolfSSL CVE-2026-6679 (DTLS 1.3 ACK state machine, fixed 5.9.1) and HTSlib
  CVE-2026-62257 (CRAM v4 pointer write, fixed 1.24 and backports): rank 3/4.
- HnswLib2Shell CVE-2026-124959: frontier find #11, HELD by operator (#906)
  because no released fixed version exists in hnswlib or Voyager; do not
  re-hand-off.
- libexpat CVE-2026-77214 is an OOB READ, not this plant's write primitive.

## Scope and boundaries

Local process only: no socket, listener, broker or external probe; sources were
fetched read-only as provisioning. Harness stand-ins and exact copied ranges
are enumerated in `PROVENANCE.md`. No other plant's lane or wake unit was
touched.
