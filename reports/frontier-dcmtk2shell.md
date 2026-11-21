# Frontier brief — DCMTK JPEG encoder planar-configuration OOB write (Dcmtk2Shell)

**Status: HELD, not admitted under standing approval #6 (operator disposition
#775, 2026-11-21 ~10:06Z, recorded in `docs/task.md` commit `6b4e3be`).** The
finding is verified: rungs 1/2/3 ESTABLISHED and attacker-chosen bytes read
back byte-exact at chosen offsets past the allocation in an extracted,
source-bound harness; rung 4 is INSTRUMENTED CHOSEN-VALUE CONTROL, NOT a
live-DCMTK, real-object-layout or execution demonstration. No live process,
DICOM network service, real allocator neighbour, function pointer or code
execution was observed — all of those stay UNKNOWN. Both artifacts exist:
this brief and a two-pane `dcmtk2shell` window with a registry entry and
seed wall, retained as a frontier research artifact. No charter, status
file, admission, engine route, wake unit or presentation entry was created;
no person action is owed.

**Scope judgment (now decided, see disposition above)**: DCMTK is a C++ DICOM
toolkit, not a language runtime or HTTP server. It was submitted as an
X2Shell-class candidate because the primitive is a heap out-of-bounds write
of attacker-chosen bytes from a crafted color-by-plane DICOM image, and
DICOM storage services are network-facing. The advisory itself rates
AV:Local and UI:Passive, so network reachability through a real DICOM
service is **UNKNOWN and untested** here. Scope fit was the weakest of the
recent finds; the operator held it on that basis.

**Operator disposition #775**: held purely on scope and reachability. DCMTK
is a C++ DICOM toolkit, not a language runtime or web-facing server; the
advisory rates AV:L/UI:P, and no live DICOM service, network trigger or
stock allocator neighbour was exercised. Witness replay #775 independently
replayed the committed harness from a clean `git archive HEAD` extraction:
8 PASS / 0 FAIL, rc 0, five-run digest
`03eb9e16ef2f16d64b4ef0d1b1f77f6549f885752debe15a050f5810fc970649`
matching the brief, rung 3 ASan `WRITE of size 1` at pinned
`djcodece_v3.7.1.cc:1525`, rung 4 INSTRUMENTED chosen-value control. That
verdict verifies the finding, not admission. Revisit only with a live
loopback DICOM C-STORE or real 3.7.1 `DJCodecEncoder` path reaching this
frame with chosen bytes at chosen offsets on a network-reachable path; a
measured no-network-path negative is a valid outcome.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-133168 / GHSA-vhjh-fq99-4gmr, "DCMTK 3.7.1 Heap Buffer
  Overflow via JPEG Encoder Planar Configuration Conversion" (CNA VulnCheck,
  published 2026-11-19), CWE-787, CVSS 4.0 8.5 High,
  `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`. Claim: a crafted
  color-by-plane DICOM image with more rows than columns, compressed with the
  true-lossless JPEG codec, corrupts heap memory and may permit code execution.
  The RCE claim is advisory prose; no exploit or live demonstration shipped
  with it and this lab demonstrated no execution.
- **Affected/fixed**: affected `DCMTK 3.7.1`; the GHSA lists no patched release
  number, but the upstream fix commit is public and its two hunks are present
  verbatim in the fixed source read at that commit.
- **Fix commit**: `c22836c449bb81834fee5d883e9ebd9d7dab90b9` ("Fixed stride
  calculation when changing planar config.", Marco Eichelberg, 2026-11-01),
  closes DCMTK issue #1298; the commit says the bug was introduced by the
  attempted fix to issue #1285 in 3.7.1. Credit: Peter Klotz and Federico
  Muttis (Diphrakt B.V.). Vulnerable bytes read at tag `DCMTK-3.7.1`; fixed
  bytes read at the fix commit.
- **Claim sources read**: the GHSA entry, the CVE record, the VulnCheck
  advisory and the fix commit message/patch, plus raw source at both refs.
  Exact URLs, tags, local paths and SHA-256 digests in
  `lab/frontier/dcmtk2shell/PROVENANCE.md`. Read-only provisioning only;
  **no probe, connection or traffic to any non-loopback system**.
- **Scope separation**: distinct from the owned ruby2shell, php2shell,
  node2shell, Apache, bzfs and every other lane on the wall. No credential or
  non-default codec prerequisite appears in the patch beyond the attacker's
  crafted image and the true-lossless JPEG encoder path.
- **Ranking**: high tractability for the memory-corruption ladder despite the
  weak scope fit. The defect is one wrong stride (`rows` for `columns`) in one
  function, the fix diff changes two functions, the trigger is one crafted
  image, and the bytes crossing the buffer boundary are the attacker's own
  pixel data. Ranked above the screened-out list; scope is the only open
  judgment.

## Source-bound mechanism (read from both pins and the fix)

Line numbers are from the pinned `DCMTK-3.7.1` file unless marked fixed.

1. `djcodece.cc:598` — the caller rejects a PixelData `length` only when
   `bytesAllocated * samplesPerPixel * columns * rows * frames > length`.
   Declaring extra bytes is accepted; the calls at `:620` and `:736` pass that
   declared `length` straight through as `numValues`.
2. `djcodece.cc:1503` — `togglePlanarConfiguration8()` allocates
   `new Uint8[numValues]`. With the crafted header, that is the declared
   length, not a value derived from the real frame size.
3. `djcodece.cc:1519`/`:1536` — the row stride is `r_x_rows = r * rows`. It
   must be `r * columns`. When `rows > columns`, the computed destination
   offset grows quadratically in `rows`.
4. `djcodece.cc:1525`/`:1540` — the conversion writes
   `outPtr[off + s] = inPtr[...]` / `outPtr[off + c] = inPtr[...]`. The source
   is the attacker's PixelData; the destination is the `numValues`-byte buffer.
   With `rows > columns`, writes run well past that buffer.
5. `djcodece.cc:1549` — `memcpy(pixelData, px8, numValues)` copies the whole
   declared length back, in bounds for the caller's buffer. The corruption is
   the earlier `outPtr` writes, not this copy.
6. `djcodece.cc:1555-1617` — the 16-bit twin has the same stride bug and the
   same fix; this harness exercises the 8-bit function only.
7. **Fix** (`c22836c`, at `djcodece_fixed.cc:1491-1541`): computes
   `totalValues` from columns/rows/samples/frames, rejects
   `numValues < totalValues` at `:1503`, replaces the nested row/column loops
   with a flat index `i` at `:1520`/`:1530`, and copies `totalValues` at
   `:1538`. Both the size mismatch and the wrong stride are closed.

## Consumer-reality check

The write is a sequence of C++ byte assignments from pinned source, not a libc
routine with implementation-dependent dispatch. The harness places the exact
`new Uint8[numValues]` allocation at the head of a 1 MiB mapping, so past-end
writes land in a controlled collaborator and can be read back byte-exact; a
second placement ends the allocation at a `PROT_NONE` guard page and faults on
the first past-end write. The ASan build uses ordinary allocation. What remains
unknown is stock-layout attribution: no real DCMTK encoder, PixelData buffer
or allocator neighbour was exercised, and which useful member a given offset
would reach is **UNKNOWN**.

## Local evidence (extracted harness, all replayed)

Harness `lab/frontier/dcmtk2shell/` (`gen_driver.py`, `normalize.py`, `run.sh`,
`PROVENANCE.md`, pinned `src/`). `gen_driver.py` verifies all three upstream
pins and copies the complete vulnerable and fixed function bodies verbatim
under `#line` pointing at the pinned files; it aborts on drift. The harness
uses columns=100, rows=200, samples=3, one frame: true frame size 60000 bytes,
declared PixelData length 80000. From committed HEAD,
`bash lab/frontier/dcmtk2shell/run.sh <outdir>` prints **8 PASS / 0 FAIL**,
`ALL CHECKS PASS rc 0`, five-run digest
`sha256=03eb9e16ef2f16d64b4ef0d1b1f77f6549f885752debe15a050f5810fc970649`.

- **Rung 1 (reproducible trigger)**: input byte 39899 = `0x5a` is written to
  `px8+119697`; input byte 59899 = `0xa5` is written to `px8+119698`, both
  read back byte-exact. Both source indices are inside the declared 80000-byte
  PixelData, so both written bytes are chosen.
- **Rung 2 (accounting failure)**: first past-end write at offset 80000, last
  at 119699, overshoot 39700 bytes past the 80000-byte allocation.
- **Rung 3 (confirmed corruption)**: ASan build reports
  `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`, frame
  `togglePlanarConfiguration8` at pinned `djcodece_v3.7.1.cc:1525`, `0 bytes
  after 80000-byte region`. All other builds are un-instrumented.
- **Rung 4 (instrumented chosen-value control)**: chosen `0x5a`/`0xa5` at
  `px8+119697`/`px8+119698`; benign run with those input bytes zeroed reads
  back zero at both offsets; a guard-page placement faults at the first
  past-end write (rc 139). No pointer, function-pointer, allocator-metadata
  or execution claim.
- **Negative controls**: the fixed function with the same declared length
  leaves the past-end region untouched (`first_oob=1048576`); with
  `numValues=59999 < totalValues` it returns `EC_IllegalParameter` (rc 1) and
  writes nothing; a square image (rows == columns) produces no past-end write
  in the vulnerable build.

**Grade**: rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4
INSTRUMENTED chosen-value control only. No live DCMTK process, DICOM service,
real object layout, neighbouring heap object, function-pointer overwrite,
execution or code-execution claim. The witness replay #775 reproduced every
labelled rung and found no nit; the operator then held the lane on scope and
reachability. Independent verification is not admission.

## Cheapest next experiments to move up a rung

1. Build stock DCMTK 3.7.1 `dcmjpeg` + a loopback DICOM service and feed the
   crafted color-by-plane image with rows > columns through the real
   `DJCodecEncoder` path; capture a symbolised ASan `recv`/assignment report at
   the real `togglePlanarConfiguration8` frame. This closes the live-path gap.
2. Measure the real caller's PixelData allocation and the bytes after it in a
   stock build; determine whether a chosen offset reaches a pointer-bearing
   member or a neighbouring allocation.
3. Only if (2) yields a pointer or vtable, attempt a benign marker write back
   from it. No execution claim until that is observed.

## Witness replay instructions

From a clean checkout of the committed HEAD, run
`bash lab/frontier/dcmtk2shell/run.sh <your-outdir>`; compare the eight PASS
lines and the five-run digest above with `PROVENANCE.md`. Do not accept this
author report as a verdict.
