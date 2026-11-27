# PoC provenance: CVE-2026-111151 / GHSA-5g7q-q9vm-h587

## Sources (exact URLs)

- Archived writeup (authoritative text used for the generator):
  `https://web.archive.org/web/20261015201033/https://hackmd.io/@haind-pwn/openjph-htj2k-degenerate-codeblock-cleanup-oob-write`
  Wayback capture `20261015201033`, HackMD note id `oGPGwwxZQAyGhOtj1xag4Q`.
  The capture is served gzip-encoded; the generator is the fenced `python` block
  under "Detailed attack steps".
- Live HackMD URL (same path without the Wayback prefix):
  `https://hackmd.io/@haind-pwn/openjph-htj2k-degenerate-codeblock-cleanup-oob-write`
  Verified HTTP 404 at retrieval time; no live copy was available.
- GitHub advisory:
  `https://github.com/advisories/GHSA-5g7q-q9vm-h587`
  (moderate, CWE-787, published 2026-10-15, "OpenJPH through 0.32.0 ... heap
  out-of-bounds write ... cleanup-pass decoder ... one-row codeblocks").
- Upstream fix patch:
  `https://github.com/aous72/OpenJPH/commit/345a8bcd1c7a3908e3870797057277660a412073.patch`
  (commit `345a8bcd1c7a3908e3870797057277660a412073`, "Fixes CVE-2026-111151";
  rounds codeblock allocation rows up to an even number).
- Pinned upstream parser source, read-only cross-check (no OpenJPH build/run):
  `lab/openexr2shell-real/src/openexr-3.5.2/external/OpenJPH/src/core/codestream/ojph_params.cpp`
  `lab/openexr2shell-real/src/openexr-3.5.2/external/OpenJPH/src/core/codestream/ojph_subband.cpp`
  `lab/openexr2shell-real/src/openexr-3.5.2/external/OpenJPH/src/core/codestream/ojph_codeblock.cpp`
  `lab/openexr2shell-real/src/openexr-3.5.2/external/OpenJPH/src/core/coding/ojph_block_decoder32.cpp`
  The writeup also lists raw pinned-source URLs at commit
  `23c422895ce6c3a156935222e4715ee0b7be952c`.

## Verbatim vs derived

- **Verbatim from the archived note:** the entire Python 3 generator — `be16`,
  `be32`, `BitWriter`, `siz`, `cap`, `cod`, `qcd`, `codeblock_header`,
  `packet_res0`, `packet_res1`, `tile`, the final `packets`/`stream` assembly,
  all field values, all comments, and both `bytes([0x02, 0x00])` cleanup
  segments. HTML entities (`&gt;`, `&lt;`, `&amp;`, `&#34;`) were decoded back
  to Python syntax; no logic or constants were changed.
- **Only adaptation:** added `import sys` and replaced the archived final line
  `open("crash.j2c", "wb").write(stream)` with
  `open(sys.argv[1], "wb").write(stream)` so the script honours `argv[1]`.
  A line-by-line comparison of the archived 88 code lines against
  `gen_j2c.py` is an exact match after these two adaptations.
- **Derived bytes: none.** The archived code is complete and unambiguous, so
  no codestream byte or packet bit had to be reconstructed from parser source.
- **Cross-checks only (not derivations):** the pinned parser confirms the
  field layout the archived generator relies on: COD precinct bytes are read
  after `SPcod` with a guard rejecting a zero nibble for resolutions above the
  coarsest (`ojph_params.cpp:1205-1217`; `0x11` has both nibbles 1 and passes);
  `Lcod = 12 + 1 + num_decompositions` for user precincts
  (`ojph_params.cpp:1219`), matching `Lcod = 14` here; SOT `Psot` counts from
  the SOT marker through the tile-part data and the local header reports
  `Psot - 12` as payload (`ojph_params.cpp:2818`, `:1078`), matching the
  patched `Psot = 0x15`; `xcb_prime`/`ycb_prime` subtract the transform
  offsets and floor to log 0 (`ojph_subband.cpp:144-147`), giving the 1x1
  detail codeblock; the sample buffer is `stride * nominal.h` in the
  vulnerable version (`ojph_codeblock.cpp:56`, `:82`), which the fix patch
  changes to an even row count.

## Generated vector

Command:
`python3 lab/frontier/openjphcleanup2shell/gen_j2c.py lab/frontier/openjphcleanup2shell/vectors/crash.j2c`

- Size: **103 bytes**
- SHA-256: `394b6c4ac43ab5a66cb3d6ee6a51dfcffdb7067a22fcfff3dbb38bcc438814f1`
- Two independent runs produced identical SHA-256 (second run written to
  `/tmp/crash-second.j2c` for the check).

Full bytes:

```
00000000: ff4f ff51 0029 4000 0000 0002 0000 0002  .O.Q.)@.........
00000010: 0000 0000 0000 0000 0000 0002 0000 0002  ................
00000020: 0000 0000 0000 0000 0001 0701 01ff 5000  ..............P.
00000030: 0800 0200 0000 01ff 5200 0e01 0000 0100  ....R...........
00000040: 0104 0440 01ff 11ff 5c00 0740 4040 4040  ...@....\..@@@@@
00000050: ff90 000a 0000 0000 0015 0001 ff93 e202  ................
00000060: 00e2 0002 00ff d9                        .......
```

Expected marker layout (offsets decimal/hex as shown):

| Offset | Marker | Bytes | Meaning |
| --- | --- | --- | --- |
| 0x00 | SOC | `FF4F` | start of codestream |
| 0x02 | SIZ | `FF51 0029` + 39-byte body | `Rsiz=4000` (HT), image `2x2`, tile `2x2` at origin, `Csiz=1`, `Ssiz=07`, `XRsiz/YRsiz=01` |
| 0x2D | CAP | `FF50 0008` + `00020000 0001` | `Pcap=00020000` (HT part), `Ccap=0001` |
| 0x37 | COD | `FF52 000E` + `01 00 0001 00 01 04 04 40 01 FF 11` | user precincts, LRCP, 1 layer, no MCT, 1 decomposition, 64x64 codeblocks, HT cleanup style, reversible 5/3; precinct byte `0xFF` at resolution 0 and **`0x11` at resolution 1** (log 1 by log 1, i.e. size 2x2) |
| 0x47 | QCD | `FF5C 0007` + `40 40404040` | 2 guard bits, no quantization, one exponent per subband |
| 0x50 | SOT | `FF90 000A` + `0000 00000015 00 01` | tile 0, `Psot=0x15` (21 bytes: SOT segment + SOD + packets), one tile part |
| 0x5C | SOD | `FF93` | start of packet data |
| 0x5E | res0 packet | `E2 02 00` | packet-not-empty + included LL codeblock header, then 2-byte cleanup segment `02 00` |
| 0x61 | res1 packet | `E2 00 02 00` | packet-not-empty + included detail codeblock header (`E2`), remaining two detail subbands absent (`00`), then the **included detail codeblock's `02 00` cleanup segment at 0x63-0x64** |
| 0x65 | EOC | `FFD9` | end of codestream |

The decisive bytes are the COD resolution-1 precinct byte `0x11` at offset
`0x46`, the included first-detail-subband bit in `0xE2` at offset `0x61`, and
the cleanup length bytes `02 00` at offsets `0x63-0x64`.

## Author's claim status

The writeup is explicit that the bug was **not** reproduced at runtime:

> "The out-of-bounds write is source-confirmed. A runtime crash was not
> executed in this phase. The intended runtime confirmation builds the library
> with AddressSanitizer, drives the public decode API with the generated file,
> and expects a WRITE of size 4 ... at element offset `stride` ..."

Earlier in the same section it says the full chain was traced in the pinned
released source, with exact file/line references. No ASan log, crash output, or
sanitizer trace is present in the archived note. This lab therefore treats the
generator as a faithful public artifact and leaves runtime confirmation to
the parent's instrumented build; no OpenJPH build or decode was performed
here.

## Uncertainty

- Runtime triggering is unverified by the author and by this work. The note's
  expected ASan failure mode is a report, not an observed result.
- The packet-header bit semantics (inclusion bit, unary missing-MSBs, one
  coding pass, `Lblock`, 3-bit cleanup length 2) are taken verbatim from the
  archived generator. They were not independently decoded by an OpenJPH build
  in this task, per the no-build/no-run constraint.
- The `0x02 0x00` cleanup payload is the archived value; the note labels it
  "scup 2" but does not show a runtime decode of that payload.
- Only the single `20261015201033` Wayback capture was available; the live
  note is 404, so later edits by the author (if any) cannot be compared.
