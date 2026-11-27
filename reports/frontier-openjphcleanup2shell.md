# Frontier brief: openjphcleanup2shell — CVE-2026-111151 (HT cleanup writes past a one-row codeblock buffer)

**Status: STAGED 2026-11-27 W302, unowned. Operator admission and independent
witness replay are owed; this author report is not acceptance.** The two-pane
window 204 (panes %414/%415, dead=0) is live on the inner socket and
registered. Grade at handoff:
**R1 — / R2 ✓ / R3 ✓ (ASan on the pinned decoder via a direct-sink harness;
full-program ASan is a preserved negative) / R4 — / R5 —**. All bytes and
observations below come from pinned lab trees, not advisory prose.

## Verified ground truth (claim sources read 2026-11-27)

- **Claim sources:** GitHub advisory
  `https://github.com/advisories/GHSA-5g7q-q9vm-h587`; CVE record
  `https://www.cve.org/CVERecord?id=CVE-2026-111151`; VulnCheck advisory
  `https://www.vulncheck.com/advisories/openjph-through-0.32.0-heap-out-of-bounds-write-in-htj2k-cleanup-pass-decoder`;
  upstream fix
  `https://github.com/aous72/OpenJPH/commit/345a8bcd1c7a3908e3870797057277660a412073.patch`;
  upstream issue `https://github.com/aous72/OpenJPH/issues/409`; archived
  researcher writeup
  `https://web.archive.org/web/20261015201033/https://hackmd.io/@haind-pwn/openjph-htj2k-degenerate-codeblock-cleanup-oob-write`
  (the live HackMD is 404).
- **Versions:** affected `<= 0.32.0`; vulnerable tag `0.32.0` is commit
  `23c422895ce6c3a156935222e4715ee0b7be952c`. Fixed tag `0.33.0` is commit
  `345a8bcd1c7a3908e3870797057277660a412073`; 29 unrelated commits lie between
  the pins, so attribution uses the verbatim one-file fix patch
  (`pins/fix.patch`) plus byte-identical decoder bodies on both pins.
- **Claimed primitive:** CWE-787 heap out-of-bounds write, CVSS 6.9 v4.0 /
  6.1 v3.1; CISA SSVC records exploitation `poc`. A degenerate one-row HT
  codeblock makes the cleanup pass write a second row past the sample buffer.
  The advisory claims memory corruption and crash, not a chosen pointer or
  command.
- **Fix (source-bound):** eight insertions and three deletions in
  `src/core/codestream/ojph_codeblock.cpp`. `pre_alloc` adds
  `rows = (nominal.h + 1u) & ~1u` and allocates `rows * stride` elements;
  `finalize_alloc` sets `buf_size = stride * ((nominal.h + 1u) & ~1u)`. The
  decoder itself is unchanged.

## Source-bound mechanism (pinned bytes)

`pins/vuln.tar.gz` and `pins/fixed.tar.gz` are verbatim GitHub archives of the
two commits above; SHA-256s are in `pins/SHA256SUMS`, and the pinned upstream
blobs in `pins/SINK_SHA256.txt`. The vulnerable `ojph_codeblock.cpp` blob is
`3a2773fa…` and sizes the sample buffer as `nominal.h * stride`; the fixed blob
is `78ea7f3b…` and rounds the row count up to an even number. Both pins carry
the byte-identical decoder blob `6cc2ef06…`.

In the raw vulnerable decoder, the HT cleanup quad loop writes `dp[0]` and
then `dp[stride]` at raw `src/core/coding/ojph_block_decoder32.cpp:1155`
(the same pattern recurs at `:1199`, `:1265`, `:1309` and `:1522`; a 64-bit
analogue exists in `ojph_block_decoder64.cpp` and was not tested). When the
codeblock has one sample row, `dp[stride]` is one complete row past the
allocation. A precinct geometry that yields a one-row detail codeblock is
reachable from a normal codestream: the pinned compressor produces one from a
2x2 reversible image with one decomposition, and gdb observes the vulnerable
full decoder executing raw `:1155` on that codestream. The fix removes the
mismatch by allocating two rows; no upstream source file was edited.

## Local observation (2026-11-27 W302, GCC ASan and plain controls)

`gen_j2c.py` transcribes the archived public generator verbatim apart from an
argv output path; it writes a deterministic 103-byte codestream
(`394b6c4a…`). `gen_tiny.py` writes a 2x2 PGM; the pinned compressor turns it
into a 147-byte codestream (`0d5774ea…`). `sh build-all.sh` rebuilds both pins
with `-DOJPH_DISABLE_SIMD=ON` (the default x86 dispatch would choose SSSE3/AVX2
and bypass the cited generic decoder) and links the direct-sink harness
against the pinned vulnerable ASan library. `sh run-all.sh`: **PASS=27 FAIL=0**,
rc 0 (`runs/run-all.log`); runner SHA-256
`2c02c8be816631e1c971ee854fb494a4568e61d18270339625d4c2bef4466f0e`.

- Direct sink, one exact 32-byte row: GCC ASan reports
  `heap-buffer-overflow`, `WRITE of size 4`, `0 bytes after 32-byte region`,
  at raw `ojph_block_decoder32.cpp:1155` in the pinned decoder
  (`runs/sink-1row-asan.out`).
- Two-row control, matching the fixed allocation contract: ASan and plain
  harnesses exit 0 with no finding and show `ROW1_OR=b0000000` in the second
  row, i.e. the cleanup pass does write the second row
  (`runs/sink-2row-asan.out`, `runs/sink-2row-plain.out`).
- Full-program controls: vulnerable and fixed ASan expanders both decode the
  147-byte codestream without a fault and produce identical PGM output; fixed
  ASan also decodes the archived 103-byte PoC cleanly. GDB reaches the raw
  sink in the vulnerable full decoder on the 147-byte codestream
  (`runs/gdb-reach.out`).
- **Preserved negative:** full vulnerable ASan decoding does *not* report the
  overflow. The library's `mem_fixed_allocator` serves codeblocks from one
  slab with a 5% size margin, so the second-row store lands in allocator
  slack, not an ASan redzone. The rung-3 claim therefore rests on the direct
  sink with an exactly sized buffer, not on a redzone fault in the real
  decoder. No decoded-output difference was observed on the small sweep of
  compressor-generated images (2..66 pixels square): those codestreams reach
  the sink but their overwrite does not alter the returned image.
- The archived writeup explicitly says the author did not execute the crash;
  our run of its 103-byte vector is also clean. No public binary PoC or
  sanitizer log was recovered.

Full provenance, flags, compiler versions and negatives:
`lab/frontier/openjphcleanup2shell/PROVENANCE.md` and `poc-source.md`.

## Rung-4 feasibility (honest)

- **Rung 1 NOT CLAIMED.** No plain-program crash was observed.
- **Rung 2 confirmed.** The decoder writes a second row when the pinned
  vulnerable allocation provides only one; the fixed allocation provides two.
- **Rung 3 confirmed for the pinned decoder body.** ASan reports a 4-byte
  heap OOB write at the verbatim raw sink with a zero-byte-over allocation and
  a clean two-row control. Full-program ASan is a preserved negative because
  of slab slack.
- **Rung 4 NOT CLAIMED.** The overwriting value (`0xb0000000` in this harness)
  comes from cleanup-pass decoding parameters; no chosen offset in a live
  object, chosen pointer, consumer readback or control-flow effect was
  measured. A sweep of cleanup bytes at fixed missing-MSBs showed only one
  accepted encoding, so arbitrary value control is not claimed.
- **Rung 5 NOT CLAIMED.** No network listener, remote request, shell command
  or side effect was exercised.

## Cheapest local experiment that could move this up a rung

1. Craft a codestream whose odd-height codeblock is the last data allocation
   in the fixed slab, so the second-row write crosses the slab's end instead
   of its 5% slack, then check full-decoder ASan and plain crash behavior.
2. Build a real local HTJ2K consumer with attacker-influenced allocations
   following the codeblock buffer and measure whether a chosen second-row
   word is read back at a chosen offset; only then consider rung 4.
3. Sweep cleanup coding parameters and missing-MSBs together to learn which
   second-row values are reachable before claiming value control.

## Ranking note (W302)

Four read-only scouts screened the W301 backup list. OpenJPH ranked first:
exact pins, a single-file eight-line fix, a tiny deterministic generator, a
small CMake build and a direct measured sink. NanoMQ CVE-2026-73863 has a wire
PoC but is a broker-side OOB read needing a NanoNNG build and has a conflicting
fixed-version claim; node-re2 CVE-2026-71498 is a native-addon OOB read of up
to three bytes and needs Node headers; L-SMASH CVE-2026-120456 has no public
runtime PoC and writes only NUL bytes. libexpat (multi-GB trigger), PyMongo
(~3 GiB input) and Wasmtime (heavy Rust build, 4 GiB reservation) remain
lower-value backups. No charter, wall, lab directory or window existed for
this slug before this wake, and it is not in the do-not-duplicate list.
