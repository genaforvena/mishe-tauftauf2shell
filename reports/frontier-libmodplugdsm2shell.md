# Frontier brief: libmodplugdsm2shell — CVE-2026-111270 (unchecked `nPat` writes past `Patterns[]`/`PatternSize[]`)

**Status: STAGED 2026-11-27 W301, unowned. Operator admission and independent
witness replay are owed; this author report is not acceptance.** The two-pane
window 203 is live on the inner socket and registered. Grade at handoff:
**R1 — / R2 ✓ / R3 ✓ (UBSan array-bounds, not ASan redzone) / R4 — / R5 —**.
All bytes and observations below are from the pinned lab trees, not from the
advisory prose.

## Verified ground truth (claim sources read 2026-11-27)

- **Claim sources:** CVE record `https://www.cve.org/CVERecord?id=CVE-2026-111270`
  (CNA VulnCheck, published 2026-10-15; title "libmodplug through 0.8.9.1 Heap
  Out-of-Bounds Write via CSoundFile::ReadDSM"); GitHub advisory
  `https://github.com/advisories/GHSA-rxvf-jg5h-5fv5`; fix commit
  `https://github.com/Konstanty/libmodplug/commit/b824d9b32a1aa8b9145bbd53cbb73179ccc95acd.patch`;
  fixed release `https://github.com/Konstanty/libmodplug/releases/tag/v0.8.9.2`.
  The advisory's two HackMD write-ups returned HTTP 404 when fetched: no public
  standalone reproducer was recovered (UNKNOWN, negative preserved).
- **Versions:** affected `0` through `0.8.9.1`; the advisory's technical
  reference pins source commit `d1b97ed0020bc620a059d3675d1854b40bd2608d`
  (no `v0.8.9.1` tag found — UNKNOWN). Fixed tag `v0.8.9.2`, commit
  `a52647673746f5ba944bf3cc09be8ccb51cc9db5` (release notes cite this CVE);
  fix commit `b824d9b3…`, applied before the release commit.
- **Claimed primitive:** CWE-787 heap OOB write, CVSS 6.9 v4.0 / 6.1 v3.1. A
  DSM file with more than `MAX_PATTERNS` (240) `PATT` chunks, or a wrapping
  `patt_len`, drives `nPat` past both `Patterns[]` and `PatternSize[]` inside the
  heap-allocated `CSoundFile`. The advisory calls this a crash/heap corruption
  primitive; it claims no chosen pointer or command.
- **Fix (source-bound):** the fix adds `if (nPat >= MAX_PATTERNS) break;` before
  the index use and rewrites `dwMemPos + ppatt->patt_len >= dwMemLength` as
  `ppatt->patt_len >= dwMemLength - dwMemPos` (same rewrite for `inst_len`).
  The first hunk is the actual bound; the second closes the DWORD-wrap path.

## Source-bound mechanism (pinned bytes)

`pins/vuln.tar.gz` is the verbatim GitHub source archive of
`d1b97ed0020bc620a059d3675d1854b40bd2608d`; `pins/fixed.tar.gz` is the archive
of `a52647673746f5ba944bf3cc09be8ccb51cc9db5`. SHA-256s are in
`pins/SHA256SUMS` and `pins/SINK_SHA256.txt`; the pinned `load_dsm.cpp` blobs are
`12da2736…` (vulnerable) and `bab8763e…` (fixed). Builds compile these trees
without source edits.

In the raw vulnerable file, the `while (dwMemPos < dwMemLength - 8)` loop at
raw `:119` casts the current offset to `DSMPATT*`. The PATT branch advances
`dwMemPos += 8`, checks only the (wrap-prone) length guard, allocates a 64-row
pattern, then performs raw `:138` `PatternSize[nPat] = 64;` and raw `:139`
`Patterns[nPat] = m;` with no `nPat < MAX_PATTERNS` check. `MAX_PATTERNS` is 240
(`sndfile.h:28`) and both arrays have exactly 240 entries (`sndfile.h:570-571`).
The next member, `Order[128]`, follows them in `CSoundFile`. The harness calls
the pinned public `CSoundFile::ReadDSM()` directly on a locally generated
buffer; it is frontier scaffolding, not upstream source. No sockets, no daemon
and no external systems are used.

## Local observation (2026-11-27 W301, clang array-bounds UBSan and plain GCC)

`gen_dsm.py` writes a packed DSM header, a 192-byte `DSMSONG` with `numtrk=4`,
`numord=0`, then N eight-byte `PATT` chunks (`patt_len=0`) plus 16 trailing
bytes (the loop condition requires `dwMemPos < dwMemLength - 8` at the last
chunk). Attack N=241 → 2156 bytes; safe N=240 → 2148 bytes. `sh build-all.sh`
rebuilds both pins from the pinned tarballs; `sh run-all.sh`: **PASS=11 FAIL=0**,
rc 0 (`runs/run-all.log`).

- Vulnerable + 241 chunks, clang `-O1 -g -fsanitize=array-bounds`: UBSan reports
  `index 240 out of bounds for type 'WORD[240]'` at raw `load_dsm.cpp:138` and
  `index 240 out of bounds for type 'MODCOMMAND *[240]'` at raw `:139`
  (`runs/bounds-vuln-241.out`). This is the sanitizer-observed OOB write, not a
  redzone fault.
- Plain vulnerable + 241 chunks: `Order[0..7]` changes from `ffffffffffffffff`
  to `4000ffffffffffff` (`runs/plain-vuln-241.out`) — the stored pattern pointer
  corrupts the adjacent member. Plain vulnerable + 240 chunks and fixed + 241
  chunks (sanitizer and plain) stay `ffffffffffffffff` with no runtime error.
- **Preserved negative:** clang ASan with
  `-fsanitize-address-field-padding=2` did *not* report the intra-object write
  on this build (only a LeakSanitizer finding from the allocated pattern). The
  rung-3 evidence here is UBSan array-bounds plus the plain state differential,
  not an ASan redzone report. Do not relabel it as ASan-confirmed.

Full pin provenance, build flags, compiler versions and negatives:
`lab/frontier/libmodplugdsm2shell/PROVENANCE.md`.

## Rung-4 feasibility (honest)

- **Rung 1 NOT CLAIMED.** Plain vulnerable attack exits 0; no crash was observed.
- **Rung 2 confirmed.** Adjacent `Order[]` state changes on the vulnerable pin
  and not on fixed or 240-chunk controls.
- **Rung 3 confirmed as sanitizer-observed OOB write.** UBSan array-bounds at
  the verbatim sink, with fixed/safe controls clean. ASan intra-object detection
  was a negative, recorded above.
- **Rung 4 NOT CLAIMED.** The overwritten bytes are the low bytes of an
  allocator-returned pattern pointer (e.g. `0x40 0x00` observed), not
  attacker-chosen bytes at a chosen offset. No follow-on consumer readback,
  pointer dereference, control-flow effect or chosen value was measured.
- **Rung 5 NOT CLAIMED.** No DSM wire path, player process, remote request,
  command or side effect was exercised.

## Cheapest local experiment that could move this up a rung

1. Compile a real libmodplug consumer (e.g. a small local decoder feeding a
   DSM file from a 127.0.0.1-only path) on both pins, then inspect whether the
   corrupted `Order[]` changes pattern selection or a subsequent write/read:
   that is rung 4 in a consumer only if chosen bytes are read back at a chosen
   offset.
2. Groom the allocation following the 241st `AllocatePattern()` so the pointer
   low bytes land on a chosen live object field, and assert readback. Do not
   promote allocator-derived bytes to "chosen" without an observed control.
3. Exercise the advisory's second trigger (`patt_len` wrap) with a small file
   and compare its write pattern to the 241-chunk path.

## Ranking note (W301)

Three read-only scouts screened public 2026 advisories against the frontier
exclusion list. libmodplug ranked first by tractability: a two-line fix, a
2156-byte deterministic input, a small CMake library, and a direct public sink
call gave measured results within one wake. Backups left unstaged: NanoMQ
CVE-2026-73863 / GHSA-pf97-vm7h-q84m (wire PoC, NanoNNG build),
node-re2 CVE-2026-71498 / GHSA-j4r3-hg7j-8chg (native addon, OOB read),
OpenJPH CVE-2026-111151 (patch + archived PoC), L-SMASH CVE-2026-120456 (zero
writes only), libexpat CVE-2026-118370 (multi-GB trigger), PyMongo
CVE-2026-96749 (~3 GiB input), Wasmtime CVE-2026-35195 (heavy Rust build,
4 GiB reservation). FFmpeg, Pillow, OpenEXR, msgpack-c, QuickJS-NG and Ruby
candidates were duplicates of existing lanes; Java/AVX-512 and Wasmtime
aarch64/Winch variants are unreachable on this host. No charter, wall, lab
directory or window existed for this slug before this wake, and it is not in
the do-not-duplicate list.
