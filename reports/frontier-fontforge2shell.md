# frontier brief — fontforge2shell (candidate, FRONTIER-STAGED)

## Ground truth (provisioning only; no external probes)

- Claim: VulnCheck advisory dated 2026-11-23,
  <https://www.vulncheck.com/advisories/fontforge-through-20251009-heap-out-of-bounds-write-via-pcf-encodings-table>,
  CVE-2026-135295, CWE-787, CVSS4 8.5 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`.
  Affected: FontForge <= 20251009. Credit: Deus Rex. Claimed primitive:
  heap out-of-bounds write before the `encs` array from negative glyph
  indices in a truncated PCF BDF_ENCODINGS table, via GUI/script `Import()`.
  The claim says "potential code execution"; no working exploit or RCE is
  asserted by the advisory.
- Fix: commit `65e80b5dfb6691a1c8a532cfbb8ec905949e0c9a` (PR #5957,
  parent `c83ff048c461faa26148e0d658536cb69e692218`, 2026-11-19),
  one file `fontforge/fvimportbdf.c`, +1/-1. The patch is pinned verbatim at
  `lab/frontier/fontforge2shell/pinned/fix-65e80b5.patch`.
- Vulnerable source: FontForge tag `20251009`, raw
  `fontforge/fvimportbdf.c`, 2530 lines,
  sha256 `df766f9c881848cc4ea57456678e67c0e85fcf2a6ed308d1912b54181f0eb30d`.
  The advisory's line range 1719-1755 matches
  `PcfReadEncodingsNames()`; the fix hunk applies at pinned line 1763.

## Source-bound mechanism (from pinned bytes + fix hunk)

`PcfReadEncodingsNames()` allocates `encs = malloc(glyphcnt*sizeof(int))`.
After optional glyph-name parsing, it reads the PCF BDF_ENCODINGS table:

```c
min2 = getformint16(file,format); max2 = getformint16(file,format);
min1 = getformint16(file,format); max1 = getformint16(file,format);
tot = (max2-min2+1)*(max1-min1+1);
for ( i=0; i<tot; ++i ) {
    glyph = getformint16(file,format);
    if ( glyph!=0xffff && glyph<b->glyphcnt )        /* vulnerable */
        encs[glyph] = (i/(max2-min2+1) + min2)*256 +
                      (i%(max2-min2+1) + min1);
}
```

`getformint16()` uses `getc()` without an EOF check. A table truncated
before all `tot` glyph indices makes `getc()` return `EOF == -1` twice,
so `glyph == -1`. The lower-bound check is missing: `-1 != 0xffff` and
`-1 < glyphcnt`, so `encs[-1]` is written with a file-derived 32-bit value.
The fix adds `glyph>=0` to the condition. Repeats with a shorter table and
either byte order; `0xffff` is already excluded separately.

## Local experiment actually run (loopback-free, direct call)

`lab/frontier/fontforge2shell/harness.c` copies
`PcfReadEncodingsNames()` and the PCF helper functions verbatim from the
pinned source; only FontForge struct types are reduced to stand-ins and
`figureProperEncoding()` is stubbed to `-1`. A crafted 18-byte in-memory
BDF_ENCODINGS table sets `min2=max2=0x5346`, `min1=0x4d`, `max1=0x50`
(`tot=4`) and supplies glyph indices 0,1,2; the fourth read hits EOF.
The fixed line is compiled only under `-DFIXED`, exactly as in the patch.

Measured with gcc 14 `-g -O0` in this lab (2026-11-24 04:38Z):

- ASan attack: `heap-buffer-overflow`, `WRITE of size 4`, address 4 bytes
  before a 16-byte region, stack `PcfReadEncodingsNames harness.c:126` ←
  `main:203`; exit 1. `evidence/asan-attack.out`.
- ASan with `glyph>=0` fix: clean, exit 0. `evidence/asan-fixed.out`.
- ASan complete-table control (four in-range glyph indices): clean,
  exit 0. `evidence/asan-safe.out`.
- Plain build: abort 134 with glibc `double free or corruption (out)`
  after the negative write hits heap metadata. `evidence/plain-attack.out`.
- Plain gdb at the line after the loop: `encs[-1] = 0x53494d` and bytes
  `4d 49 53 00` ("MIS\\0") at `encs-4`, allocation at `encs`.
  `evidence/gdb.txt`. Three bytes are attacker-chosen; the fourth is
  structurally zero because the pin is `(i+min2)*256 + min1` with 16-bit
  fields (an honest constraint, not a rung-5 pointer primitive).

Reproduce: `cd lab/frontier/fontforge2shell && ./run-all.sh`.

## Rung-4 assessment and rank

Rungs 1-4 are demonstrated in the direct-call model: deterministic trigger,
observed heap-accounting failure, ASan-confirmed corruption, chosen bytes
at a chosen offset before the allocation, with fixed and valid-input
controls. Rank: high tractability (one-line fix, small parser, tiny
crafted table), low escalation (local file, UI:P, no network, no pointer
control, no consumer path measured). This is a staged candidate, not an
admitted target and not a rung 5.

## Ceiling / UNKNOWNs preserved

- The function is static; this harness calls it directly with stand-in
  structs. No real FontForge build, PCF file loader, GUI `Import()` path
  or scripting consumer was exercised; real-file reachability is UNKNOWN.
- No external probing; all evidence is local. No loopback server involved.
- No control-flow diversion, pointer/IP, command execution, ASLR/grooming
  study, real-process marker, witness replay or rung 5.
- Author-side clean-archive replay from `e5e4a65` repeated 5/5 expected
  RCs and the same chosen bytes; normalized hash `56fd8ada…5633bb`
  (`lab/frontier/fontforge2shell/REPLAY.md`). This is not an independent
  witness verdict.
- Operator owns admission; the person owns charter, wake units and the
  full-flag sync. Do not duplicate this lane.
