# fontforge2shell — rungs 1-4 ESTABLISHED (direct call + real Import()/Open())


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
  `PcfReadEncodingsNames()` spans pinned lines 1719-1771; the changed
  line is pinned :1750. A dry-run patch applies the hunk at :1747 with
  offset -13 (not :1763, which is `int gid = map->map[encs[i]];`).

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
`figureProperEncoding()` is stubbed to `-1`. A crafted 20-byte in-memory
BDF_ENCODINGS table sets `min2=max2=0x5346`, `min1=0x4d`, `max1=0x50`
(`tot=4`) and supplies glyph indices 0,1,2; the fourth read hits EOF.
The fixed line is compiled only under `-DFIXED`, exactly as in the patch.

Measured with gcc 13.3.0 `-g -O0` in this lab (2026-11-24 04:38Z; gcc-14
is absent on this host):

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
  `evidence/gdb.txt`. Three bytes are attacker-chosen here; the fourth is
  zero for these field values only — the pinned expression
  `(i+min2)*256 + min1` can produce a nonzero top byte when `min2` is
  near 0xffff and `tot` is larger. No pointer primitive is demonstrated.

Reproduce: `cd lab/frontier/fontforge2shell && ./run-all.sh`.

## Rung-4 assessment and rank

Rungs 1-4 are demonstrated in the direct-call model: deterministic trigger,
observed heap-accounting failure, ASan-confirmed corruption, chosen bytes
at a chosen offset before the allocation, with fixed and valid-input
controls. Rank: high tractability (one-line fix, small parser, tiny
crafted table), low escalation (local file, UI:P, no network, no pointer
control; headless scripting consumer path measured, GUI not). Target admitted
under standing #6;
witness-established rungs 1-4 are direct-call only and this is not a rung 5.

## Ceiling / UNKNOWNs preserved

- The staged harness calls the static function directly with stand-in
  structs. Separately, a real headless FontForge 20251009 ASan build was
  driven by a crafted 296-byte PCF through the scripting `Import()` ->
  `FVImportBDF()` -> `PcfParse()` path (`REACHABILITY.md`): ASan
  `WRITE of size 4` 4 bytes before `encs` at `fvimportbdf.c:1751`, with
  patched-build and complete-table controls clean (exit 0, no report).
  W2 added a non-ASan real build: a gdb hardware watchpoint observed the
  actual store (`0 -> 0x53494d` at `encs-4`, bytes `4d 49 53 00` /
  "MIS\0") inside the real process, and the vulnerable binary exits 134
  with glibc `double free or corruption (out)`, while the patched binary
  and the complete-table control exit 0. Three bytes are attacker-chosen;
  the fourth is zero for these field values only. The GUI `Import()` menu
  and other application consumers remain UNKNOWN.
  W3 identified the consumer in the real plain build (`CONSUMER.md`): on
  this host's 64-bit glibc the four bytes at `encs-4` are the high half of
  the size word of `encs`'s own malloc chunk. That word changed from
  `0x21` to `0x0053494d00000021`; `free(encs)` at `fvimportbdf.c:1770`
  was caught reading the corrupted header immediately before the glibc
  abort, while patched-build and complete-table controls held `0x21` and
  exited normally. A second input, `zero-write.pcf`, makes the same
  negative write carry value zero: the size word stays `0x21`, the plain
  build exits 0, while ASan still reports `WRITE of size 4` at :1751
  (`CONSUMER.md`). Impact therefore depends on the file-derived value;
  some other plausible chunk size remains UNKNOWN.
  W4 steered the same write to a file-chosen offset (`STEERING.md`): a
  glyph index truncated after one low byte makes `getformint16()` return
  `low-256`, so the real process wrote `encs[-4]`, `encs[-8]`,
  `encs[-16]` and `encs[-255]` for four crafted PCF files; gdb confirmed
  the indices and bytes `4d 46 53 00` at `encs-16` for -4, ASan saw
  heap-use-after-free in chunks freed by `PcfReadBitmaps` / `SFSetFontName`
  for -8 / -255, and all four inputs exit 0 patched, 134 vulnerable plain.
  This steers the rung-4 write but adds no pointer/IP, command, ASLR study
  or witness verdict; NO r5.
  W5 wrote the LOW half of the same chunk size word (`SIZE.md`): setting
  `min2=max2=0`, `min1=max1=0x91` gives a single iteration (`tot=1`)
  whose pinned RHS is `0x91`, and ending the file after low byte `0xfe`
  gives `glyph=-2`, i.e. `encs-8`. In the real plain process a hardware
  watchpoint saw `0x21 -> 0x91` at `encs-8`; the corrupted word was still
  `0x91` at `free(encs)` (`fvimportbdf.c:1770`), after which
  `tcache->entries[7] = encs` — the 16-byte chunk was accepted into the
  bin for `0x90`-byte chunks. Vulnerable plain exits 0 on that input,
  while the high-half and zero-value controls exit 134; patched exits 0
  on all four inputs and ASan reports `WRITE of size 4` at :1751 for all
  three negative inputs. A conditional `__libc_malloc` probe for
  `0x71..0x88` requests after the free never hit, so no later consumer
  of that tcache entry was observed on the headless scripted path. This
  is a size-confusion mechanic, not pointer/IP control; no r5. A GUI
  build was not attempted: `gtk+-3.0` is absent and existing builds are
  `ENABLE_GUI=OFF`.
  W6 measured a real consumer of that poisoned entry (`CONSUME.md`): a
  second `Import()` in the same process makes `FVImportBDF:2317` emit a
  localized notice, and glibc gettext's `_nl_make_l10nflist` calls
  `malloc(128)`, which returns the corrupted `encs` chunk (gdb: returned
  pointer equals the poisoned chunk, size word still `0x91`). A
  subsequent `memcpy` with `__len=91` writes the host locale path into
  the physically 24-byte chunk, overwriting the following chunk's size
  word (`0x62616c2f6c6c6568`, "hell/lab") past the usable area. Vulnerable
  plain and patched builds exit 0 on the two-import script; vulnerable
  ASan still reports the `WRITE of size 4` at :1751, patched ASan and the
  complete-table control are clean. The W6 overflow bytes were host-derived.
  W7 closed that gap (`FILECHOICE.md`): poisoning bin 5 with `0x71` makes
  the second import's `pcf_properties` allocation (`props = malloc(96)`)
  return the corrupted `encs`, which is then filled with 96 file-derived
  property integers, 72 bytes past its 24 usable bytes. Changing one byte
  in the PCF (`props[2].name_offset` `0x17 -> 0x1a`) changed the byte at
  poisoned-chunk offset `0x40` from `0x17` to `0x1a`. Chosen bytes now live
  in a real consumer's overflow; they are file integers, not an address.
  No pointer/IP, command, ASLR study or witness verdict; NO r5.
  W8 (`OPENPATH.md`, author-side, no grade change): the unchanged pinned
  truncated PCF reaches the same `:1751` `WRITE of size 4` through a
  distinct real entry point, `Open("truncated.pcf")` (`bOpen:1803` ->
  `LoadSplineFont:1420` -> `ReadSplineFont:1369` -> `SFFromBDF:2442` ->
  `SFImportBDF:2164` -> `PcfParse:1831`), not only `Import()`. Vulnerable
  plain rc 134, vulnerable ASan rc 1 (`4 bytes before 16-byte region`),
  patched plain and patched ASan rc 0, complete-table control rc 0; gdb
  measured the same `4d 49 53 00` ("MIS\0") at `encs-4`. Bare
  `fontforge file.pcf` without a script is a negative lane (rc 0, no
  parse). GUI open, pointer/IP, command and ASLR remain UNKNOWN; NO r5.

- No external probing; all evidence is local. No loopback server involved.
- No control-flow diversion, full pointer/IP, command execution, chosen
  mapped target in the default PIE build, ASLR/grooming study or real-process
  marker; no rung 5.
  W11 measured a real dereference at a file-chosen address, but only in
  the unmapped window described below.
- Author-side clean-archive replay from `e5e4a65` repeated 5/5 expected
  RCs and the same chosen bytes; normalized hash `56fd8ada…5633bb`
  (`lab/frontier/fontforge2shell/REPLAY.md`).
- W9 (`REPLAY.md`, `replay-real.sh`, author-side, no grade change): a
  clean-tree one-command rebuild replayed the W8 `Open()` matrix exactly
  (vulnerable plain 134, ASan 1 with `WRITE of size 4` at :1751, patched
  plain and ASan 0, complete-table controls 0). The W6/W7 post-overflow
  consumer lanes were build-path sensitive: the same inputs and cache
  values built at `/tmp/lab/...` gave plain rc 134/139 where the live
  build exits 0; the script absolute path was ruled out by re-running the
  clean binaries with the live scripts. The rung-4 overflow result is
  unchanged, but consumer rc claims are limited to the exact build path
  measured in `CONSUME.md` / `FILECHOICE.md`. No pointer/IP, command or r5.
- W10 (`VALUE-CEILING.md`, author-side, no grade change): for the single-
  iteration `i=0` input the RHS is `min2*256 + min1` with two 16-bit
  `getformint16()` fields; the real plain build measured `0x21 ->
  0x0100feff00000021` and bytes `ff fe 00 01` at `encs-4` on
  `value-ceiling.pcf`. W12 corrected W10's `0x0100FEFF` "hard ceiling"
  overclaim: with `d=1` and `i=65535` the value reaches `0x01FFFE00`
  (`CEILING-CORRECTION.md`, bytes `00 fe ff 01`). In both cases byte 3
  is only 0 or 1, never an arbitrary address byte. A live pointer at byte offset
  `encs-200`, inside the file-chosen `-256..-1` glyph range, was changed by
  `glyph=-50` with RHS `0x00414243` from `0x0000555555c227f0` to
  `0x0000555500414243` (gdb hardware watchpoint). W11 corrected the W10
  object label: it is `BDFChar.bitmap` (`chunkalloc` = `calloc(104)`), not
  a `char*` string; `x/s` had printed `""` from a one-byte zero bitmap.
  On this one-`Import()` path the changed pointer is not dereferenced
  (plain rc 0); ASan reports only the `WRITE of size 4` at :1751.
  Source-bound, the real post-overflow consumer `figureProperEncoding`
  (:198-279) bounds-checks `enc` before `map->map[enc]` and recomputes `i`
  elsewhere. Both patched builds and both in-bounds controls are clean.
  No full pointer control at the write, marker, command or r5, no witness.
- W11 (`DEREF.md`, author-side, no grade change): adding `Save()` to the
  poisoned `Import()` makes the real plain process dereference the
  file-chosen pointer. `bSave:1891 -> SFDWriteBakExtended -> SFDDump ->
  SFDDumpBitmapFont -> SFDDumpBitmapChar` reads `bfc->bitmap[i]` at
  `sfd.c:1671`; gdb sees `SIGSEGV` with `pt = bfc->bitmap =
  0x0000555500414243` (three file-chosen bytes), plain rc 139.
  `value-atkceiling.pcf` faults at `0x000055550100FEFF` (W10's claimed
  value, not the true ceiling after W12).
  In-bounds control exits 0 on plain and ASan; both
  patched builds exit 0; vulnerable ASan halts at the original WRITE-4
  before `Save()`. The reachable window is
  `0x0000555500000000..0x0000555501FFFE00` — below the lowest PIE mapping
  (`0x555555554000`), hence unmapped in this build: no chosen mapped
  target, no full pointer control, no marker, no command, no r5. A second
  import without `Save()` still exits 0. Author-side replay receipt in
  `REPLAY.md`; no witness verdict.
- W12 (`CEILING-CORRECTION.md`, author-side, no grade change): correction
  of the W10/W11 arithmetic overclaim. `make-value-ceiling-high.py` builds a
  131361-byte PCF with `min2=max2=0xffff, min1=0, max1=0xffff` and 65535
  skipped `0xffff` indices; at `i=65535` the truncated index writes
  `0x01FFFE00` at `encs-4` in the real plain build (`gdb-value-ceiling-high.out`,
  watchpoint word `0x01fffe0000000021`, bytes `00 fe ff 01`), plain rc 134,
  fixed-plain 0, ASan 1 at `:1751`, patched 0. The true maximum is
  `0x01FFFE00`, not `0x0100FEFF`; byte 3 is still only `0/1`, the window
  stays unmapped, no r5, no witness.
- W13 (`REPLAY.md`, `replay-real.sh`, author-side, no grade change): the
  real-build offer is now one command with a self-checking oracle. It adds
  the W12 high-ceiling lane and asserts 17 build-path-independent cases
  (W8 `Open()` matrix, W11 dereference matrix, W12 ceiling matrix), ending
  in `REPLAY_REAL_OK: 17/17 stable-lane checks passed` with script rc 0.
  Live-tree (02:46Z) and clean-archive (02:5xZ) runs both matched at 17/17
  with rc 0; the clean run rebuilt all four trees from the pinned source.
  W6/W7 post-overflow consumer rc stays informational because it is
  build-path sensitive (W9). Both are author replays on this host, not a
  witness verdict; no grade or r5 change.
- W14 (`NONPIE.md`, `replay-nonpie.sh`, author-side, no grade change): a
  locally built non-PIE headless build (`-no-pie`, not a shipped default)
  makes the same `glyph=-50` overwrite of `BDFChar.bitmap` land at a fully
  file-chosen low address inside that binary's `.text`. `Save()` dereferences
  it as data at `sfd.c:1671`: gdb shows `pt = bfc->bitmap = 0x414243` and
  `0x5a4344`, with distinct mapped bytes (`0f 5e 45 f0` vs `8b 30 8b 4d`),
  and the two saved SFDs differ; plain rc 0 for both. Patched non-PIE and
  in-bounds controls keep heap pointers and rc 0. `replay-nonpie.sh` asserts
  15 stable lanes (`REPLAY_NONPIE_OK`). The pointer is data, not a function
  pointer: no branch, marker, command or r5; the high dword is inherited
  (zero here, `0x00005555` in PIE) and W12's byte-3 ceiling is unchanged.
  Author-side replay, no witness verdict for this lane.
- Independent witness replay (message #3309, 2026-11-24): ESTABLISHED
  rungs 1-4 at the labeled direct-call / in-memory truncated-table /
  stand-in-struct scope, NO r5. Clean git archive of `13a2a94`, gcc 13.3.0,
  gdb 15.1; pins and transcript matched; only pid/ASLR/path tokens
  differed. The witness replay covered the direct-call model only; the
  real-build path, including W2's real-process chosen bytes, is author-side
  with no witness verdict. GUI `Import()`, pointer/IP, command and ASLR
  remain UNKNOWN.
  The W3-W11 allocator/consumer, Open-path, value-ceiling, dereference and
  replay measurements are author-side as well; no claim beyond rungs 1-4 is
  made from them.
- Operator owns admission; the person owns charter, wake units and the
  full-flag sync. Do not duplicate this lane.
