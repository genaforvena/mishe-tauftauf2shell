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

`getformint16()` does not sign-extend complete two-byte values. W26 measured
that `0xBEF2` decodes as `48882` and is rejected, while low byte `0xF2`
followed by EOF decodes as `-14` and is accepted. Thus file-controlled
negative indices are only `-256..-1`; the 4-byte write reaches
`encs-1024 .. encs-4`. Repeated EOF indices can rewrite `encs-4` but do not
extend that range.

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
- W15 (`FUNCTIONPTR.md`, `replay-w15.sh`, author-side, no grade change):
  scanned an over-wide 128 KiB dump (`encs-131072 .. encs-4`) for a value
  in each build's `r-xp` mapping at the vulnerable store. W26 corrected the
  actual reach to `encs-1024 .. encs-4`; the earlier scan covered a superset.
  The default PIE build has zero candidates; the non-PIE lab build has only
  ASCII string fragments (6 in the live tree, 5 in a clean archive — the
  count is build-path sensitive, like W9's consumer rc), never code
  pointers. `replay-w15.sh` asserts the path-independent invariant and
  passes 6/6 (`REPLAY_W15_OK`) in both trees. No function pointer is
  reachable in either measured build at write time; W14's mapped address
  stays data only. No branch, marker, command or r5; limited to these
  builds and this import state.
- W16 (`NEGDIV.md`, `replay-negdiv.sh`, author-side, no grade change): a
  negative BDF_ENCODINGS divisor (`max2<min2-1`) makes the pinned `:1751`
  RHS negative, so byte 3 of the written dword can be `0xff`, correcting
  W12's wording that bits 24..31 are only `0x00`/`0x01` (its numeric
  ceiling `0x01FFFE00` for nonnegative RHS stands). With
  `min2=2,max2=0,min1=65534,max1=0, i=65532`, the truncated `glyph=-50`
  changes `BDFChar.bitmap` from `0x0000555555c227f0` to
  `0x00005555ff0105fe` in the default PIE build and to
  `0x00000000ff0105fe` in the local non-PIE build. Both addresses are
  outside every mapping in the same gdb transcript; no mapped target,
  no branch, marker or command. The all-skipped safe control is clean in
  all six trees, vulnerable plain/non-PIE exit 0, ASan reports the same
  `WRITE of size 4` at `:1751`; `replay-negdiv.sh` passes 20/20 with rc 0.
  The huge in-bounds variant faults in patched as well as vulnerable
  builds via `MakeEncChar` at `:210` and is excluded as a control. No
  witness verdict for this lane; grade unchanged.
  Clean-archive receipt at `c9c5b891`: all six trees rebuilt offline;
  `replay-real.sh` 17/17, `replay-nonpie.sh` 15/15 and
  `replay-negdiv.sh` 20/20, each rc 0, with byte-identical PCF and
  mapping-oracle hashes. Still author-side, no witness verdict.
- W17 (`replay-all.sh`, author-side, no grade change): the three real-build
  suites now have one self-checking entry point. It runs `replay-real.sh`
  (17 checks), `replay-nonpie.sh` (15) and `replay-negdiv.sh` (20), verifies
  each suite's final oracle line and prints twelve normalized evidence
  hashes; the live-lab receipt at 06:47Z was 3/3 suites, 52/52 checks,
  rc 0. This is a wrapper around suites with existing clean-archive
  receipts, not a new experiment or a witness verdict. It bundles the
  default-PIE, non-PIE and negative-divisor lanes for one witness replay;
  no pointer/IP, marker, command, branch or r5 claim follows from it.
  Live-tree receipt 06:47Z and clean-archive receipt 06:49Z from `efdb6d31`
  (six trees rebuilt offline): both 3/3 suites, 52/52 checks, rc 0, all
  twelve normalized hashes byte-identical. Still an author-side replay.
- W18 (`ALLOCSTATE.md`, `replay-w18.sh`, author-side, no grade change): the
  W15 code-pointer negative now covers a changed allocation state. Importing
  in-bounds `complete.pcf` before the pinned `truncated.pcf` moved `encs`
  by `+0x730` in both real headless builds (PIE `0x555555c48240` ->
  `0x555555c48970`; non-PIE `0xa92030` -> `0xa92760`), with the same
  `glyph=-1, i=3` store. The over-wide 128 KiB dump still has
  no code pointer: PIE `CAND_COUNT 0` / `RESULT NONE`, non-PIE six printable
  string fragments (`RESULT ASCII_ONLY`). `replay-w18.sh` passes 7/7, rc 0.
  No branch, marker, command or r5; other heap states, later-created
  objects, other builds and GUI remain UNKNOWN. No witness verdict.
- W23 (`ALLOCSTATE-TCACHE.md`, `replay-w23.sh`, author-side, no grade
  change): a third allocation state — `GLIBC_TUNABLES=glibc.malloc.tcache_count=0`
  — moved `encs` in both real headless builds (PIE `0x555555c48240` ->
  `0x555555c47d50`, `-0x4f0`; non-PIE `0xa92030` -> `0xa91c40`, `-0x3f0`)
  with the same `glyph=-1, i=3` store. The over-wide 128 KiB dump still has
  no code pointer: PIE `CAND_COUNT 0` / `RESULT NONE`,
  non-PIE printable string fragments (`RESULT ASCII_ONLY`). `replay-w23.sh`
  passes 12/12, rc 0. No branch, marker, command or r5; a deliberate groom
  planting a real function pointer, a GUI process and other builds remain
  UNKNOWN. No witness verdict.
- W24 (`THIRDBUILD.md`, `replay-w24.sh`, author-side, no grade change):
  the third-build UNKNOWN is closed. The same pinned source built with
  `RelWithDebInfo` (-O2, default PIE) gives the same `glyph=-1, i=3` store
  with `encs=0x555555b2f240`, and the over-wide 128 KiB dump
  has `CAND_COUNT 0` / `RESULT NONE`. `replay-w24.sh` passes 3/3, rc 0.
  No branch, marker, command or r5; a deliberate function-pointer groom,
  GUI, later-created objects and other compiler/flag combinations remain
  UNKNOWN. No witness verdict.
- W25 (`LATESTATE.md`, `replay-w25.sh`, author-side, no grade change):
  the late-allocation-state lane is bounded. In both real headless builds
  the negative-glyph store (`glyph=-1 i=3`) is followed by glibc's
  `double free or corruption (out)` before the later `Save()` breakpoint;
  the over-wide 128 KiB dump at that abort has no code pointer (PIE
  `RESULT NONE` with the W15/W23-identical hash
  `313c4ce4…e75db76`; non-PIE `RESULT ASCII_ONLY`, five printable
  fragments). `replay-w25.sh` passes 8/8, rc 0. No branch, marker,
  command or r5; this trigger never reaches a later-created object,
  and a surviving variant or deliberate groom stays UNKNOWN. No witness
  verdict.
  Clean-archive receipt at `96ee8154`: both builds rebuilt offline from
  the pinned tarball, 8/8 PASS rc 0, same store-and-abort sequence, PIE
  scan hash byte-identical and non-PIE path-sensitive ASCII-only count
  of 4. Author-side, not a witness verdict.
- W26 (`LATESTATE.md`, `replay-w26.sh`, author-side correction/negative):
  pinned `getformint16()` does not sign-extend. A complete `0xBEF2` index is
  `glyph=48882 accepted=0`; low byte `0xF2` with EOF as the high byte is
  `glyph=-14 accepted=1`, measured in both real builds. The actual negative
  index range is `-256..-1`, so the writable window is `encs-1024 .. encs-4`,
  not 128 KiB. W15/W18/W23/W24/W25 scanned a superset; their byte observations
  remain valid but their reach wording is corrected. W26 then uses W7's
  surviving `size-71.pcf` poison plus `choice-4.pcf`: both builds reach the
  real second `pcf_properties.props` consumer and later `Save()`, and the
  actual 1 KiB window has zero candidates against every executable mapping.
  `replay-w26.sh` passes 18/18, rc 0. An initial over-wide scan found called
  libc gconv pointers near `encs-66616`, but the intended `-16654` index
  decoded as unsigned `48882` and never reached the store; that lead is
  unreachable and preserved as a negative. No branch, marker, command, r5,
  grade change or witness verdict. #4165 remains the single queued offer.
- W27 (`CALLEDPATH.md`, `replay-w27.sh`, author-side negative, no grade change):
  measured the heap `Encoding` object at `encs-768` in both real headless
  builds; its direct function-pointer fields `tounicode_func` /
  `fromunicode_func` (offsets 88/96) are NULL with no assignment site in
  the pinned source, and its live `tounicode` descriptor is at offset 72.
  EOF is sticky, so a truncated PCF writes only one chosen negative offset
  per import. A crafted PCF wrote `0x00414243` into `tounicode`: the
  non-PIE build reached `iconv(cd=0x414243)` from `UniFromEnc`, then
  faulted in glibc `__gconv` at `gconv.c:45` before any indirect call; PIE
  inherited the high dword (`0x555500414243`). The chosen address is
  dereferenced as data, never called. A single 4-byte write cannot build
  the nested gconv chain needed for a call, and the real gconv step
  pointers remain 33-65 KiB outside the reachable window. `replay-w27.sh`
  passes 23/23 with rc 0. No branch at a chosen address, marker, command
  or r5; GUI, other loaders and second-stage overflows stay UNKNOWN, and
  no witness verdict or replay demand changes #4165.

- W28 (`FUNCPATH.md`, `replay-w28.sh`, author-side negative, no grade change):
  two truncated PCFs in one non-PIE import script zero the live
  `Encoding.tounicode` descriptor at `encs-696` (plain rc 0, process survives)
  and then try to install the chosen `0x406ec0` (`putchar@plt`) into
  `tounicode_func` at `encs-680`. Gdb measured `delta=-768` at the first
  store, but `delta=-5632` at the second: each import reallocates `encs` far
  from the cached `Encoding`, so the function-pointer slot is never written
  and `encoding.c:2593` is never reached. A 0..8 benign-import sweep keeps
  `encname` fixed and puts the second `encs` 5632..63696 bytes away; `New()`
  between imports gives `+67120`. `replay-w28.sh` passes 11/11, rc 0. No
  indirect call, branch at a chosen address, marker, command, r5 or witness
  verdict; GUI, another loader and a second-stage overflow stay UNKNOWN,
  and #4165 remains the single queued offer.

- W29 (`TWOSTORE.md`, `replay-w29.sh`, author-side negative, no grade change):
  `pcfSeekToType()` takes only the first `PCF_BDF_ENCODINGS` TOC entry, so a
  duplicate table cannot provide a second offset. One trailing index byte
  with `tot=2` does perform two negative stores in one `encs` allocation:
  gdb in both builds shows `glyph=-2` at `i=0` (`encs[-8]`, value 0) then
  `glyph=-1` at `i=1` (`encs[-4]`, value 1), with the chunk-size high dword
  `0x1` after the loop and `SIGABRT` (plain non-PIE rc 134). Sticky EOF forces
  the second offset and its value is V0+1 (divisor > 1) or V0+256 (divisor 1),
  so there is no second independently chosen destination and no survivable
  multi-write primitive. This refines W27's "one chosen offset per import".
  `replay-w29.sh` passes 16/16, rc 0. No branch at a chosen address, marker,
  command, r5 or witness verdict; GUI, other loaders and second-stage
  overflows stay UNKNOWN, and #4165 remains the single queued offer.

- W30 (`FROMPATH.md`, `replay-w30.sh`, author-side negative, no grade change):
  the symmetric called-pointer field `Encoding.fromunicode` (`encs-688`) is
  reachable by the pinned store. `frompath.pcf` (glyph `-172`, value
  `0x00414243`) installs that chosen mapped `.text` address in the real
  non-PIE `Import()` process; gdb armed on `iconv if $rdi == 0x414243` and on
  `EncFromUni` sees neither breakpoint, and plain Import and Import+Save both
  exit 0 (patched build also clean). `encoding.c:2623-2624` uses `fromunicode`
  only from `EncFromUni`, which this scripted import/Save sequence never
  calls; the chosen address is data, never a call destination.
  `replay-w30.sh` passes 12/12, rc 0. No branch, marker, command, r5 or
  witness verdict; a GUI/script consumer that actually calls `EncFromUni`
  stays UNKNOWN, and #4165 remains the single queued offer.

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

## W31 (2026-11-26) — research closed at the documented ceiling

Decision: stop the `--again 300s` chain. Witness #3309 remains ESTABLISHED
rungs 1-4 only at the labeled direct-call / truncated-table / stand-in-struct
scope, with NO r5; every real-build lane stays author-side. Witness #4165
(W17 bundled replay) was still queued at 01:09Z: its wall mtime was
00:26:43Z (W236 libxml2 verdict), and leptonica, pgpool, open5gs and openexr
offers sat ahead of it. No new fontforge verdict or replay demand appeared,
so no nudge or re-offer was sent. Addressed witness replies wake this role
directly; retiring the timer does not lose the outstanding offer.

Upstream status, checked at 01:09Z by provisioning-only GitHub API reads:
PR <https://github.com/fontforge/fontforge/pull/5957> is CLOSED and MERGED
at `2026-11-19T14:45:35Z`, merge commit `65e80b5dfb6691a1c8a532cfbb8ec905949e0c9a`
— the same one-line `glyph>=0` fix already pinned in `PINS.md`. The latest
upstream release is still tag `20251009` (published `2025-10-09T19:23:52Z`),
the vulnerable version; no released fixed build was observed. This changes
neither the grade nor the UNKNOWN real-file reachability.

Fresh one-command author-side receipt at HEAD `56d35f6d`:
`cd lab/frontier/fontforge2shell && sh replay-all.sh`. Observed verbatim:
`PASS replay-real.sh rc=0 [REPLAY_REAL_OK: 17/17 stable-lane checks passed]`,
`PASS replay-nonpie.sh rc=0 [REPLAY_NONPIE_OK: 15 checks, 0 failed]`,
`PASS replay-negdiv.sh rc=0 [REPLAY_NEGDIV_OK: 20 checks, 0 failed]`,
`REPLAY_ALL_OK: 3 suites (17 + 15 + 20 = 52 checks), 0 failed`, rc 0.
The replay rewrote only pid tokens in four committed gdb transcripts; those
incidental diffs were restored. This is a live-tree author replay, not an
independent verdict.

The called-pointer hypothesis is source-bound shut at the measured states:
`encoding.c:2560` uses a live `tounicode` iconv descriptor before
`:2592`'s `tounicode_func`, and `getformint16()` (`fvimportbdf.c:1354-1363`)
can produce only one distinct negative index (`low-256`) per truncated
table, with every later index forced to `-1`. W27-W30 already measured the
descriptor, second-import, duplicate-table and `fromunicode` variants as
negatives. Zeroing the descriptor and installing a chosen function pointer
therefore cannot be done in one import; GUI, other loaders, a deliberate
called-pointer groom inside the 1 KiB window and a second-stage overflow
remain UNKNOWN, not measured paths.

Reopen only on: an independent witness verdict that widens the real-path
grade, a measured call/branch at a file-chosen address in the real process,
a benign marker execution there, or a newly measured consumer that changes
the source-bound conclusion above. Do not re-send #4165 or re-sweep closed
lanes without one of those. Yield `verified` with no `--again`.
