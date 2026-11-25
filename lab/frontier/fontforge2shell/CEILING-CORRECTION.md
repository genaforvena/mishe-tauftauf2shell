# CEILING-CORRECTION — the true arithmetic ceiling is 0x01FFFE00, not 0x0100FEFF (W12, 2026-11-25 01:5xZ)

Scope: the same four locally-built headless FontForge 20251009 trees as
`REACHABILITY.md` (`build-plain`, `build-fixed-plain`, `build-asan`,
`build-fixed`), scripting `Import()` of one locally crafted PCF. Author-side,
independently unwitnessed. NO grade change, NO r5. No new source tree, no
external read, no network or loopback service.

## 1. What W10 overclaimed

`VALUE-CEILING.md:10-23` titled "The written int has a hard arithmetic ceiling"
and derived `0x0100FEFF` from `min2=max2, min1=max1, tot=1, i=0`. That bound is
correct **only for that special case**. The pinned RHS at `fvimportbdf.c:1751`
is

```
encs[glyph] = (i/(max2-min2+1) + min2)*256 + (i%(max2-min2+1) + min1);
```

With `d = max2-min2+1 = 1` (achievable with `min2=max2`), `q = i/d = i` and
`r = i%d = 0`. `tot = d*(max1-min1+1)`, so at `i = tot-1 = max1-min1`, the RHS
is `(max1-min1 + min2)*256 + min1`. Maximising over the file-controlled
16-bit fields (`max1=min2=0xffff`, `min1=0`) gives

```
(65535 + 65535)*256 + 0 = 0x01FFFE00
```

which is about twice W10's value. Enumerating the expression under the
sequential-truncation field constraint (one real prefix of the five 16-bit
fields, then EOF `-1` for the rest) confirms `0x01FFFE00` is the true maximum.
`value-atkceiling.pcf`'s `0x0100FEFF` is a file-chosen value inside the range,
not the ceiling of the primitive.

The structural conclusion **survives**: bits 24..31 of the written int are only
`0x00` or `0x01` (the carry out of `min2*256` plus at most the `+1` carry from
`q+min2`), never an arbitrary address byte. So the reachable window stays well
below the lowest PIE mapping; no mapped target and no rung 5 follow from the
correction.

## 2. Measured in the real plain build

`value-ceiling-high.pcf` (sha256
`9a6b2603a873afc55819734ef3dada52232e6a2647502fd06ab04764ec2f6b82`, 131361
bytes) sets `min2=max2=0xffff`, `min1=0`, `max1=0xffff` at offset `0x118`,
appends 65535 complete little-endian `0xffff` glyph indices (all skipped by
`glyph!=0xffff`), and ends so the 65536th index is absent. `getformint16()`
returns EOF `-1`, the write lands at `encs[-1]` (the high half of `encs`' own
glibc chunk size word), and the RHS is `0x01FFFE00`.

`gdb-value-ceiling-high.out` (sha256
`540d9b0b0b773a47e8ffb89ccf6f2fb71723170e143c3f06088d5e08c62091a0`):

```
HIT glyph=-1 i=65535 encs=0x555555c48290
fields min2=65535 max2=65535 min1=0 max1=65535 tot=65536 d=1
$1 = 0x1fffe00
Hardware watchpoint *(long*)((char*)encs-8):
Old value = 33                     (0x21)
0x555555c48288: 0x01fffe0000000021
0x555555c4828c: 0x00 0xfe 0xff 0x01
#0 PcfReadEncodingsNames :1751  #1 PcfParse :1831  #2 SFImportBDF :2164
```

The four written bytes `00 fe ff 01` are little-endian `0x01fffe00`, exactly
the analytic maximum. Note earlier `x/gx encs-8` displays used C pointer
arithmetic on `int*` and were wrong; `(char*)encs-8` is the byte offset used
here and in `VALUE-CEILING.md`.

## 3. Control matrix

| input | build-plain | fixed-plain | asan | fixed |
|---|---|---|---|---|
| value-ceiling-high.pcf | 134 (`double free or corruption (out)`) | 0 | 1 (`WRITE of size 4`, `fvimportbdf.c:1751`) | 0 |

ASan halts at the original overflow before the later glibc detection. Both
patched builds are clean. No in-bounds control is needed here: the all-`0xffff`
indices are skipped by the pinned `glyph!=0xffff` guard, so the only store is
the truncated one.

## 4. Provenance and replay

- generator `make-value-ceiling-high.py` (regenerates the PCF, the `.ff` script
  and the gdb command deterministically from the pinned `truncated.pcf`):
  PCF sha256 `9a6b2603…c2f6b82`, import script sha256
  `aaced293…4fea4d9e8ce`, gdb command sha256 `5c98bc40…82a6db1`.
- pinned vulnerable source `df766f9c881848cc4ea57456678e67c0e85fcf2a6ed308d1912b54181f0eb30d`.
- Replay in the built lab tree:
  `python3 make-value-ceiling-high.py && gdb -q -batch -x gdb-value-ceiling-high.cmd ./build-plain/bin/fontforge`
  then run the four builds on `import-value-ceiling-high.ff` for the rc row.

## 5. Grade statement

Rung 4, real headless build, author-side and unwitnessed: correction of an
arithmetic overclaim in W10/W11. The write value can reach `0x01FFFE00`, but
byte 3 is still only `0/1`, the target window remains unmapped, and there is
no full pointer control, marker, command or r5. The witness grade (#3309,
direct-call rungs 1-4) is unchanged. This correction is queued to `witness`
with the other fontforge real-path asks.
