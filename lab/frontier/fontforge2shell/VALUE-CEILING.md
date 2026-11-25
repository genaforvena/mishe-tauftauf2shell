# VALUE-CEILING — write-value limit and a pointer-bearing target (W10, 2026-11-25 00:4xZ)

Scope: real headless FontForge 20251009, the same four locally-built trees as
`REACHABILITY.md` (`build-plain`, `build-fixed-plain`, `build-asan`,
`build-fixed`), scripting `Import()` of locally crafted PCFs. Author-side,
unwitnessed, NO grade change, NO r5. No external read, probe, loopback
service or new source tree: every PCF is derived from the already-pinned
`truncated.pcf` by `make-value-ceiling.py` / `make-ptr-target.py`.

## 1. The written int has a hard arithmetic ceiling

Pinned `fvimportbdf.c:1751` (source-bound hash `df766f9c…eb30d`):

```
encs[glyph] = (i/(max2-min2+1) + min2)*256 + (i%(max2-min2+1) + min1);
```

`min2/max2/min1/max1` all come from `getformint16()` (`:1354`), whose value
is `getc() | (getc()<<8)` in `[0,65535]`. With `min2=max2`, `min1=max1`,
`tot=1`, iteration `i=0`, the RHS is exactly `min2*256 + min1`, bounded by
`65535*256 + 65535 = 0x0100FEFF`. Bits 24..31 are only the carry out of
`min2*256`; they are `0x00` or `0x01`, never a chosen address byte. The
first three bytes are fully chosen by the file.

`value-ceiling.pcf` (sha256
`0785b632664dfb2f2252a48c5165d6f8adcbeb134100f5afe7883b16a78b426f`,
291 bytes) sets all four fields to `0xffff` and ends one byte into the
first index (`low byte 0xff`), so `glyph=-1` and the write lands at
`encs-4`. `gdb-value-ceiling.cmd` /
`gdb-value-ceiling.out` (sha256
`be1f935647ab9fc0908c377174097c016f18f9b4fcd70141d95010603e6f836d`)
measured, in the real plain process:

```
HIT glyph=-1 i=0 encs=0x555555c48240
fields min2=65535 max2=65535 min1=65535 max1=65535 tot=1
Hardware watchpoint *(long*)((char*)encs-8):
Old value = 33                     (0x21)
New value = 72337965208043553     (0x0100feff00000021)
x/4xb (char*)encs-4 -> 0xff 0xfe 0x00 0x01
```

So the fourth byte reaches its maximum (`0x01`), exactly as the arithmetic
predicts, and still is not an arbitrary pointer byte. `value-ptrlow.pcf`
(`bd1de2381aa060d09d3d9f258699fa467ac83ad6d87c274894558c852e5cc984`)
sets `min2=0x4882, min1=0x43` (RHS `0x00488240`) — three chosen bytes,
byte 3 zero. `value-complete.pcf` is the in-bounds control.

## 2. A chosen write into a live heap pointer (BDFChar.bitmap), and the no-dereference-on-Import result

The same real-process heap dump shows a pointer-shaped word at byte offset
`encs-200`, inside a live 0x70-byte chunk. W10 called it a `char*` because
`x/s` of its target printed `""`; W11 corrected the identification: the
chunk is a `calloc(104)` `BDFChar` (`chunkalloc` at `splinefont.h:1425`,
`PcfParse:1809`) and offset `0x18` is `BDFChar.bitmap`, pointing at a
one-byte zero bitmap buffer. See `DEREF.md` section 1.

The file-chosen negative-glyph range from a one-byte-truncated index is
`-256..-1` (`STEERING.md`), so `glyph=-50` writes at `encs[-50]` =
`(char*)encs-200`. `value-atk50.pcf` (sha256
`8f0da475c8019d1c78a8e851a7e6dab5dbd35ea24754f5fb9b69a99b1b84fd67`,
RHS `0x00414243`) does exactly that. `gdb-ptr-target.out` (sha256
`01141c33168978ffa14559fe1f417dca38ae8836828c16917bab19e2f175181b`):

```
HIT glyph=-50 i=0 encs=0x555555c48240
Hardware watchpoint *(long*)((char*)encs-200):
Old value = 93824999368688        (0x0000555555c227f0)
New value = 93823564857923        (0x0000555500414243)
x/gx (char*)encs-200 -> 0x0000555500414243
x/4xb (char*)encs-200 -> 0x43 0x42 0x41 0x00
```

Three of the pointer's low bytes are file-chosen; bits 32..47 keep the
host's `0x00005555`, so this is NOT a full pointer primitive. `DEREF.md`
identifies the object and shows that a later `Save()` does dereference the
changed pointer (plain rc 139 at the file-chosen address).

Negative result preserved: the corrupted pointer is NOT dereferenced on
this one-`Import()` path. The plain process continued through `PcfParse`
to normal exit (rc 0) and ASan's only finding is the `WRITE of size 4` at
`:1751` (`atk50-build-asan.out`, sha256
`b57e48b79b7a3c360eb26f72e413523a701428b17656d54f018ece1dbff7d8cb`).
No chosen-address fault was claimed in W10; `DEREF.md` now measures one
on the `Import()`-then-`Save()` path. No marker execution or command is
claimed anywhere.

## 3. The real post-overflow consumer bounds-checks file ints

After the overflow loop, `:1757-1769` passes every `encs[i]` to
`figureProperEncoding(sf,map,b,encs[i],name,…)` and then reads
`map->map[encs[i]]`. With no glyph-name table the argument `name` is
`".notdef"`, so the branch at `:202-218` computes
`gid = (enc>=map->enccount || enc<0) ? -1 : map->map[enc]`: the file-derived
`enc` is bounds-checked before it indexes `map->map`. The other branches
(`:219-241`) recompute `i` via `UniFromEnc`/`EncFromUni`/`SFFindSlot`, and
`:242-252` clamps any out-of-range `i` up to `map->enccount`. Therefore
file-chosen `encs[]` ints are not consumed as a raw index into `map->map`
and no file integer becomes a stored pointer here. Source: pinned
`fvimportbdf-20251009.c:198-279`.

## 4. Control matrix (`value-controls.txt`, sha256
`6098a9c2dbb6c894994aba355cf1331761f049f5b4175cc856e0e689687d2b6f`)

| input | glyph | build-plain | fixed-plain | asan | fixed |
|---|---|---|---|---|---|
| value-ceiling.pcf | -1 (rhs 0x0100FEFF) | 134 | 0 | 1 | 0 |
| value-ptrlow.pcf | -1 (rhs 0x00488240) | 134 | 0 | 1 | 0 |
| value-complete.pcf | in-bounds control | 0 | 0 | 0 | 0 |
| value-probe.pcf | in-bounds control | 0 | 0 | 0 | 0 |
| value-atk50.pcf | -50 (pointer word) | 0 | 0 | 1 | 0 |
| value-atkceiling.pcf | -50 (rhs 0x0100FEFF) | 0 | 0 | 1 | 0 |

The ASan build reports `WRITE of size 4` at `fvimportbdf.c:1751` for every
attack input; both patched builds and both in-bounds controls are clean.
The plain `glyph=-1` cases abort with glibc `double free or corruption
(out)` because they corrupt `encs`' own chunk size word; the `glyph=-50`
cases corrupt live heap data instead and need no glibc detection.

## 5. Grade statement

Rung 4, real headless build, author-side and unwitnessed: three chosen bytes
at a chosen offset inside a live `BDFChar.bitmap` field (pointer-bearing
object; W10's `char*` label was corrected in W11), plus the exact arithmetic
ceiling of the primitive (byte 3 is 0/1 only). W11 adds a measured
dereference at a file-chosen address during `Save()` (`DEREF.md`). NO full
pointer control, no marker execution, no command, no ASLR/grooming study,
no GUI, no r5. No witness verdict is implied and the existing #3309 grade
is unchanged.
