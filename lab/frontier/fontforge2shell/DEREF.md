# DEREF — a file-chosen heap pointer is dereferenced in the real process (W11, 2026-11-25 01:2xZ)

Scope: the same four locally-built headless FontForge 20251009 trees as
`REACHABILITY.md` (`build-plain`, `build-fixed-plain`, `build-asan`,
`build-fixed`), scripting `Import()` followed by `Save()`. Author-side,
independently unwitnessed. NO grade change, NO r5. No network, loopback
service, external probe or new source tree: the inputs are the already-pinned
`value-atk50.pcf` / `value-atkceiling.pcf` / `value-probe.pcf` from
`VALUE-CEILING.md`.

## 1. Correction to W10: the pointer is a BDFChar bitmap, not a C string

W10 called the word at `encs-200` a live `char*` because `x/s` of its target
printed `""`. That label was wrong. Debug-info and heap layout identify it
as `BDFChar.bitmap`:

- `gdb -batch -ex 'ptype /o BDFChar' build-plain/bin/fontforge`: `BDFChar`
  is 104 bytes (`0x68`), `sc` at 0, the four 16-bit bounds at 8–15,
  `width=8` at 16, `bytes_per_line=1` at 18, **`bitmap` at 24 (`0x18`)**.
- `chunkalloc` is `calloc(1,size)` (`splinefont.h:1425`); `PcfParse:1809`
  allocates each `b->glyphs[i]` with `chunkalloc(sizeof(BDFChar))`.
  `malloc(104)` lands in a `0x70` glibc chunk, exactly the chunk at
  `encs-240` reported in `gdb-ptr-ident.out`.
- The live words at that chunk's user base `(char*)encs-224` were
  `sc=0`, `xmin=0 xmax=7 ymin=0 ymax=7` (`0x0007000000070000`),
  `width=8 bytes_per_line=1` (`0x0000000000010008`), and
  `bitmap=0x0000555555c227f0`. The target of that pointer is a one-byte
  zero-filled bitmap buffer, which `x/s` renders as `""`.

`value-atk50.pcf` (glyph `-50`, RHS `0x00414243`) therefore overwrote
`BDFChar.bitmap`, not a string pointer. The write, value ceiling and other
W10 evidence stand; only the object label is corrected.

## 2. The corrupted pointer is dereferenced by Save()

`Save()` (`scripting.c:1891`) calls
`SFDWriteBakExtended -> SFDWrite -> SFDDump -> SFD_Dump ->
SFDDumpBitmapFont -> SFDDumpBitmapChar`. At `sfd.c:1668-1671`:

```c
uint8_t *pt = (uint8_t *) (bfc->bitmap + i*bfc->bytes_per_line);
uint8_t *end = pt + bfc->bytes_per_line;
while ( pt<end ) { SFDEnc85(&encrypt,*pt); ++pt; }
```

With the poisoned `bitmap`, `*pt` faults at the file-chosen address.
`gdb-deref.out` (sha256
`1eb69600d354a42befb4bb391867ec05d81497d24bc66c108b203e140d512ac2`):

```
Program received signal SIGSEGV, Segmentation fault.
0x...6d1883 in SFDDumpBitmapChar (bfc=0x555555c48170, enc=261, ...) at sfd.c:1671
1671	    SFDEnc85(&encrypt,*pt);
$1 = 0x555500414243
$2 = 0x555500414243
#0 SFDDumpBitmapChar sfd.c:1671
#1 SFDDumpBitmapFont sfd.c:1769
#2 SFD_Dump sfd.c:2834  #3 SFDDump sfd.c:2956
#4 SFDWrite sfd.c:3061  #5 SFDWriteBak sfd.c:3186
#6 SFDWriteBakExtended sfd.c:3124  #7 bSave scripting.c:1891
```

`$1` is the faulting `pt`, `$2` is `bfc->bitmap`: three low bytes `41 42 43`
are file-chosen (the pinned file's RHS), byte 3 is `0x00`, upper four bytes
stay host-derived `0x00005555`. Plain rc 139.

`value-atkceiling.pcf` (RHS `0x0100FEFF`, glyph `-50`) gives the maximum
reachable value; `gdb-deref-ceiling.out` (sha256
`f84d661d859aade7792f8eb44daad29263bb47f238b1c3c5cea7236fb024562f`):

```
Program received signal SIGSEGV ... SFDDumpBitmapChar sfd.c:1671
$1 = 0x55550100feff
$2 = 0x55550100feff
```

Plain rc 139. So two different file-chosen fault addresses were measured,
including the exact arithmetic ceiling from `VALUE-CEILING.md`.

## 3. Control matrix (`deref-controls.txt`)

| input | build | rc |
|---|---|---|
| value-atk50 + Save | build-plain | 139 (SIGSEGV at 0x0000555500414243) |
| value-atkceiling + Save | build-plain | 139 (SIGSEGV at 0x000055550100FEFF) |
| value-probe (in bounds) + Save | build-plain | 0 |
| value-atk50 + Save | build-fixed-plain | 0 |
| value-atk50 + Save | build-asan | 1 (halts at original `WRITE of size 4`, `fvimportbdf.c:1751`) |
| value-probe + Save | build-asan | 0 |
| value-atk50 + Save | build-fixed (patched ASan) | 0 |

`value-atk50 + Import(complete.pcf)` (reimport, no Save) still exits 0: the
pointer is not dereferenced merely by a second import. ASan aborts on the
original overflow before `Save()`, so the dereference is a plain-build
observation only. Both patched builds and both in-bounds controls are clean.

## 4. Address bound (why this is not rung 5)

One 32-bit store writes `min2*256 + min1 <= 0x0100FEFF`; the upper four
bytes of the original heap pointer stay `0x00005555`. The reachable
target window is therefore
`0x0000555500000000 .. 0x000055550100FEFF`. In the measured process,
`info proc mappings` puts the lowest PIE mapping at `0x555555554000`
and the heap at `0x555555bc4000..0x555555c68000`, both well above that
window. The chosen addresses are unmapped, so both observed dereferences
fault rather than execute chosen bytes. There is no full 8-byte pointer
control, no benign marker execution, no command, no ASLR/grooming study,
and no way shown to redirect the dereference to a chosen mapped object.
Treat the advisory's "potential code execution" as still unmeasured.

## 5. Provenance and replay

Input/script/transcript hashes (sha256):

- `value-atk50.pcf` `8f0da475c8019d1c78a8e851a7e6dab5dbd35ea24754f5fb9b69a99b1b84fd67`
- `value-atkceiling.pcf` `544081401864454ca19be602857bf2243fd0af419b041d3b3f7155a369f8bbdb`
- `value-probe.pcf` `4b37ed447b2709f1170f73c3e3accc333b62d2424ab3406c62aa02704467d7b6`
- pinned vulnerable source `df766f9c881848cc4ea57456678e67c0e85fcf2a6ed308d1912b54181f0eb30d`
- pinned fix patch `f2745243789404ed4b6c737362dd963264ba92a848292a71db6c885675e99175`

Clean-tree one-command replay:
`FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-real.sh`;
the appended `W11 file-chosen pointer dereference` section regenerates its
own `replay-value-*-save.ff` and `replay-gdb-deref.cmd` from `$PWD`, runs all
seven cases above, prints the gdb fault address/backtrace and hashes the
three PCFs. It does not alter the W2-W9 sections. On this host at 01:2xZ the
appended section reproduced rc 139/0/139/0/1/0/0 and
`pt=bitmap=0x0000555500414243` at `sfd.c:1671` exactly.

## 6. Grade statement

Rung 4, real headless build, author-side and unwitnessed, now including a
**real dereference at a file-chosen address** in the same process: three
chosen bytes in a live `BDFChar.bitmap`, then a fault at that address during
`Save()`. NO full pointer/IP control, no chosen mapped target, no marker
execution, no command, no network path, no witness verdict. NO r5. The
existing witness grade (#3309, direct-call rungs 1-4) is unchanged; this
claim is queued to `witness` for independent replay.
