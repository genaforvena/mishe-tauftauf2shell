# STEERING — file-chosen negative glyph index (2026-11-24 10:3xZ, W4)

Scope: real headless FontForge 20251009, non-ASan Debug `build-plain/`,
ASan `build-asan/`, patched `build-fixed-plain/`, scripting `Import()` of
crafted PCF files. Author-side; no witness verdict and no change to the
witness grade (rungs 1-4 ESTABLISHED at the labeled direct-call scope, NO r5).

## Mechanism (pinned source)

`getformint16(file, format)` at `fvimportbdf.c:1354` is

```c
val = getc(file);
val |= (getc(file)<<8);          /* PCF_DEFAULT_FORMAT: no PCF_BYTE_MASK */
return val;
```

with no EOF check. `truncated.pcf` (W1/W2) ends after two whole glyph
indices, so later reads return `EOF == -1` twice and `glyph == -1`: the
offset was fixed by truncation, not chosen. If the file instead ends **one
byte into** a glyph index, the surviving low byte `b` is followed by
`EOF`, so `glyph = b | (-1<<8) = b-256`, a file-chosen negative index in
`encs[-256] .. encs[-1]`. The next and all later iterations of the `tot`
loop read EOF twice and keep writing `encs[-1]`. All negative values still
pass `glyph != 0xffff && glyph < b->glyphcnt`; the fix `glyph>=0` rejects
all of them.

## Inputs

Each file is `truncated.pcf` cut at 0x122 (start of the first glyph index)
with one low byte appended; all other PCF bytes, including
`min2=max2=0x5346`, `min1=0x4d`, `max1=0x50`, `tot=4`, are unchanged.

| file | low byte | glyph at i=0 | sha256 |
|---|---|---|---|
| `idx-fc.pcf` = `half-trunc.pcf` | `fc` | -4 | `b78a9e9d7fae06eeb18a6b89ce047699eb0a60cf0acf0531cd2fe8c9abb5141f` |
| `idx-f8.pcf` | `f8` | -8 | `5306b242f8d1b40591bd147c966903cc09c7fcc43ad81a8f4ba1722e48a01b49` |
| `idx-f0.pcf` | `f0` | -16 | `c73c10ea163824dc7ed7ecd4bf2011610e7bb31cb4e7c4c20dd96aa18ed29913` |
| `idx-01.pcf` | `01` | -255 | `346dddeafaa034147ef761895ec49b884fdf628cf659aeeb0d935e3459c93977` |

Scripts `import-half.ff` / `import-idx-<hex>.ff` run `New()` then
`Import("<absolute path>")`; all paths are local files, no loopback server.

## Measured result

gdb at `fvimportbdf.c:1751 if glyph < 0` in the plain build (one transcript
per offset, scripts `gdb-idx-*.cmd`, `gdb-half.cmd`):

- `i=0, glyph=-4/-8/-16/-255` respectively, `encs=0x555555c48240` in each
  run. Transcripts `gdb-idx-fc.out` (`5f0e27bc…b4221f2`), `gdb-idx-f8.out`
  (`b9a8fa05…9e00ad6`), `gdb-idx-f0.out` (`9f9c1804…7a82`), `gdb-idx-01.out`
  (`03674953…d0287c7`).
- With `glyph=-4, i=0`, RHS `0x53464d`; a hardware watchpoint on
  `*(int*)((char*)encs-16)` caught `Old value = 0`, `New value = 5457485
  (0x53464d)` at `encs-16 = 0x555555c48230`, and `x/4xb` read
  `4d 46 53 00` (`gdb-half-watch.out` sha256
  `f7a6e35fad75f94fcde037504cc5462f11c44a3e3e3c14e1b4998baa205c7813`).
  Three bytes are file-chosen; the fourth is structurally zero for this
  16-bit-derived expression.

ASan build, `ASAN_OPTIONS=detect_leaks=0` (transcripts `idx-<hex>-asan.out`):

| glyph | rc | first ASan report | where |
|---|---|---|---|
| -4 | 1 | heap-buffer-overflow, WRITE of size 4 | `16 bytes before 16-byte region` (the `encs` allocation at :1726) |
| -8 | 1 | heap-use-after-free, WRITE of size 4 | `0 bytes inside of 16-byte region` freed by `PcfReadBitmaps` at :1715 |
| -16 | 1 | heap-buffer-overflow, WRITE of size 4 | `4 bytes before` the `encs` region (the later -1 write; the -16 store itself was not the first report) |
| -255 | 1 | heap-use-after-free, WRITE of size 4 | `4 bytes inside of 10-byte region` freed by `SFSetFontName` at :1972 |

The -8 and -255 rows show the steered write can land in freed heap chunks,
not only in the `encs` chunk header. ASan addresses depend on this run's
allocator state; the glyph indices and offsets are determined by the input.

Controls (`steer-controls.txt` sha256
`79b5edbd765a3f6789428415547806f48b865fa03138d3cc15e6ee2d96e4ce5f`):
all four steered files exit 0 on `build-fixed-plain` and exit 134 with
glibc `double free or corruption (out)` on `build-plain`.

## Failed attempt and limits

The first crafted file appended the byte at 0x123 (after the surviving low
byte); gdb showed the first index `0xfc01 = 64513 >= glyphcnt`, so it was
skipped and only the EOF `-1` writes occurred (`half-build-asan.out`
reported `4 bytes before`). Correcting the file to put the byte at 0x122
produced the chosen negative indices above.

No pointer/IP control, no command, no ASLR or grooming study, no GUI menu
path and no witness verdict on this extension. For -8/-255 the freed-chunk
target and its position depend on heap layout; the value remains three
chosen bytes plus a structural zero. This is a steering extension of the
same rung-4 write, not a new grade claim and not rung 5.
