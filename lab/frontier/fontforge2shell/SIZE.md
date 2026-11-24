# SIZE — low half of the chunk size word (2026-11-24 14:0xZ, W5)

Scope: real headless FontForge 20251009, non-ASan Debug `build-plain/`,
ASan `build-asan/`, patched `build-fixed-plain/`, scripting `Import()` of
locally crafted PCFs. Author-side only. NO grade change: witness #3309
remains rungs 1-4 ESTABLISHED at the direct-call scope, NO r5.

## Hypothesis and source bound

`encs` is `int*`; on this host's 64-bit glibc a `malloc(16)` chunk has its
size word at `encs-8`, with the low four bytes at `encs-8` and the high
four at `encs-4`. W3 measured a write at `encs[-1]` (`encs-4`) corrupting
only the high half and causing `free(encs)` to abort. W4 measured a
file-chosen glyph `b-256` from an index cut after one low byte. Combining
them: a single iteration with glyph `-2` (low byte `0xfe`) writes `encs-8`,
the **low half**, and if `tot` is 1 there is no following `-1` write to
spoil the high half.

Pinned expression at `fvimportbdf.c:1751`:
`encs[glyph] = (i/(max2-min2+1) + min2)*256 + (i%(max2-min2+1) + min1)`.
Crafted table layout (byte offsets in the W1 `truncated.pcf`, verified by
`xxd`): `0x114` format(4)=0, `0x118` min2=0, `0x11a` max2=0, `0x11c`
min1=0x0091, `0x11e` max1=0x0091, `0x120` def(2)=0, `0x122` first index.
With `min2=max2=0`, `min1=max1=S`, `tot=(0-0+1)*(S-S+1)=1`, divisor 1 and
`i=0`, the RHS is exactly `S`. Ending the file after the surviving low
byte `0xfe` yields `glyph = 0xfe | (EOF<<8) = -2`. Generator:
`make-size-case.py` (sha256 `310a34961e74bf041404bd8e693936cd6e13fbce9e97219715d42bf3a0efff10`).

## Inputs

| file | low byte / index | glyph | intended value | sha256 |
|---|---|---|---|---|
| `size-91.pcf` (291 B) | `fe` | -2 | `0x91` | `e29a2e464c4fbafadc09fc68776e295d2e165e6113f75b6ff93d40f27f3c9dd2` |
| `size-ff.pcf` (291 B) | `ff` | -1 | `0x91` | `56b62c1e6d22c76869210efdc8f6e91d531bebcdcedd42d223ab4b6481356fbe` |
| `size-zero.pcf` (291 B) | `fe` | -2 | `0x0` | `79fc8f7e707deeacac565e544f7ce89f76c233a16ac7c22e98a72a3ff41c1f9f` |
| `size-complete.pcf` (292 B) | full `0x0001` | none | — | `2cc1a4238476420c7d2b97ac636ffce934af13c3aec581a896e3037e56eca16d` |

Scripts `import-size-*.ff` are `New()` then `Import("<absolute path>")`.

## Measured result (real process)

`gdb -q -batch -x gdb-size-word.cmd ./build-plain/bin/fontforge`
(`gdb-size-word.out`, sha256
`10b215aa52500577b17d1e75e5b642103f658ff7e008d163a59ab2904480ffd9`):

- `HIT glyph=-2 i=0 encs=0x555555c48240`; header at `encs-16` before the
  write shows `prev_size=0`, `size=0x21`.
- Hardware watchpoint on `*(long*)((char*)encs-8)`: `Old value = 33`,
  `New value = 145`. `x/gx (char*)encs-8` after the write =
  `0x0000000000000091`; bytes `91 00 00 00 00 00 00 00` at `encs-8`.
- At `fvimportbdf.c:1770` (`free(string); free(offsets); free(encs);`)
  the size word is still `0x91`. Conditional breakpoint on
  `__libc_free($rdi==encs)` confirms `free(encs)` is invoked.
- After that free, `tcache->entries[7] = encs` — glibc accepted the
  corrupted size and placed the originally 16-byte-usable chunk into the
  bin used for `0x90`-byte chunks. This is a size-confusion primitive
  in the real process, not a pointer or IP control.

Plain return codes (`build-plain-*.out`, `build-fixed-plain-*.out`):

| input | vulnerable plain | patched plain |
|---|---|---|
| `size-91.pcf` (glyph -2, value 0x91) | 0 | 0 |
| `size-ff.pcf` (glyph -1, high half) | 134 | 0 |
| `size-zero.pcf` (glyph -2, value 0) | 134 | 0 |
| `size-complete.pcf` | 0 | 0 |

ASan (`ASAN_OPTIONS=detect_leaks=0`, `asan-size-*.out`): `size-91`,
`size-ff` and `size-zero` each exit 1 with `WRITE of size 4` at
`fvimportbdf.c:1751`; `size-91` specifically reports `8 bytes before a
16-byte region` (the low half at `encs-8`), `size-ff` reports 4 bytes
before (the high half). `size-complete.pcf` exits 0 with no report.
The patched build rejects all negative indices with `glyph>=0`.

## Bounded negative: no observed tcache consumer

`gdb -q -batch -x gdb-tcache-reuse.cmd` (`gdb-tcache-reuse.out`) set a
conditional breakpoint on `__libc_malloc` for requests `0x71..0x88` after
the corrupted `free(encs)` and ran the same script to completion. No such
allocation occurred: the inferior exited normally without hitting the
breakpoint. The tcache entry was observed (`tcache[7]=encs`) but no later
consumer of it was seen on this headless scripted path. Do not infer an
overlapping-chunk or pointer primitive from that observation.

## Limits

Still no GUI `Import()` menu (GTK-3 dev packages absent on this host, so a
GUI-enabled build was not attempted), no pointer/IP control, no command,
no ASLR/grooming study, no witness replay of the real path, NO r5. The
chosen value here is a plausible glibc chunk size, not an address.
Any new claim goes to `witness`.
