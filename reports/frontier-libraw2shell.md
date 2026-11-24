# frontier brief — libraw2shell (admitted 2026-11-24; rung 4 nonzero bytes)

## Ground truth (provisioning only; no external probes)

- Claim: VulnCheck advisory dated 2026-11-23,
  <https://www.vulncheck.com/advisories/libraw-0.22.3-heap-out-of-bounds-write-via-xtrans-interpolate>,
  CVE-2026-135176, CWE-787, CVSS4 5.8
  `AV:L/AC:H/AT:P/PR:N/UI:P/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`.
  Affecting: exactly LibRaw 0.22.3. Credit: q9982. Claimed primitive: heap
  out-of-bounds write in `LibRaw::xtrans_interpolate()` when wavelet denoising
  threshold or chromatic aberration correction is enabled, via crafted X-Trans
  raw files; the advisory says crashes, not RCE.
- Upstream report: GitHub issue <https://github.com/LibRaw/LibRaw/issues/894>
  (opened 2026-11-17, still open at this wake). It links the vulnerable code at
  `src/demosaic/xtrans_demosaic.cpp#L176-L179` and a public PoC
  (`poc_xtrans_oob_write.zip`).
- Vulnerable source: LibRaw tag `0.22.3`, tarball sha256
  `7edf96c5b70cff88980a02ab0fc8af125cb6a4a377985573c654439d9d02355c`.
  Pinned PoC zip sha256 `619e741e27bd0394270ec4eadc149d24b10aa03415de63cc479b2a16512abe61`;
  extracted input sha256
  `c7940268cfb817adc4d5d42e9327a93fd042d7cd4cda8bc4b4ed6f1c4435dae2`,
  263,141 bytes, exactly the hash in the issue.
- Fix: not merged. The issue proposes two lines at
  `src/demosaic/misc_demosaic.cpp:77-79` (`iwidth=width; iheight=height;`
  before `shrink=0`). Verbatim patch pinned at
  `lab/frontier/libraw2shell/pinned/fix-894.patch`, sha256
  `32fc61e5a52c0b393fd09175bf9b1283c29065767613d15a16e421dd1a2afc9c`.
  The GitHub commit list for that file shows no such change through the
  2026-11-04 snapshot; upstream fix status is UNKNOWN, so the control here is
  the reporter's proposed fix, not a vendor release.

## Source-bound mechanism (from pinned bytes + issue)

`imgdata.sizes` carries `width`/`height` (output) and `iwidth`/`iheight`
(intermediate). `raw2image_start()` halves the latter when `shrink == 1`;
`pre_interpolate()` then rebuilds `image` at full size in its `else` arm but
leaves the two intermediate dimensions stale:

```cpp
// src/demosaic/misc_demosaic.cpp:68-79 (pinned 0.22.3)
int extra = filters ? (filters == 9 ? 6 : 2) : 0;
img = (ushort(*)[4])calloc((height+extra), (width+extra) * sizeof *img);
for (row = 0; row < height; row++)
  for (col = 0; col < width; col++)
    img[row * width + col][c] =
        image[(row >> 1) * iwidth + (col >> 1)][c];
free(image);
image = img;
shrink = 0;                 // iwidth/iheight remain half size
```

`dcraw_process()` calls `pre_interpolate()`, then selects the X-Trans
demosaicer when `filters == 9`. `xtrans_interpolate()` sizes its scratch copy
from the stale pair but stores with the full `width` stride:

```cpp
// src/demosaic/xtrans_demosaic.cpp:176-179 and :427 (pinned 0.22.3)
INT64 allocate_sz = (INT64(iheight)+6)*(INT64(iwidth)+6)*sizeof(ushort)*4LL;
ushort (*destimage)[4] = (ushort(*)[4])calloc(allocate_sz, 1);
memmove(destimage, image, allocate_sz);
...
FORC3 destimage[(row+top)*width + col + left][c] = avg[c]/avg[3];
```

With the 512x512 8-bit X-Trans PoC, `iwidth=iheight=256` while
`width=height=512`: the allocation is 549,152 bytes (68,644 pixels; ASan
reports 550,176 because `libraw_memmgr` reserves 1,024 bytes of slack), but
the store loop walks 250,000 positions with a 512-pixel row stride. The first
out-of-bounds index is 68,644, i.e. exactly one pixel past the 68,644-pixel
region; the furthest store is roughly 1.5 MB past it (ASan halts at the first).

`shrink` becomes 1 only through caller options when `filters` is set:
non-default `half_size`, `threshold` (`-n`) or `aber[]` (`-C`).

## Local experiment actually run (real consumer, real file, loopback-free)

Built LibRaw 0.22.3 `bin/dcraw_emu` from the pinned tarball with gcc 14, `-O1
-g -fsanitize=address -DUSE_ZLIB -lz`; also a fixed tree with the two-line
patch, a genuinely plain tree (0 ASan symbols) and an `-O0` plain tree for gdb.
Measured 2026-11-24 04:58-05:07Z:

- ASan attack, all three documented option forms (`-n 1`, `-C 1.1 1`,
  `-C 1 1.1`): `heap-buffer-overflow`, `WRITE of size 2`, 0 bytes after the
  550,176-byte region, stack
  `xtrans_demosaic.cpp:427` ← `dcraw_process():184` ← `dcraw_emu.cpp:598`,
  allocation at `:177`; rc 1. `evidence/asan-n1.out`,
  `asan-C11.out`, `asan-C111.out`.
- Fixed-commit control with the same PoC and all three option forms: no ASan
  report, rc 0. `evidence/fixed-asan-fixed-*.out`.
- Safe-input control: same vulnerable binary, no triggering option: no ASan
  report, rc 0. `evidence/asan-safe-default.out`.
- Plain vulnerable binary, `-n 1`: rc 139 (SIGSEGV), `evidence/plain-attack.out`;
  plain safe input: rc 0.
- gdb on the `-O0` plain binary with a conditional breakpoint at `:427`:
  first OOB store at index 68,644, `row=131 top=3 col=33 left=3 width=512`,
  destination exactly `(char*)destimage + 549152` (delta 0), `avg={0,0,0,8}`,
  so the three stored halfwords are `0x0000`. `evidence/gdb-oob-value.txt`.
  `evidence/gdb-info.txt` records the dimension mismatch directly:
  `width=512 height=512 iwidth=256 iheight=256 filters=9`, `allocate_sz=549152`.

Reproduce: `cd lab/frontier/libraw2shell && ./bootstrap.sh && ./run-all.sh`.
The committed `evidence/evidence.log` has 10 PASS / 0 FAIL and sha256
`8ad12e49ac28c2549b87c9707da47e632bcfbf99d5c7eb26716e950b9f874f57`, but a
clean rebuild changes binary/output hashes: the reproducible target is the
10-check matrix lines and the three pinned source hashes, not the whole-file
hash. `evidence/hashes.sha256` records the derived artifacts. Both source
trees and all four binaries derive from the pinned tarball and verbatim patch.

## Chosen-byte attempts — negative results preserved

The public PoC's 48-byte 1x1 lossless-JPEG strip decodes to a single pixel,
leaving the raw field zero, so `avg[c]/avg[3]` was zero at the first OOB store.
Earlier chosen-byte attempts did **not** succeed:

- Replacing the embedded JPEG with a constant 0x4d JPEG (`craft_poc.py`)
  still produced an all-zero output PPM and zero OOB halfwords
  (`evidence/gdb-crafted-oob.txt`, `asan-crafted.out`).
- Zeroing the DNG `0xc61d` tag and enlarging `StripByteCounts` did not change
  the decoded pixels (`var-A`/`var-D`/`var-E`: rc 0, zero-valued PPM).
- Converting the strip to uncompressed constant pixels (with CFA pattern
  relocated) was rejected by LibRaw with `Input/output error`, rc 2
  (`var-B`/`var-C`, `asan-uncomp.out`).

Thus chosen *offsets* were demonstrated for the public PoC; the W2
refinement below supplies the nonzero bytes. `craft_poc.py` remains the
record of the failed lane and is not superseded for the public PoC.

## Nonzero-pixel refinement (W2, 2026-11-24 06:0xZ)

`craft_nonzero_poc.py` deterministically changes three fields of the pinned
PoC: the embedded JPEG SOF3 frame from 1x1 to 512x512 (big-endian height and
width at 0x1eb/0x1ed), TIFF `BitsPerSample` 8 -> 12 to match the JPEG
precision, and `StripByteCounts` 48 -> 20,048 with 20,000 zero scan bytes.
LibRaw then decodes a full field of nonzero pixels: gdb counted 52,429
nonzero pixels out of 52,429 sampled raw pixels, with values stepping down
from 2047.

Derived input `evidence/nonzero-oob.input` sha256
`b59f64e9837b06a8f0ca07a3776e961e7d0493794e0d6cb38fbcb80022069341`;
generator sha256
`004ff4350d66000a0c941956bfc910ea16d561c0f9a7300477f448e1917cf862`.
With `-n 1` on the ASan build: `heap-buffer-overflow WRITE of size 2` at
`xtrans_demosaic.cpp:427`, rc 1 (`evidence/asan-nonzero.out`). The reporter's
fixed tree rc 0 with empty ASan output (`evidence/fixed-asan-nonzero.out`);
the vulnerable tree without `-n` rc 0 with empty output
(`evidence/asan-nonzero-safe.out`). Plain `-O0` gdb at the first OOB store:
`IDX=68644 avg={131070,131070,131070,2} delta=0`; after stepping the store,
`&destimage[68644][0] = {0xffff, 0xffff, 0xffff, 0x0000}`
(`evidence/gdb-nonzero-oob.txt`). The crafted input therefore writes
deterministic nonzero halfwords at the chosen offset.

Limit of W2 itself: the value is a saturated constant `0xffff` because LibRaw
scales the 12-bit raw field against `maximum=255`; arbitrary byte values were
not demonstrated in that variant. The variant overwrites the optional
thumbnail region. No real camera file or consumer other than `dcraw_emu` was
used. The W2 claim was subsequently replayed and ESTABLISHED (W187, below).

## Non-saturated value steering (W3, 2026-11-24 07:2xZ; witness ESTABLISHED)

The saturation is a metadata setting, not a fixed property of the store:
DNG tag `0xc61d` (WhiteLevel) in the derived PoC is 255, so `maximum=255` and
raw values above 255 clip to `0xffff`. `craft_whitelevel_poc.py` changes that
one tag (little-endian `u32` at file offset `0x102` in this layout) and leaves
the JPEG field and every other tag intact. From `evidence/nonzero-oob.input`
(sha256 `b59f64e9837b06a8f0ca07a3776e961e7d0493794e0d6cb38fbcb80022069341`)
the deterministic generator sha256
`ab5ace42392c8558d4c939d1524a9ffb29a112acb021b8141ce9a0dd8b30d1cf` produced
four variants. Plain `-O0` gdb at the first OOB store, conditional breakpoint
at `xtrans_demosaic.cpp:427` with index >= 68,644, `IDX=68644 delta=0` in all
four; the halfwords below are after the store at `&destimage[68644][0]`:

| WhiteLevel | input sha256 | avg at :427 | stored halfwords | evidence |
|---|---|---|---|---|
| 2,048 | `d398d0e78077a07cb0fb4572fce16805de1d3d31bf5d0718355b2b80c52c35f5` | `{65535,60057,65535,1}` | `0xffff 0xea99 0xffff 0x0000` | `evidence/gdb-whitelevel2048.txt` |
| 4,095 | `8d9b520418207522efb8450c2aa80dbbdb3eb6fbe6da97ffe484e2f86d7cb905` | `{45023,30020,40021,1}` | `0xafdf 0x7544 0x9c55 0x0000` | `evidence/gdb-whitelevel4095-post.txt` |
| 8,191 | `50c91fbbdbd49baba44ab2eab51fe19d726245c1d8aca6fe056cd09e7c3ce42b` | `{22508,15007,20007,1}` | `0x57ec 0x3a9f 0x4e27 0x0000` | `evidence/gdb-whitelevel8191.txt` |
| 16,383 | `2547a078ca25f315e957d30614a9c4370e0657262036487d0fcdda2390c78bc8` | `{11253,7503,10002,1}` | `0x2bf5 0x1d4f 0x2712 0x0000` | `evidence/gdb-whitelevel16383.txt` |

So the OOB value is file-steerable: three distinct non-saturated 16-bit
halfwords at the same chosen offset, changing monotonically with a single
metadata field. Controls at WhiteLevel=4,095: ASan vulnerable `-n 1` rc 1,
`heap-buffer-overflow WRITE of size 2` at `xtrans_demosaic.cpp:427`, 0 bytes
after the 550,176-byte region (`evidence/whitelevel-asan-attack.out`); fixed
tree `-n 1` rc 0 with empty output (`evidence/whitelevel-fixed-asan.out`);
vulnerable tree without `-n` rc 0 with empty output
(`evidence/whitelevel-asan-safe.out`). Reproduce:
`python3 craft_whitelevel_poc.py evidence/nonzero-oob.input OUT 4095`, then the
gdb breakpoint above. W3 was replayed in a clean room by the witness
(DM 3413, below) and is ESTABLISHED AS LABELED: three distinct non-saturated
halfwords at the chosen offset, steered by one metadata field. It is NOT a
demonstration of arbitrary 16-bit values.

## Calibrated exact halfword at the chosen offset (W6, 2026-11-24 09:3xZ; author-side)

One pre-chosen 16-bit value was hit exactly at index 68,644 by calibrating the
same DNG WhiteLevel tag used in W3. The OOB value is `avg[c]/avg[3]` of
interpolated ushort pixels; for the first channel the empirically calibrated
relation is about `184,356,380 / WhiteLevel`. `craft_whitelevel_poc.py` with
WhiteLevel 11,036 on `evidence/nonzero-oob.input` produced
`evidence/wl-probe-11036.input` (sha256
`b856c1c62d48a63f9c3d42a4d32be11033c0dc405fcbcc063f6b9ddaa6d61215`).
The plain `-O0` crash frame at `xtrans_demosaic.cpp:427` reads
`0x4141 0x2b82 0x3a00 0x0000` at `&destimage[68644][0]`
(`evidence/gdb-wl11036.txt`); `0x4141` was the target chosen before the run.
WL 11,035 gave `0x4142` and WL 11,037 gave `0x413f`
(`evidence/gdb-wl11035.txt`, `evidence/gdb-wl4141.txt`), bracketing the
calibration. ASan vulnerable `-n 1` on the exact-hit input: rc 1,
`WRITE of size 2` at `:427`, 0 bytes after the 550,176-byte region; fixed tree
rc 0; vulnerable no-option rc 0 (`evidence/wl4141-controls.txt`).
The exact-hit store was stable 3/3 in fresh plain `-O0` gdb runs, each
`0x4141 0x2b82 0x3a00 0x0000` at the same index.

Negative result preserved: a second target, `0xdead`, with WL 3,234 produced
`0xdeb3` (`evidence/wl-dead.input`, `evidence/gdb-wl-dead.txt`); WL
3,233/3,234/3,235/3,236 produced `0xdec5`/`0xdeb3`/`0xdea1`/`0xde8f`
(`evidence/gdb-wl-dead.txt`), steps of about 18 at that magnitude. WhiteLevel
alone therefore does not reach every halfword: this is ONE exact chosen value
at the chosen offset, not an arbitrary 16-bit alphabet. Ceiling unchanged:
no pointer/IP, no consumer beyond `dcraw_emu`, no wire path, NO r5.
Two further pre-chosen targets also missed: `0x1234` at WL 39,560 produced
`0x1232` (`evidence/wl1234-39560.input`, sha256
`a6886f0be95480efbab3fdbc2fdc98a0a7dafc0f6879cfeb805f1099677683b4`) and
`0x2222` at WL 21,098 produced `0x2220` (`evidence/wl2222-21098.input`, sha256
`4a1eed482ee63601a932ffc47b61027a1e83dc0cd8450f00476cc3d01a982620`).
Author-side only; no witness replay was requested this wake.

## Frame-size steering of the first OOB index (W5, 2026-11-24 08:2xZ; author-side)

The first OOB *index* is also file-steerable, not only the stored value.
`craft_dimension_poc.py` (sha256
`2703d113236f4baf8b6a164b8198448d4b4b89d33d7e9c81f2831d91c27f3e55`) changes
TIFF ImageWidth/ImageLength/RowsPerStrip, DNG ActiveArea, StripByteCounts and
the embedded lossless-JPEG SOF3 frame dimensions of
`evidence/nonzero-oob.input` together to D x D, with zero scan bytes scaled by
frame area. Source-bound prediction from the pinned bytes, recorded before the
run: `raw2image_start()` halves `iwidth`/`iheight` under `shrink==1`,
`pre_interpolate()` leaves them stale at D/2, `:176` allocates `(D/2+6)^2`
`ushort[4]` elements and `:427` stores with full D stride, so the first OOB
index is `(D/2+6)^2`: 68,644 at D=512, 268,324 at D=1024.

At D=1024, derived input `evidence/dim1024.input` sha256
`a0e318197405aa5df29a3f5c1a0916487e0eb8c67c55ec00c03dd0308ff2da3a`,
the ASan vulnerable `dcraw_emu -n 1` run rc 1 with `heap-buffer-overflow WRITE
of size 2` at `xtrans_demosaic.cpp:427` (via `dcraw_process():184` ←
`dcraw_emu.cpp:598`), 0 bytes after the 2,147,616-byte region allocated at
`:177` (`evidence/dim1024-asan.out`). Fixed-tree `-n 1` rc 0 with empty output
(`evidence/dim1024-fixed-asan.out`); vulnerable tree without `-n` rc 0 with
empty output (`evidence/dim1024-asan-safe.out`). Plain `-O0` gdb with a
conditional breakpoint at `:427` (index >= 268,324) measured
`w=1024 h=1024 iw=512 ih=512 IDX=268324 avg={131070,131070,131070,2}
delta=0`, zeros before the store and `0xffff 0xffff 0xffff 0x0000` after it
(`evidence/gdb-dim1024.txt`, `evidence/gdb-dim1024-post.txt`). This is an
author-side result; witness replay is requested and has not yet arrived.

Negative result, preserved: D=256 and D=384 variants are rejected before the
store at `xtrans_demosaic.cpp:40` because `width < LIBRAW_AHD_TILE` (512);
the consumer cannot reach a smaller frame (`evidence/dim256-reject.out`,
`evidence/dim384-reject.out`, `evidence/gdb-dim256-reject.txt`). Larger D is
bounded here by the CFA pattern offset at 262,144 in the pinned file layout.
Ceiling unchanged: the value is still the saturated constant `0xffff`, no
arbitrary bytes, no pointer/IP, no consumer beyond `dcraw_emu`, NO r5.


## Combined index + value steering at D=1024 (W7, 2026-11-24 10:0xZ; author-side)

The two steerable axes are independent: the W6 exact-hit WhiteLevel does not
transfer to the W5 far frame. `craft_whitelevel_poc.py` with WL 11,036 on
`evidence/dim1024.input` produced `evidence/dim1024-wl11036.input` (sha256
`6df37eb18792169d21fbd60179a1368a992fe1e1537c22d89ed7a7e40e76ae70`);
plain `-O0` gdb at index 268,324 read `avg={10392,10383,10384,1}` and stored
`0x2898 0x288f 0x2890` (`evidence/gdb-dim1024-wl11036.txt`). The far frame's
raw-field scale constant is about 1.147e8, not the 1.844e8 of the D=512 field,
because `craft_dimension_poc.py` scales the zero scan field with frame area.

Pre-registered target 1, `0x4141`, was NOT reachable at the far index: WL
6,864 / 6,866 / 6,867 gave `0x4146` / `0x4142` / `0x413e`
(`evidence/gdb-dim1024-wl6864.txt`, `-wl6866.txt`, `-wl6867.txt`); local
granularity there is 2-4 halfwords per WhiteLevel unit. Pre-registered target
2, `0x1234`, WAS hit exactly after recalibration to WL 24,601 on the same far
frame: `evidence/dim1024-wl24601.input` sha256
`b894e63c5e70cf685bb1a309e9c14ee265bcec8068a6bbe4aac55023138c0f77`,
`IDX=268324 avg[0]=4660`, zeros before the store and `0x1234 0x1231 0x1231`
after it (`evidence/gdb-dim1024-wl24601.txt`, plus two byte-identical fresh
runs `-run2.txt` and `-run3.txt`). WL 24,600 / 24,602 / 24,603 gave `0x1235`
/ `0x1233` / `0x1234`; the sweep is preserved in `gdb-dim1024-wl246*.txt`.
ASan on the exact-hit input: vulnerable `-n 1` rc 1 with `WRITE of size 2` at
`:427`; fixed rc 0 empty; vulnerable no-option rc 0 empty
(`dim1024-wl24601-asan-*.out`). The same three controls on the WL 6,864
combined input were also clean (`dim1024-wl6864-asan-*.out`).

This is a pre-chosen 16-bit value at a second pre-chosen offset (268,324),
calibrated independently of the D=512 hit. It does not change the ceiling:
no arbitrary alphabet at either offset, no pointer/IP, no consumer beyond
`dcraw_emu`, no wire path, NO r5. Author-side only; no replay requested.

## Allocator-config dependence of the OOB reach (W9, 2026-11-24 13:4xZ; author-side)

Prediction recorded before the run: at D=512 the ~524 KB shrunk `image`
freed in `pre_interpolate()` would raise glibc's dynamic mmap threshold
enough that `destimage` (549,152 bytes) would be mmap-backed and fault
within a page or two of the region. The prediction was WRONG under the
default environment: `destimage=0x55555573abc0` is on the main `[heap]`
(0x555555716000-0x5555557e2000), requested end `0x5555557c0ce0`, gap to
the mapping edge ~135,968 bytes. With the breakpoint deleted the first
OOB index 68,644 advances to a fault at `IDX=85,640` (16,996 extra
indices), address `0x5555557e2000`, exactly the `[heap]` end.
`malloc_stats()` reports Arena 0 system bytes 835,584 / in use 636,128
(`w9/extent512.txt`). D=512 and D=1024 (W8) are therefore nearly the same
layout: one ~135 KB free top chunk, then the mapping edge.

Testing the cause: the gap matches glibc's default 128 KB `top_pad`.
With `MALLOC_TOP_PAD_=0` in the process environment, `destimage` becomes
mmap-backed (`0x7ffff7a82010` at D=512, `0x7ffff73ee010` at D=1024) and
the stores continue far past the region. D=512 faults at `IDX=172,038`
(103,394 extra indices), address `0x7ffff7bd2040`, the start of
libgcc_s.so.1's read-only page; D=1024 faults at `IDX=533,510` (265,186
extra), address `0x7ffff7800040`, the start of libc's read-only page
(`w9/toppad-nonzero-oob.input.txt`, `w9/toppad-dim1024-wl24601.input.txt`).
At D=512 a contiguous anonymous rw mapping spans `0x7ffff7a82000` to
`0x7ffff7bd2000` and is traversed before the fault; `/proc/maps` cannot
show whether that is one object or several, and no live object, pointer
or value was identified there (`w9/toppad-map.txt`).

So W8's "one free chunk then the guard page" is the default glibc
configuration in this consumer, not a fixed property of the bug: the OOB
reach is allocator-state dependent and changes by roughly 6x (D=512) or
15x (D=1024) when the environment changes. `MALLOC_TOP_PAD_` is a lab
environment knob, not attacker-controlled through the crafted image;
this is a config sensitivity, not a grooming exploit. No pointer/IP,
marker, command or wire path. Rung 4 and rung 5 are unchanged: NO r5.

## Plain-build heap extent of the OOB store (W8, 2026-11-24 12:1xZ; author-side)

Prediction recorded before the run: the scratch buffer would be mmap'd and
the first OOB store would fault on an unmapped guard page. That prediction
was wrong — in the plain `-O0` build the buffer is a heap chunk. With the
D=1024 exact-hit input `evidence/dim1024-wl24601.input`, the first OOB stop
gives `destimage=0x55555573abc0`, requested `allocate_sz=2,146,592` bytes
(`(512+6)^2*8`, requested end `0x555555946ce0`), `malloc_usable_size=2,147,624`
and a chunk header of 2,147,632 bytes, so the chunk ends at `0x5555559470f0`.
The `[heap]` mapping ends at `0x555555968000`; the chunk walk from
`0x5555559470f0` finds exactly one chunk, size 134,944 bytes, ending at the
heap boundary — the free top chunk. No live allocation lies between the
scratch buffer and the mapping edge. `malloc_stats()` reports
`Arena 0: system bytes=2,433,024, in use bytes=2,233,568`
(`w8/mallocstat-dim1024.txt`, `w8/heapwalk2-dim1024.txt`).

With the breakpoint deleted, stores continue 17,378 indices past the first
OOB index before faulting in the store loop itself: `IDX=285,702`,
`row=276 col=3 top=3 left=3`, `SIGADDR=0x555555968bf0`, backtrace `:427` ←
`dcraw_process():184` ← `dcraw_emu.cpp:598` (`w8/segv-dim1024.txt`,
`w8/heapwalk-dim1024.txt`). The fault is about 139 KB past the requested
allocation and just past the `[heap]` mapping. Plain (no gdb) `-n 1` runs of
`nonzero-oob.input`, `whitelevel4095.input` and `dim1024-wl24601.input` all
exit 139 with empty stderr (`w8/plain-rc.txt`), so the terminal fault is not
a gdb artifact. The overwrite first crosses the one free chunk's metadata and
then faults on an unmapped page; no adjacent live object or pointer was
observed on this host, and no post-corruption allocation is reached in this
path. This is a structural negative result, not a new primitive: no
pointer/IP, no marker, NO r5.

Preserved measurement error: an initial plain-run rc loop printed rc 0
because `$?` was read after a command substitution had reset it; re-running
with `rc=$?` captured immediately gave 139 for all three inputs. The wrong
value was never published in the report or the wall.

## Second file-controlled value knob: DNG BlackLevel (W10, 2026-11-24 14:1x-14:3xZ; author-side)

Prediction recorded before the experiment in
`lab/frontier/libraw2shell/w10/prediction.txt`: the pinned TIFF parser handles
DNG `BlackLevel` (tag `0xc61a`) at `src/metadata/tiff.cpp:1275`, and the
`len == 1` branch at `:1307-1310` sets `dng_black`/`black`. If that field is a
second integer knob, the W6 target `0xdead`, unreachable with WhiteLevel
alone, should become reachable. `craft_blacklevel_poc.py` rewrites the PoC's
unused IFD slot 2 (tag `0x00fe`, LONG count 1 value 0) as tag `0xc61a`, SHORT
count 1; the JPEG strip, CFA and WhiteLevel are untouched.

On the unmodified `-O0` build under gdb with `-n 1` and WhiteLevel 11,036,
BlackLevel 0/1/2/10/100/1000 produced first-OOB stores
`0x4141 / 0x4139 / 0x4132 / 0x40f7 / 0x3e57 / 0x217e` at index 68,644, and
gdb reported `black=1 ... white=11036` for BL=1: the tag is parsed and
steers the value. A one-shot `fprintf` patch to a copied `-O0` tree
(`w10/instrument.patch`) made a 441-point grid practical; all final claims
below were re-measured on the unmodified build.

Corrected grid over WhiteLevel 3,225-3,245 and BlackLevel 0-20
(`w10/grid-wide-results.txt`) hit the pre-chosen `0xdead` at WL=3,230, BL=6.
Input `w10/targetdead.input` sha256
`a1367d1e73606b183ef5175174c64d3a54070827e1184643c1a24a526772553c`.
Three fresh unmodified `-O0` gdb runs gave `IDX=68644`, `avg=57005,38009,
50670,1`, `black=6 white=3230`, and stored `0xdead 0x9479 0xc5ee 0x0000`
(`w10/dead-gdb-1.txt` .. `-3.txt`). Controls: ASan vulnerable `-n 1` rc 1
`WRITE of size 2` at `:427`; fixed `-n 1` rc 0 empty; vulnerable without
`-n` rc 0 empty. A second pre-chosen target, `0x2222` (also missed by W6's
WL-only sweep), was hit at WL=21,084, BL=1 with input
`w10/target2222.input` sha256
`eb69f4e3ffd3f288f9244f0da73e12071a753c546a7accaac501d8eeeabf90c3`;
3/3 gdb runs stored `0x2222 0x16c2 0x1e57 0x0000` at index 68,644, with the
same ASan/fixed/no-option control triple.

Measurement error preserved: the first grid passed `"-n 1"` as a single argv
element, so the consumer printed `Unknown option "-n 1".` and produced a
different value map. It falsely indicated WL=3,235, BL=1 -> `0xdead`; correct
argv and gdb give `0xde95` there. The invalid map is kept in
`w10/grid-invalid-argv.txt` and is not evidence. The two exact values are a
refinement, not an arbitrary alphabet: the grid left many targets
unreachable at their local (WL, BL) granularity. W6/W7 WL-only misses stay
valid negatives for that narrower method. No pointer/IP, marker, command,
adjacent live object, GUI, wire path or r5. Full method, hashes and raw
traces: `lab/frontier/libraw2shell/w10/results.txt`.

## Arbitrary 16-bit value from DNG LinearizationTable (W11, 2026-11-24 15:5x-16:1xZ; author-side)

Prediction recorded on the wake wall before the first run: the pinned
`src/metadata/tiff.cpp:1109-1113` parses DNG tag `0xc618` (LinearizationTable)
with `linear_table(len)`, which fills `curve[]` from file bytes and extends the
last entry over all 65,536 samples (`src/utils/curves.cpp:145-155`);
`src/decoders/dng.cpp:34-51` stores `curve[raw]` into every decoded pixel.
`craft_linearization_poc.py` (sha256
`74ca3ee9a74e410682bb3588c0e99fa9c499f294ca79eb76e1055d4fb213cc1c`) rewrites
the PoC's unused IFD slot 2 as `0xc618` SHORT count 1. With the source
WhiteLevel of 255 the store still saturated to `0xffff`; setting WhiteLevel
to 65535 with the existing `craft_whitelevel_poc.py` makes the scale factor
65535/65535 and removes that confound. The saturation is preserved as a
negative, and a low-value probe (`0x0010`, WL=255, stored about `0x1010`)
showed the table is applied rather than overwritten by a later gamma curve.

Seven pre-chosen values were mapped with a fast breakpoint probe: `0x0001`,
`0x00a5`, `0x1337`, `0x7f7f`, `0x8000`, `0xbeef` and `0xffff` each produced
exactly the same value in the second stored halfword. Exact first-OOB index
(68,644) was then confirmed on the unmodified `-O0` build under gdb with
`-n 1`, 3/3 byte-identical runs each: `0xbeef` stored
`0xffff 0xbeef 0xfe93 0x0000`, `0x1337` stored
`0x1cd1 0x1337 0x199e 0x0000`, `0x00a5` stored
`0x00f6 0x00a5 0x00db 0x0000`; the edges `0x0001` and `0xffff` were confirmed
once each (`0x0000 0x0001 0x0001 0x0000` and all three `0xffff`). Input hashes,
traces and the exact command sequence are in
`lab/frontier/libraw2shell/w11/results.txt` and PINS.md. Each input passed the
same control triple: ASan vulnerable `-n 1` rc 1 `WRITE of size 2` at `:427`,
fixed `-n 1` rc 0 empty, vulnerable without `-n` rc 0 empty.

This is an arbitrary 16-bit value in **one** of the three halfwords written at
the chosen offset, from two ordinary DNG metadata fields. The other two
halfwords are X-Trans interpolation results and are not independently chosen
(see the exact values above); this is not an arbitrary byte sequence across
the whole store. No pointer/IP, marker, command, adjacent live object, GUI
consumer, wire path or r5. Author-side only; no witness replay.


## BlackLevel cannot separate the OOB channels (W12, 2026-11-24 17:3xZ; author-side negative)

Prediction recorded before the run: W11's LinearizationTable makes `curve[]`
uniform, so BlackLevel should not independently steer the two interpolation-
determined halfwords at index 68,644. Tested two placements of DNG tag 0xc61a
on top of `w11/targetbeef.input` (WL=65535, LIN=0xbeef):

- IFD1 slot 0, originally `0x00fe` LONG/1 on the 8x8 thumbnail, rewritten as
  `0xc61a` SHORT/1 (`craft_dual_knob_poc.py`, sha256
  `040d072625aa6e7394754232ede77585b2a3bed7502ecf4223487f134c908441`):
  BL=0/1/10/100/1000 left `black=0` and the stored halfwords byte-identical
  at `ffff beef fe93 0`. Prediction confirmed.
- IFD0 slot 21, `0xc68d` ActiveArea=(0,0,512,512), rewritten as `0xc61a`
  SHORT/1: this one parses (`black=0/6/1000`). Unmodified `-O0` gdb at the
  exact first OOB index: BL=0 `c0=65535 c1=0xbeef c2=0xfe93`; BL=6
  `c0=65535 c1=0xbeed c2=0xfe91`; BL=1000 `c0=65535 c1=0xbedb c2=0xfd39`.
  In a uniform field all three channels shift together. The map is effectively
  degenerate (`c2 ~= 4/3 * c1` at every BL), so the pair (LIN, BL) still cannot
  set two channels independently. This is a coupled fine shift, not a second
  arbitrary alphabet.

Controls on `w12/ifd0beef-bl6.input`: ASan vulnerable `-n 1` rc 1 `WRITE of
size 2` at `:427`, fixed rc 0, vulnerable without `-n` rc 0. Raw traces,
hashes and both negatives are in `lab/frontier/libraw2shell/w12/results.txt`
and PINS.md. Upstream issue #894 was rechecked 17:30Z: still open, last
updated 2026-11-17, no merged fix; fixed status UNKNOWN. Ceiling unchanged
from W11; author-side only, no replay requested for a negative.

## Rung-4 assessment and rank

Rungs 1-3 are demonstrated in the real `dcraw_emu` consumer with the public
file (W186 witness ESTABLISHED). Rung 4 is demonstrated for a crafted nonzero
input and ESTABLISHED by the W187 witness replay: the OOB store at index
68,644 writes chosen nonzero halfwords with clean fixed and no-option
controls. W3 additionally shows witness-established (DM 3413) file steering
of the value to distinct non-saturated halfwords. W6 adds an author-side exact
hit on one pre-chosen halfword (`0x4141`) at index 68,644 via WhiteLevel
calibration, with a preserved negative for a second target. W5 adds
author-side, replay-pending steering of the first OOB index from 68,644 to
268,324. W7 combines them: a second pre-chosen halfword (`0x1234`) hit exactly
at the steered index 268,324 with its own calibration, while the W6
calibration does not transfer. W10 adds a second independent file field,
DNG BlackLevel, that makes two further pre-chosen halfwords (`0xdead`,
`0x2222`) exact at index 68,644, each 3/3 stable with clean controls;
WL-only misses are not erased. W11 adds a file-chosen arbitrary 16-bit value
in the second halfword at index 68,644 via the DNG LinearizationTable plus
WhiteLevel=65535, exact 3/3 for `0xbeef`, `0x1337` and `0x00a5`, with both
edges checked once and clean controls; the other two halfwords remain
interpolation-determined. W8 adds a host-specific heap-layout result:
the store crosses one free top chunk and faults at the heap edge, with no
live neighbor to hijack in this path; it is a structural negative result,
not a new primitive. W11 does not change the offset, the other two halfwords
or the local-file threat model; fully arbitrary byte sequences and pointer/IP
control remain UNKNOWN. Rank: high
tractability, low escalation
(local file, UI:P, no network, no pointer/command execution). Admitted frontier
target since 2026-11-24 05:4xZ; NO rung 5.

## Witness verdicts (W186, W187 and W3 steering, 2026-11-24)

W186: independent clean-room replay from only the pinned tarball, patch, PoC,
zip, bootstrap.sh and run-all.sh: every pinned hash matched, bootstrap rc0,
run-all rc0 with 10 PASS / 0 FAIL. The first 13 `evidence.log` lines are
byte-identical to the committed log; the tail differs only in negative-result
artifacts and build-path-dependent binary/output hashes. Verdict: CLAIM
ESTABLISHED AS LABELED — rungs 1-3 confirmed in the real consumer, chosen
offset at index 68,644, zero stored halfwords, rung 4 PARTIAL, NO r5.

W187 (DM 3405, 07:23Z): clean-room replay of the W2 nonzero refinement in the
surviving `/tmp/w186-libraw` tree, live tree untouched; generator
`004ff435...f862` and derived input `b59f64e9...9341` hashes matched PINS.md.
ASan vulnerable `-n 1` rc 1 with `WRITE of size 2` at `:427`; fixed tree rc 0;
vulnerable tree without `-n` rc 0; plain `-O0` gdb `IDX=68644
avg={131070,131070,131070,2} delta=0` and stored `0xffff 0xffff 0xffff 0x0000`.
Verdict: ESTABLISHED AS LABELED; rung 4 upgraded from PARTIAL to demonstrated
chosen-nonzero-halfword write at the chosen offset; ceiling unchanged (constant
`0xffff`, no arbitrary byte, no r5). The W3 steering result is covered by the
DM 3413 verdict below.

W3 steering (DM 3413, 2026-11-24): the witness regenerated the generator
`ab5ace42...b30d1cf`, source `b59f64e9...9341` and all four derived inputs
(`d398d0e7...35f5`, `8d9b5204...b905`, `50c91fbb...e42b`, `2547a078...bc8`)
in the surviving `/tmp/w186-libraw` clean room built only from the pinned
artifacts; live tree untouched, all PINS.md hashes matched. `cmp` of
WhiteLevel=4095 against the nonzero source showed exactly one differing byte:
the `u32` at `0x102` (255 -> 4095); the 22-entry IFD and JPEG strip were
unchanged. Plain `-O0` gdb at `xtrans_demosaic.cpp:427`: `IDX=68644 delta=0`,
zeros before the store and, after it, WL2048 `avg={65535,60057,65535,1}`
`0xffff 0xea99 0xffff 0x0000`; WL4095 `avg={45023,30020,40021,1}`
`0xafdf 0x7544 0x9c55 0x0000`; WL8191 `avg={22508,15007,20007,1}`
`0x57ec 0x3a9f 0x4e27 0x0000`; WL16383 `avg={11253,7503,10002,1}`
`0x2bf5 0x1d4f 0x2712 0x0000` — all matching the committed
`gdb-whitelevel*.txt`. WL4095 controls: ASan vulnerable `-n 1` rc 1,
`WRITE of size 2` at `:427` 0 bytes after the 550,176-byte region; fixed
tree rc 0 empty; vulnerable no-option rc 0 empty. Verdict: CLAIM ESTABLISHED
AS LABELED — rung 4 refined to three distinct file-steered non-saturated
16-bit halfwords at the chosen offset. Ceiling preserved: reporter-patch
control only, optional thumbnail region, no real camera/GUI/network path, no
arbitrary byte alphabet or pointer/IP/command, NO r5.

## Ceiling / UNKNOWNs preserved

- No upstream fix release or merged patch; the fixed control is the
  reporter's proposed two lines. Upstream fix status remains UNKNOWN.
- No real camera file, GUI consumer, network path, pointer/IP, command
  execution, grooming/ASLR study or rung 5. Witness verdicts cover the
  original zero-valued claim (W186), the W2 nonzero claim (W187) and the W3
  WhiteLevel steering claim (DM 3413); all ESTABLISHED AS LABELED.
- W8 measured the plain-build heap extent on this host under the default
  environment (one free top chunk, then the unmapped heap edge; crafted
  inputs exit 139); W9 added D=512 and `MALLOC_TOP_PAD_=0` measurements
  showing the reach is allocator-config dependent, not a fixed bug
  property. Neither is a grooming study or an adjacent-object exploit:
  no live object or pointer was identified between the scratch buffer
  and the fault. No pointer/IP, no marker, NO r5.
- Arbitrary byte sequences remain UNKNOWN, but a 16-bit value in one stored
  halfword is now file-controlled: W2 wrote a saturated constant `0xffff`; W3
  steered three distinct non-saturated halfwords via one DNG metadata tag; W6
  hit one pre-chosen value `0x4141` exactly at index 68,644 and W7 hit another
  (`0x1234`) exactly at index 268,324, each with its own WhiteLevel
  calibration. `0xdead` and `0x2222` were unreachable at D=512 via
  WhiteLevel alone (W6 negatives), but W10 reached both exactly by adding a
  second DNG integer field, BlackLevel (`0xdead` at WL=3,230/BL=6; `0x2222`
  at WL=21,084/BL=1). W11's DNG LinearizationTable with WL=65535 put seven
  pre-chosen 16-bit values, including both edges, into the second halfword at
  index 68,644 (three confirmed 3/3). W13 extended this to THREE independently
  file-chosen halfwords at the same offset (`0x9000 0xbeef 0xdead`, 3/3) by
  giving each CFA color its own raw sample and curve entry. That is six chosen
  bytes at one chosen offset, not an arbitrary byte sequence across memory;
  pointer/IP control remains an open prerequisite.
- The W5 frame-size/IDX steering result, the W6/W7 exact-hit results, the
  W10 two-field exact hits, the W11 linearization values and the W13
  three-channel chosen triple are author-side only; witness replay for W5
  (note 3451) and W11 (note 3717) has not arrived. Do not treat them as
  ESTABLISHED.
- Target admitted 05:4xZ as route #127. Operator owns standing approvals;
  the person owns the charter, wake units and full-flag sync. No external
  probing was done.

## Three independently chosen halfwords (W13, 2026-11-24 20:2xZ; author-side)

W12 closed BlackLevel as a channel-separating knob; the open prerequisite was
a non-uniform raw field. `craft_uncompressed_poc.py` (sha256
`0d91b5a8324a814fb7097051a456949dac610ff9d21d8c22d717beedddf1749c`) turns
the W11 input into a compression=1 DNG: 512x512 packed 12-bit samples plus a
4096-entry SHORT LinearizationTable at the formerly unused IFD slot 2.
`packed_dng_load_raw()` (`src/decoders/dng.cpp:140-180`) feeds every sample
through `curve[]` in `adobe_copy_pixel()` (`:34-51`), so each CFA color can be
given a distinct file-chosen raw sample. The real `dcraw_emu` consumer and the
vulnerable code path are unchanged.

An all-2048 baseline reproduces W11 exactly under the unmodified `-O0` gdb
probe: `IDX=68644 avg={131070,97758,130342,2}`, stored
`0xffff 0xbeef 0xfe93 0x0000`. Giving color-0 pixels raw 1 -> `curve[1]=0x1234`
and color-2 pixels raw 2 -> `curve[2]=0x5678` (green still `0xbeef`) stored
`0x8e74 0xbeef 0x9c1c 0x0000` at the same index: c0 and c2 moved separately.
Calibration sweeps (recorded in `lab/frontier/libraw2shell/w13/results.txt`)
mapped each curve value to its halfword; target `0xa5a5` was NOT reachable
(26113/26114 produced `0xa5a4`/`0xa5a6`), preserved as a negative.

Final pre-chosen triple `0x9000 0xbeef 0xdead`: spec
`w13/dead-target.json` sha256
`b3e416486b13e0fb2994b1c194c9ed50dbea573febe15894ef9f0ff830eea43e`, input
`w13/dead-target.input` sha256
`18b012c98809a9f4822a173ee591b046db3b6eb612326e30e259984467149e78`.
Three fresh plain `-O0` gdb runs, byte-identical: `IDX=68644
avg={73728,97758,114010,2}` and `&destimage[68644][0] =
{0x9000,0xbeef,0xdead,0x0000}`. Controls on the same input: ASan vulnerable
`-n 1` rc 1 with `WRITE of size 2` at `xtrans_demosaic.cpp:427`; fixed tree
rc 0 empty; vulnerable no-option rc 0 empty. Reproduce with the generator,
spec and the pinned `-O0` tree or the `probe.gdb` breakpoint used in W11.

Grade: six chosen bytes at a chosen heap offset in the real consumer, each
halfword steered by a distinct file-controlled field. NOT an arbitrary byte
sequence across memory, no pointer/IP, marker, command, adjacent live object,
GUI, wire path, merged upstream fix or r5. Author-side only; no witness
replay yet. All experiments local and loopback-free.
