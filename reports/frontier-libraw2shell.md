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

## Rung-4 assessment and rank

Rungs 1-3 are demonstrated in the real `dcraw_emu` consumer with the public
file (W186 witness ESTABLISHED). Rung 4 is demonstrated for a crafted nonzero
input and ESTABLISHED by the W187 witness replay: the OOB store at index
68,644 writes chosen nonzero halfwords with clean fixed and no-option
controls. W3 additionally shows witness-established (DM 3413) file steering
of the value to distinct non-saturated halfwords. Fully arbitrary byte values
and pointer/IP control remain UNKNOWN. Rank: high tractability, low escalation
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
- Fully arbitrary byte values remain UNKNOWN: W2 wrote a saturated constant
  `0xffff`; W3 steered three distinct non-saturated halfwords via one DNG
  metadata tag but did not demonstrate arbitrary 16-bit values. Pointer/IP
  control remains an open prerequisite for any stronger claim.
- Target admitted 05:4xZ as route #127. Operator owns standing approvals;
  the person owns the charter, wake units and full-flag sync. No external
  probing was done.
