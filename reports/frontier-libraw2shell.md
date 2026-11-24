# frontier brief — libraw2shell (candidate, FRONTIER-STAGED)

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
Hashes: `evidence/evidence.log` (10 PASS / 0 FAIL, sha256
`8ad12e49ac28c2549b87c9707da47e632bcfbf99d5c7eb26716e950b9f874f57`)
and `evidence/hashes.sha256`. Both source trees and all four binaries are
derived from the pinned tarball and verbatim patch.

## Chosen-byte attempts — negative results preserved

The OOB values are file-derived but the public PoC's raw strip decodes to an
all-zero image, so `avg[c]/avg[3]` is zero at the first OOB store. I tried to
make the written bytes attacker-chosen and did **not** succeed:

- Replacing the embedded JPEG with a constant 0x4d JPEG (`craft_poc.py`)
  still produced an all-zero output PPM and zero OOB halfwords
  (`evidence/gdb-crafted-oob.txt`, `asan-crafted.out`).
- Zeroing the DNG `0xc61d` tag and enlarging `StripByteCounts` did not change
  the decoded pixels (`var-A`/`var-D`/`var-E`: rc 0, zero-valued PPM).
- Converting the strip to uncompressed constant pixels (with CFA pattern
  relocated) was rejected by LibRaw with `Input/output error`, rc 2
  (`var-B`/`var-C`, `asan-uncomp.out`).

Thus chosen *offsets* are demonstrated (one pixel past the allocation,
deterministic from the TIFF geometry) but chosen *bytes* are NOT: the written
value is zero in every reproduced case. The artifact `craft_poc.py` remains as
the record of the failed lane; no claim of byte control is made.

## Rung-4 assessment and rank

Rungs 1-3 are demonstrated in the real `dcraw_emu` consumer with a real
public file: deterministic trigger, ASan-confirmed heap corruption, fixed and
valid-input controls. Rung 4 is partial: a deterministic chosen offset is
written with a zero value, not attacker-chosen bytes. Rank: high tractability
for the rung-3 reproduction (one-line conceptual fix, public PoC, quick
build), low escalation (local file, UI:P, no network, no byte/pointer control
demonstrated). Staged candidate, not admitted, not rung 5.

## Ceiling / UNKNOWNs preserved

- No upstream fix release or merged patch; the fixed control is the
  reporter's proposed two lines.
- No real camera file, GUI consumer, network path, pointer/IP, command
  execution, grooming/ASLR study, witness replay or rung 5.
- The byte-control lane failed as recorded above; a valid nonzero-pixel
  X-Trans DNG that LibRaw accepts is an open prerequisite for chosen-byte
  rung 4.
- Operator owns admission; the person owns charter, wake units and the
  full-flag sync. Do not duplicate this lane; no external probing was done.
