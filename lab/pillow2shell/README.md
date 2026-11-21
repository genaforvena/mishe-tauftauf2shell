# Pillow2Shell W1 — real-path consumer check artifacts

Supporting material for `reports/pillow2shell-consumer-reality.md`
(CVE-2026-112398). No network probe: the two Pillow sdists were fetched from
PyPI as provisioning; all runs were local processes.

Files:

- `make_case.py` — builds a real OLE2/FlashPix file from Pillow 12.2.0's
  `Tests/images/input_bw_five_bands.fpx` by replacing three equal-size streams
  with `olefile.write_stream`: a 2-band LA property set, a one-tile JPEG header
  (`internal_color_conversion=1` -> `jpegmode=None`), and a 256-wide 4-component
  CMYK JPEG whose decoded bytes are chosen by its coefficients.
  Usage: `python3 make_case.py OUT.JPX JPEG_WIDTH FILL16 TILE_W TILE_H`.
- `case.fpx` — 16x16 tile, input fill `0x5a` (decodes `0xa5`).
- `case5a.fpx` — 16x16 tile, input fill `0xa5` (decodes chosen `0x5a`).
- `case64.fpx` — 64x64 tile, input fill `0xa5`; accepted by both 12.2.0 and
  13.0.0 front ends, so it isolates the decoder guard in the fixed build.
- `observe.gdb`, `observe200.gdb` — hardware-watchpoint scripts for the first
  past-end byte and for offset +200, respectively.
- `load_v12.log`, `load_v13.log` — vulnerable load succeeds; fixed load fails
  with `OSError: broken data stream when reading image file`.
- `gdb_watch32.log`, `gdb_watch200.log` — watchpoint fires from
  `libjpeg.so.8` with `0x00 -> 90 'Z'` at +32 of a 32-byte buffer and +200 of
  a 128-byte buffer.

Rebuild:

```
CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address" python3 -m pip install --no-binary :all: \
  --no-deps --target /tmp/pw2-w1/v12 pillow-12.2.0.tar.gz
# same for 13.0.0 -> /tmp/pw2-w1/v13
PYTHONPATH=/tmp/pw2-w1/v12 LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
  ASAN_OPTIONS=detect_leaks=0 python3 -c \
  'from PIL import Image; Image.open("case64.fpx").load()'
```

ASan alone stays silent because the host `libjpeg.so.8` is uninstrumented;
the gdb logs are the corruption detector. No pointer, object neighbour or
control-flow claim is made here.

Case-file SHA-256 (regeneration of `case64.fpx` is byte-identical):

```
8bd3fcd3a1b6b8515617da9964b5c57913bb169c103767f9ca5ce95aac8128d4  case.fpx
32ab85471e9fefd9dd03be540e7fca006840ee870c672e2e4b11dec62ea4dbd1  case5a.fpx
0b258df0b41064a975aed808b32866157ffb7cc60bfe29e8a1c00db9902fa9c0  case64.fpx
```

In-library ASan evidence (ASan-instrumented libjpeg-turbo 2.1.5.1, `WITH_SIMD=0`):

- `asan_libjpeg_v12.log` — `heap-buffer-overflow`, `WRITE of size 1` exactly
  0 bytes after the 128-byte tile buffer, stack
  `null_convert` -> `sep_upsample` -> `jpeg_read_scanlines` ->
  `ImagingJpegDecode src/libImaging/JpegDecode.c:252`, allocation from
  `_setimage src/decode.c:226`.
- `asan_libjpeg_v13_fixed.log` — same file, fixed build: opens, then load
  fails with `OSError: broken data stream when reading image file`, no ASan
  report.
- `build12ja.log`, `build13ja.log`, `jpeg-cmake.log`, `jpeg-make.log` —
  build records with `JPEG_ROOT=/tmp/pw2-w1/jpegasan` and the instrumented
  libjpeg prefix.
