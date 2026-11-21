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
the gdb logs are the corruption detector. This W1 section makes no
object-neighbour or pointer claim; the W3 section below does.

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

Rebuild the in-library ASan case (instrumented libjpeg). `_imaging.so` has no
RUNPATH, so bare `ldd` can show the system `libjpeg.so.62` even with
`JPEG_ROOT`. Export `LD_LIBRARY_PATH` both when checking the loader and when
running the case; the witness needed the same export on its own rebuild:

```
cmake -S <libjpeg-turbo-2.1.5.1> -B /tmp/pw2-w1/jpeg-build \
  -DCMAKE_INSTALL_PREFIX=/tmp/pw2-w1/jpegasan -DWITH_SIMD=0 \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
cmake --build /tmp/pw2-w1/jpeg-build --target install
CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address" JPEG_ROOT=/tmp/pw2-w1/jpegasan \
  python3 -m pip install --no-binary :all: --no-deps \
  --target /tmp/pw2-w1/v12ja /tmp/pw2-dl/pillow-12.2.0.tar.gz
LD_LIBRARY_PATH=/tmp/pw2-w1/jpegasan/lib ldd /tmp/pw2-w1/v12ja/PIL/_imaging*.so
LD_LIBRARY_PATH=/tmp/pw2-w1/jpegasan/lib PYTHONPATH=/tmp/pw2-w1/v12ja \
  LD_PRELOAD=$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0 \
  python3 -c 'from PIL import Image; Image.open("case64.fpx").load()'
```

Use `/tmp/pw2-w1/libjpeg-turbo-2.1.5.1` source layout if following W1's paths;
`CMAKE_INSTALL_LIBDIR=lib` in `jpeg-cmake.log` confirms the exported `lib`
directory name.

## W2 — plain glibc heap evidence (2026-11-21)

A plain, no-sanitizer Pillow 12.2.0 build (`/tmp/pw2-w2/v12plain`, links host
`libjpeg.so.8`) makes the tile buffer's `calloc` come from glibc, so the
past-end bytes hit real heap metadata rather than an ASan redzone. On
`case64.fpx`:

- `glibc_raw_layout_v12.log` — non-PIE python3.12, brk heap, buffer chunk size
  field `0x91` (144-byte chunk, 136 usable).
- `glibc_first_store_v12.log` — hardware watchpoint at `buffer+128` fires with
  `0x00 -> 90 'Z'` in `libjpeg.so.8`, stack through pinned
  `ImagingJpegDecode src/libImaging/JpegDecode.c:252`.
- `glibc_metadata_overwrite_v12.log` — after the row write the next chunk's
  size field is `0x5a5a5a5a5a5a5a5a` and its user bytes are all `0x5a`.
- `glibc_live_chunks_v12.log` — the overrun crosses two live chunks (32 bytes
  at `buffer+144`, 992 bytes at `buffer+176`).
- `glibc_plain_run_run[1-5].log` — 5/5 runs print `OK (90, 90, 90, 90)` then
  exit rc 139. `glibc_malloc_check_v12.log` — `MALLOC_CHECK_=3`, rc 134,
  `corrupted double-linked list`.
- `glibc_crashbt_v12.log` — SIGSEGV in `PyGC_Collect()` / `Py_FinalizeEx()`.
- `plain_v13_fixed_control.log` — plain 13.0.0 on the same file raises
  `OSError` and exits rc 1, no crash. `build12_plain.log`,
  `build13_plain.log` — build records.

Rebuild the plain case:

```
python3 -m pip install --no-binary :all: --no-deps \
  --target /tmp/pw2-w2/v12plain /tmp/pw2-dl/pillow-12.2.0.tar.gz
PYTHONPATH=/tmp/pw2-w2/v12plain python3 -c \
  'from PIL import Image; Image.open("case64.fpx").load()'
```

W2 established chosen bytes plus live heap-metadata corruption and a
deterministic abort; W3 below adds a real Python object's pointer field.
No valid-pointer value, PC, marker or control-flow diversion was observed.

## W3 — CPython object field overwrite (2026-11-21)

- `glibc_pyobject_type_v12.log` — in the unmodified plain build, the 992-byte
  chunk at `buffer+176` has `ob_refcnt=2` and `ob_type = &PyUnicode_Type` at
  `ImagingJpegDecode` entry. A hardware watchpoint on `buffer+191` (last byte
  of `ob_type`) catches `0x00 -> 90 'Z'` from `libjpeg.so.8` through pinned
  `JpegDecode.c:252`; after the row both words read `0x5a5a...`. Chosen bytes
  replace a live Python object's pointer-typed field; the value is the
  repeated byte, not a chosen valid address.
- `glibc_pyobject_alloc_stack.log` — separate LD_PRELOAD allocator trace with
  shifted layout: the neighbour chunk came from `PyObject_Malloc` /
  `_PyObject_NewVar` / `_PyCode_New`. Supporting only; the `PyUnicode_Type`
  identification above is the direct observation.

Reproduce the direct observation with the plain build and `case64.fpx`:

```
PYTHONPATH=/tmp/pw2-w2/v12plain gdb -q -batch \
  -ex 'set breakpoint pending on' -ex 'break ImagingJpegDecode' -ex 'run' \
  -ex 'set $b=(unsigned char*)state->buffer' -ex 'p &PyUnicode_Type' \
  -ex 'x/4gx $b+176' -ex 'watch *(unsigned char*)($b+191)' -ex 'continue' \
  -ex 'printf "TYPE=%lx\n",*(unsigned long*)($b+184)' -ex 'x/4gx $b+176' \
  --args python3 -c 'from PIL import Image; Image.open("case64.fpx").load()'
```
