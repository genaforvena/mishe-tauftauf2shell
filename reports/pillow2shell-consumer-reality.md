# Pillow FPX scanline write — real-path consumer check (W1, 2026-11-21)

**Status: rung 4 CHOSEN BYTES AT CHOSEN OFFSETS, LIVE GLIBC HEAP METADATA
CORRUPTION AND A DETERMINISTIC PROCESS ABORT are now observed in a real
Python + Pillow 12.2.0 process, via a real OLE2/FlashPix file and libjpeg.
W1 observed an in-library AddressSanitizer `heap-buffer-overflow` WRITE with a
stack from `null_convert` through `jpeg_read_scanlines` to pinned
`JpegDecode.c:252`. W2 adds a plain non-ASan build where the chosen `0x5a`
overwrites the next malloc chunk's size field and two live heap chunks, then
5/5 runs end in SIGSEGV inside `PyGC_Collect()` at Python finalization, with
`MALLOC_CHECK_=3` reporting `corrupted double-linked list`. No pointer or PC
control, control-flow diversion, code execution or socket/server was observed;
those stay UNKNOWN. This extends the frontier harness result in
`reports/frontier-pillow2shell.md`. Witness replay #898/#900 returned
ESTABLISHED AS CLAIMED at this labeled grade; the witness's own rebuild matched
the stores and the fixed-build control. Author/operator replays are not
independent acceptance.**

## Repro (loopback-free local process; no network probe)

Everything durable is under `lab/pillow2shell/`. The volatile build tree was
`/tmp/pw2-w1/`; the two Pillow sdists came from PyPI as provisioning only.

1. Build both tags with ASan (rc 0 for each):
   `CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" LDFLAGS="-fsanitize=address" python3 -m pip install --no-binary :all: --no-deps --target /tmp/pw2-w1/v12 /tmp/pw2-dl/pillow-12.2.0.tar.gz`
   (same for `v13` / `13.0.0`). `nm -D PIL/_imaging*.so | grep -c asan` = 74
   (v12) / 76 (v13).
2. Craft a real OLE2 file: `python3 make_case.py case.fpx 256 0x5a 16 16`
   (also `case5a.fpx 256 0xa5 16 16`, `case64.fpx 256 0xa5 64 64`).
   The generator copies Pillow 12.2.0's real
   `Tests/images/input_bw_five_bands.fpx` and uses `olefile.write_stream` to
   replace three equal-size streams in place:
   - `\005Image Contents`: a minimal property set with width/height and a
     12-byte-plus-4 `VT_BLOB` of `bands=2`, colors
     `(0x00018000, 0x00017FFE)` -> `MODES` gives `("RGBA","LA")`;
   - `Subimage 0000 Header`: one tile, `xtile=ytile=width=height`,
     `compression=2`, `internal_color_conversion=1`, `jpeg_tables=0` ->
     `jpegmode=None` -> the `JCS_UNKNOWN` fallback at pinned
     `JpegDecode.c:220-221`;
   - `Subimage 0000 Data`: a 4-component CMYK JPEG, 256 px wide, quality 100,
     flat coefficient fill `0xa5` which decodes to exactly `0x5a`; JPEG starts
     at stream offset 56 (`tile offset 28 + 28`, matching the sample).
   The embedded JPEG's 4 x 256 = 1024-byte row is written into a tile buffer
   sized 2 bytes/pixel x 16 or 64 pixels = 32 or 128 bytes.
3. Open and load, with the ASan runtime preloaded because the host `python3`
   is not ASan-linked:
   `PYTHONPATH=/tmp/pw2-w1/v12 LD_PRELOAD=$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0 python3 -c 'from PIL import Image; im=Image.open("case64.fpx"); im.load()'`
4. Observe the actual store with a hardware watchpoint, because the host
   `libjpeg.so.8` is not ASan-instrumented:
   `LD_PRELOAD=<libasan.so> PYTHONPATH=<v12> gdb -q -batch -x observe200.gdb --args python3 -c '...'`

## Observed bytes and frames

- `Image.open()` succeeds in both builds:
  `open (64, 64) RGBA LA`, tile
  `_Tile(codec_name='jpeg', extents=(0, 0, 64, 64), offset=56, args=('LA', None))`
  (`lab/pillow2shell/load_v12.log`).
- Real decoder geometry, observed by interposing `jpeg_read_scanlines` in the
  live v12 process:
  `[JPEG-TRACE] output_width=256 output_components=4 jpeg_color_space=0
  out_color_space=0 scale=1/1 max_lines=1`, called from
  `ImagingJpegDecode src/libImaging/JpegDecode.c:252`. `0` is `JCS_UNKNOWN`.
  (The interposer's `dlsym(RTLD_NEXT)` failed after printing this line, so that
  one run aborted; the printed geometry precedes the failure and is not used
  as the corruption detector.)
- v12 `load()` returns `LOAD OK (90, 90, 90, 90)` — `0x5a` is the chosen
  decoded byte — with **no ASan report**: ASan cannot see the uninstrumented
  libjpeg stores.
- 16x16 tile (`gdb_watch32.log`): at `ImagingJpegDecode` entry
  `buffer=0x50300001f120 bytes=32 xsize=16 ysize=16`. Watch
  `buffer + 32` (first past-end byte) ->
  `Old value = 0 '\000'`, `New value = 90 'Z'`,
  frame `0x... in ?? () from /lib/x86_64-linux-gnu/libjpeg.so.8`.
- 64x64 tile (`gdb_watch200.log`): entry
  `buffer=0x50c0000007c0 bytes=128 xsize=64 ysize=64`. Watch
  `buffer + 200` (72 bytes past the allocation) -> same `0x00 -> 90 'Z'` in
  `libjpeg.so.8`; `x/16bx buffer+200` reads back `0x5a` at the watched byte.
- Fixed `13.0.0` on the byte-identical `case64.fpx`
  (`lab/pillow2shell/load_v13.log`): `open (64, 64) RGBA LA` succeeds, then
  `OSError: broken data stream when reading image file` — the decoder guard
  at fixed `JpegDecode.c:247-253` rejects `output_width (256) > state->xsize
  (64)` before the scanline. 13.0.0 also adds a front-end guard rejecting
  tiles other than 64x64, which is why the first 16x16 case was rejected at
  open time; the 64x64 case isolates the decoder guard.

## In-library ASan report (instrumented libjpeg-turbo)

To remove the "ASan cannot see libjpeg" limitation, libjpeg-turbo 2.1.5.1
was fetched as provisioning, built from source with `WITH_SIMD=0` and
`-fsanitize=address -fno-omit-frame-pointer -g -O1`, and both Pillow tags were
rebuilt with `JPEG_ROOT=/tmp/pw2-w1/jpegasan` pointing at that prefix. The
built `_imaging.so` has no RUNPATH, so bare `ldd` can resolve the system
`libjpeg.so.62` despite `JPEG_ROOT`. Verify with
`LD_LIBRARY_PATH=/tmp/pw2-w1/jpegasan/lib ldd PIL/_imaging*.so` and use the
same export at run time:
`LD_LIBRARY_PATH=/tmp/pw2-w1/jpegasan/lib PYTHONPATH=/tmp/pw2-w1/v12ja LD_PRELOAD=$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0 python3 -c 'from PIL import Image; Image.open("case64.fpx").load()'`.
The witness hit the same loader gap on its independent rebuild and used the
analogous `/tmp/w73-pw2/jpegasan/lib` export. On the byte-identical `case64.fpx`:

- v12 (`lab/pillow2shell/asan_libjpeg_v12.log`):
  `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1` at
  `0x50c000000840`, reported as `0 bytes after 128-byte region
  [0x50c0000007c0,0x50c000000840)`, allocated by `calloc` at
  `_setimage src/decode.c:226`. Stack:
  `null_convert jdcolor.c:391` -> `sep_upsample jdsample.c:98` ->
  `process_data_simple_main jdmainct.c:313` -> `jpeg_read_scanlines
  jdapistd.c:298` -> `ImagingJpegDecode src/libImaging/JpegDecode.c:252` ->
  `_decode src/decode.c:132`. The reported address equals the gdb watchpoint
  buffer start `0x50c0000007c0` plus its 128-byte size — both detectors see
  the same allocation boundary.
- v13 built the same way (`lab/pillow2shell/asan_libjpeg_v13_fixed.log`):
  `open (64, 64) RGBA` succeeds, `.load()` fails with
  `OSError: broken data stream when reading image file`, **no ASan report**.

Build commands and full logs are in `lab/pillow2shell/`. This is not the host
libjpeg byte-for-byte (2.1.5.1 rebuilt here vs the host 2.1.5 runtime); it is
an ASan-instrumented build of the same upstream version family, used only to
make the store visible. The earlier uninstrumented-host run and the gdb
watchpoints are preserved as the independent observations.

## W2 — real glibc heap metadata corruption and deterministic abort (2026-11-21)

W1's gdb watchpoint buffer was a `0x50c...` ASan-heap address: its past-end
neighbour is an ASan redzone (`fa` in the shadow at
`asan_libjpeg_v12.log:46`), so that build cannot answer whether a live object
is reached. A PLAIN non-ASan Pillow 12.2.0 was built from the same pinned
sdist with pip build isolation and no sanitizer flags
(`/tmp/pw2-w2/v12plain`, build record `lab/pillow2shell/build12_plain.log`);
its `_imaging` links the host `/lib/x86_64-linux-gnu/libjpeg.so.8` and its
`calloc` at `_setimage src/decode.c:226` comes from glibc.

On the byte-identical `case64.fpx`, under gdb (`glibc_raw_layout_v12.log`):
`python3.12` is non-PIE (text at `0x400000`), brk heap `[0xbab000,0xdbf000)`,
buffer at `0xd7d8a0`, chunk header `0x91` (144-byte chunk, 136 usable).
`glibc_first_store_v12.log` catches the first past-end store with a hardware
watchpoint: `Old 0x00 -> New 90 'Z'` at `buffer+128` from `libjpeg.so.8`,
stack `jpeg_read_scanlines` -> `ImagingJpegDecode src/libImaging/JpegDecode.c:252`
-> `_decode src/decode.c:132`. At that instant the next chunk is live: user
`= buffer+144`, size field `0x21`, first words `0x0000000000c990d0` (brk heap)
and `0x00007ffff7e04b30` (libc rw data).

By the time a watchpoint at `buffer+200` fires (`glibc_metadata_overwrite_v12.log`):
the next chunk's **size field is `0x5a5a5a5a5a5a5a5a`**, its first 48 user bytes
are all `0x5a`, and the tile region `buffer+120 .. +167` is all `0x5a`. The
overrun crosses two live chunks (`glibc_live_chunks_v12.log`): a 32-byte chunk
at `buffer+144` and a 992-byte chunk at `buffer+176`, reaching 80 bytes into
the latter's user data. This is live heap data, not allocator slack.

Observable consequence, no debugger attached: five consecutive plain-build
runs each print `OK (90, 90, 90, 90)` and then exit with rc 139 (SIGSEGV);
`MALLOC_CHECK_=3` exits rc 134 with glibc `corrupted double-linked list`
(`glibc_malloc_check_v12.log`). The crash backtrace
(`glibc_crashbt_v12.log`) is `#0 0x61cb5a` -> `#2 PyGC_Collect()` ->
`#3 Py_FinalizeEx()` -> `Py_RunMain`. Control: a plain 13.0.0 build on the
same file opens, then `.load()` raises `OSError: broken data stream when
reading image file` and exits rc 1 without a crash
(`plain_v13_fixed_control.log`).

## Evidence-ladder disposition

- Rung 1 (primitive identified): ESTABLISHED (source + advisory pins).
- Rung 2 (deterministic trigger): ESTABLISHED (real FPX file, two builds).
- Rung 3 (confirmed memory corruption): ESTABLISHED twice independently —
  a gdb hardware watchpoint on a real libjpeg store past a live heap
  allocation in a real Pillow process, and an in-library ASan
  `heap-buffer-overflow` WRITE with a stack through `jpeg_read_scanlines` to
  pinned `JpegDecode.c:252`.
- Rung 4 (demonstrated security impact): **CHOSEN BYTES AT CHOSEN OFFSETS IN
  THE LIVE PROCESS, WITH LIVE GLIBC HEAP METADATA CORRUPTION AND A
  DETERMINISTIC PROCESS ABORT**. W1: +32 and +200 past 32- and 128-byte tile
  buffers, byte value chosen through JPEG coefficients (`0xa5` in -> `0x5a`
  out). W2: next malloc chunk size field `0x21 -> 0x5a5a5a5a5a5a5a5a`, two
  live chunks overwritten, 5/5 SIGSEGV in `PyGC_Collect()` at finalization,
  glibc `corrupted double-linked list` under `MALLOC_CHECK_=3`. Not
  demonstrated: control of a pointer value, PC or control flow, code
  execution, or the advisory's non-PIE `system@plt` chain. Do not upgrade the
  label beyond this.

## Boundaries and open work

All work was local; no socket, server, external probe or other plant was
touched. The real FPX front end, OLE2 parser, Pillow build, Python process and
host libjpeg are now all exercised. W2 resolves the W1 open question: the
bytes reach live glibc heap chunks and their metadata, not only slack, and
the corrupted heap deterministically aborts the process. Still UNKNOWN: which
specific Python object (if any) owns the crossed chunks; whether the write can
be steered into a chosen adjacent `bytes` object; any pointer value or marker;
control-flow diversion or execution; and the advisory's ASLR-disabled non-PIE
`system@plt` chain. A pointer or marker claim still waits for direct
observation of a controlled pointer. Witness replay of W1 (#898) and W2
returned ESTABLISHED AS CLAIMED at the report's labeled rung-4 grade; no
pointer, object-neighbour, control-flow or execution claim was verified.
