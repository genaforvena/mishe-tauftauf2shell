# Frontier brief — ccextractor2shell (CCExtractor issue #2500, no CVE)

Status 2026-11-25 10:37Z (W10): rung 3 and rung 4 CONFIRMED; rung 5 and the
witness verdict remain UNKNOWN. W9 measured a loopback wire-to-sink path in a
live CCExtractor process: `--udp 127.0.0.1:PORT` fed 257 paced 8192-byte
datagrams from `inputs/attack.gxf` reaches `parse_mpeg_packet`, where ASan
reports `WRITE of size 4160` at `buffer+BUFSIZE`; `readback.gxf` also
reproduces the program-consumed `READ of size 3900` at `boundary+76`. W10
then measured the heap layout on that same wire path under the plain pinned
build: the bytes after `data->buffer` are still bare top, no resolvable code
pointer exists in 64 KiB past the boundary, and the five post-parse mallocs
come from tcache below the buffer, so the wire path does not change the
structural ceiling for pointer control. W8 closed a sixth rung-5-adjacent
idea negatively: forging a small top-chunk size (`0x21`, `0x41`) does not
make post-parse allocations carve from the overflow region, and terminal
`free` consolidates the same way on safe input. The earlier bounded negatives
(W3-W7) are preserved. No controlled indirect call, pointer or command was
observed. Issue #2500 was rechecked 08:54Z via the GitHub issue API: still
open, created `2026-11-24T13:58:29Z`, last updated at creation, no fix PR or
CVE observed. No CVE/GHSA and no upstream fix PR were observed; the guard is
a local hunk, not a vendor patch.
All input files, logs and generators live in
`lab/frontier/ccextractor2shell/real-build/`; the harness source and its
evidence were not edited.

## Verified ground truth (read-only provisioning)

- Upstream: `https://github.com/CCExtractor/ccextractor.git`, shallow depth 1
  clone into `lab/frontier/ccextractor2shell/upstream` on 2026-11-25. Pinned
  HEAD `2c1c1c6f0602563d2064f2b0c36f13b3c7a09489`
  (`2026-11-24T07:50:42-0800`, "Clear the decoders' caption counts after a
  report (#2495)").
- Public claim: https://github.com/CCExtractor/ccextractor/issues/2500 ,
  opened `2026-11-24T13:58:29Z`, still open as of `2026-11-25T04:07Z`. No
  CVE/GHSA found; no upstream fix PR found. The proposed bounds guard below
  is a locally written hunk in the harness, **not** an observed vendor patch.
  Fix status UNKNOWN.
- Provisioning fetch/clone only; no probe touched an external target and the
  harness reads no network. Screened `reports/frontier-*.md`, the status
  reports and the frontier wall do-not-duplicate list before staging: no prior
  ccextractor entry. SOES, Assimp, FFmpeg, ClamAV, QuickJS-NG, OpenSSL/AWS-LC,
  Wireshark and all admitted targets were not touched.
- Exact file hashes are in `lab/frontier/ccextractor2shell/pins.sha256`;
  origin, stand-ins and build matrix are in `PROVENANCE.md` beside it.

## Source-bound mechanism (pinned bytes, no hand-edited vulnerable source)

`harness/parse_mpeg_packet.inc` is the verbatim function from
`src/lib_ccx/ccx_gxf.c:938-949` at the pinned HEAD, sha256
`d3ee937bfb03e07a34e383eb85f4836fb03d3402c7c1a848ba1ebf195416749a`
(the whole pinned `ccx_gxf.c` is
`519b5fd0672c949ec12cc811038e148e51260c3ef3796afb3cd704bf2693d14f`).
The sink, with no check against the buffer capacity:

```
result = buffered_read(demux, data->buffer + data->len, len);
data->len += len;
demux->past += result;
if (result != len)
    ret = CCX_EOF;
```

Size source, `ccx_gxf.c:1148-1150`: `mpeg_pic_size = buffered_get_be32(demux);
mpeg_frame_desc_flag = mpeg_pic_size >> 24; mpeg_pic_size &= 0xFFFFFF;`.
Verbatim excerpts of the size derivation and the MPEG2 caller are in
`harness/parse_media_pin.inc` (sha256
`4ba401660b3720a30fadcd74853b7ef7b95a20d549341483e0bdea58071b7334`); the
caller at `ccx_gxf.c:1219` is `parse_mpeg_packet(demux, mpeg_pic_size, data);`
followed by `:1220` `len -= mpeg_pic_size;`.

Buffer: `alloc_demuxer_data()` at `src/lib_ccx/ccx_demuxer.c:452` does
`data->buffer = (unsigned char *)malloc(BUFSIZE);` (file sha256
`84dee2fead39946f40d239366daf4726eca91eb312f2fbcbf90b93cd6635bcfc`).
`src/lib_ccx/ccx_common_constants.h:32-33` defines `ONEPASS 120` and
`#define BUFSIZE (2048 * 1024 + ONEPASS)`, i.e. **2097272** bytes (file sha256
`a704a86a42a3d7b1d06911eedf23b6920b02c112bfde7119ecf39ad3ddfa7b49`).
The real consumer behind `buffered_read` is `file_functions.c:376`
`i = read(ctx->infd, buffer, bytes);` into that destination (file sha256
`bf9ac0845d9124388ca81a3922fad67b2112194861584591ac89a48b5c0c9f6b`).

The harness derives the length from a 4-byte wire header with the same
be32-plus-mask arithmetic (the caller helper, not a driver-supplied integer):
attack header `00 20 10 00` → `0x201000` → derived `mpeg_pic_size=2101248`,
which is 3976 bytes past `BUFSIZE`; safe header `00 00 10 00` → 4096 bytes.
Only the read consumer, structs and allocation layout are stand-ins; the
vulnerable function is not edited.

## Lab evidence (`lab/frontier/ccextractor2shell/`)

`sh harness/run.sh` builds all six binaries and runs the matrix. Exact build
commands from `harness/run.sh`:

```
gcc -O1 -g -fsanitize=address -DASAN_BUILD -o vuln-asan harness.c
clang -O1 -g -fsanitize=address -DASAN_BUILD -o vuln-asan-clang harness.c
clang -O1 -g -fno-builtin-memcpy -fsanitize=address -DASAN_BUILD -o vuln-asan-clang-nobuiltin harness.c
gcc -O1 -g -o vuln-plain harness.c
gcc -O1 -g -DFIXED_BUILD -DASAN_BUILD -o fixed-asan harness.c
gcc -O1 -g -DFIXED_BUILD -o fixed-plain harness.c
```

Result: **17 PASS / 0 FAIL, rc 0**, recorded in the lab `harness/evidence/`
files and reproduced here from a read-only `cp -a` replay in
`/tmp/ccx2shell-replay` (that replay did not modify any lab file). Raw
results: `harness/evidence/*.out`.

- gcc ASan attack (`vuln-asan.out`): `ERROR: AddressSanitizer:
  heap-buffer-overflow`, `WRITE of size 2101248`, `0 bytes after 2097272-byte
  region`, stack `buffered_read harness.c:71` → `parse_mpeg_packet
  parse_mpeg_packet.inc:10` → `main harness.c:157`, rc 1.
- clang ASan with `-fno-builtin-memcpy` (`vuln-asan-clang-nobuiltin.out`):
  same `WRITE of size 2101248` and same region/frames, rc 1.
- **Preserved negative**: clang ASan with default builtins
  (`vuln-asan-clang.out`) did **not** report; it printed only
  `mode=attack derived_len=2101248 BUFSIZE=2097272 alloc=2097272 ret=0
  past=2101248` and exited 0. No rung-3 claim rests on that build.
- Plain build with slack allocation (`vuln-plain-attack.out`, `alloc=2105464`):
  `canary_at_BUFSIZE=5348452d434345584d495348452d4343` and `expected=`
  identical. Those are 16 bytes
  `53 48 45 2d 43 43 45 58 4d 49 53 48 45 2d 43 43` = "SHE-CCEXMISHE-CC",
  the repeating `"MISHE-CCEX"` pattern read from offset `BUFSIZE`, rotated by
  `BUFSIZE % 10 == 2`. The literal 0xCC sentinel is written at
  `BUFSIZE + 4000`, 24 bytes beyond the 3976-byte write end, and is not what
  the printed `canary_at_BUFSIZE` line samples.
- Local-guard FIXED_BUILD (`if (data->len + (size_t)len > BUFSIZE) return
  CCX_EOF;`) attack: `fixed-asan-attack.out` `ret=1 past=0`, ASan clean;
  `fixed-plain-attack.out` `ret=1 past=0` and `canary_at_BUFSIZE=0000…` (16
  zero bytes). Safe mode (`derived_len=4096`, `ret=0`) is clean in every
  build, including both ASan compilers.

## Honest rung assessment and ceiling (updated after real build)

Rung 3 is now confirmed twice: in the verbatim pinned function under gcc/clang
ASan with a memcpy stand-in (earlier), and in a real ASan build of the pinned
tree through `read(2)` from a local `.gxf` into `malloc(BUFSIZE)` (below). The
clang-default-ASan negative and the stand-in build remain part of the record.

Rung 4 is now CONFIRMED for chosen bytes at a chosen offset past the real
allocation, read back by the program's own consumer. The earlier debugger-only
observation is retained as history but is no longer the basis for the grade:
`real-build/inputs/readback.gxf` places `00 00 01 B3` as the first four bytes
past `BUFSIZE`. In the plain build the conditional `process_m2v` breakpoint
shows `length=2101248`, and `finish` shows the program's own consumed count
`got=2097348` (76 bytes past `BUFSIZE`), versus `got=2101248` for the original
attack payload with no start code. With ASan `halt_on_error=0` the same input
reports the original WRITE and then a second heap-buffer-overflow,
**`READ of size 3900` at `boundary+76`**, stack `memmove` interceptor →
`process_data general_loop.c:1041` → `process_non_multiprogram_general_loop
general_loop.c:1298`. The 3900 bytes are exactly
`2101248 - 2097348`, the unprocessed remainder the program shifts with
`memmove`. No pointer, instruction pointer or command was controlled.

There is no live process beyond these local lab runs, no pointer/IP/command
control, no rung 5, no independent witness replay, and no observed upstream
fix. Fix status and witness verdict are UNKNOWN.

## Executed local experiment: real pinned tree + crafted GXF

The previously planned cheapest experiment was executed on 2026-11-25
05:37-05:46Z. A clean copy of the pinned tree at
`/tmp/ccx2shell-upstream-asan` (HEAD `2c1c1c6f0602563d2064f2b0c36f13b3c7a09489`)
was configured and built under ASan:

```
cmake -S /tmp/ccx2shell-upstream-asan/src -B /tmp/ccx2shell-asan \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address -L/tmp/ccx2shell-deps/root/usr/lib/x86_64-linux-gnu -Wl,-rpath-link,/tmp/ccx2shell-deps/root/usr/lib/x86_64-linux-gnu -Wl,-rpath,/tmp/ccx2shell-deps/root/usr/lib/x86_64-linux-gnu' \
  -DWITH_FFMPEG=OFF -DWITH_OCR=OFF -DWITH_HARDSUBX=OFF
cmake --build /tmp/ccx2shell-asan -j2
```

gpac development files were absent on the host. Ubuntu `libgpac-dev`,
`libgpac12t64`, `libmad0` and `liba52-0.7.4` `.deb` files were downloaded and
extracted under `/tmp/ccx2shell-deps/` (provisioning only, no host install or
package changes); a corrected `gpac.pc` there supplies local include and
library paths. Rust/corrosion dependencies were provisioned during configure.
No pinned source file was edited: `ccx_gxf.c` in the committed lab tree still
has sha256 `519b5fd0672c949ec12cc811038e148e51260c3ef3796afb3cd704bf2693d14f`,
matching `pins.sha256`. The ASan executable is
`/tmp/ccx2shell-asan/ccextractor`, sha256
`c401190479cd2e6fdf71093e512f3ebcd1138d3856aaf68d0c33741631899ad1`. The
final ASan link log is `real-build/evidence/build.log` and the configure log
is `real-build/evidence/cmake.log`; the control build log is
`real-build/evidence/guard-build.log`.

GXF inputs: `real-build/make_gxf.py` generates `inputs/attack.gxf` (sha256
`4b5841e2be606f3a4ffcc699e417789d088915b735cf48f0f53dad8c74aa13b3`,
2101312 bytes) and `inputs/safe.gxf` (sha256
`22fd3523538ef937ebc3fc2d90f4d5f62d612f118a21786141fceccfc1c6a2bb`,
4160 bytes). Both start with the GXF probe sequence `00 00 00 00 01 BC`,
carry a MAP packet that creates an MPEG2-525 video track (type `0x8B`, id
`0xC0`, 25 fps tag), then a MEDIA packet of type `0xBF`. The MEDIA body
carries media type `0x0B`, the 4-byte big-endian `mpeg_pic_size` field
`00 20 10 00` (2101248) for attack / `00 00 10 00` (4096) for safe, and a
payload of repeating `MISHE-CCEX`. The program autodetected GXF and reached
the sink; no early validation rejection, length bound or short-read EOF
blocked the attack.

```
ASAN_OPTIONS=detect_leaks=0 /tmp/ccx2shell-asan/ccextractor \
  lab/frontier/ccextractor2shell/real-build/inputs/attack.gxf \
  -o /tmp/ccx2shell-attack.scc
```

Attack rc 1 with `ERROR: AddressSanitizer: heap-buffer-overflow`,
**`WRITE of size 1052736`** at `0x7aa4760d0878`, `0 bytes after 2097272-byte
region`, frames `read (ASan interceptor)` → `read /usr/include/.../unistd.h:28`
→ `buffered_read_opt file_functions.c:376` → `buffered_read file_buffer.h:72`
→ `parse_mpeg_packet ccx_gxf.c:943` → `parse_media ccx_gxf.c:1219` →
`read_packet ccx_gxf.c:1335` → `ccx_gxf_get_more_data ccx_gxf.c:1403` →
`general_loop.c:1447` → `start_ccx` → `main`; allocation stack `malloc` →
`alloc_demuxer_data ccx_demuxer.c:452` → `ccx_gxf_get_more_data ccx_gxf.c:1387`.
The 1052736-byte WRITE is one real `read(2)` chunk that crossed the boundary;
the wire-derived requested length is 2101248. Safe rc 10, no ASan report,
"No captions were found in input". Raw logs:
`real-build/evidence/{asan-attack,asan-safe}.out`.

A plain `-O0 -g` build (`/tmp/ccx2shell-plain/ccextractor`) stopped at
`ccx_gxf.c:1220` with gdb. At that point `data->len=2101248` and the real
buffer at `data->buffer+2097272` held
`53 48 45 2d 43 43 45 58 4d 49 53 48 45 2d 43 43`; the first bytes of the
buffer were `4d 49 53 48 45 2d 43 43 45 58` ("MISHE-CCEX"), and the eight
bytes eight positions before the computed write end were again
"MISHE-CCEX". Full transcript: `real-build/evidence/gdb-plain-attack.out`.

A real-tree negative control was also built: a copy at
`/tmp/ccx2shell-upstream-guard` with the local hunk
`if (data->len + (size_t)len > BUFSIZE) return CCX_EOF;` inserted immediately
before the `buffered_read` call in `parse_mpeg_packet`, built under the same
ASan flags as `/tmp/ccx2shell-guard-build/ccextractor` (sha256
`a246eda46a8d5ee53987e098f7abcfafc3d44ef30e26a87264c5aba0956226c2`). This
hunk is a locally written control, not an upstream patch. On the attack GXF
it exits rc 10 with no ASan report and logs
`Processing ... attack.gxf 0 ended prematurely 80 < 2101312`; on the safe GXF
it is also rc 10 with no ASan report. Logs:
`real-build/evidence/{guard-asan-attack,guard-asan-safe}.out`, build log
`real-build/evidence/guard-build.log`. The committed pinned tree was not
edited; the temporary guarded source copy lives in the gitignored site.

## Measured 2026-11-25 06:08-06:09Z: in-program readback of chosen bytes

Question for this wake: does any program consumer, not just the debugger,
read the bytes written past `malloc(BUFSIZE)`? Answer: yes, measured in two
independent builds of the pinned tree.

`real-build/make_readback_gxf.py` writes
`real-build/inputs/readback.gxf` (sha256
`fc2faead02480aa92a240df5e63c0787e0acb88633e52bb7c7d64a5ee734a1d4`,
2101312 bytes). It keeps the W1 MAP packet, MEDIA packet and size field
`00 20 10 00`, but makes the payload zero-free `"MISHE-CCEX"` for the first
BUFSIZE bytes and then places `00 00 01 B3` (MPEG sequence_header_code),
12 bytes of `0x41`, `00 00 01 B7` (sequence_end_code) and `0x41` padding to
2101248 bytes. The first four attacker-chosen bytes past the allocation are
therefore a start code, and the program's own start-code scanner must walk
to them because nothing before them is zero. No pinned source file was
edited; only new files were added under `real-build/`.

Plain `-O0 -g` build (`/tmp/ccx2shell-plain/ccextractor`), script
`real-build/gdb-consumed-generic.cmd`: at `ccx_gxf.c:1220` the bytes at
`buffer+2097272` are `00 00 01 b3 41 41 41 41 41 41 41 41 41 41 41 41`;
conditional breakpoint at `process_m2v` shows `length=2101248`; `finish`
shows the program's own `got=2097348` (76 bytes past `BUFSIZE`). The same
measurement on the original attack payload gives `got=2101248` (3976 bytes
past `BUFSIZE`) with overflow bytes `53 48 45 2d 43 43 45 58 4d 49 53 48`.
Chosen bytes in the overflow region therefore change a program-computed
value. Transcripts: `real-build/evidence/gdb-consumed-{attack,readback}.out`.

Real ASan build (`/tmp/ccx2shell-asan/ccextractor`, sha256
`c401190479cd2e6fdf71093e512f3ebcd1138d3856aaf68d0c33741631899ad1`) with
`ASAN_OPTIONS=detect_leaks=0:halt_on_error=0` on `readback.gxf` exits rc 10
and reports two heap-buffer-overflows: the W1 `WRITE of size 1052736` from
`read`, then **`READ of size 3900` at `boundary+76`** with stack
`memmove (ASan interceptor)` → `memmove string_fortified.h:36` →
`process_data general_loop.c:1041` →
`process_non_multiprogram_general_loop general_loop.c:1298`. The read address
and size match the plain build exactly: `buffer+got = boundary+76` and
`data->len-got = 2101248-2097348 = 3900`, the remainder the program shifts
out of the overflowed region. Controls under the same options: `attack.gxf`
reports only the WRITE (its `got == data->len`, so the memmove length is 0);
`safe.gxf` reports nothing. Logs: `real-build/evidence/asan-readback.out`,
`real-build/evidence/asan-halt0-{attack,safe}.out`.

Preserved negative: GDB hardware watchpoints on an overflow byte did not
stop the program (both 8-byte and 1-byte `-location` watchpoints); that
instrumentation is not part of the evidence. A `PROT_NONE` page spanning the
boundary did fault inside the Rust start-code scanner
(`bitstream.rs:372`), but the page begins 120 bytes before the boundary and
also overlaps the malloc chunk metadata, so it is supporting context only,
not boundary-isolated proof. Transcript: `real-build/evidence/gdb-pageguard.out`.
A separate slice inspection (`real-build/evidence/gdb-readback-slice.out`)
shows the next general-loop iteration calling `process_m2v` with `length=3900`
on bytes left by that shift, further downstream program use of the region.

## W3 bounded negative 2026-11-25 06:46Z: no function pointer in overflow reach

Question: can chosen bytes directly overwrite a code pointer in the heap
region reached by the 3976-byte overflow? In this build and heap layout,
none was found. `real-build/gdb-heap-pointers.cmd` breaks at
`ccx_gxf.c:1220`, reads 64 KiB from `buffer+BUFSIZE`, tests every aligned
8-byte word that looks like an address with GDB `info symbol`, and reports
resolvable code pointers. On `safe.gxf` (untouched heap after the
allocation) `codeptr_hits=0`; the next chunk header is
`0x2061` (size 0x20600, PREV_INUSE) followed by zeros. The post-write
`attack.gxf` and `readback.gxf` scans also report `codeptr_hits=0`, but
their region already contains our own payload, so only the safe-input scan
describes the pre-write layout. For `readback.gxf`,
`malloc_usable_size(data->buffer)` returned 0 at that breakpoint,
consistent with corrupted chunk metadata; that value is not used as a scan
bound. `info symbol` would miss an opaque or unloaded code address, and one
build/layout is not proof for all layouts. Log:
`real-build/evidence/gdb-heap-pointers.out`. This negative closes the
direct function-pointer-overwrite hypothesis for this layout; it does not
alter the rung 3/4 grades or establish rung 5.

## Explicit unknowns

- No CVE/GHSA and no upstream fix PR observed; the local guard is not a
  vendor patch and no fixed release/version is known.
- Whether the real write can be followed by a controlled indirect call or
  command execution: UNKNOWN; nothing measured supports a rung-5 claim.
- Independent witness replay and operator-visible acceptance: UNKNOWN.

## W4 bounded negative 2026-11-25 07:12Z: forged chunk metadata merges with top

Question: can attacker-chosen bytes past `BUFSIZE` forge the malloc
next-chunk header so the program's terminal `free(data->buffer)` performs a
controlled unlink (a chosen pointer written to a chosen address)? Answer: no
in this build and layout. The chunk reached by the overflow **is the arena
top chunk**, so glibc takes the top-merge path and never dereferences the
forged `fd`/`bk`.

`real-build/make_unlink_gxf.py` writes `inputs/unlink.gxf` (sha256
`a50991c9dcb974e8a28f1cb6c94ea5ab7baa85a801331f19defc75271273aa7e`,
2101312 bytes). It keeps the W1 MAP/MEDIA packets and size field
`00 20 10 00`, and fills the first 2097264 payload bytes with `0x41` before
planting, at payload offsets relative to `data->buffer`: `0x200070` =
`0x200080` (nextchunk `prev_size` = buffer chunk size), `0x200078` =
`0x7f9` (forged nextchunk size 0x7f8 + PREV_INUSE), `0x200080`/`0x200088` =
safe-linked `fd = T-0x18` and `bk = P-0x18`, `T = P+0x100` holding `P`
(satisfying both unlink checks), and `P+0x800` = `0x810` (clear
PREV_INUSE so forward consolidation should be selected). `P` is taken from
a GDB observation; the generator takes it as an argument, because GDB's
`disable-randomization` fixes it per invocation but stdio redirection
shifts the heap base by `0x4020` here.

Plain pinned build under GDB (`/tmp/ccx2shell-plain/ccextractor`, redirected
stdout: `buffer=0x5555564209b0`, `P=0x555556620a20`): all forged words were
present at the breakpoint, and the conditional `free` breakpoint hit at
`delete_demuxer_data ccx_demuxer.c:440` with `mem=0x5555564209b0`. A hardware
watchpoint on `T` never fired; `T` stayed `0x555556620a20` through the free
and the program exited rc 10 with no glibc diagnostic. Logs:
`real-build/evidence/gdb-unlink-watch.out`,
`real-build/evidence/unlink-generate.out`.

The causal reason was measured directly in
`real-build/evidence/gdb-top-watch.out`: `main_arena.top` was
`0x555556620a20` **before** the free, i.e. equal to `P`. A watchpoint on
that pointer fired inside
`_int_free_create_chunk (nextsize=2040, nextchunk=0x555556620a20,
size=2099320, p=0x5555564209a0, av=main_arena) at malloc.c:4758`, called by
`_int_free_merge_chunk (malloc.c:4700)` from `__GI___libc_free
(malloc.c:3398)`. `nextsize=2040` is exactly the forged `0x7f8`: the chosen
size field is consumed by glibc, but because `nextchunk == av->top` the
allocator merges with the top chunk (`main_arena.top` becomes
`0x5555564209a0 = buffer-16`) and never calls `unlink_chunk`. No pointer
write, no rung-5 mechanic.

Limits: one glibc build, one heap layout, one allocation order; a layout
where a regular free chunk follows `data->buffer` (not measured here) could
take a different path. Rung 3 and rung 4 are unchanged; rung 5 and the
witness verdict remain UNKNOWN. No pinned source, harness source or earlier
evidence was edited.

## W5 bounded negative 2026-11-25 07:39-07:41Z: truncated MEDIA payload

Last open hypothesis from W4: `ccx_gxf.c:943-944` adds the full declared
`mpeg_pic_size` to `data->len` even when `buffered_read` returns short at EOF.
Prediction was that this might drive a much larger `memmove` of stale heap
bytes. Measured answer: no new write primitive and no larger attacker-steered
read. With a short or absent payload the `read(2)` never crosses `BUFSIZE`,
so no chunk metadata is corrupted; the inflated length only makes the
program's scanner walk stale heap bytes and shift a tiny, stale remainder.

`real-build/make_short_gxf.py` keeps the full `00 20 10 00` (2101248) field
and complete-packet header length but cuts the file payload to 4096 bytes
(`inputs/short.gxf`, 4160 bytes, sha256
`669ad20202d822aa3865b1795fae3501dec38096ba9a35130b47c7b9f4990745`) or to
zero bytes (`inputs/short0.gxf`, 64 bytes, sha256
`e2b32bf30cc2673e2ee9b85db1b45d94949e7d14f8f732b3654f12cc60cd1ee2`).
No pinned source, harness source or earlier evidence was edited.

Real ASan build with `ASAN_OPTIONS=detect_leaks=0:halt_on_error=0` on both
inputs: rc 10, exactly one heap-buffer-overflow each —
**`READ of size 3` at `boundary+3973`**, stack `memmove` interceptor →
`memmove string_fortified.h:36` → `process_data general_loop.c:1041` →
`process_non_multiprogram_general_loop general_loop.c:1298`. There is **no**
`read()`-origin `WRITE` report and no `free()` diagnostic, unlike the
full-payload W1/W2 inputs. Logs: `real-build/evidence/asan-short.out`,
`real-build/evidence/asan-short0.out`.

Plain pinned build under GDB (`real-build/gdb-short.cmd`) confirms the
mechanism for both inputs: at `ccx_gxf.c:1220` `data_len=2101248` although
only 4096 (or 0) bytes arrived; at `general_loop.c:1041` `got=2101245`,
`data_node->len=2101248`, so `move_len=3` and the source is
`buffer+2101245 = boundary+3973`. The scanner's chosen offset comes from
stale heap content, not from attacker-supplied bytes, and the shifted 3 bytes
are stale as well. Transcripts: `real-build/evidence/gdb-short.out`,
`real-build/evidence/gdb-short0.out`.

Limits: one glibc build, one heap layout; a different stale-heap content
could place `got` elsewhere and change the tiny read size, but the truncated
file supplies no bytes past `BUFSIZE` to write with, so this path cannot
restore the W1/W2 write primitive. Rung 3 and rung 4 are unchanged; rung 5
and the witness verdict remain UNKNOWN.

## W6 bounded negative 2026-11-25 08:53-08:54Z: no live ordinary chunk after the buffer

W4 left one structural idea open: forge the nextchunk header so glibc unlink,
rather than top merge, consumes attacker-controlled `fd`/`bk`. GDB on the
pinned plain build with `inputs/safe.gxf` (`gdb-layout.cmd`) measures at
`ccx_gxf.c:1220` and again at the terminal `free`:
`buffer=0x5555564209b0`, `P=buffer+2097264=0x555556620a20`,
`main_arena.top=P`, `P.size=0x205e1`, `ctx->vid_track=0x5555563d7f20`
(before the buffer), `ctx->ad_track=NULL`. The free stack is
`delete_demuxer_data ccx_demuxer.c:440` → `delete_datalist general_loop.c:866`.
So the chunk after the overflowed buffer is the live top chunk, not an
ordinary allocated chunk.

Source reason: GXF reuses one `demuxer_data` (`ccx_gxf.c:1385-1401`), and the
16 MiB `filebuffer` is allocated in `init_demuxer` (`ccx_demuxer.c:83`,
`file_functions.c:231`) before that buffer, so no earlier object can sit
above it. A trace of the first 24 `malloc` calls after the MEDIA parse
(`gdb-late-malloc.cmd`) found only five small Rust allocations (8, 8, 32, 8, 8
bytes); all were released before the terminal free and `main_arena.top`
stayed at P. There is therefore no live adjacent chunk to unlink and no
post-overflow allocation overlapping the corrupted top.

Logs: `real-build/evidence/gdb-w6-layout.out`,
`real-build/evidence/gdb-w6-late-malloc.out`. No GXF input, pinned source,
harness source or prior evidence was changed. Rung 3 and rung 4 are
unchanged; rung 5 and the witness verdict remain UNKNOWN. At W6 time all
four known structural ideas were measured negatives; W7 adds a fifth.

## W7 bounded negative 2026-11-25 09:39-09:43Z: no post-parse allocation in overflow bytes

W6 traced the late Rust allocations only on `safe.gxf`, where the top chunk
size field was intact. The open question was whether the overflow-corrupted
top becomes the source of a later allocation whose content — and possibly a
callable object — is attacker-controlled. Answer in this build/layout: no.

`real-build/gdb-w7-malloc-ret.py`, loaded by
`real-build/gdb-w7-malloc-ret.cmd`, breaks at `ccx_gxf.c:1220` and logs the
entry and return of the next 24 `__libc_malloc` calls through GDB
`FinishBreakpoint`, then the terminal free of `data->buffer`. Plain pinned
build, GDB disables ASLR, no stdout redirection. At parse and at free the
top chunk size field at `buffer+BUFSIZE` holds attacker bytes on
`attack.gxf` (`0x584543432d454853`) and `readback.gxf`
(`0x41414141b3010000`), versus `0x205e1` on `safe.gxf`. Nevertheless
`main_arena.top` stays `0x555556620a20` at every malloc entry and at the
free, and all returned pointers are at most `0x55555640ce10` — 80800 bytes
before `data->buffer=0x5555564209b0`, never in the overflow region starting
at `buffer+BUFSIZE`. Five allocations occur on attack/safe and twelve on
readback; all come from earlier free chunks, not the corrupted top. The old
`gdb-late-malloc.cmd`, run unchanged on attack/readback, shows the same
sizes and unchanged top.

Log: `real-build/evidence/gdb-w7-malloc-ret.out`. Limits: one glibc build,
one heap layout, allocations only through the terminal `free`; no crafted
input was added and no pinned or harness source was edited. Rung 3 and rung
4 are unchanged; there is still no controlled indirect call, pointer or
command, so rung 5 and the witness verdict remain UNKNOWN.

## W8 bounded negative 2026-11-25 09:56-10:00Z: small forged top size

W7 left one malloc-internals idea open: the top chunk's size field at
`buffer+BUFSIZE` is attacker-controlled, so a small value should force glibc's
`sysmalloc` path and possibly expose the forged old top as a live chunk. Two
new inputs place `0x21` and `0x41` there (`inputs/topsize-{21,41}.gxf`,
sha256 `1b8421bc62790e7c0ec42d81a961afebaf5bb5915e964f698760cce53b8c0226`
and `2af49554d6663afddd0a3afff9f835f7ce77774c51b8068153a3a3b72ac83517`),
generated by `real-build/make_topsize_gxf.py` from the pinned W1 layout.

Measured in the plain pinned build under GDB: the five post-parse mallocs
(8, 8, 32, 8, 8 bytes) all return tcache pointers; `main_arena.top` stays at
the corrupted top and no `sysmalloc` is entered. At the terminal
`free(data->buffer)` the buffer chunk merges with top identically on attack
and safe input (`top` moves to `buffer-16`), and the six 8-byte allocations
before `exit` all return the same tcache pointer `0x5555563ca520`. No object
is carved from attacker-controlled overflow bytes; no pointer or command
control. Scripts `real-build/gdb-w8-postfree.{py,cmd}`, log
`real-build/evidence/gdb-w8-postfree.out`. One glibc build and layout only;
rungs unchanged.

## W9 measured 2026-11-25 10:00-10:03Z: loopback UDP wire reaches the sink

The pinned tree has a network input mode: `--udp [[src@]host:]port`
(`params.c:88-91`) binds a listener, and `buffered_read_opt`
(`file_functions.c:418-423, 458-469`) fills the 16 MiB `filebuffer` from that
socket before copying into the sink destination. A live ASan build
(`/tmp/ccx2shell-asan/ccextractor`, sha256
`c401190479cd2e6fdf71093e512f3ebcd1138d3856aaf68d0c33741631899ad1`, pinned
source hash unchanged) was started as `--udp 127.0.0.1:PORT -o /tmp/...` and
fed the existing GXF inputs as 257 paced 8192-byte UDP datagrams plus three
GXF EOS packets, all to 127.0.0.1. Driver `real-build/udp_wire_replay.py`;
raw captures `real-build/evidence/udp-{attack,readback,safe}.out`.

`attack.gxf`: rc 10 and `ERROR: AddressSanitizer: heap-buffer-overflow`,
**`WRITE of size 4160`** at `0x...878`, `0 bytes after 2097272-byte region`,
stack `memcpy` → `buffered_read_opt file_functions.c:463` → `buffered_read
file_buffer.h:72` → `parse_mpeg_packet ccx_gxf.c:943` → `parse_media
ccx_gxf.c:1219` → `read_packet ccx_gxf.c:1335` → `ccx_gxf_get_more_data
ccx_gxf.c:1403`; allocation stack `malloc` → `alloc_demuxer_data
ccx_demuxer.c:452`. The 4160-byte WRITE is one UDP datagram chunk copied
through `buffered_read_opt`; the wire-derived requested length remains
2101248.

`readback.gxf`: the same WRITE, followed by **`READ of size 3900`** at
`0x...d8c4` — exactly `boundary+76` — in `memmove` → `process_data
general_loop.c:1041` → `process_non_multiprogram_general_loop
general_loop.c:1298`, with the same `malloc(BUFSIZE)` allocation stack. The
chosen `00 00 01 B3` bytes at the first overflow offset again change the
program's own consumed length to 2097348 over the wire, and ASan observes the
program reading the 3900-byte remainder from past the allocation. This is a
wire-shaped reproduction of the W2 rung-4 result, in a live process bound to
loopback; it is not a command-execution result.

`safe.gxf` control: no sink WRITE or downstream READ; the process remained in
the live UDP read loop and was killed by the 30 s driver timeout. Every UDP
run reports an independent ASan `READ of size 10` in `strlen` called from
`ccxr_start_udp_srv` (`src/rust/src/libccxr_exports/net.rs:243`), where the
9-byte non-NUL-terminated `"127.0.0.1"` address string is passed to
`CStr::from_ptr`. That is a separate setup-path observation on all inputs,
not evidence for issue #2500 and not part of this grade.

Rung 3 and rung 4 remain CONFIRMED with a stronger delivery path; rung 5
remains UNKNOWN (no controlled indirect call, pointer or command), and the
witness verdict is unchanged. No pinned source, harness source or earlier
evidence was edited; all testing stayed on 127.0.0.1.

## W10 bounded negative 2026-11-25 10:36Z: wire path keeps the same heap ceiling

Prediction: `--udp` delivery could place a live object after `data->buffer`
or make a post-parse allocation come from the corrupted top, opening a
pointer target absent from the file path (W3/W6/W7/W8). Test: the plain
pinned build (`/tmp/ccx2shell-plain/ccextractor`) under GDB with `--udp
127.0.0.1:45172`, broken at `ccx_gxf.c:1220` just after
`parse_mpeg_packet(demux, 2101248, data)`, while
`real-build/udp_send_only.py` fed 257 paced 8192-byte datagrams from the
unchanged `inputs/attack.gxf` to loopback only. Scanner
`real-build/gdb-w10-udp.py`/`.cmd` reuses the W3 code-pointer test and the
W7 malloc-return tracer.

Measured: `data->buffer=0x555556420870`, `boundary=0x5555566208e8`,
`main_arena.top=0x5555566208e0` (the chunk header sits 8 bytes before the
nominal boundary), and the top size field at the boundary is the attacker
pattern `0x584543432d454853` ("SHE-CCEX..." rotated). `codeptr_hits=0` in
64 KiB past the boundary. `main_arena.top` stayed `0x5555566208e0` at all
five post-parse mallocs (8, 8, 32, 8, 8 bytes), whose returns
(`0x5555563ca420`, `0x55555640cdb0`, `0x5555564047d0`, ...) are all below
the buffer; the terminal `free(data->buffer)` merged with the same top. No
carved object, no pointer or command control, rung grades unchanged. Raw
transcript `real-build/evidence/gdb-w10-udp.out`. One glibc build and heap
layout only; this is a bounded negative, not a proof for other builds.
No pinned source, harness source or earlier evidence was edited.
