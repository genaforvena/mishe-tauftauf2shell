# Frontier brief — ccextractor2shell (CCExtractor issue #2500, no CVE)

Status 2026-11-25 05:4xZ: **real pinned-tree build executed**. Rung 3 is
CONFIRMED through the real `buffered_read`/`read(2)` consumer into a real
`malloc(BUFSIZE)` region: an ASan `WRITE` from a locally crafted `.gxf` MEDIA
packet, with the full call stack through `parse_mpeg_packet`. Rung 4 is
CONFIRMED with the condition that chosen bytes were observed by debugger
inspection of the live buffer after the read (no in-program consumer readback,
no pointer/IP/command control). Rung 5 and witness verdict remain UNKNOWN.
No CVE/GHSA and no upstream fix PR were observed; the guard is a local hunk,
not a vendor patch. All input files, logs and generators live in
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

Rung 4 is confirmed for chosen bytes at a chosen offset in the real process:
the plain build stopped after `parse_mpeg_packet` with `data->len=2101248` and
`data->buffer+BUFSIZE` containing the attacker-chosen repeating pattern
`53 48 45 2d 43 43 45 58 4d 49 53 48 45 2d 43 43` ("SHE-CCEXMISHE-CC").
Condition: the bytes were inspected in the live process with gdb; no program
consumer read them back, and no pointer or instruction pointer was controlled.
The earlier stand-in rung-4 PARTIAL result is retained as history, not as the
basis for this grade.

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

## Explicit unknowns

- No CVE/GHSA and no upstream fix PR observed; the local guard is not a
  vendor patch and no fixed release/version is known.
- Whether the real write can be followed by a controlled indirect call or
  command execution: UNKNOWN; nothing measured supports a rung-5 claim.
- No in-program consumer readback of the chosen bytes (the rung-4 observation
  used a debugger on the live buffer): UNKNOWN.
- Independent witness replay and operator-visible acceptance: UNKNOWN.
