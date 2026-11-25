# Frontier brief — ccextractor2shell (CCExtractor issue #2500, no CVE)

Status 2026-11-25 (staging): **STAGED**, rung 3 in the pinned verbatim
`parse_mpeg_packet()` under ASan with a stand-in `buffered_read` (`memcpy`) and
stand-in structs; rung 4 PARTIAL (chosen bytes readable at the nominal
`BUFSIZE` boundary in a slack-allocated stand-in layout). No CVE/GHSA found,
no upstream fix PR found (fix status UNKNOWN; the guard in the harness is a
local hunk only), no real ccextractor build, no GXF file or wire path, no
pointer/IP/command control and no rung 5. Witness verdict UNKNOWN. No
admission, window, registry or resolver action is claimed by this brief.

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

## Honest rung assessment and ceiling

Rung 3 is confirmed on the verbatim pinned function under gcc ASan and clang
ASan with `-fno-builtin-memcpy`; the store is executed by a stand-in
`buffered_read` that copies attacker-supplied bytes with `memcpy`. Rung 4 is
PARTIAL: attacker-chosen bytes are readable at a chosen offset (the nominal
`BUFSIZE` boundary) in a stand-in allocation layout; ASan redzones poison
that region in the instrumented build, and the real `read(2)` consumer plus
real struct/allocator layout were never exercised. There is no real
ccextractor executable, no GXF file or wire delivery, no live process, no
pointer/IP/command control, no rung 5, and no witness replay. Fix status and
witness verdict are UNKNOWN; the clang-default ASan negative above is part of
the record.

## Cheapest local experiment to move up a rung

Build the pinned upstream tree locally under ASan (`src/CMakeLists.txt`,
`linux/autogen.sh`; defaults `WITH_FFMPEG=OFF`, `WITH_OCR=OFF`) and feed it a
locally crafted minimal `.gxf` whose MPEG2 MEDIA packet carries the 4-byte
field `00 20 10 00` followed by at least 2101248 payload bytes. Observe
whether ASan reports a WRITE through the real `buffered_read`/`read(2)` path
into the `malloc(BUFSIZE)` destination; repeat with the local bounds guard.
This would test the two stand-ins at once (real consumer and real layout) and
is entirely local-file work. It may fail earlier at GXF header validation, at
a length bound in the real caller, or via a short `read(2)` returning less
than `len` (which yields `CCX_EOF` after the partial store); any such outcome
is a measured result, not a rung upgrade. No external system is involved.

## Explicit unknowns

- No CVE/GHSA and no upstream fix PR observed; local guard is not a vendor
  patch and no fixed release/version is known.
- Whether a real GXF demux accepts a 24-bit `mpeg_pic_size` of 0x201000, whether
  any earlier length bound exists, and how much a real `read(2)` stores in one
  call: UNKNOWN.
- Real `struct demuxer_data` layout, allocator neighbors, any live field after
  `buffer`, and chosen-byte readback in a real process: UNKNOWN.
- Witness replay, operator admission and any rung-5 path: UNKNOWN.
