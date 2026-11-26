# Frontier brief — sailtga2shell (CVE-2026-54626 / GHSA-744p-cqg2-m33h)

Status: **ADMITTED 2026-11-26 under standing #6 as the 163rd target mind;
window 171 adopted.** Witness W246 replayed the unmodified wrapper from a
clean `git archive 2bcda7e8` and ruled ESTABLISHED AS LABELED at this claim's
scope; no grade change, NO r5.
Rungs 1–3 observed locally with the real public `sail_load_from_file()` API and
GCC+Clang ASan; rung 4 demonstrated in the lab under a plain allocator —
attacker-chosen bytes `AA BB CC DD` land at offsets 256..263 past a 256-byte
pixel allocation. No pointer control, no command execution, no wire path, no r5.
Duplicate check before provisioning: no `sail` slug in the do-not-duplicate
list, no `reports/frontier-*sail*`, no sail window/charter/mind on the tape.
Admission is the operator's; wake units and full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: `https://github.com/HappySeaFox/sail/security/advisories/GHSA-744p-cqg2-m33h`,
  published 2026-06-07, Critical 9.8, CVE-2026-54626, affected `<= 0.9.10`,
  patched `1.0.0`, CWE-122/787. Advisory claims heap OOB write of
  attacker-controlled bytes through `sail_load_from_file()` in any application
  loading an untrusted TGA; incomplete fix of CVE-2026-40494.
- Advisory PoC: 28-byte 16×16 indexed-RLE TGA (`image_type=9`, header `bpp=32`)
  with two `0xFF` RLE run packets carrying four-byte pixels; 256-byte pixel
  buffer, 1024 bytes written. Advisory's pasted ASan log reports `WRITE of
  size 4`, 0 bytes after a 256-byte region, at `tga.c:303`, with a `Version:
  1.0.0` banner — see the discrepancy below.
- Verified by my own fetches: vulnerable tag `v0.9.10` (`cdd9d5f20bd0bf83683637afee61dd7e954162b2`),
  fixed tag `v1.0.0` (`0f969168b9d19d43f448d2237990ec247ba822ca`), fix commit
  `fa24bceb93958ad665dbc3cf6b49a1079ab12559` with parent
  `2a4c3b7af46af7e244155e305027507e9e7493bd`. Raw `tga.c` SHA-256 pins are in
  `lab/frontier/sailtga2shell/PROVENANCE.md`.

## 2. Source-bound mechanism

`helpers.c`'s `tga_private_sail_pixel_format()` maps `image_type=9` to
`SAIL_PIXEL_FORMAT_BPP8_INDEXED` regardless of header `bpp`, so
`sail_load_next_frame()` allocates `width*height*1` bytes. The RLE decoder in
`tga.c` nevertheless computes `pixel_size = (file_header.bpp + 7) / 8`
(verbatim `tga.c:237` at v0.9.10), validates only `1..16` bytes, and then
advances the pointer by `pixel_size` per pixel in both packet types:
`memcpy(pixels, pixel, pixel_size)` at `tga.c:269` (run) and
`strict_read(..., pixels, pixel_size)` at `tga.c:277` (raw). With `bpp=32`,
four chosen bytes are written per one-byte pixel slot. Each `0xFF` packet
holds 128 pixels, so the first packet's 65th write already crosses byte 256;
both packets overshoot and 1024 bytes are written in total. The earlier
CVE-2026-40494 clamp bounds pixel *count*, not bytes per pixel.

Vendor fix (commit `fa24bce…`, identical raw bytes at tag `v1.0.0`) adds
`if (sail_bits_per_pixel(pixel_format) != (unsigned)file_header.bpp) return
SAIL_ERROR_INVALID_IMAGE;` before allocation and replaces the header-derived
stride with `sail_bits_per_pixel(image->pixel_format)`. Both hunks are present
in the pinned fixed source; no local synthetic patch is used.

## 3. Local result

`lab/frontier/sailtga2shell/` builds five real static SAIL trees from the
pinned tarballs with `-DSAIL_ONLY_CODECS=tga`: v0.9.10 with clang ASan, gcc
ASan and gcc plain, plus v1.0.0 with clang ASan and gcc plain. The driver calls
only `sail_load_from_file()` on three local 28-byte TGA files.

- `bash harness/run-all.sh`: **38 PASS / 0 FAIL**, rc 0.
- GCC+Clang ASan on the attack input: `heap-buffer-overflow`, `WRITE of size
  4`, 0 bytes after a 256-byte region, frame
  `sail_codec_load_frame_v8_tga` at verbatim `tga.c:269`, allocation through
  `sail_malloc` via `sail_load_next_frame`, caller `sail_load_from_file`.
- Plain vulnerable build, beyond-allocation probe: bytes at offsets 256..263
  are `aa bb cc dd aa bb cc dd` — attacker-chosen bytes at chosen offsets.
- Safe controls: `bpp=8` indexed-RLE with matching one-byte stride and
  `bpp=32` truecolor-RLE with matching four-byte stride both stay clean under
  ASan; in the plain build their bytes at 256..263 are either absent or
  inside a 1024-byte allocation. Vendor-fixed v1.0.0 rejects the attack input
  with `SAIL_ERROR_INVALID_IMAGE` (`rc=213`) under both compilers, no ASan
  report.
- `bash run-witness.sh`: `REPLAY_PASS=14/0`, inner `TOTAL: 38 PASS / 0 FAIL`,
  in-tree and from a clean `git archive` (see wall for archive hash).

## 4. Cheapest next experiment

For a dedicated mind: drive the same 28-byte input through
`sail_load_from_memory()` and through a real local image-decoding application
to check whether the public junior API is the only consumer path; then place a
live adjacent allocation under a plain allocator and test whether the four-byte
stride can change a pointer-bearing field before the pixel buffer is freed.
No external probing is authorized; all testing stays in the lab and on loopback.

## 5. Negatives, discrepancies and UNKNOWNs

- Advisory's ASan paste claims a `Version: 1.0.0` build still crashes at
  `tga.c:303`, and its text calls the header-bpp clamp `1..32`; raw v0.9.10
  `tga.c:240` rejects `pixel_size > 16` and the sink is `:269`. Raw `v1.0.0`
  contains both vendor guards and the pinned v1.0.0 build rejects the input.
  Treat the paste as a claim from a different (likely pre-release master)
  build, not as the tag's behavior; the raw tag bytes are authoritative.
- v1.0.0 needs optional libswscale headers absent on this host. Empty stub
  headers are supplied through `CMAKE_C_FLAGS` and libswscale is forced OFF;
  only unused code behind `SAIL_MANIP_SWSCALE_ENABLED` sees them. No upstream
  source byte is modified.
- An early safe-8 body was misparsed as mixed RLE/raw packets and caused an
  OOB write; it was replaced with two valid one-byte run packets plus padding.
  An early `bpp=24` truecolor body returned `SAIL_ERROR_READ_IO`; replaced by
  the valid `bpp=32` truecolor control. Both negatives are preserved here.
- The driver's optional beyond-allocation read is gated behind the `probe`
  argument; without it ASan controls stay clean, avoiding a false positive
  from the measurement itself.
- No RCE, no pointer overwrite, no r5. Real-world application reachability
  beyond "any app that loads an untrusted TGA through SAIL" is UNKNOWN. This
  mind does not claim a witness verdict. Independent witness W246 replayed the
  unmodified wrapper from a clean `git archive 2bcda7e8` and ruled
  ESTABLISHED AS LABELED, no grade change, NO r5
  (`artifacts/witness-w246-sailtga2shell/detail.md`).

## 6. W1 target-mind results (2026-11-26)

All new files are un-pinned and local to the lab; `run-witness.sh` pins are
untouched and a fresh replay still reads `REPLAY_PASS=14 REPLAY_FAIL=0`,
inner `TOTAL: 38 PASS / 0 FAIL`.

- `harness/run-memory.sh` — **10 PASS / 0 FAIL**. Junior
  `sail_load_from_memory()` on the 28-byte TGA returns `rc=301`
  `SAIL_ERROR_CODEC_NOT_FOUND`: TGA has no magic number, so auto-probe never
  selects the codec and this entry point does not reach the sink by itself.
  The documented advanced memory path
  `sail_codec_info_from_extension("tga")` ->
  `sail_start_loading_from_memory()` -> `sail_load_next_frame()` ->
  `sail_stop_loading()` DOES reach it: GCC ASan `WRITE of size 4` at verbatim
  `tga.c:269`, 0 bytes after 256 bytes; plain chosen bytes at 256..263;
  v1.0.0 `rc=213`. Evidence `evidence-w1/`.
- `harness/run-realapp.sh` — **9 PASS / 0 FAIL**. Two SHIPPED SAIL
  applications reach the sink. The v0.9.10 `sail` CLI `convert` shows ASan
  `WRITE of size 4` at `tga.c:269` with the real stack
  `convert_impl` (`examples/c/sail/sail.c:185`) -> `sail_load_next_frame` ->
  `tga.c:269`. The shipped v1.0.0 `advanced` example faults the same sink on
  v0.9.10 libs and is rejected by vendor-fixed v1.0.0 libs with the guard at
  `tga.c:146`. Evidence `evidence-w2/`.
- `harness/run-pointer.sh` — **13 PASS / 0 FAIL**. An LD_PRELOAD malloc
  interposer places a live pointer-bearing victim 272 bytes after the
  256-byte pixel buffer. Crafted RLE packets control arbitrary 4-byte-aligned
  dwords across the written 1 KB region (packet boundaries choose each
  dword's value). The victim `fp` was set to chosen canonical
  `0x00007f0000414243`; with ASLR disabled it was retargeted to a lab benign
  marker and called, producing `BENIGN_MARKER_EXECUTED` and a side-effect
  file. Matching-stride `safe8` leaves `fp`, `magic` and canary intact;
  vendor-fixed v1.0.0 rejects the input (`rc=213`) and places no victim.
  Evidence `evidence-w3/`. This is pointer control plus benign marker
  execution in a SYNTHETIC in-process consumer with ASLR disabled, no free
  of corrupted metadata and no wire/request path: **rung-4 mechanics only,
  not r5**.
- Negative result preserved: a libc allocation inside the benign marker
  aborts on glibc metadata corrupted by the overflow. The marker now uses
  `write`/`open`/`close` syscalls only; the call completes and the destructor
  still reports the victim.
- Still UNKNOWN: a naturally occurring application object (not a lab
  interposer victim) reached before free; any network/request consumer; r5.

