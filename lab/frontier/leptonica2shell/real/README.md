# Real Leptonica replay — CVE-2026-137063

The staged harness (`../run-all.sh`) uses verbatim function excerpts. This
lane builds **real upstream Leptonica** at both pins and calls the real
`l_byteaInitFromFile()` API. No upstream source byte was edited.

## Provisioning and pins

Fetched with `git clone --filter=blob:none --no-checkout
https://github.com/DanBloomberg/leptonica.git src` (provisioning only), then
`git -C src checkout 1.87.0` (HEAD `13275a278eb55b5746e33f95fbf5a2c8f604b3ab`)
and `git -C src worktree add ../src-fixed
c493a776e6bc6cfb1d8d15152a0b74f3d15b33fd`.

`sha256sum src/src/bytearray.c src-fixed/src/bytearray.c` matches both pinned
copies in `../pins/` exactly:

- vulnerable: `b5740bbd65a5a7d18fa60220138411a5cc72ad838045e86d015889d835eccbc7`
- fixed: `e37f74fd680a917bc5c37a9b54d51e6ab242dd26fea6c30017e88c1b50e96e65`

## Build

One-command clean-archive replay: `bash provision.sh` clones both pinned
trees, builds them with ASan and runs `run-real.sh`. The manual equivalent is
below.

```
for pair in 'src build-vuln' 'src-fixed build-fixed'; do set -- $pair
  cmake -S "$1" -B "$2" -DCMAKE_BUILD_TYPE=Debug -DBUILD_PROG=OFF \
    -DSW_BUILD=OFF -DENABLE_ZLIB=OFF -DENABLE_PNG=OFF -DENABLE_GIF=OFF \
    -DENABLE_JPEG=OFF -DENABLE_TIFF=OFF -DENABLE_WEBP=OFF \
    -DENABLE_OPENJPEG=OFF \
    -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' \
    -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address'
  cmake --build "$2" -j4
done
bash run-real.sh
```

Clean-archive replay verified 2026-11-26 14:58Z: extract with `git archive
HEAD lab/frontier/leptonica2shell/real`, then `bash provision.sh` → 7 PASS /
0 FAIL, rc 0. Script hashes: `provision.sh`
`073c55d82e852cb53ee8db3058308c87e5f3a8fed0064c184062d94911b9b789`,
`run-real.sh`
`ce0a0ae3c109bd3561281fb966b55eeeae424f0b8e18402f1d34751e18b4e4f7`.

`run-real.sh` creates a sparse 1,000,000,001-byte file (chosen
`MISHE-LEPTONICA` at offset 201) and a 16-byte safe file, then reports
`TOTAL: 7 PASS / 0 FAIL` (rc 0).

## Observed evidence

- `evidence/real-vuln-asan.out`: `heap-buffer-overflow`,
  `WRITE of size 1000000001`, `0 bytes after 201-byte region`; write frame
  `l_byteaInitFromStream src/src/bytearray.c:192`, call frame
  `l_byteaInitFromFile :162`, allocation frame `l_byteaCreate :105`.
- `evidence/real-caller-asan.out`: same WRITE with stack
  `l_byteaInitFromStream` → `l_byteaInitFromFile` →
  `saConcatenatePdfToData src/src/pdfio1.c:2169`; an in-tree library caller
  reaches the overflow.
- `evidence/real-fixed-asan.out`: `stream too large`, `ba not made`,
  `BA=NULL`, no sanitizer report.
- `evidence/real-vuln-safe.out`: `BA=nonnull`, `SIZE=16 FIRST=4d`, clean.


## Plain-build heap-neighborhood probe (rung-4 mechanics only)

`bash run-neighbor.sh` builds a non-sanitized copy of the same pinned tree
(`build-plain`) and compiles `neighbor.c` with `-Wl,--wrap=calloc`. The
lab-only wrapper recognizes the vulnerable `calloc(201, 1)` in
`l_byteaCreate()` and immediately allocates a live 512-byte sentinel filled
with `0x5a`; the fixture plants `MISHE-LEPTONICA` at offsets 208..1024 (step
32) so whichever small offset the sentinel occupies receives chosen stream
bytes. A SIGSEGV observer prints the sentinel before exiting 77. No upstream
byte is changed; the sentinel and observer are synthetic lab mechanics.

Observed 2026-11-26 ~16:09Z, `TOTAL: 5 PASS / 0 FAIL`, rc 0:

```
SIGNAL=SIGSEGV SENTINEL_OFFSET=224
FAULT_ADDR=0x617109a4e000 FAULT_OFFSET_FROM_DATA=129504
DATA_ADDR=0x617109a2e620 SOURCE_ADDR=0x7193f2853010 SOURCE_DELTA=17742122076656
SENTINEL_FIRST32=000000000000000000000000000000004d495348452d4c4550544f4e49434100
CHOSEN_AT_OFFSET=16
```

The two address lines are new: the SIGSEGV observer now uses `sigaction` and
reports `siginfo_t.si_addr` plus the live `/proc/self/maps` dump kept in
`evidence/neighbor-plain-attack.out`. No upstream byte is changed; the
sentinel, observer and map reader are lab mechanics.

Script hashes: `run-neighbor.sh`
`d37b459cad45ffb87bf2013c3065a938e9069d47cc8b3e54e575a0e3c29a5101`,
`neighbor.c`
`4cf69a40567efd8a2f577bf848348833ef48d02c139f5b8e00a89c6592e9971b`.

So in a plain real-library process the oversized `memcpy` writes chosen file
bytes into a live adjacent heap object 224 bytes past `ba->data` before it
faults on unmapped memory. The sentinel is lab-groomed and the readback is a
fault handler, not a request-reachable consumer: this strengthens the rung-4
PARTIAL label, it is **not** a live-consumer readback and no pointer or
command is claimed. Safe 16-byte stream: `BA=nonnull`, `SIZE=16
NO_FAULT=1`, rc 0, and no sentinel is created because the 201-byte allocation
never occurs. A first runner revision checked `NO_FAULT` before `SIZE` and
reported 2 PASS / 1 FAIL on that safe control; only the check pattern was
reordered, no observation was changed.

## Measured structural boundary (2026-11-26 16:09Z)

The fault address is the first byte past the process heap mapping:
`617109a2d000-617109a4e000 rw-p ... [heap]` is 135,168 bytes, `ba->data` is
at `0x617109a2e620`, and `si_addr` is exactly the mapping end, 129,504
(`0x1f9e0`) bytes past `ba->data`. The 1,000,000,001-byte source buffer is
**not** adjacent: `l_binaryReadSelectStream()` calls `calloc(1,
bytestoread + 1)` (utils2.c:1508), which glibc places in a separate
1,000,001,536-byte anonymous mapping at `0x7193f2853000`, 17,742,122,076,656
bytes above `ba->data`. An overflow of 1,000,000,001 bytes therefore cannot
land on its own source buffer in this build; it marches past the small heap
and faults. A live consumer would need its own contiguous writable mapping
of about a gigabyte immediately after the 201-byte allocation to survive;
no such consumer is present in this checkout (see caller enumeration below).
This is a measured boundary for this plain real-library process, not a proof
about every possible host allocator or future consumer.

## Caller enumeration and boundary

`l_byteaInitFromStream()` is called only by `l_byteaInitFromFile()` inside
`src/`; the remaining hits are the declaration in `allheaders.h` and the
`l_binaryReadStream()` doc in `bbuffer.c`. In-tree callers of
`l_byteaInitFromFile()` are `src/pdfio1.c:2169` (`saConcatenatePdfToData`,
reached above) and test/regression programs `bytea_reg.c`, `pdfio2_reg.c`,
`xtractprotos.c`. No socket, HTTP, or request-dispatch caller exists in this
tree. This is still rung 3 in real bytes, not rung 5: no wire input, no
live server, no pointer-bearing victim object and no command side effect.
Chosen-byte readback is held by the staged harness's synthetic bounded
consumer and by the lab-groomed live neighbor in the plain real-library
probe above (rung 4 PARTIAL in both cases).

## External caller hunt (2026-11-26 16:1xZ, bounded negative)

A read-only search of the checkout's `lab/` C/C++/header sources
(gitignore-respecting, ~185 frontier projects) found **no** external caller
of `l_byteaInitFromStream()`, `l_byteaInitFromFile()` or any other `l_bytea*`
API outside this project. The only other project including Leptonica's
`allheaders.h` is `ghostscript2shell`'s
`src/ghostpdl-ghostpdl-10.07.0/base/tessocr.cpp:60`; it uses in-memory `Pix`
APIs and `gp_fread` for Tesseract tessdata, never a Leptonica stream reader.
Untracked bulk trees (`lab/src/`, `lab/frontier/*/deps/`, other gitignored
directories) were not exhaustively enumerated: a gitignore-disabled scan
timed out. This is a bounded negative for tracked sources and docs, not a
claim about every local file or about production hosts. No request-reachable
consumer was found; the measured fault boundary above is the conclusion for
this checkout.

## Preserved negative

The first caller-path check expected the stack frames in caller-to-callee
order; ASan prints them callee-first, so the runner reported 6 PASS / 1 FAIL.
The check pattern was reversed; no upstream byte or observed ASan report was
changed. The failed run is preserved in this note rather than erased.
