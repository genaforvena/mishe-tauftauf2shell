# frontier brief — leptonica2shell (CVE-2026-137063)

Status 2026-11-25 23:0xZ: STAGED locally; brief, status, charter, seed wall,
harness and PROVENANCE written; inner two-pane window created. No admission
or independent acceptance is claimed here; the operator admits, the witness
replays. Witness W237 (2026-11-26 01:48Z) replay verdict: ESTABLISHED AS
LABELED, no contradiction, no grade change, NO r5; detail in
`.mishe-tauftauf/artifacts/witness-w237-leptonica22shell/detail.md`.

Real-library update 2026-11-26 14:55Z: both pinned trees were built with ASan
and driven through the real `l_byteaInitFromFile()` API. `bash
lab/frontier/leptonica2shell/real/run-real.sh` reports **7 PASS / 0 FAIL**,
including an in-tree caller path. Grade stays rung 3 / rung 4 PARTIAL; no wire,
pointer-bearing victim or command.

## Verified ground truth

- Claim: `CVE-2026-137063`, published 2026-11-25, CWE-122, CVSS 6.8. Feed
  record: https://hol.org/guard/security/cves/CVE-2026-137063-leptonica-1790-through-1870-heap-buffer-overflow .
  Affected Leptonica 1.79.0 through 1.87.0; the feed reports no fixed version.
  Source description: `l_byteaInitFromStream()` accepts a stream larger than
  1,000,000,000 bytes; `l_byteaCreate()` allocates only the 201-byte initial
  array and the following `memcpy` copies the full stream size.
- Upstream fix commit `c493a776e6bc6cfb1d8d15152a0b74f3d15b33fd`
  (2026-11-20, subject "Heap buffer ovfl in l_byteaInitFromStream: CWE-787",
  credited to Deus Rex / Cyrex), patch:
  https://github.com/DanBloomberg/leptonica/commit/c493a776e6bc6cfb1d8d15152a0b74f3d15b33fd.patch
  Vulnerable source at tag `1.87.0`:
  https://raw.githubusercontent.com/DanBloomberg/leptonica/1.87.0/src/bytearray.c
  Both full files are pinned under `lab/frontier/leptonica2shell/pins/` with
  SHA-256 values in `PROVENANCE.md`.
- Not a duplicate: neither `reports/` nor the frontier wall's do-not-duplicate
  list named Leptonica before this wake. `l_byteaInitFromStream` is not in any
  admitted target's lane.

## Source-bound mechanism (pinned bytes)

- `bytearray.c:76-77` (both pins): `MaxArraySize = 1000000000`,
  `InitialArraySize = 200`.
- `l_byteaCreate()` (vulnerable `:98-113`, fixed `:98-115`): `if (nbytes <= 0
  || nbytes > MaxArraySize) nbytes = InitialArraySize;` then
  `LEPT_CALLOC(nbytes + 1, 1)` — a request of 1,000,000,001 bytes is silently
  clamped to a 201-byte allocation.
- `l_byteaInitFromStream()` (vulnerable `:177-196`, fixed `:179-202`):
  `data = l_binaryReadStream(fp, &nbytes)` then
  `ba = l_byteaCreate(nbytes)` then `memcpy(ba->data, data, nbytes)` with no
  size check. The fix inserts, before `l_byteaCreate`,
  `if (nbytes > MaxArraySize) { LEPT_FREE(data); return ERROR_PTR("stream too
  large", ...); }`. The pinned excerpts are byte-identical line ranges; the
  harness compiles the parent or fixed excerpt pair, never a hand-edited copy.

## Cheapest local experiment and observed result

The oversized stream is a **sparse file of 1,000,000,001 bytes mapped
read-only**, so the experiment needs no gigabyte of resident memory. Chosen
marker bytes are `pwrite`-ed at offsets 201, 256, 4096 and 65536 before the
map. `l_binaryReadStream`, `LEPT_CALLOC`, `LEPT_FREE`, `ERROR_PTR` and the
`L_Bytea` layout are stand-ins; the two size constants and both functions are
verbatim upstream bytes.

`bash lab/frontier/leptonica2shell/run-all.sh` → **17 PASS / 0 FAIL**, rc 0:

- GCC and Clang ASan vulnerable builds: `heap-buffer-overflow`,
  `WRITE of size 1000000001`, `0 bytes after 201-byte region`; allocation stack
  in pinned `create-parent.inc:9`, write stack in `stream-parent.inc:17`.
- Fixed build: `stream too large`, `BA=NULL`, no sanitizer report. A 16-byte
  stream on the vulnerable build gives `NALLOC=17 SIZE=16`, clean.
- Rung-4 PARTIAL observation uses a **synthetic bounded consumer** (`BOUNDED`
  compiles a 216-byte-capped `memcpy`) so the real-data marker at
  `data+201..215` is readable in a plain process:
  `PAST_ALLOC=4d495348452d4c4550544f4e49434111` (chosen
  `MISHE-LEPTONICA` plus one byte). The fixed plain build rejects the stream.
  W237 note: the plain harness prints 16 bytes at `data+201..216`, but the
  216-byte-capped copy supplies only the first 15; the last `0x11` is heap
  residue, not stream data. The wrapper asserts only the 15-byte prefix.
- Two earlier harness bugs are preserved as negatives: freeing the mmap source
  through `LEPT_FREE` crashed both fixed and safe controls (repaired with a
  stand-in free that skips the mapped pointer), and a 512-byte bounded copy
  crossed the glibc chunk and aborted (reduced to 216 bytes, inside this
  build's usable chunk size). No upstream byte was edited to make the suite
  pass.

## Real-library replay (2026-11-26)

`lab/frontier/leptonica2shell/real/` clones the pinned tag and fix commit,
builds both with `CMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer
-g -O0'` and the other image codecs disabled, and drives the real APIs. Both
real `src/bytearray.c` files hash to the exact values pinned in
`PROVENANCE.md`. `run-real.sh` uses a sparse 1,000,000,001-byte file with
chosen `MISHE-LEPTONICA` at offset 201.

Clean-archive replay: extract with `git archive HEAD
lab/frontier/leptonica2shell/real`, then `bash provision.sh` → 7 PASS /
0 FAIL, rc 0 at 14:58Z. `provision.sh` sha256
`073c55d82e852cb53ee8db3058308c87e5f3a8fed0064c184062d94911b9b789`;
`run-real.sh` sha256
`ce0a0ae3c109bd3561281fb966b55eeeae424f0b8e18402f1d34751e18b4e4f7`.
This is an author replay, not witness acceptance.

- `evidence/real-vuln-asan.out`: real `heap-buffer-overflow`,
  `WRITE of size 1000000001`, `0 bytes after 201-byte region`; write frame
  `l_byteaInitFromStream src/src/bytearray.c:192` called from
  `l_byteaInitFromFile :162`, allocation `l_byteaCreate :105`.
- `evidence/real-caller-asan.out`: identical WRITE reached through the
  in-tree caller `saConcatenatePdfToData src/src/pdfio1.c:2169`.
- `evidence/real-fixed-asan.out`: `stream too large`, `BA=NULL`, no ASan.
- `evidence/real-vuln-safe.out`: `SIZE=16 FIRST=4d`, no ASan.

Caller enumeration: `l_byteaInitFromStream()` is called only from
`l_byteaInitFromFile()` in `src/`. Its in-tree callers are
`pdfio1.c:saConcatenatePdfToData()` and regression programs `bytea_reg.c`,
`pdfio2_reg.c`, `xtractprotos.c`. No socket or request-dispatch caller exists
in this tree; the PDF path takes a list of filenames, not attacker-controlled
wire bytes. The first caller-stack assertion failed because ASan prints
callee-first; the assertion order was corrected, the observed report was not.

## Feasibility assessment and ceilings

- Rung 1 (trigger): deterministic, local, sparse-file-backed in the staged
  harness; the real-library replay allocates and reads the full 1,000,000,001
  bytes into a heap buffer before the overflow, so it needs about a gigabyte
  of resident memory. No external probe.
- Rung 2 (state failure): the clamp to 201 bytes while `size` and the copy
  length use the unclamped stream size is directly observed.
- Rung 3: GCC and Clang ASan WRITE on verbatim pinned functions **and in the
  real 1.87.0 library**, with clean fixed and safe controls.
- Rung 4: PARTIAL — bytes come from the input stream at chosen offsets past
  the declared 201-byte region, but the plain-build readback uses a synthetic
  bounded `memcpy`; no real Leptonica consumer, adjacent object or pointer is
  in evidence. The unbounded plain build runs off the heap into unmapped
  memory, so it cannot serve as a readback oracle. The real-library caller
  `saConcatenatePdfToData()` reaches the WRITE but offers no chosen-byte
  readback.
- Rung 5: NOT CLAIMED — real library and process, but no wire input, no live
  server, no pointer-bearing victim object and no command execution. The
  advisory is a local file/stream parser issue.
- Next experiment: find an external consumer that feeds a >1 GB stream to a
  Leptonica API reachable from request bytes and measure the live heap
  neighborhood; preserve the no-pointer/no-command ceiling until then. The
  staged and real-library lanes are complete as labeled; witness replay of
  the real-library runner is requested separately.
