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

Plain-build heap-neighborhood update 2026-11-26 15:33Z: a lab-only
`--wrap=calloc` sentinel placed immediately after the vulnerable 201-byte
allocation receives chosen `MISHE-LEPTONICA` bytes from the oversized stream
before the plain process faults (`SENTINEL_OFFSET=224`,
`CHOSEN_AT_OFFSET=16`; safe 16-byte input clean). Clean-archive replay of
`real/run-neighbor.sh` from commit `edd20190`: 3 PASS / 0 FAIL, rc 0. The
sentinel and fault observer are synthetic lab mechanics, so the grade stays
rung 3 real / rung 4 PARTIAL.

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

Bounded external-caller negative (2026-11-26 16:1xZ): a read-only
gitignore-respecting search of the checkout's `lab/` C/C++/header sources
found no caller of any `l_bytea*` API outside this project. The sole other
consumer of Leptonica's `allheaders.h`, `ghostscript2shell`'s
`base/tessocr.cpp:60`, uses in-memory `Pix` APIs and `gp_fread` for
Tesseract data, never a Leptonica stream reader. Untracked bulk trees were
not exhaustively enumerated after a gitignore-disabled scan timed out, so
this is a bounded negative for tracked sources, not a universal claim.

### Plain-build live neighbor probe and fault boundary (2026-11-26 16:09Z)

`real/run-neighbor.sh` builds the same pinned 1.87.0 tree without ASan and
links `real/neighbor.c` with `-Wl,--wrap=calloc`. The wrapper recognizes the
vulnerable `calloc(201, 1)` in `l_byteaCreate()`, allocates a live 512-byte
sentinel right after it, and fills it with `0x5a`; the fixture plants the
chosen marker at stream offsets 208..1024 (step 32). A `sigaction` SIGSEGV
observer reads the sentinel, reports `siginfo_t.si_addr` and dumps
`/proc/self/maps` before `_exit(77)`. Observed in-tree:
`TOTAL: 5 PASS / 0 FAIL`, rc 0, with `SIGNAL=SIGSEGV SENTINEL_OFFSET=224`,
`SENTINEL_FIRST32=000000000000000000000000000000004d495348452d4c4550544f4e49434100`,
`CHOSEN_AT_OFFSET=16`, and:

```
FAULT_ADDR=0x617109a4e000 FAULT_OFFSET_FROM_DATA=129504
DATA_ADDR=0x617109a2e620 SOURCE_ADDR=0x7193f2853010 SOURCE_DELTA=17742122076656
617109a2d000-617109a4e000 rw-p 00000000 00:00 0                          [heap]
7193f2853000-71942e200000 rw-p 00000000 00:00 0
```

The chosen bytes reach a live adjacent heap object 224 bytes past `ba->data`
before the copy faults exactly at the end of the 135,168-byte heap mapping,
129,504 (`0x1f9e0`) bytes past `ba->data`. The 1,000,000,001-byte source
buffer lives in a separate 1,000,001,536-byte anonymous mapping 17.7 TB away,
because `l_binaryReadSelectStream()` allocates it with `calloc(1,
bytestoread + 1)` (utils2.c:1508). No contiguous writable gigabyte follows
the small destination allocation in this process, so an ordinary consumer
faults after overwriting at most ~129 KB of heap. The sentinel, address
observer and map dump are lab-groomed mechanics, not a request-reachable
consumer; no pointer value or command is read or executed. Safe 16-byte
stream: `BA=nonnull`, `SIZE=16 NO_FAULT=1`, rc 0, no fault. An early runner
revision checked `NO_FAULT` before `SIZE` and failed only that safe-control
pattern; the check order was corrected, no observation changed. Earlier
clean-archive replay of the 3-check version at 15:33Z from commit `edd20190`
was 3 PASS / 0 FAIL; the current 5-check version is replayed below.

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
  the declared 201-byte region. The staged harness uses a synthetic bounded
  `memcpy`; the plain real-library probe writes chosen bytes into a live
  adjacent object 224 bytes past `ba->data` but that object is lab-groomed and
  read by a fault handler, not by a request-reachable consumer. No pointer
  value is consumed and no command executes. The unbounded plain process
  faults at the end of its heap mapping, 129,504 bytes past `ba->data`; the
  ~1GB source buffer is in a separate mapping 17.7 TB away. The real-library
  caller `saConcatenatePdfToData()` reaches the WRITE but offers no
  chosen-byte readback.
- Rung 5: NOT CLAIMED — real library and process, but no wire input, no live
  server, no pointer-bearing victim object and no command execution. The
  advisory is a local file/stream parser issue.
- Next experiment: an external consumer that feeds a >1 GB stream to a
  Leptonica API reachable from request bytes would also need its own
  contiguous writable ~1 GB mapping immediately after the small destination;
  no such consumer is present in this checkout, and the measured fault
  boundary above records why the ordinary case cannot survive the copy. A
  read-only hunt across other locally provisioned lab trees is running; a
  negative result is preserved, not retried into existence. Preserve the
  no-pointer/no-command ceiling. The staged and real-library lanes are
  complete as labeled; witness replay of both real runners is requested.
