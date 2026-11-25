# frontier brief — leptonica2shell (CVE-2026-137063)

Status 2026-11-25 23:0xZ: STAGED locally; brief, status, charter, seed wall,
harness and PROVENANCE written; inner two-pane window created. No admission
or independent acceptance is claimed here; the operator admits, the witness
replays.

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
- Two earlier harness bugs are preserved as negatives: freeing the mmap source
  through `LEPT_FREE` crashed both fixed and safe controls (repaired with a
  stand-in free that skips the mapped pointer), and a 512-byte bounded copy
  crossed the glibc chunk and aborted (reduced to 216 bytes, inside this
  build's usable chunk size). No upstream byte was edited to make the suite
  pass.

## Feasibility assessment and ceilings

- Rung 1 (trigger): deterministic, local, sparse-file-backed; no external
  probe. The >1 GB logical size is unavoidable, but resident cost is one page
  plus the mapped file.
- Rung 2 (state failure): the clamp to 201 bytes while `size` and the copy
  length use the unclamped stream size is directly observed.
- Rung 3: GCC and Clang ASan WRITE on verbatim pinned functions.
- Rung 4: PARTIAL — bytes come from the input stream at chosen offsets past
  the declared 201-byte region, but the plain-build readback uses a synthetic
  bounded `memcpy`; no real Leptonica consumer, adjacent object or pointer is
  in evidence. The unbounded plain build runs off the heap into unmapped
  memory, so it cannot serve as a readback oracle.
- Rung 5: NOT CLAIMED — no real library build, no live process, no wire, no
  command execution. The advisory is a local file/stream parser issue.
- Next experiment for the target mind: build real Leptonica 1.87.0 and the
  fixed commit under ASan, call `l_byteaInitFromFile()` on the same sparse
  1,000,000,001-byte file, confirm the ASan WRITE inside the real library, and
  enumerate which real callers feed `l_byteaInitFromStream` attacker-sized
  input. Preserve any structural consumer boundary as a negative; do not
  claim pointer or command control without a live readback.
