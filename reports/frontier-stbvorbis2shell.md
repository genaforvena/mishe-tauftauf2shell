# frontier brief — stbvorbis2shell (CVE-2026-89266)

Status 2026-11-24 09:22Z: **STAGED and handed off**, rung 4 partial in the
real upstream library via its public API. Brief, seed wall, pins and
`lab/frontier/stbvorbis2shell/` evidence are committed at `e6ef1fc`;
two-pane window 135 is live on the inner socket and registered (136/136
unique). Operator owns final admission; person owns wake units.

## Verified ground truth

- Claim: VulnCheck advisory dated 2026-09-11,
  [CVE-2026-89266](https://www.vulncheck.com/advisories/stb-vorbis-through-1.22-heap-buffer-overflow-via-codebook-multiplicands),
  CWE-787 out-of-bounds write, CVSS 8.8
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`,
  stb_vorbis <= 1.22. Credit: boergeson, Përparim Mjeku.
- Public record: nothings/stb issues
  [#1928](https://github.com/nothings/stb/issues/1928) (bug 14),
  [#1933](https://github.com/nothings/stb/issues/1933) (truncation debate),
  [#1947](https://github.com/nothings/stb/issues/1947) (205-byte OGG PoC).
- Vulnerable bytes: `stb_vorbis.c` v1.22 at commit
  `2c980bb59875b0d32144a71867fbdebb2f77cd20`, sha256
  `4c7cb2ff1f7011e9d67950446b7eb9ca044f2e464d76bfbb0b84dd2e23e65636`.
- Fixed control: dev-branch `stb_vorbis.c`, sha256
  `daedcc5ca51d5af8e910816d30ac6d791c4c0364ea5c8c7625bff429371e86a5`.
  A `CODEBOOK_LIMIT (1<<18)` check at line 3815 rejects the oversized
  codebook; issue #1933 records its merge on 2026-10-26. Numeric fixed
  release: UNKNOWN (dev branch only).
- All bytes, hashes, logs and negative results are in
  `lab/frontier/stbvorbis2shell/PROVENANCE.md`.

## Source-bound mechanism

`setup_malloc(vorb *f, int sz)` (pinned line 950) rounds `sz` up to a
multiple of eight and calls `malloc(sz)`. At pinned line 3880 the codebook
multiplicands allocation is
`setup_malloc(f, sizeof(float) * c->entries * c->dimensions)`; `entries` and
`dimensions` come straight from the crafted Vorbis setup header. Left-to-right
evaluation promotes the product to `size_t` (correctly), then the call
truncates it to `int`:

```
4 * 16519105 * 65 = 4294967300 = 2^32 + 4  ->  int 4  ->  malloc(8)
```

The pre-expansion loop at lines 3883-3889 writes one float per
`j * dimensions + k`, so the second in-bounds float is followed by writes
past the 8-byte region. The multiplicand value is computed from file-derived
`minimum_value`, `delta_value` and multiplicand table: with delta zero and
all multiplicands zero, every stored float equals `minimum_value`.

## Observed evidence (real upstream library, public API)

Harness calls `stb_vorbis_open_memory()` on a crafted 205-byte OGG.
`sh lab/frontier/stbvorbis2shell/run-all.sh` -> 9 PASS / 0 FAIL, rc 0,
2026-11-24T09:17Z:

- ASan vulnerable build: `heap-buffer-overflow`, `WRITE of size 4` at
  `stb_vorbis.c:3889` in `start_decoder`, called from `stb_vorbis_open_memory`
  via `harness.c:21`; address is 0 bytes after an 8-byte region allocated at
  `setup_malloc` line 960 from call site line 3880. rc 1.
- Dev-branch fixed build on the same PoC (and on the chosen-byte PoC): rc 0,
  no ASan report. Plain vulnerable rc 134; plain fixed rc 0; vulnerable
  build with a non-OGG input rc 0.
- Chosen bytes: a second 205-byte PoC encodes `minimum_value` in Vorbis
  float32 form so the in-memory IEEE bits are `4b 43 41 48` ("HACK"). gdb at
  line 3890, third write (`j=0, k=2`, `c->multiplicands[2]`, the first OOB
  float): `val = 0x4b434148` and the stored word is `0x4b434148`.
- Negative: passing the raw IEEE bit pattern instead of the Vorbis-encoded
  value produced zero-valued writes; `float32_unpack()` at line 1057 converts
  the file field. Total number of OOB writes before death: UNKNOWN.

## Rung-4 feasibility and ceiling

**Rung 1** (deterministic trigger) and **rung 2** (undersized allocation with
oversized write loop) are observed. **Rung 3** is ASan-confirmed in the
unmodified upstream source through the real public entry point. **Rung 4 is
partial**: four file-chosen bytes (`HACK`) land at a chosen offset (first OOB
float, +8) in the harness driving the real upstream library through its
public API. That harness is a minimal driver, not a real application build;
the alphabet is a single repeating 4-byte word, not per-offset arbitrary
bytes; the write count past the allocation is not measured. No
pointer/IP/command control, no network/wire input, no rung 5. Build cost is
seconds, unlike the screened-out MediaInfoLib candidate.

## Cheapest next experiment

Instrument the vulnerable build with a custom allocator that places a guard
page immediately after the 8-byte multiplicands allocation, then count the
exact OOB extent and test whether distinct per-offset 32-bit values can be
steered through `minimum_value`, `delta_value` and the multiplicand table.
Then reproduce the same PoC through a real consumer built from source
(issue #1947 used whisper.cpp) to see whether the overwritten word reaches a
pointer or control datum. Any r5 claim requires an independent witness replay.

## Handoff

Operator owns final admission; the person owns charter, wake units and
full-flag sync. This brief is not independent acceptance.
