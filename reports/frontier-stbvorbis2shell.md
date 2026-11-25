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

### W202 (2026-11-25) — distinct file-derived words at consecutive OOB offsets

The W201 PoC set `sequence_p=0` (pinned `:3854`). At `j=0`, `off` is
`(z/div) % lookup_values`, which is 0 for every `k`, so
`val = mults[0]*delta + minimum + last` is constant (`last` stays 0):
hence the single repeating "HACK" word.
`gen_poc.py` now takes an optional 5th argument setting the `sequence_p`
header bit (default 0, so `run-all.sh` is unchanged). With `sequence_p=1`,
pinned `:3890-3891` sets `last = val` after each store, so successive floats
are `minimum, 2*minimum, 3*minimum, …`. A 205-byte PoC
(`evidence/chosen-seq.ogg`, `sequence_p=1`, `minimum_value` encoding IEEE
`0x4b434148`) was replayed under gdb (break `:3890`, `ignore 1 2`):

| OOB index | observed word | predicted |
|-----------|---------------|-----------|
| `multiplicands[2]` | `0x4c1270f6` | `0x4c1270f6` |
| `multiplicands[3]` | `0x4c434148` | `0x4c434148` |
| `multiplicands[4]` | `0x4c74119a` | `0x4c74119a` |
| `multiplicands[5]` | `0x4c9270f6` | `0x4c9270f6` |

Four distinct file-derived words at four consecutive OOB offsets, each
matching an independent float32 model. ASan on this PoC: `WRITE of size 4`
at `:3889`, rc 1; fixed dev-branch build rc 0. `run-all.sh` still 9 PASS /
0 FAIL. Logs in `lab/frontier/stbvorbis2shell/evidence/gdb-chosen-seq.out`
and `asan-{vuln,fixed}-chosen-seq.out`.

One-command witness replay: `sh lab/frontier/stbvorbis2shell/run-seq.sh`
(4 PASS / 0 FAIL, rc 0) rebuilds the plain harness, regenerates the PoC and
checks all four words; it leaves `run-all.sh` and its 9 PASS baseline intact.

## Rung-4 feasibility and ceiling

**Rung 1** (deterministic trigger) and **rung 2** (undersized allocation with
oversized write loop) are observed. **Rung 3** is ASan-confirmed in the
unmodified upstream source through the real public entry point. **Rung 4 is
partial**: file-chosen float words land at chosen consecutive OOB offsets in
the harness driving the real upstream library through its public API. W201
showed one repeating word (`HACK`) at the first OOB float (+8); W202 shows
four distinct file-derived words at offsets +8..+20 via `sequence_p=1`.
That harness is a minimal driver, not a real application build; the words
remain float-representable values in an arithmetic progression, not arbitrary
per-offset bytes; the write count past the allocation is not measured. No
pointer/IP/command control, no network/wire input, no rung 5. Build cost is
seconds, unlike the screened-out MediaInfoLib candidate.

## Remaining experiments (in priority order)

1. Guard-page allocator: place a `PROT_NONE` page immediately after the
   8-byte multiplicands allocation to count the exact OOB extent before the
   process dies. The loop bound (`entries*dims` ~ 1.07e9 floats) is known
   from source; the number of consecutive words that land in writable heap
   before SIGSEGV is not. SUPERSEDED by W203 in
   `reports/stbvorbis2shell-status.md`: this PoC stops at `:3895` after 31
   writes (29 OOB words, 116 bytes); `entries*dims` is only the loop bound.
2. Real consumer build (issue #1947 used whisper.cpp) fed the same PoC: check
   whether a file-steered OOB word reaches a pointer or control datum.
3. Witness replay of any new claim before it is treated as established.
   Per-offset steering via `sequence_p` (W202) is DONE above; it is not
   arbitrary bytes and does not by itself raise the rung-4 grade.

## Handoff

Operator owns final admission; the person owns charter, wake units and
full-flag sync. This brief is not independent acceptance.
