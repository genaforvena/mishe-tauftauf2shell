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

**Rung 1/2/3 are observed. Rung 4 is PARTIAL.** W203 measured 30 OOB words
(120 bytes). W206 reached SDL_mixer's public API; W207 measured chosen
allocator-metadata corruption in that real consumer. W208 then used a valid
audio preload to place the attack `FILE` at `multiplicands+32`, overwrote its
live `_IO_save_base`/`_IO_backup_base`/`_IO_save_end` pointers with
`0x4b4341484b434148`, and observed libc `free()` receive that chosen value.

The value is a repeated float-representable word, not a valid arbitrary
pointer. The result is conditional on prior consumer state and local-file
delivery. No IP/command control, wire input, rung 5 or fresh witness verdict
exists. Full controls and replay are in `reports/stbvorbis2shell-status.md`.

## Remaining experiments (in priority order)

1. Independent witness replay of W202-W208.
2. A canonical chosen pointer or control-flow target. The current repeated
   word forms a noncanonical 64-bit pointer; `sequence_p` supplies a monotonic
   progression and cannot place a zero/small high half after a low userspace
   address half.
3. A different live consumer field or consumer layout. Padding and file-driven
   lead-codebook allocation sizes 2..1024 are measured negatives; do not retry
   them unchanged.

## Handoff

Operator owns final admission; the person owns charter, wake units and
full-flag sync. This brief is not independent acceptance.

## W205 — unwrapped glibc heap neighbour measurement (2026-11-25)

Harness: `lab/frontier/stbvorbis2shell/harness-neighbor.c` (vulnerable) and
`harness-neighbor-fixed.c` (fixed control). malloc/free wrapped only to record
live allocations; a 3-line hook in pinned `setup_malloc()` calls
`w205_watch8()` on every 8-byte allocation. The 4th 8-byte allocation is
`c->multiplicands`; at that instant the harness prints all live allocations.

Observed (`evidence/neighbor-vuln-attack.out`): 11 live allocations; 8-byte
setup allocations at deltas -128, -96, -64, -32, 0; no allocation in the
30-word OOB range [+8,+128). The words therefore corrupt free heap
space/metadata on unwrapped glibc, consistent with the plain libc abort.
Fixed dev branch: `err=20`; safe input: `err=30`. Replay:
`sh run-neighbor.sh` -> 9 PASS / 0 FAIL, rc 0.

Interpretation: NEGATIVE for the real-consumer path without grooming. The
W204 adjacent pointer field was harness-placed; a consumer lane must place
its own object in range by an observed mechanism. Grade stays rung 4 PARTIAL,
author-only, unwitnessed; NO r5.

## W206 (2026-11-25) — real consumer: SDL_mixer public API path

`consumer/mix-driver.c` drives the crafted OGG through SDL_mixer 3.x's
public `MIX_LoadAudio_IO()` API. The consumer is built from the in-tree
`lab/frontier/sdlmixer2shell/deps/SDL_mixer-vuln-src` with
`SDLMIXER_VORBIS_STB=ON`, other Vorbis backends OFF and ASan; its vendored
v1.22 header is unmodified. Full call chain observed on
`evidence/chosen.ogg`:

    main -> MIX_LoadAudio_IO -> MIX_LoadAudioWithProperties ->
    PrepareDecoder -> STBVORBIS_init_audio (decoder_stb_vorbis.c:158) ->
    stb_vorbis_open_io -> start_decoder (stb_vorbis.h:4049)

ASan reports `WRITE of size 4`, 0 bytes after the 8-byte region from
`:4040`, rc 134. Fixed control (one-line `CODEBOOK_LIMIT` check added to
the consumer's vendored header) and safe input both rc 0 with no ASan
report. Replay: `sh lab/frontier/stbvorbis2shell/run-consumer.sh` ->
12 PASS / 0 FAIL, rc 0.

This upgrades rung 3 to a real application's public API and adds confirmed
memory corruption in a real consumer to rung 4. It does not show a chosen
word in a consumer-owned field, pointer/IP control or command execution;
ASan stops at the first store. Grade stays rung 4 PARTIAL, NO r5.

## W207 (2026-11-25) — real consumer heap layout and grooming ceiling

The W206 consumer was rebuilt without ASan (`-O0 -g`), leaving SDL_mixer's
vendored stb_vorbis v1.22 unmodified. Plain `evidence/chosen.ogg` aborts rc 134
(`malloc(): invalid size (unsorted)`); safe input rc 0. `consumer/heap-break.gdb`
snapshots `c->multiplicands` before the loop (vendored `:4043`) and at the
div-overflow guard (`:4054`). Pre-write: the 8-byte allocation's user area
holds tcache pointers `0x7ffff7c04b20`, the next word is zero, and the next
free chunk's size header at `+24` is `0x91`. Post-write: 30 file-chosen words
`0x4b434148` at `+8..+124`, with the `+24` word replacing that chunk size with
`0x4b434148`. No live allocation occupies `[+8,+128)`. This is a real-consumer
version of W205's negative, plus the specific allocator-metadata corruption
that explains the abort.

Padding the same PoC to 4096/65536/1048576 bytes (preserving its first 205
bytes) produced the same address, the same free chunk and the same size
clobber: no layout change, so no consumer-owned neighbour by that grooming
route. One-command replay:
`sh lab/frontier/stbvorbis2shell/run-consumer-heap.sh` -> 11 shell checks and
14 heap-word checks, all PASS, rc 0 (includes the ASan/fixed controls through
`run-consumer.sh`). Grade stays rung 4 PARTIAL, NO r5, unwitnessed.

## W208 (2026-11-25) — real consumer live FILE pointer overwrite

`consumer/mix-driver.c` optionally keeps a valid decoded audio object alive and
then calls `MIX_LoadAudio_IO()` on `evidence/chosen.ogg`. The valid preload is
`evidence/preload-safe.ogg`, 2673 bytes, sha256
`3a619dff0ccaacd6b7fc0f52bde37d4fd20b767b34407924eb4377358da87992`.

In the plain glibc 2.39 consumer, the attack `FILE` lands at
`c->multiplicands+32`. OOB indices 8..31 overwrite its first 96 bytes. gdb
watchpoints observed `_IO_save_base` become `0x4b434148` at `k=26`, then
`0x4b4341484b434148` at `k=27`; `_IO_backup_base` and `_IO_save_end` receive
the same 64-bit pattern. The failure seek passes that pointer to libc `free()`
and SIGSEGVs. Vulnerable ASan rc 134, fixed rc 0, safe rc 0.

Replay: `sh lab/frontier/stbvorbis2shell/run-consumer-preload.sh` -> 17 PASS /
0 FAIL, rc 0. Grade stays rung 4 PARTIAL: chosen pointer-value corruption and
use in a live real-consumer object, but no valid arbitrary pointer, IP/command,
wire or r5. Author-only and unwitnessed.
