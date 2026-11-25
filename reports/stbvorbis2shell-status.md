# stbvorbis2shell — admitted status (2026-11-25 10:58Z)

**ADMITTED under standing #6 as the 147th route** by operator at 10:58Z:
hy4-flash `max_parallel: 3` route, both resolver keys, three wake units
minted with the exact full-flag sync (`written 3, removed 0`), path enabled
and active, pinned full-flag doctor PASS / GREEN rc 0. Window 135 was already
live and registered; it was adopted, not duplicated. Charter created at
admission; the seed wall and lab already existed. No grade, rung cell or R5
cell moved by the admission; witness verdict is UNKNOWN.

## Staged evidence preserved from the frontier brief

The full staged claim, hashes, negatives and cheapest-next experiment remain
in `reports/frontier-stbvorbis2shell.md` and
`lab/frontier/stbvorbis2shell/PROVENANCE.md`. In brief: CVE-2026-89266
(VulnCheck 2026-09-11, CWE-787, CVSS4 8.8, stb_vorbis <= 1.22); vulnerable
v1.22 at `2c980bb` sha256 `4c7cb2ff…e65636`, dev-branch fixed control
`daedcc5c…e86a5` with `CODEBOOK_LIMIT (1<<18)` (numeric fixed release
UNKNOWN). The pinned `setup_malloc(vorb*, int)` truncates a file-derived
`size_t` product `4 * 16519105 * 65 = 2^32+4` to 4 and `malloc(8)`, while the
expansion loop writes floats past it. `sh lab/frontier/stbvorbis2shell/run-all.sh`
gave 9 PASS / 0 FAIL: ASan `WRITE of size 4` at `stb_vorbis.c:3889` in
`start_decoder` through the real public `stb_vorbis_open_memory()`, fixed
control and safe input clean, plain vulnerable rc 134, and gdb observed four
file-chosen bytes `4b 43 41 48` ("HACK") at the first out-of-bounds float.

Current grade (W208): rung 1/2/3 observed; **rung 4 PARTIAL**. W203 measured
30 OOB words, W206 reached a real SDL_mixer consumer, W207 measured chosen
allocator-metadata corruption, and W208 overwrote a live libc `FILE` pointer
with a file-chosen 64-bit pattern under a valid-audio preload. The pattern is
not a valid arbitrary pointer; IP/command control, wire input, rung 5 and a
fresh witness verdict remain absent. Any r5 claim needs independent replay.

## W202 (2026-11-25) — measured update

Added an optional `sequence_p` bit to `gen_poc.py` (default 0, so the 9
PASS / 0 FAIL `run-all.sh` is unchanged). With `sequence_p=1`, pinned
`:3890-3891` accumulates `last` into each write, so the OOB floats become
distinct file-derived values instead of one repeating word. gdb on the new
205-byte `evidence/chosen-seq.ogg` observed `0x4c1270f6`, `0x4c434148`,
`0x4c74119a`, `0x4c9270f6` at `multiplicands[2..5]` (offsets +8..+20), each
matching an independent float32 prediction. ASan on that PoC: `WRITE of
size 4` at `:3889` rc 1; fixed dev branch rc 0. Full table and logs in
`reports/frontier-stbvorbis2shell.md` and `lab/frontier/stbvorbis2shell/evidence/`.

One-command witness replay: `sh lab/frontier/stbvorbis2shell/run-seq.sh`
(4 PASS / 0 FAIL, rc 0).

Grade unchanged: rung 1/2/3 observed, **rung 4 PARTIAL** — now four distinct
file-chosen words at consecutive offsets, but still float-representable
values in an arithmetic progression, not arbitrary per-offset bytes. Exact
OOB extent, real consumer build, pointer/IP, wire, command and fresh witness
verdict on this new claim remain UNKNOWN. NO rung 5. Next: guard-page
allocator, then a real consumer build.

## W203 (2026-11-25) — exact OOB extent, corrected loop bound

`harness-guard.c` wraps only malloc/free in the pinned vulnerable source:
each 8-byte setup allocation is placed at the start of a RW page followed by
a `PROT_NONE` page. `c->multiplicands` was that guarded allocation
(`guarded_pages[4]`, page start `0x7ffff7fb3000` in the replay). At the
source's own div-overflow guard `stb_vorbis.c:3895`, gdb observed `j=0`,
`k=31`, `div=0x80000000`, `lookup_values=2`; indices `2..31` — 30 four-byte
words, 120 bytes past the 8-byte region — hold distinct file-derived words
from `0x4c1270f6` through `0x4dc34143` (all 30 in
`lab/frontier/stbvorbis2shell/evidence/gdb-guard-extent.out`). The guard page
is never reached: `VORBIS_invalid_setup` returns first. The plain libc build
of the same input instead aborts with `malloc(): invalid size (unsorted)`
(rc 134) from those 30 words; the guarded and fixed builds exit 0.

This corrects the staged "~1.07e9 writes execute" description: that is the
source loop bound, not what this PoC performs. `sh
lab/frontier/stbvorbis2shell/run-guard.sh` gives 12 PASS / 0 FAIL, rc 0.

Grade UNCHANGED: rung 1/2/3 observed, **rung 4 PARTIAL** — distinct
file-chosen words at consecutive offsets with a measured extent for this
PoC, but float-representable arithmetic progression only, no real consumer,
pointer/IP, wire, command or independent verdict on W202/W203. NO rung 5.
Replay offered to the witness at chat event 4336; both new claims stay
UNVERIFIED until that verdict lands.

## W204 (2026-11-25) — file-chosen words reach an adjacent object's pointer field

`harness-object.c` keeps the pinned source verbatim and wraps only
malloc/free: every 8-byte setup allocation starts a RW page followed by
`PROT_NONE`, and a distinct live `struct victim { canary[64]; void (*fp)(void);
tail[64]; }` is memset to `0x5a` immediately after the allocation. The
pointer is only read back, never called. With `evidence/chosen.ogg`
(`sequence_p=0`) the vulnerable build stops at `:3895` with `err=20`, and
`victim[4] changed=120 sizeof=136 fp=0x4b4341484b434148
fp_low=0x4b434148`: all 30 file-chosen OOB words overwrite the adjacent
object's canary, both halves of its pointer field and 44 bytes of its tail.
The other four guarded victims stay untouched. Fixed dev branch rejects the
same file before any guarded allocation (`err=20`, `guarded=0`); a
non-OGG input also stays clean (`err=30`, `guarded=0`). One-command replay:
`sh lab/frontier/stbvorbis2shell/run-object.sh` -> 9 PASS / 0 FAIL, rc 0.

Two ways to remove the source-level `div` stop were measured and REJECTED,
not assumed: (a) dims=260 with the same wrapped product still gives
`lookup_values=2` — `lookup1_values()` casts `pow(2,260)` to `int` before
comparison, so the guard still fires at `k=31`; (b) `lookup_type=2` has no
`div` guard, but its `mults` allocation is `2 * entries * dimensions` and
exceeds `INT_MAX` for every wrapped `4 * entries * dimensions` under the
24-bit `entries` header field, so parsing fails with out-of-memory first.
The guarded dims=260 file `evidence/nodiv-seq.ogg` (sha256
`26306dfa5e5c9d1f3d24163c8a0d048d45de614fb86e748b10d555c52d254ea6`)
is kept as a negative-result artifact only; it is not a new trigger.

Grade UNCHANGED at rung 4 PARTIAL: file-chosen 32-bit words now reach a
pointer-typed field in an adjacent live object, but the value is the same
float-representable word repeated, the victim is harness-placed, the pointer
is never dereferenced, and there is no real consumer, arbitrary 64-bit
value, wire, IP hijack, command or r5. W204 is author-only and unwitnessed;
the earlier replay offer at event 4336 has no verdict yet.

## W205 (2026-11-25) — unwrapped glibc heap: no live object in the OOB range

W204's adjacent victim was harness-placed. To test the real-consumer question
without building an app, `harness-neighbor.c` wraps only malloc/free to
record live allocations and adds a 3-line hook to the pinned `setup_malloc()`
that calls `w205_watch8()` on every 8-byte allocation. The fourth 8-byte
allocation in this PoC is `c->multiplicands`; at that instant the harness
dumps all live allocations and any overlap with the 30-word OOB run
`[p+8, p+128)`. No victim is planted, no allocator layout is forced, and no
wrapped pointer is called.

Result (vulnerable v1.22, `evidence/chosen.ogg`): 11 live allocations; the
setup allocations sit at deltas -128, -96, -64, -32, 0 relative to
`c->multiplicands`; the input buffer and three `mults` arrays are thousands of
bytes away. **Zero live allocations overlap `[+8,+128)`** — the file-chosen
words land in free heap space/metadata, consistent with the plain libc abort
(`malloc(): invalid size (unsorted)`, rc 134) already recorded in W203. The
fixed dev branch and a non-OGG input remain clean (`err=20`/`err=30`).
One-command replay: `sh lab/frontier/stbvorbis2shell/run-neighbor.sh` ->
9 PASS / 0 FAIL, rc 0.

This is a NEGATIVE RESULT for the unassisted real-consumer path: on the
lab's glibc a consumer has no live object placed in the OOB path, so the
W204 pointer-field overwrite requires harness placement. Grade stays
rung 4 PARTIAL; no r5. W205 is author-only and unwitnessed.

## Replay receipt (2026-11-25 14:05Z)

In-tree: `run-all.sh` 9/0, `run-seq.sh` 4/0, `run-guard.sh` 12/0,
`run-object.sh` 9/0, `run-neighbor.sh` 9/0, all rc 0.

## W206 (2026-11-25) — real consumer: SDL_mixer public API faults on the PoC

For the first time the crafted OGG was driven through a real application's
**public** decoding API, not a purpose-built harness. `consumer/mix-driver.c`
calls `MIX_LoadAudio_IO(NULL, io, 1, 1)` on SDL_mixer 3.x built from the
in-tree `lab/frontier/sdlmixer2shell/deps/SDL_mixer-vuln-src` with
`SDLMIXER_VORBIS_STB=ON` (other Vorbis backends OFF) and ASan. SDL_mixer's
own vendored `src/stb_vorbis/stb_vorbis.h` is unmodified v1.22; its line
4040/4049 is the same truncation and OOB store as pinned `:3880/:3889`.

Observed with the 205-byte `evidence/chosen.ogg` (sha256
`31c4686a65b13f2303f6d0e39020c8390fda1a5f81c2d4e997ddaae3aa86050d`):

    ASan: heap-buffer-overflow, WRITE of size 4, 0 bytes after an 8-byte
    region allocated at stb_vorbis.h:4040, write at :4049 in start_decoder.
    Call chain: main -> MIX_LoadAudio_IO -> MIX_LoadAudioWithProperties ->
    PrepareDecoder -> STBVORBIS_init_audio (decoder_stb_vorbis.c:158) ->
    stb_vorbis_open_io -> start_decoder. rc 134.

Controls: same consumer with a one-line `CODEBOOK_LIMIT` check added to its
vendored header rejects the file cleanly (rc 0, no ASan report); the same
vulnerable consumer on `evidence/safe-input.bin` is also clean (rc 0).
One-command replay: `sh lab/frontier/stbvorbis2shell/run-consumer.sh` ->
12 PASS / 0 FAIL, rc 0. Evidence: `lab/frontier/stbvorbis2shell/consumer/
evidence/{vuln-attack,fixed-attack,vuln-safe,replay}.out`.

Interpretation: rung 3 now includes a real consumer's public API path, and
rung 4 includes **confirmed memory corruption in that real consumer**,
not only in a minimal harness. ASan stops at the first OOB store, so this
does NOT show a chosen word surviving into a consumer-owned object, pointer
control or command execution. Grade stays **rung 4 PARTIAL**, NO r5; W206 is
author-only and unwitnessed. Wire/network input (the PoC is delivered as a
local file here) and consumer-object landing remain UNKNOWN.

Clean archive of amended HEAD `eb785d31` into `/tmp/w206-stbvorbis` at
14:53Z replayed all committed scripts with the SDL_mixer dependency copied
to the sibling path: `run-consumer.sh` 12/0,
`run-all.sh` 9/0, `run-seq.sh` 4/0, `run-guard.sh` 12/0,
`run-object.sh` 9/0, `run-neighbor.sh` 9/0 — all rc 0.
Live tree untouched.

## W207 (2026-11-25) — real consumer heap: chosen word clobbers a free chunk size

W206's ASan build stops at the first store, so a plain (-O0 -g, no ASan) build
of the same unmodified SDL_mixer consumer was used to observe the full 30-word
OOB run in the real application. On `evidence/chosen.ogg` the plain consumer
aborts rc 134 with `malloc(): invalid size (unsorted)`; the safe input exits 0.
`consumer/heap-break.gdb` stops at vendored `stb_vorbis.h:4043` (before the
expansion loop) and `:4054` (the source div-overflow guard, after all 30
stores), then dumps the chunk around `c->multiplicands`.

Observed at `c->multiplicands = 0x5555555f3c50` (chunk header `0x21`, 24 usable
bytes): before the stores, the 8-byte user area held tcache pointers
`0x7ffff7c04b20`, the following word was zero, and the next free chunk's size
header at `+24` was `0x91`; no live allocation overlapped `[+8,+128)`. After
the stores, all 30 file-chosen words `0x4b434148` ("HACK") filled offsets
`+8..+124`, and the word at `+24` changed the next chunk's size from `0x91`
to `0x4b434148`. This is the measured mechanism behind the plain-libc abort:
the chosen bytes corrupt allocator metadata belonging to the consumer's heap,
not a consumer-owned data field.

A bounded grooming attempt padded the PoC to 4096, 65536 and 1048576 bytes
(first 205 bytes unchanged, so parsing is identical). The multiplicands
address, the free chunk and the resulting size clobber were identical in every
run: padding gives no consumer-owned neighbour (negative result, preserved).
An LD_PRELOAD malloc logger tried first perturbed the allocator and crashed
before the guard; it was discarded and is not part of the claim.

One-command replay: `sh lab/frontier/stbvorbis2shell/run-consumer-heap.sh` ->
11 PASS / 0 FAIL shell checks plus 14 PASS / 0 FAIL heap-word checks, rc 0;
it also replays `run-consumer.sh` (12 PASS / 0 FAIL) for the ASan and fixed
controls. Raw snapshots in `lab/frontier/stbvorbis2shell/consumer/evidence/
{heap-gdb-snapshots,plain-attack,plain-safe,sweep-*}.out` (gitignored).

Grade UNCHANGED: rung 1/2/3 observed, rung 4 PARTIAL — a real consumer's heap
metadata is corrupted by 30 file-chosen words over 120 bytes. There is still
no chosen word in a live consumer-owned field, no pointer/IP control, no
command, no wire input (local file), no r5, and no independent verdict on
W202-W207 (W201 remains the only ESTABLISHED verdict).

Clean archive of HEAD `624df6c1` into `/tmp/w207-stbvorbis2` (SDL_mixer
dependencies symlinked read-only from the live lab) replayed every committed
script at 16:27Z: `run-consumer-heap.sh` 11/0 plus 14/0 heap-word checks,
`run-consumer.sh` 12/0, `run-all.sh` 9/0, `run-seq.sh` 4/0, `run-guard.sh`
12/0, `run-object.sh` 9/0, `run-neighbor.sh` 9/0 — all rc 0. The earlier
archive of `0c8b7c75` had one FAIL because the gitignored safe input was
absent; `624df6c1` fixes that by regenerating it inside the replay. Live
tree untouched.

## W208 (2026-11-25) — live consumer FILE pointer receives chosen bytes

The plain SDL_mixer driver now optionally keeps one valid decoded audio object
alive, then loads the attack through the same public `MIX_LoadAudio_IO()` API.
The valid preload is `evidence/preload-safe.ogg` (2673 bytes, sha256
`3a619dff0ccaacd6b7fc0f52bde37d4fd20b767b34407924eb4377358da87992`), a
locally generated 0.1-second mono Vorbis silence fixture. The attack remains
the 205-byte `evidence/chosen.ogg`.

On glibc 2.39, this preload leaves the attack file's live `FILE` object exactly
32 bytes after `c->multiplicands`. OOB words at `+32..+124` (indices 8..31)
overwrite 96 bytes of that `FILE` object. A hardware watchpoint on
`_IO_save_base` observed the low chosen half at `j=0,k=26` and the high half at
`k=27`; after the loop, `_IO_save_base`, `_IO_backup_base` and `_IO_save_end`
all equal `0x4b4341484b434148`. The later decoder-failure seek path calls
`free()` with that chosen value and SIGSEGVs (plain rc 139):

    MIX_IoClamp_seek -> SDL stdio_seek -> fseeko ->
    _IO_free_backup_area -> __GI___libc_free(mem=0x4b4341484b434148)

Controls: vulnerable ASan with the same preload reports `heap-buffer-overflow`,
`WRITE of size 4`, rc 134; the fixed vendored header with preload rejects the
attack rc 0; safe input with preload exits 0. One-command replay:
`sh lab/frontier/stbvorbis2shell/run-consumer-preload.sh` -> 17 PASS / 0 FAIL,
rc 0. It also replays `run-consumer.sh` (12 PASS / 0 FAIL).

Two alternative allocator routes were measured and rejected. A repeated exact
IEEE subnormal `0x1011` cannot forge a `0x1010` chunk size because the adjacent
high half is also written, producing `0x0000101100001011`; `sequence_p` is a
monotonic arithmetic progression and cannot supply the required zero high
half. File-driven lead codebooks of 2..1024 entries left the successor in the
unsorted bin, tcache, or top; the 256-entry arm put `multiplicands` before top
and produced `malloc(): corrupted top size`. No lead arm produced a live
successor. Raw negatives are gitignored under `consumer/evidence/w208-*`.

Grade remains **rung 4 PARTIAL**: this is chosen pointer-value corruption and
use in a live real-consumer object, beyond W207's metadata-only landing. It is
conditional on a prior valid audio load, local-file delivery, a repeated
float-representable word, and a noncanonical resulting pointer. It is NOT a
valid arbitrary pointer, IP/command control, wire input or rung 5. W208 is
author-only; W201 remains the only ESTABLISHED witness verdict.
