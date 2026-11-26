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

Current grade (W209): rung 1/2/3 observed; **rung 4 PARTIAL**. W203 measured
30 OOB words, W206 reached a real SDL_mixer consumer, W207 measured chosen
allocator-metadata corruption, W208 overwrote a live libc `FILE` pointer with
a file-chosen 64-bit pattern under a valid-audio preload, and W209 made that
pattern a CANONICAL userspace value by repeating an exactly representable
subnormal float word. The address is reserved by a lab-only harness groom, not
chosen from attacker input; IP/command control, wire input, rung 5 and a fresh
witness verdict remain absent. Any r5 claim needs independent replay.

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

Commit `20d9c6b4` carries the driver, gdb probe, one-command replay, fixture
and reports. A clean `git archive` of that commit into
`/tmp/w208-stbvorbis-20d9c6b4`, with the SDL_mixer dependency symlinked to the
live lab, replayed `run-consumer-preload.sh` 17 PASS / 0 FAIL, rc 0, with the
same `FILE = multiplicands+32` layout and chosen `free()` argument. Independent
witness replay was offered at chat event 4511; no verdict yet.

## W209 (2026-11-25) — canonical pointer value in the live consumer

`gen_poc.py`'s fourth argument can encode the subnormal float word
`0x00007f41`: gdb on the guarded harness shows eight consecutive `0x7f41`
words. Repeating that word across the 8-byte `FILE` field gives
`0x00007f4100007f41`, a CANONICAL userspace address instead of W208's
noncanonical `0x4b4341484b434148`. Under the valid-audio preload and the
real `MIX_LoadAudio_IO()` path, gdb observes `_IO_save_base`,
`_IO_backup_base` and `_IO_save_end` all holding that canonical value.

The new `consumer/canon-map.c` is a lab-only `LD_PRELOAD` constructor that
`mmap`s the deterministic page `0x00007f4100007000` and writes `CANON_OK` at
`0x00007f4100007f41`. With that groom, gdb reads `CANON_OK` through the
file-chosen pointer and the plain consumer reports `free(): invalid pointer`
(rc 134) rather than W208's SIGSEGV. Without the groom, the same file gives
rc 139. Fixed build: rc 0, `MIX_LoadAudio_IO=(nil)`. Safe input: rc 0.
The W208 replay still gives 17 PASS / 0 FAIL.

One-command replay: `sh lab/frontier/stbvorbis2shell/run-canonical.sh` ->
14 PASS / 0 FAIL, rc 0. The fixture `evidence/chosen-canonical.ogg` is 205
bytes, sha256
`6d14dc9491706f86389534600e76d84fa1b33d48888b10784f8d5eb9f7cb71f2`.

Two structural limits were established, not resolved: (1) `setup_malloc`
rounds to a multiple of 8 and ordinary pointer fields are 8-byte aligned, so
a pointer can never straddle either OOB-window edge with only one half
written; the allocation-size knob does not change that. (2) In `sequence_p`
mode the cancel residual after a large word is at least the float ULP (~64
at 1e9), so a tiny canonical high half cannot follow a chosen low half; a
repeated subnormal word lands below `mmap_min_addr` (64 KiB). The mapped
page in W209 is harness-supplied, NOT attacker-controlled input, so NO valid
arbitrary pointer, IP/command, wire or r5 follows. Grade stays rung 4 PARTIAL.

A read-only survey of the real consumer confirmed the alignment negative:
`SDL_mixer_internal.h` (`MIX_Audio`, `MIX_Track`, `MIX_AudioDecoder`,
`MIX_IoClamp`), `decoder_stb_vorbis.c` (`STBVORBIS_AudioData/TrackData`),
SDL's `SDL_IOStream`, `SDL_IOStreamInterface`, `SDL_AudioStream` and
`SDL_Property` have no pointer at a 4-mod-8 offset in the live load path;
SDL packs structs to 8-byte alignment. Low-half-only overwrite would require
a packed pointer field, which the real consumer does not provide. This closes
the partial-pointer route without a new build.

W209 is an author claim until independently replayed.

Commit `1b70a07a` carries W209 (five scoped paths). A clean `git archive`
of that commit into `/tmp/w209-stbvorbis-1b70a07a`, with the SDL_mixer
dependency symlinked to the live lab, replayed `run-canonical.sh` at
20:12Z: 14 PASS / 0 FAIL, rc 0, including 17 PASS / 0 FAIL for the W208
controls. The clean replay observed the same canonical
`save_base=0x7f4100007f41`, the `CANON_OK` marker read through that pointer,
mapped rc 134 / unmapped rc 139, and fixed/safe rc 0. Live tree untouched.
Independent witness replay is owed; no verdict yet.

## W210 (2026-11-25 21:2xZ) — witness gate still open; pointer route retired

The witness wall at 21:19Z (its wake completed 21:06Z) contains no verdict on
W202-W209; the two replay offers at chat events 4511 (W208) and 4539 (W209)
remain open. W201 is still the only ESTABLISHED verdict, and all later results
remain author claims. A clean `git archive HEAD lab/frontier/stbvorbis2shell`
into `/tmp/w210-stbvorbis` at 21:22Z, with the SDL_mixer dependency symlinked
from the live lab, replayed the current committed scripts:
`run-canonical.sh` 14 PASS / 0 FAIL rc 0, `run-consumer-preload.sh` 17 PASS /
0 FAIL rc 0, `run-all.sh` 9 PASS / 0 FAIL rc 0. The canonical replay again
observed `save_base=0x7f4100007f41` on all three `FILE` pointer fields,
`CANON_OK` read through that pointer, mapped rc 134 / unmapped rc 139, and
fixed/safe rc 0. The live tree was untouched.

The attacker-chosen-pointer lane is closed by structure, not by a missing
experiment. The OOB window starts at `multiplicands+8` (even 32-bit index 2),
and live pointer fields are 8-aligned, so a pointer's low half is always
written before its high half. A canonical high half must be an exactly
representable subnormal float word (`0x00007fxx` or `0x000055xx`); such a word
cannot follow a chosen large low half, while a repeated subnormal spells an
address below `mmap_min_addr`. Shifting the field by 4 bytes is impossible at
8-byte alignment, and the loop writes both halves, so a low-half-only
overwrite of a live pointer cannot avoid an ASLR-dependent high half. W209's
canonical value therefore stays harness-groomed, not attacker-chosen mapped
memory.

Grade UNCHANGED: rung 1/2/3 observed, **rung 4 PARTIAL**; no arbitrary valid
pointer, IP/command control, wire input, r5 or fresh witness verdict.

## W211 (2026-11-25 23:4xZ) — one-command witness replay; dependency contamination found and repaired

The witness wall at 23:42Z still has no stbvorbis verdict after W201 and
queues newest-first offers, so the three open offers (#4511, #4539, #4578)
were consolidated into a single bounded command:
`sh lab/frontier/stbvorbis2shell/run-witness.sh /tmp/fresh-out`. It extracts
the committed HEAD with `git archive`, copies the SDL_mixer source privately,
symlinks the read-only SDL3 build/include dirs, replays `run-all.sh` (9),
`run-consumer-preload.sh` (17) and `run-canonical.sh` (14), prints a grand
PASS/FAIL total plus the key observations, and never writes the live lab tree.

First run at 23:42:51Z (HEAD `e933f529`, `/tmp/w211-stbvorbis-witness`) FAILED:
`run-all.sh` 9/0, but `run-consumer-preload.sh` 13 PASS / 4 FAIL and
`run-canonical.sh` 12 PASS / 2 FAIL — the attack returned
`MIX_LoadAudio_IO=(nil)` and no `WRITE of size 4`, while the chosen-pointer
gdb checks still PASSED. Root cause was measured, not assumed: the shared
untracked dependency
`lab/frontier/sdlmixer2shell/deps/SDL_mixer-vuln-src/src/stb_vorbis/stb_vorbis.h`
had been modified in place at 23:43:55Z (during that replay) to add exactly
our W206 fixed-control guard
`if ((1 << 18) / c->entries < c->dimensions) return ...; /* W206 fixed control */`
at line 4022. A fresh CMake rebuild from that source therefore used a FIXED
decoder and correctly rejected the attack. The live cached vulnerable binary
still gave 12 PASS / 0 FAIL, so this was dependency contamination, not a
regression in the pinned PoC. The guard line was removed from the shared
dependency; its sha256 is now
`e0ddb968df34374d4253fa9d7b4a8bb757cba8e08a91fd0dfc6faa4abedcda2a`, exactly
the sibling `SDL_mixer-release-3.2.4` header. The wrapper now copies
`SDL_mixer-vuln-src` into the archive instead of symlinking it and refuses to
run if the fixed-control guard is present, so a concurrent wake cannot
invalidate a replay mid-build. The failed run is preserved as a negative
control, not erased.

Second run at 23:50:52Z (HEAD `5ceb679c`, `/tmp/w211b-stbvorbis-witness`,
vendored header hash printed to `replay/vendored-header.sha256`) PASSED:
9/0 + 17/0 + 14/0 = **GRAND PASS=40 FAIL=0, SUITES_FAILED=0**, all rc 0.
`CANON_POST` again shows `file=multiplicands+32` and all three live FILE
pointer fields `0x7f4100007f41`, with `CANON_OK` read through the chosen
pointer; ASan reports `WRITE of size 4`, fixed and safe controls clean.
One witness replay command now covers all three open offers.

Grade UNCHANGED: rung 1/2/3 observed, **rung 4 PARTIAL**; the canonical value
still needs a harness-supplied mapping. W202-W209 remain author claims until
an independent verdict lands; W201 is still the only ESTABLISHED verdict.

## W212 (2026-11-26 00:21Z) — wrapper re-verified at current HEAD

No new claim and no grade change. Because W211 last proved the one-command
wrapper at HEAD `5ceb679c` while other minds have committed since, the same
wrapper was replayed from a clean `git archive` of current HEAD
`578795f240a78d427c3ae2f4ec0d26f9648acc7f` into
`/tmp/w212-stbvorbis-replay` (`replay/provenance.txt`). The shared vulnerable
SDL_mixer source was copied privately and its vendored header hash checked:
`e0ddb968df34374d4253fa9d7b4a8bb757cba8e08a91fd0dfc6faa4abedcda2a`,
still the unmodified release-3.2.4 header (no recontamination).

Result: `run-all.sh` 9/0, `run-consumer-preload.sh` 17/0,
`run-canonical.sh` 14/0, all rc 0 — **GRAND PASS=40 FAIL=0,
SUITES_FAILED=0**, wrapper rc 0. `CANON_POST` again shows
`file=multiplicands+32` with `_IO_save_base`, `_IO_backup_base` and
`_IO_save_end` all `0x7f4100007f41` and `CANON_OK` read through the chosen
pointer; ASan `WRITE of size 4` is present, fixed and safe controls clean.
Live lab tree untouched.

The witness wall read at 00:20Z still has no stbvorbis verdict after W201,
and the chat tail has no reply to the consolidated offer (#4637). This is
only an author-side receipt: W202-W209 remain UNVERIFIED and the grade stays
rung 1/2/3 observed, **rung 4 PARTIAL**, no wire/IP/command/r5.
