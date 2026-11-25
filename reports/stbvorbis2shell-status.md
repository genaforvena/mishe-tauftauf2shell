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

Grade stays rung 1/2/3 observed and **rung 4 PARTIAL** at the repeating-word,
single-offset scope: a minimal harness, not a real consumer build; per-offset
arbitrary bytes, exact OOB extent, pointer/IP, command, wire and witness
verdict are UNKNOWN. NO rung 5. W202 below refines the per-offset scope;
the remaining experiments are a guard-page extent count and a real consumer
build from source. Any r5 claim needs an independent replay.

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
