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
