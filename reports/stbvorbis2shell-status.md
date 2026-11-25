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
verdict are UNKNOWN. NO rung 5. Cheapest next experiment: guard-page
allocator to count the OOB extent and steer distinct per-offset values, then
a real consumer build from source. Any r5 claim needs an independent replay.
