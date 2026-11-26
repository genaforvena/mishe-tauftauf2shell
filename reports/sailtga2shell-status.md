# sailtga2shell — ADMITTED (163rd target mind, 2026-11-26)

Brief: `reports/frontier-sailtga2shell.md`. Lab: `lab/frontier/sailtga2shell/`.
Claim: CVE-2026-54626 / GHSA-744p-cqg2-m33h, SAIL TGA indexed-RLE decoder
derives its per-pixel stride from the raw header `bpp` while the pixel buffer
is allocated for the resolved indexed format (1 byte/pixel). State: **ADMITTED
05:0xZ under standing #6**; window 171 adopted from frontier (two live panes,
172/172 unique registry names); hy4-flash route and three generated wake units
remain missing (omp-only and doctor RED, person-reserved). Witness W246 replayed
ESTABLISHED AS LABELED; no grade change.

Evidence: `bash lab/frontier/sailtga2shell/harness/run-all.sh` → 38 PASS /
0 FAIL rc 0. Five real static SAIL builds from pinned v0.9.10 and v1.0.0
tarballs, driven through the public `sail_load_from_file()` API with three
local 28-byte TGAs. GCC+Clang ASan `heap-buffer-overflow`, `WRITE of size 4`,
0 bytes after a 256-byte region, frame `sail_codec_load_frame_v8_tga` at
verbatim `tga.c:269`, caller `sail_load_from_file`. Plain allocator probe:
attacker-chosen `aa bb cc dd` at offsets 256..263 beyond the allocation;
matching-stride safe controls clean; v1.0.0 vendor fix rejects the attack with
`SAIL_ERROR_INVALID_IMAGE` (`rc=213`) under both compilers.

Operator replay: unmodified `run-witness.sh` sha256
`71fc1e440e40b8814981982e33e7162bab478aa9501f9b4d6062f40fe6aee414`, ten pins
exact, `REPLAY_PASS=14 REPLAY_FAIL=0` with inner `TOTAL: 38 PASS / 0 FAIL` and
rc 0 both in-tree and from a clean `git archive 2768fb84` (serial, no harness
or pin edit).
Grade: rung 3 verbatim / rung 4 demonstrated lab impact under the stated
conditions; no wire path and no r5 (W1 adds synthetic pointer control below).

W1 target-mind work (2026-11-26) widened the consumer and mechanics evidence
without changing the grade. `harness/run-memory.sh` 10/0: junior
`sail_load_from_memory()` cannot auto-detect TGA (`rc=301`), while the
documented explicit-codec advanced memory path reaches the verbatim sink.
`harness/run-realapp.sh` 9/0: the shipped v0.9.10 `sail` CLI `convert` and the
shipped `advanced` example both fault at `tga.c:269` on the vulnerable build;
the vendor-fixed v1.0.0 libs reject the input. `harness/run-pointer.sh` 13/0:
under an LD_PRELOAD interposer with ASLR disabled, crafted RLE packets set a
live adjacent victim's pointer field to a chosen canonical value, retarget it
to a lab benign marker and call it (`BENIGN_MARKER_EXECUTED` plus a side-effect
file); matching-stride and vendor-fixed controls stay clean. All of that is
synthetic in-process rung-4 mechanics, NOT r5. Still UNKNOWN: a natural
application object reached before free and any wire/request consumer. Keep
the advisory's `Version: 1.0.0` ASan paste as a discrepancy, not a fact.
An independent witness verdict is not substitute acceptance.
