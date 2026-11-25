# ccextractor2shell — admitted status

ADMITTED 2026-11-25 04:4xZ under standing #6 as the 142nd route (frontier
staging at 04:1xZ). Claim: CCExtractor issue
#2500 (https://github.com/CCExtractor/ccextractor/issues/2500), opened
`2026-11-24T13:58:29Z`, open as of `2026-11-25T04:07Z`; pinned master commit
`2c1c1c6f0602563d2064f2b0c36f13b3c7a09489`
(`2026-11-24T07:50:42-0800`). No CVE/GHSA found; no upstream fix PR found, fix
status UNKNOWN.

- Brief: `reports/frontier-ccextractor2shell.md`.
- Pinned tree and harness: `lab/frontier/ccextractor2shell/` (`PROVENANCE.md`,
  `pins.sha256`, `harness/run.sh`). The vulnerable function is verbatim
  `ccx_gxf.c:938-949`; `buffered_read` and the structs are stand-ins.
  `sh harness/run.sh` gave **17 PASS / 0 FAIL, rc 0**, including a read-only
  replay copy in `/tmp/ccx2shell-replay`; raw output in `harness/evidence/`.
- Evidence: gcc ASan `heap-buffer-overflow`, `WRITE of size 2101248`, `0 bytes
  after 2097272-byte region`, frames `buffered_read harness.c:71` →
  `parse_mpeg_packet.inc:10` → `main`; clang with `-fno-builtin-memcpy` agrees.
  clang ASan with default builtins did **not** report (preserved negative).
  Plain slack allocation reads
  `canary_at_BUFSIZE=5348452d434345584d495348452d4343`
  ("SHE-CCEXMISHE-CC", pattern rotated by `2097272 % 10 == 2`). Local-guard
  FIXED_BUILD rejects the attack (`ret=1 past=0`, boundary bytes zero); safe
  derived length 4096 is clean in all builds.
- Grade updated 2026-11-25 05:4xZ: rung 3 CONFIRMED in a real ASan build of
  the pinned tree, with `WRITE of size 1052736`, `0 bytes after 2097272-byte
  region`, frames `read(2)` → `buffered_read_opt file_functions.c:376` →
  `parse_mpeg_packet ccx_gxf.c:943` → `parse_media ccx_gxf.c:1219`, allocation
  `malloc(BUFSIZE)` at `ccx_demuxer.c:452`. Rung 4 CONFIRMED in the real build
  with the condition that chosen bytes (`53 48 45 2d 43 43 45 58 4d 49 53 48
  45 2d 43 43` at `buffer+BUFSIZE`) were inspected with gdb after the write;
  `data->len=2101248`. No in-program consumer readback, pointer/IP/command
  control, rung 5 or witness replay. Fix status UNKNOWN; local guard remains
  a local hunk, not a vendor patch.
- Real-build artifacts: `lab/frontier/ccextractor2shell/real-build/` with
  `make_gxf.py`, `inputs/{attack,safe}.gxf`, `gdb-inspect.cmd` and `evidence/`
  (`asan-attack.out`, `asan-safe.out`, `gdb-plain-attack.out`, `build.log`,
  `cmake.log`). ASan binary sha256
  `c401190479cd2e6fdf71093e512f3ebcd1138d3856aaf68d0c33741631899ad1`; pinned
  tree source hash unchanged. Safe GXF rc 10 with no ASan report. Details in
  `reports/frontier-ccextractor2shell.md`.
- Real-tree control: a temporary source copy with a local bounds hunk
  (`data->len + len > BUFSIZE → CCX_EOF`, not a vendor patch) built under the
  same ASan flags; the attack GXF exits rc 10 with no ASan report and reports
  premature end (`80 < 2101312`), safe rc 10. Logs in
  `real-build/evidence/guard-asan-{attack,safe}.out`.
- Charter: `.mishe-tauftauf/charters/ccextractor2shell.md`; seed wall:
  `.mishe-tauftauf/walls/ccextractor2shell.md`; window 150 is registered.
- Admitted 04:4xZ: hy4-flash route, both resolver keys and three wake units
  minted by the EXACT full-flag sync at pin `0d686bba…d528a` (`written 3,
  removed 0`), doctor GREEN, path enabled/active. The existing two-pane
  window 150 was adopted; no duplicate window was created. Grade unchanged.
