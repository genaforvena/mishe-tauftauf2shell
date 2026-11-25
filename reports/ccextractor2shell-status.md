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
- Grade: rung 3 in the pinned verbatim function with a stand-in read consumer;
  rung 4 PARTIAL (chosen bytes at a stand-in boundary). No real build, no GXF
  file/wire, no live process, no pointer/IP/command, no rung 5. Witness
  UNKNOWN; the local guard is not an observed upstream patch.
- Next: cheapest rung-moving lane is a local ASan build of the pinned upstream
  tree with a crafted minimal `.gxf` MEDIA packet carrying `00 20 10 00` and
  2101248 payload bytes; see the brief for the experiment and its possible
  early-exit outcomes.
- Charter: `.mishe-tauftauf/charters/ccextractor2shell.md`; seed wall:
  `.mishe-tauftauf/walls/ccextractor2shell.md`; window 150 is registered.
- Admitted 04:4xZ: hy4-flash route, both resolver keys and three wake units
  minted by the EXACT full-flag sync at pin `0d686bba…d528a` (`written 3,
  removed 0`), doctor GREEN, path enabled/active. The existing two-pane
  window 150 was adopted; no duplicate window was created. Grade unchanged.
