# radare2pyc2shell — admitted W243 (2026-11-26)

Brief: `reports/frontier-radare2pyc2shell.md`. Lab:
`lab/frontier/radare2pyc2shell/`. Claim: CVE-2026-81878 / GHSA-9phv-v2w8-56j3,
radare2 `.pyc` marshal ASCII reader 32-bit size wrap → ~4GB `0xff` heap WRITE;
fix `6727454b666b28c33837b219a5f91136461357c0`, affected through 6.1.8, first
verified fixed release 6.2.0 (advisory's "6.1.9" has no public tag).
State: **ADMITTED 03:5xZ under standing #6 as the 160th declared target mind**;
window 168 adopted (created by frontier W243 03:40Z, registry 169/169 unique at
this wake); witness W243 replay ESTABLISHED AS LABELED, no grade change, NO r5.

Evidence now: `bash lab/frontier/radare2pyc2shell/run-all.sh` → 31 PASS / 0 FAIL,
rc 0. GCC + Clang ASan `heap-buffer-overflow WRITE of size 4294967295` with
fault frame at the verbatim `buf.c:496` sink and allocation frame in the
verbatim `get_bytes()`; fixed and safe-input controls clean. Grade: rung 3 pinned
verbatim / rung 4 PARTIAL synthetic; rung 5 NOT claimed.

Real-consumer probe W244 (2026-11-26): a real radare2 6.1.8 ASan build was
configured and built locally; a crafted `.pyc` with magic `0x0a0d0d2c` and a
TYPE_ASCII length `0xffffffff` at parse offset `0x22` reaches
`get_ascii_object()` and `get_bytes()` with `alloc_arg=0` (`usable=1`), but the
real `r_buf_read()` returns `r=-1`: `buf_io_read()` → `r_io_fd_read()` takes
`int len`, truncating `0xffffffff` to `-1`, so the `r >= 0` guard skips the
`buf.c:496` memset. Both `rabin2 -s` and `radare2 -q -c 'is'` behaved the same;
the unmodified ASan build reported no fault. This is a preserved negative: no
out-of-bounds write on the real consumer, so no real-consumer rung 4. Grade
stays rung 3 pinned verbatim / rung 4 PARTIAL synthetic, no r5; fixed control
remains the pinned synthetic build. Exact inputs, hashes and probe logs are in
`lab/frontier/radare2pyc2shell/PROVENANCE.md` (`out-real/`).

- Operator admission 2026-11-26 03:5xZ under standing #6: unmodified
  `run-witness.sh` re-run in-tree and from a second clean `git archive cee3588b`,
  both `REPLAY_PASS=10 REPLAY_FAIL=0`, `TOTAL: 31 PASS / 0 FAIL`, rc 0, wrapper
  sha256 `ec1bf9246f8b2f9225d02fe983ca060e6e86a546c8566125aaf4b3a3ab6c3d54`,
  nine pins exact; no grade change. Window 168 adopted; no route, resolver,
  unit or sync edit (person-reserved). hy4-flash route and three generated wake
  units remain missing; omp-only and doctor stay RED.
