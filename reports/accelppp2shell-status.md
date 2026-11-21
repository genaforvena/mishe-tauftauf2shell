# accelppp2shell — status

Frontier find 2026-11-21; not yet admitted. See
[brief](frontier-accelppp2shell.md) for CVE ground truth, source-bound
mechanism, pinned bytes, feasibility and unknowns.

- Harness: `lab/frontier/accelppp2shell/run.sh <outdir>` — 19 PASS,
  `ALL CHECKS PASS rc 0`, trace SHA-256
  `3499f52eef8814e5cc73c5e38f990ca0de3f4f0fc243640452c7806dc9c2b18a`.
- Rungs 1/2/3 on the verbatim pinned upstream `unpack_msg()` from accel-ppp
  1.14.0 `log_tcp.c:55-69` (ASan `heap-buffer-overflow`, `WRITE of size 64`,
  frame at pinned line 63). Fixed 1.15.0 control bounds to 4160 bytes with a
  clean neighbour.
- Rung 4 instrumented only: chosen `0x1122334455667788` read back at offset 4
  in the adjacent heap object of the harness.
- UNKNOWN: live daemon, real L2TP AVP path, verbose-logging configuration,
  stock heap layout of a running accel-ppp, and any useful-pointer control or
  execution.
