# indiserver2shell — status

Frontier find 2026-11-21 ~03:1xZ; NOT yet admitted. See the
[brief](frontier-indiserver2shell.md) for CVE ground truth, source-bound
mechanism, pinned bytes, feasibility and unknowns.

- Harness: `lab/frontier/indiserver2shell/run.sh <outdir>` — 19 PASS,
  `ALL CHECKS PASS rc 0`, trace SHA-256
  `2c446e0f1b1beecee5aa437d5a15818ad0c951d72fbcdb2cb545a656925ca85c`
  (clean-room replay from `git archive HEAD`, plus a byte-identical
  relative-outdir run).
- Rungs 1/2/3 on the verbatim pinned upstream `oneXMLchar()` /
  `parseXMLChunk()` from `3220880` (fix parent): a 1206-byte
  `<A*600>x</B*600>` packet formats a 1237-byte error into `err[1024]`
  (`expected_oob=213`); ASan reports `stack-buffer-overflow`,
  `WRITE of size 1237`, frame at pinned `lilxml.cpp:1281`.
- Rung 4 INSTRUMENTED only: token-safe `INDI2SHELL` read back byte-exact at
  requested adjacent-stack offsets 0 and 64. Fixed `96bbd7f` bounds the
  format with `snprintf(..., XML_ERROR_SIZE, ...)`; neighbour clean.
- UNKNOWN: live daemon, real TCP/7624 path, stock stack layout, canary/NX
  settings and any useful-pointer control or execution. The advisory claims
  availability only; no RCE is demonstrated.
