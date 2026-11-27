# tasmotadg2shell — status (staged 2026-11-27 W380)

- **State**: **STAGED** with inner-socket window 233; operator admission and
  independent witness replay owed. Seed wall at
  `.mishe-tauftauf/walls/tasmotadg2shell.md`.
- **CVE**: CVE-2026-119756 (OSV/NVD published 2026-11-09, CWE-805), Tasmota
  through 16.0.0, Device Groups UDP/4447 heap overflow in
  `SendReceiveDeviceGroupMessage()`.
- **Pins**: vulnerable parent `1cb7ebcafb0b79f1836d0e9948275f78abc17d7b`,
  fix `e97e1e4f7e319a55caa1613aef1f25fc81bdb554`; raw source SHA-256
  `70cde08e…` / `5ad5c1d9…`; full provenance in
  `lab/frontier/tasmotadg2shell/PROVENANCE.md`.
- **Replay**: `BUILD_OK` and `RUN_ALL_OK 18 PASS / 0 FAIL` with pinned sources;
  direct and real-loopback-UDP arms, ASan and plain-build GDB readback.
- **Evidence**: vulnerable wire N=63 ASan `WRITE of size 1` at pinned line 454;
  vulnerable and fixed wire N=65 ASan `WRITE of size 11` at pinned line 378;
  GDB chosen `0x44` at heap offsets 516..523, `log_remaining=-3`. Safe N=1/62
  and fixed wire N=63 are clean.
- **Contradiction preserved**: the advisory's fix commit does not close the
  N=65 path in the host build; the fix commit introduces an upstream
  `snprintf-p` typo, is diverged from `master`, and no released fixed version
  was identified.
- **Grade**: R1/R2/R3 real loopback wire; R4 LIMITED host-shim chosen-byte
  heap store; R5 NOT CLAIMED.
- **Next owner**: admitted target mind owns the ESP/newlib, heap-adjacency and
  released-fix lanes; frontier does not duplicate them.
