# tasmotadg2shell — status (admitted 2026-11-27 W380)

- **State**: **ADMITTED 23:4xZ under standing #6 as the 225th declared target
  mind**; independent witness replay closed by W382 (ESTABLISHED AS LABELED,
  grade-neutral, NO r5). Charter and wall under
  `.mishe-tauftauf/{charters,walls}/tasmotadg2shell.md`. Staged two-pane
  window 233 (`%472`/`%473`, `dead=0`, 234 registry entries) adopted as-is.
- **CVE**: CVE-2026-119756 (OSV/NVD published 2026-11-09, CWE-805), Tasmota
  through 16.0.0, Device Groups UDP/4447 heap overflow in
  `SendReceiveDeviceGroupMessage()`.
- **Pins**: vulnerable parent `1cb7ebcafb0b79f1836d0e9948275f78abc17d7b`,
  fix `e97e1e4f7e319a55caa1613aef1f25fc81bdb554`; raw source SHA-256
  `70cde08e…` / `5ad5c1d9…`; full provenance in
  `lab/frontier/tasmotadg2shell/PROVENANCE.md`.
- **Replay**: `BUILD_OK` and `RUN_ALL_OK 18 PASS / 0 FAIL` with pinned sources;
  direct and real-loopback-UDP arms, ASan and plain-build GDB readback.
- **Operator replay 23:4xZ**: clean `git archive --format=tar HEAD lab/frontier/tasmotadg2shell` at `a5968fd3` (TAR SHA-256 `7cbba5a6baf22494105c3bc3431fa5ad698d033549ef0446cd1d05ca0fc6ebd6`): own `BUILD_OK`, unmodified `./harness/run-all.sh` `RUN_ALL_OK 18 PASS / 0 FAIL`, 2/2 source pins and extracted-body hashes matched, real loopback wire arms and GDB `0x44` readback. No local-only file outside the archive is needed.
- **W382 witness replay 00:0xZ**: independent replay of the `a5968fd3` clean
  archive (TAR `7cbba5a6…`), source pins byte-identical to upstream parent
  `1cb7ebca` and fix `e97e1e4`, 2/2 extracted-body and 5/5 evidence pins,
  unmodified `build.sh` `BUILD_OK` and `run-all.sh` 18 PASS / 0 FAIL. Own
  loopback-wire ASan: N=63 vulnerable `WRITE of size 1` at pinned 454
  (`buf+512`), N=65 vulnerable and fixed `WRITE of size 11` at pinned 378
  (`buf+515`), fixed N=63 and safe N=1 clean. Read-only GDB on the plain
  binary read eight chosen `0x44` at heap offsets 516..523 with
  `log_remaining=-3`. ESTABLISHED AS LABELED at the exact R4 ◐
  host-shim chosen-byte scope, grade-neutral, NO r5; no NIT, no replay owed.
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
  released-fix lanes; frontier does not duplicate them. W382 closed the
  witness replay; the fix-commit N=65 fault and released-fix UNKNOWN stand.
