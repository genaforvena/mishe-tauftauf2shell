# kicad2shell — status

Admitted 2026-11-23 16:1xZ under standing approval #6 as the 117th route.
Charter: `.mishe-tauftauf/charters/kicad2shell.md`. Trigger units from the
exact full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`); path enabled/active, hy4-flash route 116→117,
resolver entries 233→235 (wake `.path` and `@.service`), two-pane window 122
adopted with no duplicate. Pinned full-flag doctor rc 0 GREEN;
`check-omp-only.py` GREEN with 117 declared roles. Admission adds no grade.

- Claim: CVE-2026-126970 / GHSA-4qjr-2gjm-9gc6 (High 7.8,
  `CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`, CWE-787, Unreviewed,
  published 2026-11-18; ZDI-CAN-33213 / ZDI-26-956). GHSA affected/patched
  version fields are Unknown; fix is GitLab commit
  `b2f51d113425cf12398eb44dd97dfc30309beccf` (2026-08-29, parent
  `bf3e3fa5497882f5b0975d03e4a74b2c086db0e2`) adding `if( ind < 1 ) continue;`.
  No numeric fixed release (UNKNOWN). The ZDI RCE claim is a claim, not a
  reproduction here.
- Evidence: `lab/frontier/kicad2shell/harness/run.sh` and `check.sh` slice the
  pinned parent/fixed `sch_io_altium.cpp` (lines 5883-5923 / 5883-5926) under
  `#line` with lab stubs for `wxString`, the compound-file/parser types and the
  scale helper. For a `SIZE` key with a non-positive suffix, `wxAtoi` gives
  `ind <= 0`, the resize guard is vacuous and `aFontSizes[ind - 1] = scaled`
  writes four bytes before the vector's heap buffer. gcc and clang ASan report
  `heap-buffer-overflow WRITE of size 4` four bytes before a 4-byte region at
  pinned `sch_io_altium.cpp.vuln:5919`; the plain build aborts with glibc
  `double free or corruption (out)`. gdb at the second `:5919` hit reads
  `IND=0 SCALED=0x24242424` and four `0x24` bytes at `data()-4`. The fixed
  guard sees `FIXED_IND=1` then `FIXED_IND=0`, leaves the vector intact and
  exits 0. `far` (no valid first allocation) is preserved as a negative.
- Operator admission replay from a clean `git archive 20d4d70` at 16:14Z:
  70 files, 4/4 `PINS.sha256` digests OK, 8 binaries rebuilt, `PASS=52 FAIL=0`,
  trace `dd64c549fa2ddc57559f0aa66a043ab6e64e20d5f8799da5181ca6678d22f9a6`
  exact. This is deterministic replay of the author's harness, not witness
  acceptance.
- Ceiling: direct-call CODE/HARNESS rungs 1-4 only. The chosen bytes land in
  ASan's left redzone (plain build: malloc metadata), not an adjacent live
  object. No real KiCad build, wxWidgets, SCHLIB file, compound-file parser,
  consumer process, socket, wire, pointer or IP control, benign marker,
  command, witness verdict or rung 5. File-format reachability and the ZDI
  RCE claim stay UNKNOWN; rung 5 is UNKNOWN.

Next for the target mind: build KiCad's `eeschema` Altium importer with ASan
and determine whether a real compound-file `FileHeader` stream preserves a
`SIZE` key with a non-positive suffix; keep any parser rejection as a
negative. Only on an observed pointer or control-flow target, attempt a
bounded benign marker with vulnerable, fixed and safe-input controls and an
independent witness replay. Hand any new claim to `witness` — the author
report is not acceptance.
