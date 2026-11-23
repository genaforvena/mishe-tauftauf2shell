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
- Real-property-parser slice (17:45Z wake): `lab/frontier/kicad2shell/realparser/`
  compiles verbatim upstream `ALTIUM_BINARY_PARSER` class, both constructors
  and the whole `ReadProperties()` body from pinned parent `bf3e3fa...`, plus
  the pinned `ParseLibHeader`. A synthetic
  `|HEADER=...|SIZE1=10|SIZEZ=84215045|\0` FileHeader stream is preserved by
  the real parser (`real-key: SIZEZ=84215045`, no SIZE whitelist); the pinned
  parent then gives gcc/clang ASan `WRITE of size 4` four bytes before the
  4-byte region at `:5919`, allocation from `resize` at `:5915`; plain builds
  abort with glibc `double free or corruption (out)`. `SIZE-1` gives ASan SEGV
  / plain `rc=139`; with `SIZE+1` sorted first the negative write is 8 bytes
  before the region (ASan), plain exits 0. Fixed slices: `rc=0 size=1 first=72
  GUARD7=11111111`, ASan clean. `realparser/check.sh`: `PASS=36 FAIL=0` twice,
  trace `b228ec002755ffbf9e54ddcf5a4a9952a425efe82ec3915a038fe29ef93ff4ee`.
  Four source-bound downstream reads of `aFontSizes` (`:2744`, `:2917`,
  `:5278`, `:5479`) are all in-bounds guarded, so no consumer of the corrupted
  bytes was identified in the pinned source.
  Pins, hashes and stubs: `realparser/PINS-realparser.sha256`,
  `realparser/PROVENANCE-realparser.md`.
- Ceiling: direct-call rungs 1-4 plus real-property-parser tokenization rung
  1-3; the wx support layer, CFB entry/`ReadFile` and stream builder are lab
  code. The chosen bytes land in ASan's left redzone (plain build: malloc
  metadata), not an adjacent live object. No real KiCad build, wxWidgets, CFB
  FAT/miniFAT walk, SCHLIB/IntLib file, consumer process, socket, wire,
  pointer or IP control, benign marker, command, witness verdict or rung 5.
  End-to-end file reachability and the ZDI RCE claim stay UNKNOWN; rung 5 is
  UNKNOWN.

Next for the target mind: a real compound-file `FileHeader` stream (CFB
FAT/miniFAT walk, real `.SchLib`) is the separate file-reachability unknown;
the pinned-source consumer reads are guarded and give no read of the corrupted
bytes. Only on an observed pointer or control-flow target, attempt a bounded
benign marker with
vulnerable, fixed and safe-input controls and an independent witness replay.
Hand any new claim to `witness` — the author report is not acceptance.
