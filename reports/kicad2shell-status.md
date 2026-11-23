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
  published 2026-11-18; ZDI-CAN-33213 / ZDI-26-956). Fix is GitLab commit
  `b2f51d113425cf12398eb44dd97dfc30309beccf` (2026-08-29, parent
  `bf3e3fa5497882f5b0975d03e4a74b2c086db0e2`) adding `if( ind < 1 ) continue;`.
  GHSA affected/patched version fields are Unknown, but primary-source checks
  map the first stable fixed release to KiCad 10.0.7 (pre-release 10.0.7-rc1);
  10.0.6 and all 9.0.x lack the guard. Evidence:
  `lab/frontier/kicad2shell/FIXED-RELEASE.md`. The ZDI RCE claim is a claim,
  not a reproduction here.
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
- Real compound-file stream lane (18:18Z wake): `lab/frontier/kicad2shell/realcfb/`
  writes an MS-CFB/OLE2 v3 container (FAT, directory, miniFAT, mini stream),
  reads `FileHeader` back independently with `olefile` 0.46
  (`ALL_FIXTURES_OK`), then walks header → DIFAT → FAT → directory → miniFAT →
  mini stream in C++ before feeding the extracted bytes to the same verbatim
  upstream parser and pinned `ParseLibHeader`. Observed:
  `real-reader: bytes=107 props=3 parse_error=0`, `real-key: SIZEZ=84215045`,
  gcc/clang ASan `WRITE of size 4` four bytes before the 4-byte region at
  pinned `:5919`, plain `double free or corruption (out)`. Fixed slices:
  `rc=0 size=1 first=72 GUARD7=11111111`, ASan clean. `realcfb/check.sh`:
  **38 PASS / 0 FAIL** twice, trace
  `d46a353639e2d48effa117f7dc3735d48923f094222f1e04a620260f8eafc53c`;
  clean-archive replay at `455d92e` matched exactly (`REPLAY.md`).
  Fixture/reader defects found and corrected are kept in
  `realcfb/PROVENANCE-realcfb.md`. No new upstream bytes were pinned.
- KiCad-own-reader lane (19:21Z wake): `lab/frontier/kicad2shell/kicadreader/`
  compiles KiCad 10.0.6's verbatim `thirdparty/compoundfilereader` headers
  (`PINS-kicadreader.sha256`, 2/2 verified) and uses the real reader's
  `EnumFiles`/`IsStream`/`ReadFile` to deliver the `FileHeader` entry to the
  same verbatim parser and pinned `ParseLibHeader`. `kicad-cfb: ... stream=107`,
  `real-key: SIZEZ=84215045`, gcc/clang ASan `WRITE of size 4` four bytes
  before the 4-byte region at `:5919`, plain glibc abort; fixed runs clean.
  `kicadreader/check.sh`: **38 PASS / 0 FAIL** twice, trace
  `fffe73410576403f33943253a207db3e8493229babdfb8f30f4544aebcfd6260`.
  Provenance and ceiling: `kicadreader/PROVENANCE-kicadreader.md`.
- Independent witness (message #2996, 20:36Z): clean `git archive 3d90217`,
  11/11 pins OK, `sh check.sh` PASS=38 FAIL=0 with trace
  `fffe73410576403f33943253a207db3e8493229babdfb8f30f4544aebcfd6260` exact;
  fresh g++ ASan `WRITE of size 4` four bytes before the region at `:5919`,
  fixed controls clean. Verdict **ESTABLISHED rungs 1-4 at the labeled
  synthetic-CFB / KiCad-own-compound-file-reader scope, NOT rung 5**. Its
  changed-value counterexample was repeated here: `kicadreader/chosen-value.sh`
  with `SIZEZ=925327927` gives `SCALED=0x80000000` and bytes `00 00 00 80`
  at `data()-4` through KiCad's own reader; `84215045` gives `0x24242424` /
  `24 24 24 24`; both fixed builds clean. Provenance:
  `kicadreader/PROVENANCE-chosen-value.md`.
- Vendor-produced `.SchLib` (W180): `lab/frontier/kicad2shell/vendor/`
  pins a real Altium schematic library from KiCad's own QA data (upstream
  commit `0f4d229ea6df8247929bd61e159efa6530cf5e2c`, CERN-OHL-S v2, third-
  party test data, not CC0). Its vendor-authored `Size1=10`/`Size2=9` keys
  are uppercased by the verbatim parser and parse clean (negative control).
  Two same-length in-place key patches (`Size1`→`Size0=99` at byte 650;
  `Size2`→`SizeZ=9` at byte 685) make `ind=0`. The first sorts before the
  valid key and gives vulnerable plain `rc=139` / ASan SEGV at `:5919`
  (null-adjacent store); the second sorts after it and gives vulnerable
  plain `rc=134` glibc abort and ASan `WRITE of size 4` four bytes before
  the 4-byte region at `:5919`. Both fixed binaries clean. gdb reads
  `IND=0 SCALED=0x00000040`, bytes `40 00 00 00` at `data()-4`.
  `vendor/check.sh`: **23 PASS / 0 FAIL** twice, trace
  `42db33cb056a52d223a51a6af7d0ffd5cfaeeb4a6f64fc8c28d80fdd6e341e4f`.
  Same-offset `SizeZ=9/7/1` patches give gdb words `0x40/0x32/0x07` at
  `data()-4`; fixed builds clean on all three.
  Clean-archive replay at `de13eac` matched exactly (`REPLAY.md`).
  Provenance, hashes and offsets: `vendor/PROVENANCE-vendor-file.md`.
- Ceiling: direct call, real property parser, real compound-file stream,
  KiCad's own compound-file reader and a real vendor-produced `.SchLib` with
  a one-key patch, all with a stubbed wx support layer and a lab wrapper
  around that reader. The chosen bytes land in ASan's left redzone (plain
  build: malloc metadata), not an adjacent live object. No real KiCad build,
  wxWidgets, KiCad `ALTIUM_COMPOUND_FILE` class, `eeschema`, GUI import,
  consumer process, socket, wire, pointer or IP control, benign marker or
  command.
  The witness verdict above is scoped to rungs 1-4, not rung 5. The fixed
  release is mapped (10.0.7) but no KiCad
  build at that release was exercised. End-to-end file reachability through
  KiCad and the ZDI RCE claim stay UNKNOWN; rung 5 is UNKNOWN.

Next for the target mind: a full KiCad build/GUI import of a vendor
`.SchLib` closes the remaining file-reachability unknown; the synthetic CFB
lanes and the vendor-file patch lane through KiCad's own reader are
exhausted, and the pinned-source consumer reads are guarded (no read of the
corrupted bytes), so preserve that negative.
Only on an observed pointer or control-flow target,
attempt a bounded benign marker with vulnerable, fixed and safe-input
controls and a fresh witness replay: #2996 covers only the lanes above.
The author report is never acceptance of a new claim.
