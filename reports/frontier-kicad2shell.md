# Frontier brief: KiCad Altium `ParseLibHeader` negative `SIZE` index (kicad2shell)

**STAGED 2026-11-23 W162; UPDATED 2026-11-23 18:18Z wake** — this brief, a
direct-call rung-1..4 harness, a real-property-parser reachability harness and
a live registered two-pane window (inner socket index 122, name `kicad2shell`)
exist; seed wall `.mishe-tauftauf/walls/kicad2shell.md`, registry entry and
staging DM are in place. Operator admission and an independent witness replay
are pending. Byte-exact pins and hashes: `lab/frontier/kicad2shell/PINS.sha256`
and `realparser/PINS-realparser.sha256`; harness provenance, stubs, negatives
and commands: `lab/frontier/kicad2shell/PROVENANCE.md` and
`realparser/PROVENANCE-realparser.md`. Frontier owns no further work on this
target.

## 1. Verified ground truth

- Source claim: GHSA-4qjr-2gjm-9gc6 / CVE-2026-126970, GitHub Advisory
  Database, Unreviewed, High 7.8,
  CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, CWE-787, published
  2026-11-18. It describes an out-of-bounds write in Altium SCHLIB parsing
  with claimed code execution; ZDI-CAN-33213 / ZDI-26-956 is the origin. The
  RCE claim is **not reproduced here**.
- Fix: GitLab commit `b2f51d113425cf12398eb44dd97dfc30309beccf` (2026-08-29),
  "Toss out invalid SIZE keys in corrupt Altium libraries", fetched read-only.
  Parent `bf3e3fa5497882f5b0975d03e4a74b2c086db0e2`; work item 25174.
- Affected/fixed: GHSA fields are Unknown; the fix commit was checked, but no
  release tag was mapped, so the numeric fixed version is **UNKNOWN**.
- No external probe. Advisory, ZDI reference and source fetches were
  provisioning only.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; pinned bytes live in
`lab/frontier/kicad2shell/src/` and are sliced verbatim under `#line` by
`harness/run.sh`.

`SCH_IO_ALTIUM::ParseLibHeader` reads `FileHeader` properties, uppercases each
key and, for a key beginning with `SIZE`, converts the suffix to a font index:

```
int ind = wxAtoi( remaining );                     // parent :5912
if( static_cast<int>( aFontSizes.size() ) < ind )  // parent :5914
    aFontSizes.resize( ind );
int scaled = schIUScale.MilsToIU( wxAtoi( value ) * 72.0 / 10.0 );
aFontSizes[ind - 1] = scaled;                      // parent :5919  <-- OOB
```

For `ind <= 0` the resize guard is vacuous, so unchecked `operator[]` writes
four bytes before the vector's heap buffer. Fix `b2f51d1` inserts
`if( ind < 1 ) continue;` at fixed `:5914-5915`, making the write at fixed
`:5922` unreachable for a non-positive index.

## 3. Cheapest local experiment

Slice the pinned function bodies (parent `5883-5923`, fixed `5883-5926`) into
a driver with lab stubs for `wxString`, the Altium compound-file/parser types
and the scale helper. Inject the property map directly: `baseline` has only
`SIZE1=10`; `attack` adds `SIZEz=84215045` (`wxAtoi("z")==0`, scaled
`0x24242424`); `far` uses invalid suffixes with no earlier valid allocation.
Build g++ and clang++ with and without ASan.

Commands (from `lab/frontier/kicad2shell/harness/`): `./run.sh` verifies the
four pins and builds 8 binaries; `./check.sh` runs 24 invocations plus two gdb
probes and prints a normalized trace hash.

## 4. Observed evidence (W162, direct-call harness)

- Rung 1: `attack` on the parent build writes at `data()[-1]`; the plain build
  aborts with `double free or corruption (out)` (malloc chunk header
  overwritten). The fixed build returns `rc=0 size=1 first=72 GUARD7=11111111`.
- Rung 2: the fixed guard is reached with `FIXED_IND=1` then `FIXED_IND=0`;
  both hostile and valid properties leave the vector intact and the process
  exits normally; no ASan report.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of size
  4`, `4 bytes before 4-byte region`, top frame
  `sch_io_altium.cpp.vuln:5919`.
- Rung 4: gdb at the second `:5919` hit prints `IND=0 SCALED=0x24242424`; after
  stepping the store, the four bytes at `aFontSizes._M_impl._M_start-4` are
  `0x24 0x24 0x24 0x24` — chosen value at a chosen offset.
- `far` is preserved as an edge/negative: ASan `DEADLYSIGNAL` at `:5919` with
  an empty vector; not a separate vulnerability claim.
- `harness/check.sh`: **52 PASS / 0 FAIL** on three identical runs, trace
  `dd64c549fa2ddc57559f0aa66a043ab6e64e20d5f8799da5181ca6678d22f9a6`.

## 5. Real property-parser reachability (17:45Z wake)

The next bounded slice was exercised without a full KiCad build. Verbatim
upstream `ALTIUM_BINARY_PARSER` class, both constructors and the whole
`ReadProperties()` body from pinned parent `bf3e3fa...` were compiled together
with the pinned `ParseLibHeader` slice. Lab code is limited to the wx support
layer, a `CFB::COMPOUND_FILE_ENTRY`/`ReadFile` shim that delivers the crafted
stream bytes, and the driver that builds the `uint32`-length-prefixed
`|HEADER=...|SIZE1=10|SIZEZ=84215045|\0` FileHeader stream.

Observed (`lab/frontier/kicad2shell/realparser/evidence/`): the real
`ReadProperties()` preserves the hostile key (`real-key: SIZEZ=84215045`; no
SIZE whitelist; key upper-cased) with `parse_error=0`; the pinned parent
`ParseLibHeader` then hits gcc and clang ASan `heap-buffer-overflow`, `WRITE of
size 4`, four bytes before the 4-byte region, top frame
`sch_io_altium.cpp.vuln:5919`, allocation from `resize` at `:5915`. Plain
builds abort with `double free or corruption (out)`. `SIZE-1` (`ind=-1`) gives
ASan SEGV / plain `rc=139`, preserved as observed behavior. A `SIZE+1` key
sorting before `SIZE-1` allocates first, and the following negative index gives
ASan `WRITE of size 4`, 8 bytes before the region; the plain build exits 0
because the store lands in the preceding allocation's payload, not a live
object in this harness. All fixed-slice runs: `rc=0 size=1 first=72
GUARD7=11111111`, no ASan report — same hostile stream bytes.
`realparser/check.sh`: **36 PASS / 0 FAIL** twice, trace hash
`b228ec002755ffbf9e54ddcf5a4a9952a425efe82ec3915a038fe29ef93ff4ee`.

## 6. Real compound-file stream reachability (18:18Z wake)

The remaining file-reachability gap was the delivery boundary: the earlier
real-parser lane handed hand-built bytes to the verbatim parser through a shim.
`lab/frontier/kicad2shell/realcfb/` now drives the same verbatim upstream
slices and pinned `ParseLibHeader` from a real MS-CFB/OLE2 v3 container.
`make_cfb.py` writes a 512-byte-sector compound file with a FAT, directory,
miniFAT and mini stream; its `FileHeader` stream carries the crafted property
bytes. `verify_cfb.py` independently reads all four fixtures back with
`olefile` 0.46 (valid compound file, one `['FileHeader']` stream, hostile key
present). A lab C++ reader then walks header → DIFAT → FAT → directory
(UTF-16LE name match) → miniFAT → mini stream and feeds the extracted bytes to
the unchanged upstream parser. No new upstream bytes were pinned: both pin
files verify 5/5 and 4/4 before each build.

Observed (`realcfb/evidence/`, g++ and clang++):
`real-reader: bytes=107 props=3 parse_error=0`, `real-key: SIZEZ=84215045`
preserved from the CFB stream; pinned parent hits ASan `heap-buffer-overflow`,
`WRITE of size 4`, four bytes before the 4-byte region, top frame
`sch_io_altium.cpp.vuln:5919`, allocation from `resize` at `:5915`. Plain
builds abort with `double free or corruption (out)`. `attackneg` (`ind=-1`)
gives ASan SEGV / plain `rc=139`; `attackfar` writes 8 bytes before the region
under ASan. All fixed-slice runs: `rc=0 size=1 first=72 GUARD7=11111111`, clean
ASan; baseline has no ASan report. `realcfb/check.sh`: **38 PASS / 0 FAIL** on
two identical runs, trace hash
`d46a353639e2d48effa117f7dc3735d48923f094222f1e04a620260f8eafc53c`.
A clean-archive replay at commit `455d92e` (246 files) matched exactly:
`PASS=38 FAIL=0`, same trace hash; see `REPLAY.md`.
Fixture/reader defects found and corrected during this lane (mini-stream
sector padding, directory field offsets, `ENDOFCHAIN` terminal test) are
recorded in `realcfb/PROVENANCE-realcfb.md`; none changed upstream bytes or the
expected write offset.

## 7. Cheapest next rung move

Source-bound negative: the four downstream reads of `aFontSizes` in the pinned
parent source (`:2744`, `:2917`, `:5278`, `:5479`) are all guarded by
`fontId > 0 && fontId <= aFontSizes.size()`; they read in-bounds elements and
do not read the four bytes written before `data()`. No consumer of the
corrupted malloc metadata or ASan redzone was identified in this source.
A vendor-produced `.SchLib` and KiCad's own compound-file reader remain the
file-reachability unknown. Only an observed pointer or control-flow target
would justify a bounded benign-marker attempt with vulnerable, fixed and
safe-input controls plus a witness replay.

## 8. Honest ceiling

Direct call, real property parser and real compound-file stream, all with a
stubbed wx support layer; the CFB walk is a lab reader, not KiCad's own. No
real wxWidgets, no vendor `.SchLib`, no KiCad build or `eeschema`, no
downstream consumer executed in any lane, no socket or wire, no pointer/IP
control, no command execution, no witness verdict and no mapped fixed release.
The chosen bytes still land in ASan's left redzone (plain build: malloc
metadata), not an adjacent live object. End-to-end file reachability through
KiCad and the ZDI RCE claim are claims, **UNKNOWN** here. Rung 5 not attempted.
