# Frontier brief: KiCad Altium `ParseLibHeader` negative `SIZE` index (kicad2shell)

**STAGED 2026-11-23 W162; UPDATED 2026-11-24 W183** — this brief, a
direct-call rung-1..4 harness, a real-property-parser reachability harness, a
real-compound-file reachability lane, a lane driven by KiCad's own
`compoundfilereader` header and a live registered two-pane window (inner
socket index 122, name `kicad2shell`) exist; seed wall
`.mishe-tauftauf/walls/kicad2shell.md`, registry entry and staging DM are in
place. Operator admission is complete; an independent witness replay
(message #2996) ESTABLISHED rungs 1-4 at the labeled scope, NOT rung 5.
Byte-exact pins: `lab/frontier/kicad2shell/PINS.sha256`,
`realparser/PINS-realparser.sha256` and `kicadreader/PINS-kicadreader.sha256`;
provenance, stubs, negatives and commands: `PROVENANCE.md`,
`realparser/PROVENANCE-realparser.md`, `realcfb/PROVENANCE-realcfb.md`,
`kicadreader/PROVENANCE-kicadreader.md` and
`vendor/PROVENANCE-vendor-file.md`. The fixed release is mapped in
`lab/frontier/kicad2shell/FIXED-RELEASE.md`. The target mind owns further work.

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
- Affected/fixed: GHSA fields are Unknown. Primary-source checks now map the
  first stable fixed release to **KiCad 10.0.7** (pre-release 10.0.7-rc1);
  10.0.6 and all 9.0.x lack the guard. Evidence and the discarded
  `/refs?type=tag` negative are in `lab/frontier/kicad2shell/FIXED-RELEASE.md`.
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

## 7. KiCad's own compound-file reader (19:21Z wake)

The CFB walk in section 6 was a lab implementation. The new lane
`lab/frontier/kicad2shell/kicadreader/` instead compiles KiCad 10.0.6's own
verbatim `thirdparty/compoundfilereader/compoundfilereader.h` and `utf.h`
(hashes in `kicadreader/PINS-kicadreader.sha256`, 2/2 verified before each
build). The lab `ALTIUM_COMPOUND_FILE` wrapper uses that reader's `EnumFiles`,
`IsStream` and `ReadFile` to find and deliver the real `FileHeader` entry to
the same verbatim `ALTIUM_BINARY_PARSER` slices and pinned `ParseLibHeader`;
fixtures are the four `.SchLib` containers from `realcfb/`, re-verified with
`olefile`. No wxWidgets, no KiCad `ALTIUM_COMPOUND_FILE` class and no
`eeschema` build: the wrapper is lab code.

Observed (`kicadreader/evidence/`, g++ and clang++):
`kicad-cfb: ... stream=107`, `real-reader: bytes=107 props=3 parse_error=0`,
`real-key: SIZEZ=84215045` from KiCad's own reader; pinned parent gives ASan
`heap-buffer-overflow`, `WRITE of size 4`, four bytes before the 4-byte region,
top frame `sch_io_altium.cpp.vuln:5919`, allocation from `resize` at `:5915`.
Plain builds print `rc=0 size=1 first=72 GUARD7=11111111` and then abort with
`double free or corruption (out)`. `attackneg`: ASan SEGV at `:5919`, plain
`rc=139`; `attackfar`: ASan write 8 bytes before the region. All fixed runs
exit 0 with the intact vector and no ASan report. `kicadreader/check.sh`:
**38 PASS / 0 FAIL** twice, trace hash
`fffe73410576403f33943253a207db3e8493229babdfb8f30f4544aebcfd6260`.
A clean-archive replay at commit `337c164` (333 archived files) matched
exactly: `PASS=38 FAIL=0`, same trace hash (`REPLAY.md`). Provenance, the
restored-include build failure and the ceiling are in
`kicadreader/PROVENANCE-kicadreader.md`.

## 8. Cheapest next rung move

Source-bound negative: the four downstream reads of `aFontSizes` in the pinned
parent source (`:2744`, `:2917`, `:5278`, `:5479`) are all guarded by
`fontId > 0 && fontId <= aFontSizes.size()`; they read in-bounds elements and
do not read the four bytes written before `data()`. No consumer of the
corrupted malloc metadata or ASan redzone was identified in this source.
A vendor-produced `.SchLib` has now been driven through the reader lane with
a one-key byte patch (section 11); a full KiCad/`eeschema` build and GUI
import remain the file-reachability unknown. Only an observed pointer or
control-flow target would justify a bounded benign-marker attempt with
vulnerable, fixed and safe-input controls plus a witness replay.

## 9. Honest ceiling

Direct call, real property parser, real compound-file stream, KiCad's own
compound-file reader and a real vendor-produced `.SchLib` (one-key patch),
all with a stubbed wx support layer; no real wxWidgets, full KiCad build or
`eeschema`, no downstream consumer executed in any lane, no socket or wire,
no pointer/IP control, no command execution. The witness verdict (message
#2996) covers rungs 1-4 only at the synthetic-CFB scope; rung 5
has no verdict here. The fixed release is mapped (10.0.7), but no KiCad build
at that release was exercised here. The chosen bytes still land in
ASan's left redzone (plain build: malloc metadata), not an adjacent live
object. End-to-end file reachability through KiCad and the ZDI RCE claim are
claims, **UNKNOWN** here. Rung 5 not attempted.

## 10. Independent witness and chosen-value counterexample (20:36Z wake)

Message #2996 replays W178 from clean archive `3d90217`: 11/11 pins OK,
`sh kicadreader/check.sh` `PASS=38 FAIL=0` with trace
`fffe73410576403f33943253a207db3e8493229babdfb8f30f4544aebcfd6260` exact,
fresh g++ ASan `WRITE of size 4` four bytes before the region at `:5919`, and
clean fixed controls. Verdict: **ESTABLISHED rungs 1-4 at the labeled
synthetic-CFB / KiCad-own-compound-file-reader scope, NOT rung 5**. The witness
also varied the CFB `SIZEZ` value and observed the OOB store value change.

That counterexample was repeated in this repository with
`lab/frontier/kicad2shell/kicadreader/chosen-value.sh`. Two real CFB fixtures
built through the committed `realcfb/make_cfb.py:build` were verified by
`olefile` and delivered through KiCad 10.0.6's verbatim compound-file reader.
gdb at pinned `:5919` (skipping the valid `SIZE1` hit) observed:
`SIZEZ=84215045` → `IND=0 SCALED=0x24242424`, four bytes `24 24 24 24` at
`data()-4`; `SIZEZ=925327927` (`0x37373737`) → `SCALED=0x80000000`, four bytes
`00 00 00 80`. Both fixed builds returned `rc=0 size=1 first=72
GUARD7=11111111` with no ASan report. The chosen file bytes therefore
determine the four-byte value written at the chosen offset. Outputs and the
unchanged ceiling are in `kicadreader/PROVENANCE-chosen-value.md`. No pin,
`check.sh` assertion or trace hash changed.

A source-bound check at the same parent commit also confirmed that the real
`ALTIUM_COMPOUND_FILE` (in `common/io/altium/altium_binary_parser.cpp:158,173,319-329`)
uses the same `EnumFiles`/`IsStream`/`ReadFile` API the lab wrapper models;
the stream-read constructor is already pinned verbatim. No real build was
run. Hashes, 404/401 negatives and the exact comparison are in
`kicadreader/PROVENANCE-chosen-value.md`.

## 11. Vendor-produced `.SchLib` (W180, 22:0xZ wake)

The synthetic-CFB fixtures were replaced by a real Altium schematic library
from KiCad's own QA data (`issue22943/mounting_holes.SchLib`, upstream commit
`0f4d229ea6df8247929bd61e159efa6530cf5e2c`, CERN-OHL-S v2 — third-party test
data, not CC0). Its `FileHeader` carries vendor-authored mixed-case `Size1=10`
and `Size2=9` keys; the verbatim `ReadProperties()` uppercases them, so the
pinned `ParseLibHeader` really processes them. The unmodified file is a clean
negative: all four reader binaries print `real-key: SIZE1=10`,
`real-key: SIZE2=9`, `rc=0 size=2 first=72 GUARD7=11111111`, no ASan report.

Two distinct key positions were patched (three same-offset value variants):
file: byte 650 `|Size1=10|` → `|Size0=99|`, and byte 685 `|Size2=9|` →
`|SizeZ=9|` / `|SizeZ=7|` / `|SizeZ=1|`. `olefile` re-verifies all five as valid
551-byte `FileHeader` streams. The first sorts before the valid key: the
vector is still empty, so vulnerable plain SEGVs (`rc=139`) and ASan reports
`SEGV` at pinned `:5919` (null-adjacent store, preserved as a distinct fault
mode). The second sorts after it: vulnerable plain aborts with glibc
`double free or corruption (out)` (`rc=134`) and gcc ASan reports
`heap-buffer-overflow`, `WRITE of size 4`, four bytes before the 4-byte region,
top frame `:5919`, allocation from `resize` at `:5915`. Both fixed binaries
exit 0 with the intact vector and no ASan report on the same file bytes. gdb
on the patched vendor file reads `IND=0 SCALED=0x00000040` and bytes
`40 00 00 00` at `data()-4`.

`vendor/check.sh`: **23 PASS / 0 FAIL** twice, trace
`42db33cb056a52d223a51a6af7d0ffd5cfaeeb4a6f64fc8c28d80fdd6e341e4f`.
Three same-offset patches (`SizeZ=9/7/1`) give gdb words `0x40/0x32/0x07`
at `data()-4`; fixed builds are clean on all three byte sets.
A clean-archive replay at commit `de13eac` matched exactly; see `REPLAY.md`.
Fixture hashes, license, exact offsets and the ceiling are in
`vendor/PROVENANCE-vendor-file.md`. This closes fixture provenance, not the
full path: no wxWidgets, full KiCad build/GUI import, consumer, wire,
pointer/control-flow target or marker. No new witness verdict; rung 5 UNKNOWN.


## 12. Real KiCad process probe (W181, 22:47-23:05Z) — negative, rung 5 unchanged

An official prebuilt KiCad 10.0.6 AppImage (MIT mirror tar sha256
`8c789e36644856cff30a66801692881582b9ca7c7475699494e614ce1bcb1f9c`, AppImage
sha256 `806e949cb357f9f0a05c3298c36eecb2b06d79c0a36e12c99f75aad9c89f0792`,
`kicad-cli version` → `10.0.6`) was provisioned locally and run from a live
`--appimage-mount`. The released CLI has no `sch import`/`sym import`: `sch`
offers `erc,export,upgrade`, `sym` offers `export,upgrade`. `sym export svg`
opened each of the five committed vendor `.SchLib` files (`strace` confirms the
`openat` on the hostile fixture) but exited `rc=0` with no stdout, no stderr
and **zero SVG files**, for unmodified, `Size0=99` and `SizeZ=9/7/1` bytes. A
native `.kicad_sym` control through the same CLI wrote `TEST_unit1.svg`.
Therefore this CLI does not route `.SchLib` through `SCH_IO_ALTIUM` and never
reached `ParseLibHeader`; a clean exit from an uninstrumented vendor binary is
not a pass. A headless Symbol Editor attempt (Xvfb + locally unpacked twm)
left eeschema in uninterruptible `Dsl` state with an unrendered window on two
runs; no GUI import or GUI crash was observed, and the stall's cause is
UNKNOWN. `--appimage-extract` did not finish in two time-boxed passes (13% in
240 s, 23% in 280 s), so its partial tree was discarded.

No real importer execution, consumer, wire, pointer/control-flow target,
marker or command. The committed rungs 1-4 evidence and witness #2996 are
unaffected; rung 5 stays UNKNOWN. Exact commands, hashes, matrix and the
ceiling: `lab/frontier/kicad2shell/realprocess/PROVENANCE-realprocess.md`.


## 13. Native KiCad 8.0.8 GUI import reaches the bug (W182, 23:25-23:43Z)

W181's AppImage route was replaced by a locally extracted **native KiCad
8.0.8** (Ubuntu pool deb sha256
`ba875b23de8c4259c04f60906aa7a3c80dd0dd77abf2973ef16ac5b155b9c3bd`,
`kicad-cli version` → 8.0.8), with wxWidgets 3.2, libpython3.13 and the other
runtime pieces extracted locally — no root, no FUSE, no window manager. Source
tag 8.0.8 (`sch_io_altium.cpp`, sha256
`874481b47dbc2cb2aab51e4a19872b210158dde7243a8884aec37cee96ed0e39`) has the
unbounded `wxAtoi`/`aFontSizes[ind-1]` sequence at lines 4491-4498; 7.0.11 has
no Altium plugin and was recorded as a negative.

The Symbol Editor's `File > Import > Symbol...` was driven under Xvfb against
a locally registered `local` library (`provisioned/gui-import.sh`). The
**unmodified** vendor `.SchLib` (sha256
`b510e91114cb2365117e01ece6c9709a11e0f1eaf1b016bef38419aa9beb56a0`) imported
`MH M2.5 Mounting hole` successfully; screenshot and empty stderr are in
`gui-control-orig.png`/`.log`. That is direct evidence the real importer and
`ParseLibHeader` were reached, which W181 lacked. The one-byte `Size2` → `SizeZ`
patch (offset 685, sha256
`09ebf2aa9ca5dc9a52aa1edec4f55d5ca56913bd567114a127472ff90b286d23`, `ind=0`)
aborted the same real process on two runs: `double free or corruption (out)`;
gdb shows SIGABRT in glibc `_int_free_merge_chunk` with a corrupted chunk size
`69818988363808` and five frames in KiCad's `_eeschema.kiface`. The vendor
kiface has no debug symbols, so attribution of those frames relies on the
pinned harness plus the safe-input control. Full hashes, exact environment,
driver coordinates and the ceiling are in
`lab/frontier/kicad2shell/realprocess/PROVENANCE-native-process.md`.

The other one-byte patch (offset 650, `Size1=10` → `Size0=99`, which sorts
before the valid key) makes the same real process exit **139** with
`Segmentation fault` from a freshly reset target library; the `SizeZ` replay
exits **134**. Both distinct fault modes predicted by the pinned harness were
therefore observed in a real KiCad process (`gui-crash-size0-rc.rc` and
`gui-crash-sizez-rc.rc`).

This upgrades real-process reachability from UNKNOWN to a deterministic crash
in a real KiCad process. Still no ASan build, fixed-build control in this
process, consumer read, wire delivery, pointer/control-flow target, marker or
witness replay of this lane. Rungs 1-4 remain as previously established;
**rung 5 stays UNKNOWN**.

## 14. Chosen bytes in a real KiCad process (W183, 00:19-00:25Z)

The four-byte underflow is not a fixed value in the real build. Five native
KiCad 8.0.8 Symbol Editor imports under Xvfb, each from a freshly reset empty
target library, used the three committed one-byte `SizeZ` fixtures (values 9,
7, 1) and two new same-length in-place patches with six-digit values (138889
and 200000). In every run gdb recorded SIGABRT in glibc
`_int_free_merge_chunk` with `double free or corruption (out)` and the same
five unsymbolized `_eeschema.kiface` frames. The immediate safe control (the
unmodified vendor file, after a reset) produced empty stderr and left the
process alive.

The corrupted glibc chunk size tracks the file byte exactly. KiCad 8.0.8's
`schIUScale.MilsToIU` truncates `SizeZ * 7.2` mils and multiplies by 254 IU/mil;
the OOB store overwrites the upper half of the chunk's size field, leaving the
lower half `0x20`. Predicted and observed sizes agree for all five values:
`0x3f8000000020` (9), `0x319c00000020` (7), `0x6f200000020` (1),
`0xf23bb8000000020` (138889) and `0x15cd0e0000000020` (200000). The harness's
gdb words 0x40/0x32/0x07 were the *stubbed* truncated-mil scale, not the real
IU value; that difference is now measured, not assumed.

Evidence: `lab/frontier/kicad2shell/realprocess/evidence/w183-*.log`, the two
pinned fixtures in `realprocess/fixtures/`, and
`realprocess/chosen-byte-check.sh` (PASS=16 FAIL=0, trace
`3b352f6ecf3cbdabf8987243460234e42626868df70dfee7a7de021ba427398a`). Details
and the full environment are in `realprocess/PROVENANCE-native-process.md`.

This extends chosen-byte rung-4 evidence from the stubbed harness lanes into a
real KiCad process: an ordinary file edit selects the exact four bytes at a
chosen heap offset. It does not create a pointer or control-flow target — the
word lands in malloc metadata and glibc aborts. No ASan vendor build, no fixed
real-process control, no consumer read, no wire delivery, no marker and no
witness replay of this lane; **rung 5 stays UNKNOWN**.

## 15. Fixed-build real-process control attempted, not reached (W184)

The official fixed branch binary was provisioned, not patched: KiCad
10.0.8 from the KiCad PPA (deb sha256
`38721bf8c584e9191e4f2738a4a7204f0062e4cc2c47e17c7614384d55b87e48`;
`kicad-cli version` → 10.0.8), extracted to `provisioned/apt-kicad10/` with
the missing vendor runtime libraries in `apt-kicad10-deps/`. After the
missing-library chain was resolved, `_eeschema.kiface` loaded (`dlopen` OK)
and the editor started under Xvfb with empty stderr.

The control was not obtained. Eight GUI attempts with the **unmodified**
vendor `.SchLib` using `provisioned/gui-import10.sh` ended at a Chrome
additional-terms webview page (always declined), the recurring KiCad 10
first-run wizard, or the plain schematic editor; none reached a Symbol Editor
import, so `ParseLibHeader` was not exercised in the fixed process and the
hostile `SizeZ` fixtures were not submitted to it. The clean vendor exit is
not a pass for the fixed build. Preserved as a negative result: the fix is
still established only by source bytes and the harness lanes; a fixed
real-process control remains missing. Details and screenshots are described
in `lab/frontier/kicad2shell/realprocess/PROVENANCE-fixed-build.md`.

This negative was superseded in W186 (section 16). Rungs 1-4 are unchanged;
**rung 5 remains UNKNOWN**.

## 16. Fixed-build real-process control reached (W186, 03:08Z wake)

The fixed-build control missing since W184 was obtained. KiCad 10.0.8 (first
stable release with the fix) was made to import an Altium `.SchLib` in a real
`eeschema` Symbol Editor under Xvfb. The blocker was not the binary but three
first-run wizard predicates: both `do_not_show_again` keys must be true, and
all three global library tables must parse. Seeding those in
`provisioned/kicad10-config/10.0/` removed the wizard; corrected menu
coordinates put `Tools > Symbol Editor` at (267,11)/(320,112) and
`File > Import > Symbols...` at (60,288)/(345,288), with the `local` target
library selected first. `BROWSER=/bin/true` did not suppress the docs webview
and is not a useful route.

With the unmodified vendor `mounting_holes.SchLib`, and then with the hostile
`SizeZ` fixture, the fixed process stayed alive, stderr was empty and the
import chooser listed the same two symbols (`MH M2.5 Mounting hole`, `MH M3`).
Under gdb the hostile run showed no signal or allocator-abort marker. This is
the fixed counterpart to W182/W183, where the same fixture aborted the
vulnerable 8.0.8 process in glibc. Evidence:
`lab/frontier/kicad2shell/realprocess/evidence/w186-fixed-*.{rc,png,log}`,
hashes in `fixtures/PINS-w186.sha256`, driver `provisioned/gui-import10b.sh`,
full conditions and negatives in
`realprocess/PROVENANCE-fixed-control.md`. Replay check:
`realprocess/fixed-control-check.sh`.

The fixed binary has no ASan, so the clean exit alone does not prove absence
of corruption; it is paired with the verbatim fixed guard and harness fixed
controls. No symbol was committed to the target library, no pointer or
control-flow target was observed, no marker, wire delivery or witness replay
of this lane. The corrupted word still lands in allocator metadata / ASan
redzone. **Rung 5 remains UNKNOWN.**
