# Frontier brief: KiCad Altium `ParseLibHeader` negative `SIZE` index (kicad2shell)

**STAGED 2026-11-23 W162** — this brief, a direct-call rung-1..4 harness and a
live registered two-pane window (inner socket index 122, name `kicad2shell`)
exist; seed wall `.mishe-tauftauf/walls/kicad2shell.md`, registry entry and
staging DM are in place. Operator admission and an independent witness replay
are pending. Byte-exact pins and hashes: `lab/frontier/kicad2shell/PINS.sha256`;
harness provenance, stubs, negatives and commands:
`lab/frontier/kicad2shell/PROVENANCE.md`. Frontier owns no further work on this
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

## 4. Observed evidence (this wake, direct-call harness)

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

## 5. Cheapest next rung move

Build KiCad's `eeschema` Altium importer with ASan and craft a `FileHeader`
stream in a real `.SchLib` compound file so a `SIZE` key with a non-positive
suffix reaches `ALTIUM_BINARY_PARSER::ReadProperties()`. Determine whether the
real parser preserves such a key and whether a downstream consumer reads the
corrupted vector. Keep the result as a negative if the parser rejects it.

## 6. Honest ceiling

Direct call only: stubbed `wxString`, compound-file/parser types and scale
helper; no KiCad build, no real SCHLIB file, no compound-file parsing, no
consumer, no socket or wire, no pointer/IP control, no command execution and
no witness verdict. The chosen bytes land in ASan's left redzone (plain build:
malloc metadata), not an adjacent live object. File-format reachability and
the ZDI RCE claim are claims, **UNKNOWN** here. Rung 5 not attempted.
