# kicad2shell — real-parser reachability harness

## Question answered

Does a hostile `SIZE` key survive KiCad's **real** Altium property parser, so
that `SCH_IO_ALTIUM::ParseLibHeader` reaches the negative-index write without
a lab-injected properties map?

**Observed: yes, at the property-parser layer.** Verbatim upstream
`ALTIUM_BINARY_PARSER::ReadProperties()` parses a synthetic `FileHeader`
property stream, canonicalizes `SIZEZ` / `SIZE-1` keys with no whitelist or
numeric validation, inserts them into `std::map<wxString,wxString>`, and the
verbatim pinned `ParseLibHeader` then reaches the `aFontSizes[ind-1]` store.
gcc and clang ASan report `WRITE of size 4`, four bytes before the vector's
4-byte region, top frame `sch_io_altium.cpp.vuln:5919`. The fixed slice exits
clean with the same stream bytes.

## Upstream material (provisioning, pinned parent bf3e3fa5497882f5b0975d03e4a74b2c086db0e2)

Fetched 2026-11-23 from `https://gitlab.com/kicad/code/kicad/-/raw/<sha>/`:

- `common/io/altium/altium_binary_parser.cpp` → `src/altium_binary_parser.cpp`,
  sha256 `3160f11e0dd08d47c13af7dc7733248db544890c2efb875800249f6043567519`.
- `common/io/altium/altium_binary_parser.h` → `src/altium_binary_parser.h`,
  sha256 `8741041b77c1cf5b96d1d5d87f36388c9a57cdbfa2e5ed6f4e4491d02fb7de5a`.

Verbatim slices (byte-for-byte, re-extracted by `run.sh`):

- `pins/altium_binary_parser.h.class.slice` — header lines 124-339 (the
  `ALTIUM_BINARY_PARSER` class: `Read<>`, `GetRemainingBytes`, members), sha256
  `f8381d45bfdb3efdfd2cb4249ecbc14d2e3902427a091225fab7a38235108398`.
- `pins/altium_binary_parser.cpp.ctors.slice` — lines 319-340 (both upstream
  constructors), sha256 `0f4fda1f72fb7068f6c5a910ef243d1ab895048e9dcbda8af8add8a6c114e548`.
- `pins/altium_binary_parser.cpp.readprops.slice` — lines 343-463 (entire
  `ReadProperties()` body), sha256
  `a81edd479ac3beea9de81030eb51fb20af7bb753db3cd933693291b7526fa99c`.

`ParseLibHeader` comes from the already-pinned parent/fixed slices in
`../pins/` (see `../PINS.sha256`); `run.sh` includes them under `#line 5883`.

## What is real and what is lab code

Real upstream bytes: the whole parser class, both constructors, the whole
`ReadProperties()` body, and the whole pinned `ParseLibHeader`.

Lab code: `stubs.hpp` models only the wx support layer (`wxString` methods
`Trim`/`MakeUpper`/`Replace`/`StartsWith`, `wxCSConv`, `wxLogTrace`,
`AltiumPropertyToKiCadString`), a `CFB::COMPOUND_FILE_ENTRY` plus a
`CompoundFileReader::ReadFile` stub that copies the crafted stream bytes into
the buffer the real file-based constructor reads, and the driver that builds
the `uint32` length-prefixed `|KEY=VALUE|...\0` stream and calls the functions.
`schIUScale.MilsToIU` is the existing lab scale stub.

**Not exercised:** real wxWidgets, real `CFB::CompoundFileReader` FAT/miniFAT
walk, a real `.SchLib`/`.IntLib` file, real `eeschema`, any caller consuming
`aFontSizes`, any wire or socket, pointer/IP control or command execution.
The synthetic stream is the `FileHeader` stream *contents*, not a compound
file. This is file-format tokenization reachability, not end-to-end file
reachability. Rung 5 remains UNKNOWN.

## Scenario bytes

- `baseline`: `|HEADER=Protel for Windows - Schematic Library Editor Binary File Version 5.0|SIZE1=10|\0`
- `attackz`: as baseline plus `|SIZEZ=84215045|` — real `ReadProperties()`
  upper-cases the key, suffix `"Z"` is non-empty, `wxAtoi("Z")==0` → `ind=0`,
  chosen value `0x24242424`.
- `attackneg`: as baseline plus `|SIZE-1=84215045|` → `ind=-1`, writes
  `data()[-2]`; vector is still empty at that point (key sorts before `SIZE1`),
  so ASan SEGV / plain `rc=139`.
- `attackfar`: as baseline plus `|SIZE+1=10|SIZE-1=84215045|`; `SIZE+1` sorts
  before `SIZE-1`, so a valid 1-element allocation happens first and the
  negative index writes `data()[-2]` (ASan: 8 bytes before the 4-byte region).

`evidence/` holds all 32 runs (2 compilers × vuln/fixed × asan/plain ×
4 scenarios) with `.rc` files. Notable observed results:

- `g++-vuln-asan-attackz.out`, `clang++-vuln-asan-attackz.out`: real-key lines
  `SIZE1=10`, `SIZEZ=84215045`, then `heap-buffer-overflow`, `WRITE of size 4`,
  `4 bytes before 4-byte region`, top frame `sch_io_altium.cpp.vuln:5919`,
  allocation from `resize` at `:5915`.
- `g++-vuln-plain-attackz.out`, `clang++-vuln-plain-attackz.out`: `rc=0 ...`
  then `double free or corruption (out)` (glibc chunk-header overwrite).
- `attackneg`: ASan `DEADLYSIGNAL/SEGV` at `:5919`; plain `rc=139`. Recorded as
  observed behavior, not a separate claim.
- `attackfar`: ASan `WRITE of size 4`, `8 bytes before 4-byte region`, top frame
  `:5919`; plain build exits 0 here — the store lands in the preceding
  allocation's payload, not into a live object this harness owns. Fixed build
  clean with identical bytes.
- All `baseline` and all `fixed` runs: `rc=0 size=1 first=72 GUARD7=11111111`,
  ASan clean.

Rebuild and replay with `sh run.sh && sh check.sh`.
