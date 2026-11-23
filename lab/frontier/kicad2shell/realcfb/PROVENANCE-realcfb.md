# kicad2shell — real compound-file lane provenance (2026-11-23 18:18Z wake)

## What is upstream, byte for byte

No new upstream bytes were pinned in this wake. This lane reuses, unchanged:

- `../realparser/pins/altium_binary_parser.h.class.slice`
- `../realparser/pins/altium_binary_parser.cpp.ctors.slice`
- `../realparser/pins/altium_binary_parser.cpp.readprops.slice`
- `../pins/sch_io_altium.cpp.vuln.slice`
- `../pins/sch_io_altium.cpp.fixed.slice`

`run.sh` verifies both pin files (`realparser/PINS-realparser.sha256`, 5/5;
`../PINS.sha256`, 4/4) before generating either translation unit. The generated
`driver-vuln.cpp` / `driver-fixed.cpp` place those slices under the same
`#line` file/line markers as the earlier lanes, so ASan frames read
`sch_io_altium.cpp.vuln:5919` and `:5915`.

## What is lab code

- `stubs.hpp` — byte-identical copy of `../realparser/stubs.hpp`: the wx string
  support layer, `ALTIUM_PROPS_UTILS`, the scale helper and the
  `ALTIUM_COMPOUND_FILE` / `CFB::COMPOUND_FILE_ENTRY` shim. Unchanged.
- `make_cfb.py` — writes a v3 (512-byte sector) MS-CFB/OLE2 container: 512-byte
  header, one FAT sector, one directory sector, one miniFAT sector, one mini
  stream sector. Directory entries use the standard field offsets (name length
  at 64, type at 66, start at 116, 64-bit size at 120). The `FileHeader` stream
  is the crafted property bytes (uint32 length prefix + `|HEADER=...|SIZE1=10`
  plus the hostile key), stored in mini sectors 0..n-1.
- `verify_cfb.py` — independent read-back with `olefile` 0.46: asserts
  `isOleFile`, a `['FileHeader']` stream and the expected hostile key for all
  four scenarios. This is the proof the fixture is a real compound file, not
  the lab's own reader agreeing with itself.
- `driver_tail.cpp` — a lab implementation of the CFB **walk**: header parse,
  DIFAT (109-entry array, plus optional chain), FAT assembly, FAT chain walk,
  128-byte directory entries with UTF-16LE name match, root-entry mini stream,
  miniFAT chain and mini-sector extraction. The extracted bytes are assigned to
  `g_streamBytes`, which the unchanged shim hands to the verbatim upstream
  constructors and to the pinned `ParseLibHeader`.
- `run.sh`, `check.sh` — build eight binaries (g++/clang++ × vuln/fixed ×
  asan/plain) and run the assertion matrix.

Scope of the CFB walk: v3, 512-byte sectors, FAT located by the 109-entry DIFAT
array (no DIFAT sector is needed by this fixture, though the chain branch is
implemented). It is a lab CFB reader, **not** KiCad's `CFB::COMPOUND_FILE` and
not wxWidgets. No KiCad source beyond the pinned slices is compiled.

## Change from the earlier lane

The earlier `realparser` lane built the `FileHeader` byte stream directly in C++
and placed it in `g_streamBytes`; its CFB step was a shim. Here the bytes travel
through a real container: Python writes a compound file, `olefile` independently
reads `FileHeader` back, and the C++ driver walks header → DIFAT → FAT →
directory → miniFAT → mini stream to extract the same bytes before the verbatim
parser sees them. The vulnerability, pins, scenarios, stubs and assertions are
otherwise identical, so the two lanes are a controlled comparison of the
delivery boundary only.

## Negative / boundary results preserved

- A first CFB build produced `bad miniFAT`: the terminal test used
  `s < FREESECT`, but `ENDOFCHAIN` is `0xFFFFFFFE < 0xFFFFFFFF`, so the walk
  consumed the end marker as a sector. Corrected to `s < ENDOFCHAIN`. The
  failing observation is recorded here rather than erased.
- The app writing a short mini stream produced an `incomplete OLE sector`
  read-back in `olefile`; the mini stream is now padded to a full 512-byte FAT
  sector while the root entry's size stays the true mini-stream length.
- Directory field offsets were initially wrong (start at 104, size at 108),
  giving `olefile` a zero-length `FileHeader`; corrected to the standard
  116/120 offsets.

None of these changed the upstream slices, the crafted payload or the expected
write offset; they were fixture/reader defects found by the independent
`olefile` check and the CFB driver's own error paths.

## Ceiling

Still absent: real wxWidgets, KiCad's own compound-file class, a real KiCad
build or `eeschema`, an actual vendor-produced `.SchLib` (the fixture is a
minimal synthetic container), any executed downstream `aFontSizes` consumer, a
socket or wire, pointer/IP control, a command, a witness verdict and a mapped
fixed release. The chosen bytes still land in ASan's left redzone (plain build:
malloc metadata), not an adjacent live object. Rung 5 remains UNKNOWN.
