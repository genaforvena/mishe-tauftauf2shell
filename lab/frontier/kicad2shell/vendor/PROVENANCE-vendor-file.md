# Vendor-produced `.SchLib` reachability (2026-11-23 W180, 22:0xZ)

## What changed

Earlier lanes fed the pinned parser synthetic CFB containers whose
`FileHeader` property bytes were lab-authored. This lane replaces those
fixtures with a **vendor-produced Altium schematic library**: KiCad's own QA
test file `qa/data/eeschema/plugins/altium/issue22943/mounting_holes.SchLib`
at `KiCad/kicad-source-mirror` commit
`0f4d229ea6df8247929bd61e159efa6530cf5e2c` (fetched 2026-11-23 ~22:02Z):

- `https://raw.githubusercontent.com/KiCad/kicad-source-mirror/0f4d229ea6df8247929bd61e159efa6530cf5e2c/qa/data/eeschema/plugins/altium/issue22943/mounting_holes.SchLib`
  — sha256 `b510e91114cb2365117e01ece6c9709a11e0f1eaf1b016bef38419aa9beb56a0`
  (6656 bytes), unchanged.
- Same path `LICENSE` — sha256
  `253ad3f89603e728abfa60c36fbcaf8225cf55c1eab12725f19fb3d74d647f3a`.
  It is **CERN-OHL-S v2**, not CC0: the fixture and its two derivatives are
  included as clearly marked third-party test data under that license, not
  relicensed. This is provisioning of a public reference fixture, not a probe
  of any external target.

The fetch was source/data provisioning only. No external system was contacted
with a crafted input.

## CFB and property inspection

`olefile` 0.46 reads all five fixtures as valid compound files, six streams
each, `FileHeader` 551 bytes. The unmodified file's `FileHeader` contains
`Size1=10` and `Size2=9` (mixed case). The verbatim
`ALTIUM_BINARY_PARSER::ReadProperties()` uppercases keys, so the pinned
`ParseLibHeader` `upperKey.StartsWith("SIZE")` branch really does process a
vendor-authored key — not just the synthetic uppercase keys used before.
The driver's `real-key:` lines confirm `SIZE1=10`, `SIZE2=9` after parsing.

## Three in-place byte patches

All patches change exactly one property key, with identical byte length, at
a fixed raw-file offset. No CFB header, FAT, directory, miniFAT or stream
length changes; `olefile` re-verifies each result.

| fixture | offset | bytes before → after | sha256 |
| --- | --- | --- | --- |
| `mounting_holes-size0.SchLib` | 650 | `\|Size1=10\|` → `\|Size0=99\|` | `06fb23f9ca050c6fc177ecb4e3c0384262e1a8696d0ec4aa2c204ee15273bd2a` |
| `mounting_holes-sizez.SchLib` | 685 | `\|Size2=9\|` → `\|SizeZ=9\|` | `09ebf2aa9ca5dc9a52aa1edec4f55d5ca56913bd567114a127472ff90b286d23` |
| `mounting_holes-sizez7.SchLib` | 685 | `\|Size2=9\|` → `\|SizeZ=7\|` | `d97a37ab6a8634d2c79bbeafae91e976e208ce8ec3d71a792e105c3ec8602eae` |
| `mounting_holes-sizez1.SchLib` | 685 | `\|Size2=9\|` → `\|SizeZ=1\|` | `20ea3a0da21d7d1e794a75947b75c2d3f102ce3cd95a442ba4f0c250a43fdb3a` |

`wxAtoi("0") == wxAtoi("Z") == 0`, so all hostile keys select `ind == 0` and hit
the unbounded `aFontSizes[ind - 1]` store. Their map ordering differs: uppercase
`SIZE0` sorts before `SIZE1`, `SIZEZ` after it.

## Observed (`sh check.sh`, two identical runs)

`vendor-pins`: 6/6 sha256 OK. `PASS=23 FAIL=0`, trace
`42db33cb056a52d223a51a6af7d0ffd5cfaeeb4a6f64fc8c28d80fdd6e341e4f`.
Raw outputs for every invocation are in `evidence/`.

- Unmodified vendor library through `g++-vuln/plain/asan` and both fixed
  binaries: `stream=551`, `props=30`, `parse_error=0`, `real-key: SIZE1=10`,
  `real-key: SIZE2=9`, `rc=0 size=2 first=72 GUARD7=11111111`, no ASan report.
  This is a clean real-file negative control.
- `size0`: vulnerable plain `rc=139` (SEGV); ASan `SEGV` at pinned `:5919`.
  Cause: the hostile key sorts first, so `aFontSizes` is still empty and the
  store targets `nullptr - 4`, not an allocated region. Preserved as a
  distinct observed fault mode, not a separate vulnerability claim. Both
  fixed binaries: `rc=0 size=2 first=0 GUARD7=11111111`, clean ASan.
- `sizez9` / `sizez7` / `sizez1`: same byte 685 patched to `SizeZ=9`, `7`,
  `1`. Each vulnerable plain build prints `rc=0 size=1 first=72` then glibc
  aborts with `double free or corruption (out)` (`rc=134`); each gcc ASan
  run reports `heap-buffer-overflow`, `WRITE of size 4`, 4 bytes before the
  4-byte region, top frame `sch_io_altium.cpp.vuln:5919`, allocation from
  `resize` at `:5915`. Both fixed binaries are clean on all three byte sets.
- gdb on each patched vendor file, skipping the first valid `:5919` hit:
  `SizeZ=9` → `SCALED=0x00000040`, bytes `40 00 00 00`; `SizeZ=7` →
  `0x00000032`, bytes `32 00 00 00`; `SizeZ=1` → `0x00000007`, bytes
  `07 00 00 00`, all at `data()-4`. The file's own hostile value determines
  the four-byte word stored at the chosen offset, now on a real vendor file.

## Ceiling

This closes the *fixture provenance* part of the file-reachability gap: a
real, vendor-authored Altium `.SchLib` with real mixed-case `Size` keys now
drives the pinned parser through KiCad's own verbatim compound-file reader.
It does **not** close the full-path gap: no wxWidgets, no real
`ALTIUM_COMPOUND_FILE` class, no full KiCad/`eeschema` build, no GUI import,
no downstream consumer executed, no socket or wire, no pointer/control-flow
target, no marker or command. The four bytes still land in ASan's left
redzone (plain build: malloc chunk metadata), not an adjacent live object.
Rung 5 remains UNKNOWN; the witness verdict (#2996) is for rungs 1-4 at the
synthetic-CFB scope and has not been re-run on this lane.
