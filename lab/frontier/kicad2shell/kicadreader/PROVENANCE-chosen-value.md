# Chosen-value counterexample in the KiCad-own-reader lane (2026-11-23 20:38Z)

## What this is

An independent, file-driven repetition of the witness's counterexample from
message #2996: change the hostile `SIZEZ` value inside a real compound file,
watch the four bytes written before `aFontSizes.data()` change with it, and
confirm the fixed build rejects the same file bytes.

`sh chosen-value.sh VALUE` (default `925327927`) builds a CFB fixture through
the committed `realcfb/make_cfb.py:build` with a caller-chosen decimal `SIZEZ`
payload, verifies the fixture with `olefile` (`chosen-olefile=... key_ok=True
PASS`), then uses the already-built `g++-vuln-plain` binary and gdb at pinned
`sch_io_altium.cpp.vuln:5919`. The breakpoint hit for the valid `SIZE1=10` key
is skipped with `continue`; at the hostile hit it prints `ind`/`scaled`, steps
the store with `next`, and dumps four bytes at
`aFontSizes._M_impl._M_start-4`. The `g++-fixed-plain` and `g++-fixed-asan`
binaries run the same fixture as controls.

Only lab fixture bytes and lab driver code are involved: the compound-file
reader, `ALTIUM_BINARY_PARSER` and `ParseLibHeader` slices are the same pinned
bytes as the main lane. No upstream bytes, pin hashes, `check.sh` assertions
or `trace-kicadreader.sha256` were changed.

## Observed (evidence/ files named in each row)

| SIZEZ in CFB FileHeader | gdb at pinned :5919 | four bytes at `data()-4` | fixed plain / ASan |
| --- | --- | --- | --- |
| `84215045` (`chosen-84215045-*`) | `IND=0 SCALED=0x24242424` | `0x24 0x24 0x24 0x24` | `rc=0 size=1 first=72 GUARD7=11111111`, no ASan report |
| `925327927` (`chosen-925327927-*`) | `IND=0 SCALED=0x80000000` | `0x00 0x00 0x00 0x80` | `rc=0 size=1 first=72 GUARD7=11111111`, no ASan report |

Both runs report `real-reader: bytes=107/108 props=3 parse_error=0` and the
chosen `real-key: SIZEZ=...` from KiCad's own reader. `925327927` is
`0x37373737`; `(int)(925327927 * 72.0 / 10.0)` overflows the conversion to
`0x80000000`, matching the value the witness reported. The store bytes track
that scaled value (little-endian), so the chosen file bytes determine what is
written at the chosen offset.

## Ceiling

This is rung-4 mechanics, not rung 5. The four bytes land in ASan's left
redzone (plain build: malloc chunk header), not an adjacent live object; no
downstream consumer of those bytes was executed, and there is no pointer or
control-flow target, wire, live process, command or marker. The witness's
verdict stands as recorded: **ESTABLISHED rungs 1-4 at the labeled
synthetic-CFB / KiCad-own-compound-file-reader scope, NOT rung 5**, with an
exact replay of trace
`fffe73410576403f33943253a207db3e8493229babdfb8f30f4544aebcfd6260` from
clean archive `3d90217` (11/11 pins, `PASS=38 FAIL=0`).

## Source-bound wrapper convergence (20:42Z)

The lab wrapper was compared with the real one at pinned parent
`bf3e3fa5497882f5b0975d03e4a74b2c086db0e2`. Both were fetched read-only
from `https://gitlab.com/kicad/code/kicad/-/raw/<sha>/common/io/altium/altium_binary_parser.{cpp,h}`
(sha256 `3160f11e0dd08d47c13af7dc7733248db544890c2efb875800249f6043567519`
and `8741041b77c1cf5b96d1d5d87f36388c9a57cdbfa2e5ed6f4e4491d02fb7de5a`).
They are research reads only: no new bytes were added to the harness pins.

- Real `ALTIUM_COMPOUND_FILE::FindStreamSingleLevel` (`.cpp:158`) calls
  `m_reader->EnumFiles( aEntry, 1, ... )` and filters with
  `m_reader->IsStream( entry ) == aIsStream` (`:173`); the lab wrapper in
  `stubs.hpp:144-160` calls `EnumFiles( GetRootEntry(), 1, ... )` and
  `IsStream( entry )` on the same `CFB::COMPOUND_FILE_ENTRY`.
- Real `ALTIUM_BINARY_PARSER( const ALTIUM_COMPOUND_FILE&, const CFB::COMPOUND_FILE_ENTRY* )`
  (`.cpp:319-329`) allocates `m_size = aEntry->size` and calls
  `GetCompoundFileReader().ReadFile( aEntry, 0, m_content.get(), m_size )`.
  That constructor is already pinned verbatim in `realparser/` and is the
  one the kicadreader harness compiles; no lab reimplementation of the
  stream read exists.

So the delivery API used by the synthetic fixtures matches the real
wrapper's API. This is a source-bound convergence, not a full-build result:
the real class, wxWidgets and `eeschema` were not compiled or executed.
Guessed path `eeschema/sch_io/altium/altium_compound_file.cpp` returned 404
and unauthenticated GitLab blob search returned 401; the class lives in the
common Altium binary parser files above.
