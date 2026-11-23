# Write-alphabet bound (munt2shell W170, 2026-11-23)

One bounded experiment, no grade change. Question: which byte values can the
pinned `libmt32emu_2_8_3` overflow actually write past the 32768-byte parser
allocation? The report previously said "the overflow bytes are 7-bit SysEx
data" from source reading alone; this measures it against the real library.

## Method

`alphabet_driver.cpp` calls `parseStream()` once on a real `Synth` and
`CountingParser` with a 40001-byte block: `0xF0` + 40000 bytes of `0x6a`,
with one optional byte replaced at a chosen offset. It reuses the existing
CMake-built static libraries in `build/`; no library source was changed.
Plain builds override `operator new[]` with `malloc(n + 16384)` and count
`0x6a` bytes after the real 32768-byte allocation; ASan builds use the real
allocator. Replay: `./alphabet_probe.sh` from this directory. Raw results:
`evidence/alphabet-*.out`, `evidence/alphabet-results.txt`.

## Measured results (vulnerable 2.8.3)

| input variant | plain readback | ASan |
|---|---|---|
| all data bytes `0x6a` (no status byte) | `alloc32768=1`, `tail_0x6a=7233/16384` | rc=1, `WRITE of size 40001` at `MidiStreamParser.cpp:250` |
| one `0x7f` at offset 32768, rest `0x6a` | `tail_0x6a=7232`, first tail byte `0x7f` | rc=1, same overflow |
| `0x80` or `0x85` at offset 32768 | no 32768 allocation, `tail_0x6a=0`, `debug=1`, 3616 short messages parsed from the tail | rc=0 |
| `0x80` at offset 32769 | no 32768 allocation, 3615 short messages | not run (same early-return source path) |
| `0xf7` at offset 32768 | `sysex=1 lastlen=32769`, no 32768 allocation | rc=0 |
| `0xf8` at offset 32768 | `realtime=1`, 32768 allocation, exact-fit copy, `tail_0x6a=0` | not run (exact-fit copy) |

Pinned-fixed ASan control with the all-`0x6a` block: rc=0, no report.

Source cause (`pins/MidiStreamParser.cpp.vuln:223-256`): a status byte
`0x80`-`0xF6` returns from `parseSysex()` at `:243` **before** setting
`streamBufferSize` or copying anything; `0xF7` dispatches from the caller's
buffer at `:231` with no copy; `0xF8`-`0xFF` breaks at `:238` before the
realtime byte, and the copy ends there. Only bytes `< 0x80` reach the
`memcpy` at `:250`. Therefore every byte landing past the 32768-byte
allocation is in `0x00-0x7F`: the write primitive cannot encode a byte with
the high bit set. Corrected hypothesis: the initial expectation was that a
status byte would truncate the copy to its offset; the measurement shows no
copy at all, which is a stronger bound.

## Limits

This bounds the write alphabet, not exploitability. No host, socket, live
object, pointer overwrite, grooming, marker or command was exercised; the C
API path and the ALSA sequencer ceiling remain as recorded in
`REAL_EVIDENCE.md` and `ALSA_CEILING.md`. Grade unchanged: real-library
rungs 1-4 ESTABLISHED by witness #2781, rung 5 UNKNOWN.
