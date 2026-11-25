# One-byte partial pointer overwrite (munt2shell W186, 2026-11-25)

One bounded experiment, no grade change. Question: W170 measured that only
bytes `0x00-0x7F` can land past the 32768-byte parser allocation. Can a *short*
overflow still redirect a live function pointer by changing only its low byte,
leaving the high bytes untouched?

## Method

`partial_driver.cpp` + `partial_probe.sh`, replayed from this directory with
the pinned plain and ASan static libraries built by `build_and_run.sh` and
`build_clang_asan.sh` (no library source byte changed). A single
`0xF0 + 32784` byte block (32785 bytes) is sent through the real
`DefaultMidiStreamParser::parseStream()`. A global `operator new[]` override
notes the library's `new Bit8u[32768]` and immediately makes an ordinary
`malloc(64)`; W179 measured its user data at `buf+32784`. That allocation holds
a `Victim { MarkerFn fp; ... }`. At runtime the driver picks two marker
functions in the same 256-byte block whose low bytes differ and whose target
low byte is `< 0x80`, so PIE layout shifts cannot invalidate the case. It
patches exactly one byte of the input at index `32784` with that target low
byte; every other block byte is `0x5a`, and there is no `0xF7` or status byte
inside the block. After `parseStream()` returns the driver prints the pointer
bytes and calls through it.

The victim and the marker functions are **harness-created**. No upstream
object, host, socket, wire input, audio pipeline or real attack surface is
involved. This is a rung-4 mechanic.

## Measured results (raw: `evidence/partial-*.out`, matrix
`evidence/partial-results.txt`)

| variant / mode | rc | observation |
|---|---|---|
| vulnerable plain `attack` | 0 | `grows=1`, victim at `delta=32784`, `victim_base=6787658aff5c0000`, `target=4987658aff5c0000`, `victim_after=4987658aff5c0000`, then `victim=marker_1` |
| vulnerable plain `safe` (102-byte terminated SysEx) | 0 | no 32768 allocation, no victim, no overflow |
| fixed `1749f7f` plain `attack` | 0 | no 32768 allocation, no victim, no overflow |
| fixed plain `safe` | 0 | same |
| vulnerable gcc ASan `attack` | 1 | `heap-buffer-overflow`, `WRITE of size 32785`, 0 bytes after the real 32768-byte region at `MidiStreamParser.cpp:250` |
| fixed gcc ASan `attack` | 0 | no 32768 allocation; ASan clean (`detect_leaks=0`) |

The attack byte in the committed run is `0x49`, chosen from the runtime marker
table; the high seven pointer bytes are unchanged. ASan's redzones change the
neighbour layout, so no marker claim is made from that lane.

## What this changes, and what it does not

New measured fact: the write primitive's 7-bit alphabet does not by itself
prevent control-flow redirection when a pointer sits at the first overwritten
byte and the desired target shares the pointer's upper bytes. A one-byte
partial overwrite is enough, and the fixed build has no such write.

Limits: the victim pointer is harness-created at a deliberately groomed
offset; no real library or host object with a function pointer at that offset
was found or measured. No ASLR defeat, no full pointer control, no host input,
no remote input, no command and no witness replay. W185's hardware watchpoint
result on chosen bytes after real dispatch and render is unchanged. Grade:
real-library rungs 1-4 ESTABLISHED by witness #2781; rung 5 UNKNOWN.
