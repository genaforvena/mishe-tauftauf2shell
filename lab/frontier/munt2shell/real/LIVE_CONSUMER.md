# W183 — downstream consumer of the forged top chunk (2026-11-24)

Scope: one bounded wake. Real pinned `libmt32emu_2_8_3` static libraries
(`build/vuln-2_8_3-plain`, `build/fixed-1749f7f-plain` from
`build_and_run.sh`), real `Synth` and `DefaultMidiStreamParser`. Driver
`live_driver.cpp`, replay `./live_probe.sh`, raw outputs `evidence/live-*.out`
and `evidence/live-results.txt`. The `operator new[]` and `--wrap=malloc`
hooks only record allocations; they never read or consume corrupted metadata.
Input buffers come from `__real_malloc`, so post-arm logs are library/stdio
activity only. No debugger-forced dispatch.

## Question and prerequisite gap

W179 forged glibc's top-chunk size with eight 7-bit bytes at source offset
32776. W182 measured that a second `parseStream()` block cannot reuse the
corrupted *buffer*. Open question: does a later **real** allocation consume
the forged *chunk header*?

The direct candidate was `Synth::playSysex() -> MidiEventQueue::pushSysex()
-> new Bit8u[sysexLength]` (`pins` source `Synth.cpp:2285`, allocator at
`:2163`). It is unreachable here: `midiQueue` is created only in
`Synth::open()` (`Synth.cpp:945`), which needs SHA1-pinned Roland ROM images
that are not provisioned; with `midiQueue == NULL`, `playSysex()` returns
false at `:1149`. All `new[]` and wrapped-`malloc` logs after arming are
`count=0`, which records that gap rather than hiding it. No ROM was fetched.

## Measured result

First call: 40001-byte unterminated SysEx. `shaped` writes
`01 00 01 00 00 00 00 00` at buf+32776 (top size `0x10001`); `unshaped`
leaves `0x5a` there. Second call: a complete 102-byte SysEx through
`parseStream()`. Because `streamBufferSize=40001 > capacity=32768` the parser
takes the overrun branch of `parseSysexFragment()` and calls `printDebug()`;
the default `ReportHandler::printDebug` is `vprintf` (`Synth.cpp:395-398`).

| case | rc | header at buf+32776 after second call |
| --- | --- | --- |
| `vuln-2_8_3 shaped` | 0 | `11 10 00 00 00 00 00 00` |
| `vuln-2_8_3 unshaped` | 134 | `malloc(): corrupted top size` before output |
| `vuln-2_8_3 none` (no second call) | 0 | `01 00 01 00 00 00 00 00` unchanged |
| `vuln-2_8_3 shaped-nobuf` (`stdbuf -o0`) | 0 | `01 00 01 00 00 00 00 00` unchanged |
| `vuln-2_8_3 safe`, `fixed safe/fixed` | 0 | no 32768 allocation |

With default stdout buffering, `post_good1_wide` additionally shows ASCII at
buf+32784: `70617273655379736578467261676d656e743a205379734578206d6573736167...`
= `"parseSysexFragment: SysEx messag..."`, the library's own overrun message.
The libc stdout buffer was allocated from the forged top chunk; libc's
internal `malloc` is invisible to `--wrap=malloc`, which is why the wrapped
log stays empty. Unbuffering stdout removes the allocation and the header
change together — an explicit causal control, not a correlated observation.

## Honest reading

This is a real downstream consumer of the corrupted allocator metadata,
reached by a normal public-API input sequence with the real library and no
harness-created consumer. It is **not** a consumer of the 7233 forged *tail
bytes*: the bytes written at buf+32784 are the library's generated debug
string, the consumer is libc stdio, and no chosen overflow byte is read back.
The `pushSysex` allocation path remains unmeasured because no ROM is
available. Grade unchanged: real-library rungs 1-4 ESTABLISHED, rung 5 UNKNOWN.
Would change the grade: a measured real host sending one >=32769-byte call
from real input, actual PoC bytes, or a measured byte >= 0x80 past the
allocation.
