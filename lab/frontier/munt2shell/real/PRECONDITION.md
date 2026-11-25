# W187: a prior complete large SysEx closes the overflow path (2026-11-25)

New bounded real-library measurement. No parser source byte changed; the two
pinned trees (`vuln-2_8_3`, `fixed-1749f7f`) and their CMake static libraries
are those W160 provisioned and W186 replayed. Driver
`precondition_driver.cpp`, runner `precondition_probe.sh`, raw output
`evidence/precondition-results.txt` and eight `evidence/precondition-*.out`.

## Code fact (pinned vulnerable source)

`checkStreamBufferCapacity()` (MidiStreamParser.cpp:132-143) grows to
`MAX_STREAM_BUFFER_SIZE` only while `streamBufferCapacity < 32768`; once the
capacity is 32768 it returns false. The parser never shrinks capacity. A
complete SysEx on the fragment path dispatches and clears `streamBufferSize`
but leaves the 32768-byte capacity in place. Therefore a parser that has
already carried one complete 32768-byte SysEx takes the safe branch on a later
oversized one-shot SysEx: `parseSysex()` writes only `*streamBuffer = *stream`
and sets `streamBufferSize = streamBufferCapacity` (lines 251-253).

## Measurement

Precondition = 32 fragments of 1024 bytes (first byte `0xF0`, last byte
`0xF7`, all other bytes `0x5a`) through `parseStream()` on one
`DefaultMidiStreamParser`. Attack = one 40001-byte block starting `0xF0`
with no `0xF7`. `fresh` omits the precondition. An `operator new[]` hook
counts 32768-byte allocations.

| variant / build / mode | rc | `large_allocs` | observation |
| --- | --- | --- | --- |
| vulnerable plain `fresh` | 134 | 1 | `double free or corruption (!prev)` |
| vulnerable plain `precondition` | 0 | 1 | no new 32768 allocation; 31 library `parseSysexFragment: SysEx message lacks end-of-sysex` reports |
| vulnerable ASan `fresh` | 1 | 1 | `WRITE of size 40001`, 0 bytes after 32768-byte region at `MidiStreamParser.cpp:250`, grow at `:137` |
| vulnerable ASan `precondition` | 0 | 1 | no ASan report; same fragment-path reports |
| fixed plain/ASan `fresh` | 0 | 0 | no 32768 allocation, clean |
| fixed plain/ASan `precondition` | 0 | 1 | 32768 allocation from the safe fragment path, clean |

## What this adds, and what it does not

Measured attacker-model boundary on the real library: a parser instance that
has carried one complete 32768-byte SysEx cannot be overflowed by a later
oversized one-shot SysEx. The vulnerable path needs a parser whose buffer has
never been grown to capacity. This further constrains, but does not by itself
close, the search for a real object with a function pointer at the first
overwritten byte: the 32768-byte buffer is created inside the overflowing
call, so the overwritten neighbour is freshly placed heap, not an object the
host allocated before the parser existed.

No real host, wire input, actual PoC bytes, known ABI, pointer control,
command, side effect or witness replay. No clean-archive replay in this wake;
this is the author's direct run over the existing pinned libraries. Grade
unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5 UNKNOWN.
