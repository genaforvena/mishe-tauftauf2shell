# W184 — in-library `pushSysex` consumer of the forged top chunk (2026-11-24)

## Question and boundary

W183 measured a downstream allocator consumer of the forged top-chunk header
(libc stdio, reached through the default debug handler), and recorded that the
obvious in-library candidate could not be reached: `Synth::open()` requires
SHA1-pinned Roland ROMs that are not provisioned, so `midiQueue` stays NULL
and `Synth::playSysex()` returns early. No ROM was fetched in any wake.

This wake uses a second, plainly-labelled lab variant to close that specific
gap. Both verbatim pinned trees are configured as static libraries with
`-DMT32EMU_WITH_TESTING` added to `CMAKE_CXX_FLAGS`; that macro only exposes
munt's own test accessor hooks (`Synth.cpp:2914`,
`c_interface/c_interface.cpp:1025`). No parser source byte is changed. The
driver links the tree's own `src/test/FakeROMs.cpp`, which builds synthetic
ROM images with the expected SHA1 via `ArrayFile`, and calls the public
`Synth::open(control, pcm)`. That opens a real `Synth` with a real `midiQueue`.
`playSysex()` then reaches the real `MidiEventQueue::pushSysex()` allocation.

Replay: `cd lab/frontier/munt2shell/real && ./push_probe.sh`. Raw output in
`evidence/push-*.out`, summary in `evidence/push-results.txt`.

## Measured result

First input through real `DefaultMidiStreamParser::parseStream()`: 40001
unterminated bytes, with eight 7-bit bytes at source offset 32776 forging
glibc top size `0x10001`. Second input: a legitimate 102-byte SysEx through
the public `Synth::playSysex()` API, with host-chosen byte `0x37`.

| case | rc | header at buf+32776 after consumer | in-library allocation |
| --- | --- | --- | --- |
| vuln `shaped` | 0 | `5a5a5a5a5a5a5a5a71000000` | `new[0] len=102`, `delta=32784` |
| vuln `unshaped` | 134 | `malloc(): corrupted top size` | none |
| vuln `none` (no `playSysex`) | 134 | `5a...5a` unchanged until teardown | none |
| vuln `safe` (no overflow) | 0 | no 32768 allocation | `new[0] len=102`, normal heap |
| vuln `shaped-nobuf` (`stdbuf -o0`) | 0 | same as `shaped` | `new[0] len=102`, `delta=32784` |
| fixed `safe` / `fixed` | 0 | no 32768 allocation | `new[0] len=102`, normal heap |

In `shaped`, `pre_consume_header=...01000100` becomes
`post_consume_header=...71000000`: glibc consumed the forged `0x10001` top
chunk and rewrote the size field to `0x71`. The `102`-byte `pushSysex` buffer
lands at `buf+32784`, exactly the region overwritten by the first attack, and
`tail=f0373737373737373737373737373737` shows the library copying the second
SysEx's bytes into that region. This is an in-library consumer of the forged
header and of the corrupted region, reached by public API calls with the real
parser, real `Synth` and real allocator. Unlike W183, `stdbuf -o0` changes
nothing, so stdio is not the consumer here.

The `none` abort is `double free or corruption (!prev)` during driver teardown
after all output: the synthetic-ROM object graph is freed while the forged
header is still in place. It is a negative control for the same teardown that
`shaped` survives after `playSysex` repairs the heap, not a claimed exploit
primitive. All `opened=1` and `playSysex=1`; allocations are left live.

## Honest reading

Grade unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5
UNKNOWN. The bytes at `buf+32784` come from the *second*, legitimate input;
no chosen byte from the 40001-byte overflow is read back. The ROM images are
synthetic test fixtures, not the SHA1-pinned Roland ROMs a deployed synth
needs, and no real host, wire input, audio pipeline, pointer control or
command execution is exercised. `MT32EMU_WITH_TESTING` is a build variant,
not the shipped library configuration.
