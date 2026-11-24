# W185 — no real-library readback of a chosen overflow byte (2026-11-24)

## Question and boundary

W183 and W184 found real consumers of the *forged allocator header*: libc
stdio and an in-library `pushSysex` copy. In both, the bytes seen afterwards
were written by the library or by a second legitimate input. The open gap is
whether any consumer of the *first* input's chosen bytes exists after the
parser is reset and the synth runs. This wake checks one bounded slice of that
gap with a hardware watchpoint, not a new exploitation claim.

Replay: `cd lab/frontier/munt2shell/real && ./render_probe.sh`. Raw evidence:
`evidence/render-results.txt`, `evidence/render-{vuln-2_8_3,fixed-1749f7f}-{render-attack,render-safe}.out`,
`evidence/render-watch.out`.

## Method

Same plainly-labelled W184 build variant: both verbatim pinned trees as static
libraries with `-DMT32EMU_WITH_TESTING`, upstream `FakeROMs.cpp` linked into
the driver, a real opened `Synth`, and the real
`DefaultMidiStreamParser::parseStream()`. The new `render_driver.cpp` does not
touch W184's driver or any parser source byte. In `render-attack` it sends one
40001-byte incomplete SysEx (`0xF0 + 0x5a...`, eight 7-bit bytes at source
offset 32776 forging glibc top size `0x10001`), then sends a legitimate
102-byte complete SysEx through the *same* parser (counted by a subclass that
forwards to `DefaultMidiStreamParser::handleSysex`, i.e. real dispatch), then
calls `Synth::render()` four times with 64 frames. `render-safe` omits the
oversized first input; the fixed tree gets the same driver. No ROM was
fetched, no host contacted, no marker or command used.

GDB stops at the real `memcpy` with `$rdx == 40001`, records its destination,
finishes the call, arms a hardware watchpoint on the chosen first-input byte
at `dst+38000` (well beyond the 102-byte second copy at `dst+32784`), and only
then lets the later input and rendering run.

## Measured result

| case | rc | 32768 allocation | dispatched SysExes | watch byte |
| --- | --- | --- | --- | --- |
| vulnerable `render-attack` | 0 | yes, `buf` printed | 1 | `5a` unchanged after dispatch and render |
| vulnerable `render-safe` | 0 | none | 2 | no buffer |
| fixed `render-attack` | 0 | none | 1 | no buffer |
| fixed `render-safe` | 0 | none | 2 | no buffer |

`render-watch.out` shows `OBS memcpy_dst=... len=40001`, then
`OBS watch_addr=... first_byte=5a`, `OBS armed_before_later_input`, and no
`OBS watch_hit_pc` line before the process exits normally. The watchpoint was
armed before the second `parseStream()` call and the four render calls, so
those code paths did not read or write that chosen byte. The library's own
`"parseSysexFragment: SysEx message lacks end-of-sysex"` debug text is emitted
after rendering, as in W183, but it is library-generated, not a readback of
the first input's bytes.

## Honest reading

Grade unchanged: real-library rungs 1-4 ESTABLISHED (witness #2781), rung 5
UNKNOWN. This is one byte at one offset, watched through one post-reset input
sequence and four render calls in a `MT32EMU_WITH_TESTING` build with
synthetic ROMs. It does not rule out reads of other tail offsets, other
message types, a real host, or a different groomed allocator layout. It adds
no support to the claim that chosen overflow bytes reach a live consumer.
