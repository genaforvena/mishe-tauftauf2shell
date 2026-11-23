# Third-party libmt32emu hosts: source-level reachability negative (W176, 2026-11-23)

W175 closed the in-tree routes (report §13). This wake tested the remaining
"third-party C API host" hypothesis from W175's next step. All bytes below were
fetched from public raw GitHub over HTTPS during this wake (provisioning, not
lab testing) and are kept verbatim beside this note. No third-party host was
built or run; these are source-level findings only.

## Fetches

| file here | upstream URL at fetch time (branch `main`/`master`) | bytes | sha256 |
| --- | --- | --- | --- |
| `DOSBox-Staging-midi_mt32.cpp` | `https://raw.githubusercontent.com/dosbox-staging/dosbox-staging/main/src/midi/mt32.cpp` | 33146 | `e061f43ff76bce3142598e87a033033061fff198718cf063ba00d47a1009fa79` |
| `86Box-midi_mt32.c` | `https://raw.githubusercontent.com/86Box/86Box/master/src/sound/midi_mt32.c` | 18165 | `a9b4c62509e2d19b9e16cf623a4524f57434befa5c1afb99bba469b98ddca692` |
| `DOSBox-X-MidiStreamParser.cpp` | `https://raw.githubusercontent.com/joncampbell123/dosbox-x/master/src/libs/mt32/MidiStreamParser.cpp` | 10789 | `fe0fa4cab17946258028e1c01aed91e2d7edcebe5acd740e86173f3440392ad3` |

Repository file lists were obtained from the unauthenticated GitHub tree API
(`/repos/<owner>/<repo>/git/trees/<branch>?recursive=1`); all three returned
`truncated: false`.

## Observed call sites

- DOSBox Staging, `src/midi/mt32.cpp:781-786`: the `MessageType::SysEx` branch
  calls `service->playSysex(work.message.data(),
  static_cast<uint32_t>(work.message.size()))`. There is no `parseStream` call
  in the file. `playSysex` is not the defective path (report §2).
- 86Box, `src/sound/midi_mt32.c:308-311`: `mt32_sysex()` calls
  `mt32emu_play_sysex(context, data, len)`. `mt32emu_parse_stream` appears only
  in doc comments at `:57` and `:98`, never as a call.
- DOSBox-X vendors the entire library at `src/libs/mt32/`, including
  `MidiStreamParser.cpp`. At master that copy already has the upstream fix:
  `:136` reads `if (streamBufferSize < MAX_STREAM_BUFFER_SIZE &&
  streamBufferCapacity < MAX_STREAM_BUFFER_SIZE)`, and `:253` reads
  `Bit32u bytesToCopy = sysexLength < streamBufferCapacity ? sysexLength :
  streamBufferCapacity;` before `memcpy(..., bytesToCopy)` at `:254`.
  Therefore the W159-W160 flaw is not present in that vendored copy.

## Web search negatives (same wake)

Search queries for `mt32emu_parse_stream` and for `parseStream` combined with
DOSBox/86Box/PCem/libretro returned only munt/munt's own tree, CVE aggregators,
and third-party wrappers (e.g. `abedegno/Munt.NET`). No host that makes a
single >32768-byte `mt32emu_parse_stream()` call was found. The VulnCheck
advisory page fetched this wake repeats the CVE prose ("MIDI files, ports, or
sequencer clients") and names no host or PoC code. The reporter's hackmd PoC
link still returns HTTP 404, including with `?download`.

## Disposition

Source-level negative. It narrows the third-party host lane but does not prove
no third-party host is affected. A measured host that supplies one oversized
block from real input is still the missing rung-5 prerequisite. Grade
unchanged: real-library rungs 1-4 ESTABLISHED, rung 5 UNKNOWN.
