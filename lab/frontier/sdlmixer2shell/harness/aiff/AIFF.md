# AIFF sibling adjacent lane — CVE-2026-122329

Named adjacent lane under the sdlmixer2shell target (same source tree, same
fix series). This is **not** the charter CVE-2026-122328 (WAV); the grades are
kept separate.

## Primary sources (provisioning only, no external probe)

- Advisory: CVE-2026-122329, "SDL_mixer 3.1.2 through 3.2.4 Stack-based Buffer
  Overflow via FetchXLaw() in AIFF Decoder", VulnCheck published 2026-11-05,
  CWE-121, CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
  (8.5 High). OSV record `CVE-2026-122329`, last modified 2026-11-14. Reporter
  hackmd link in the advisory was not relied on.
- Fix: `libsdl-org/SDL_mixer` commit
  `34486847a607540ce9ef5fbe20979c7140bf8c82` ("aiff: Apply fix from
  decoder_wav.c in df966f6...", parent tree `8aefd9d7d`), one changed line in
  `src/decoder_aiff.c`: `float *out = (float *) &buffer[(length - 1) * 4];`
  → `float *out = (float *) buffer;`. It is the identical fix to the WAV
  sibling's `df966f6`.
- Vulnerable source: tag `release-3.2.4`, raw `src/decoder_aiff.c` SHA-256
  `82824b1dd4715d3f8a70eec647b20a7c3d0bd6a06c7318d9445105e4ad71a99b`
  (byte-identical in the staged vuln/fixed source trees; the WAV fix tree never
  patched `decoder_aiff.c`). The fixed slice is the pinned bytes with only the
  `3448684` line applied. No `release-3.2.5` tag exists at fetch time; numeric
  fixed version UNKNOWN, same as the WAV sibling.

## Mechanism (source-bound)

`src/decoder_aiff.c:86-98`:

```
int length = buflen;                                             // :88
length = (int) SDL_ReadIO(tdata->io, buffer, (size_t)(length/4)); // :89
if (length % tdata->adata->framesize != 0) length -= ...;         // :90-92
float *out = (float *) &buffer[(length - 1) * 4];                 // vuln :93
for (int i = length - 1; i >= 0; i--) out[i] = lut[buffer[i]];    // :94-95
```

`out` is offset by `(length-1)*4` bytes and indexed as `float *` with stride 4
again. The real caller `AIFF_decode` (`decoder_aiff.c:531-548`) declares
`Uint8 buffer[1024]` at `:535`, `buflen = sizeof(buffer)` at `:536`, and calls
`fetch()` at `:541`. A full 256-sample read stores bytes 0..2043 — 1020 bytes
past the 1024-byte buffer. The store is at pinned `:95` in the sliced driver.

## Harness and commands

From `lab/frontier/sdlmixer2shell/harness/aiff/`:

```
sh run.sh     # verify 3/3 pins, emit 86-98 slices, generate drivers, build 12 binaries
sh check.sh   # 36 invocations + gdb chosen-byte probe, normalized trace
```

`run.sh` slices the pinned bytes under `#line 86 "decoder_aiff.c.{vuln,fixed}"`.
All other types (`AIFF_AudioData`, `AIFF_TrackData`, `DummyIO`), `SDL_ReadIO`
and the driver are lab stubs — the 1024-byte stack buffer mirrors the real
`:535` caller. 12 binaries: `g++`/`clang++` x vuln/fixed x plain/asan/nossp.
Scenarios: `small` (4 samples, in-bounds), `edge` (129 samples, framesize 1 —
one 4-byte store at `buffer+1024`), `attack` (256 samples, framesize 4 — 1020
bytes past).

Pins (`PINS.sha256`, 3/3): raw vulnerable source, vulnerable slice, fixed
slice. The fixed slice hash is derived solely from the pinned bytes plus the
one fix line.

## Observed evidence (author-observed, three identical runs)

- Rung 1: `small` returns `rc=64` with `buffer[1023]=11` intact in all 12
  binary/scenario combinations.
- Rung 2: `edge` returns `rc=516`; `attack` returns `rc=1024` — the loop
  completes while writing past the object. Fixed-tree runs return the same
  codes with every in-bounds byte chosen and no sanitizer/canary report.
- Rung 3: gcc and clang ASan both report `stack-buffer-overflow`, `WRITE of
  size 4`, top frame `FetchXLaw ... decoder_aiff.c.vuln:95`; ASan names
  `[32, 1056) 'buffer'` and `Memory access at offset 1056 overflows this
  variable` — exactly 1024 bytes into the 1024-byte object.
- Rung 4: gdb on `g++-vuln-nossp edge`, breakpoint `decoder_aiff.c.vuln:95`:
  first hit `I=128`, `LUT=5a5a5a5a`; after the store `buffer+1020..1027 =
  11 11 11 11 5a 5a 5a 5a` — chosen bytes at the chosen first OOB offset.
  Plain `attack` hits the glibc canary (gcc) or a fatal stack fault (clang);
  no-canary `attack` segfaults, preserved as edges.
- `check.sh`: **134 PASS / 0 FAIL** on three identical runs, trace
  `1bdfc38d601a558c6c600ca363293c73dcf446f87b8fb6e50ff1a1e9d43ad183`.
  Raw logs in `evidence/`.

## Ceiling of the direct-call scope

Direct call against the pinned source slice with lab stubs for AIFF IO, types
and the conversion LUT: no SDL/SDL_mixer build *in this scope*, no consumer
executed, no socket/wire delivery, no live process, no pointer or
instruction-pointer control, no benign marker, no command and no rung 5. The
advisory's own threat model is `AV:L/UI:P` (crafted local AIFF-C file, passive
victim). As with the WAV sibling, the primitive writes a fixed LUT float bit
pattern chosen by an input byte — not an address derived from input — so
control-flow steering is not claimed.

Witness #3497 (W192) graded this scope ESTABLISHED as labeled, rungs 1-4, not
rung 5, from a clean `git archive` of `61b9580`: 3/3 pins, 12 binaries,
`check.sh` PASS=134 FAIL=0 with the exact trace. The witness's LUT
counterexample (`0x41414141`) proved the stored word follows the LUT, not the
checker. The author result is now independently replayed, not merely pending.

The W195 extension in `REALAIFF.md` lifts the "no AIFF-C file / no real
decoder build / no consumer" part by driving a crafted AIFF-C file through a
real SDL_mixer 3.2.4 build with the AIFF decoder enabled (`check-real.sh`, 51
PASS / 0 FAIL, trace
`4d96b2b63ce8c86e73375d8c8ab685a494bea3b8de6a9d61d5ad18d101f9ffc8`). That
is a separately labeled scope; it still claims no wire, pointer/IP, marker,
command or rung 5. Witness #3497 graded it ESTABLISHED at rungs 1-4 as
labeled, also not rung 5.
