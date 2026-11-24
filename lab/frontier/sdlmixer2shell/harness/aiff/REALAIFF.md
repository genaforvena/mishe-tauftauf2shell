# Real AIFF-C file through the real SDL_mixer AIFF decoder (W195)

Named extension of the AIFF sibling lane (CVE-2026-122329). The direct-call
harness in `AIFF.md` uses lab stubs; this lane instead drives an **unmodified
real SDL_mixer 3.2.4 build** with a crafted on-disk AIFF-C file. Grades stay
separate from the charter WAV CVE. No network probe: every source and build
used here was already provisioned under `lab/frontier/sdlmixer2shell/deps/`.

## What was built and why

The three pre-existing mixer builds set `-DSDLMIXER_AIFF=OFF`, so they cannot
reach `decoder_aiff.c`. Three new builds set `-DSDLMIXER_AIFF=ON` and everything
else off (`WAVE=OFF VOC=OFF AU=OFF ...`), using the already-built headless SDL3
3.4.0 in `deps/SDL3-3.4.0-build`:

- `deps/mixer-aiff-vuln-asan-build/libSDL3_mixer.a` — pinned release-3.2.4.
- `deps/mixer-aiff-fixed-asan-build/libSDL3_mixer.a` — same tree plus the
  one-line fix `34486847a607540ce9ef5fbe20979c7140bf8c82` applied **only** to
  `src/decoder_aiff.c:93` in a copy `deps/SDL_mixer-aiff-fixed-src/`. The WAV
  fix `df966f6` is irrelevant here: the pinned fixed tree still has the AIFF
  bug, so a dedicated fixed tree was required.
- `deps/mixer-aiff-vuln-nossp-build/libSDL3_mixer.a` — vulnerable,
  `-fno-stack-protector`, for the plain-build/gdb observations.

`sh build-real.sh` reproduces all three builds (log `evidence/build-real.log`).
The fixed source is committed as `lab/frontier/sdlmixer2shell/src/decoder_aiff.c.fixed`
(SHA-256 `3862343222dcb862ca4aff1373c99138b3b1f419fd8453ba22769fee88034ae2`);
`build-real.sh` creates `deps/SDL_mixer-aiff-fixed-src` from the pinned
vulnerable tree plus that file, so a clean archive can rebuild the lane.

## Inputs

`craft_aiff.py` emits five minimal AIFF-C/AIFF files in `evidence/`:

| file | compression | data | role |
| --- | --- | --- | --- |
| `alaw256.aifc` | `alaw` | 256 B | attack, A-law |
| `ulaw256.aifc` | `ulaw` | 256 B | attack, mu-law |
| `alaw8.aifc` | `alaw` | 8 B | safe input |
| `raw256.aifc` | `raw ` | 256 B | negative control (`FetchPCM`) |
| `pcm8_256.aiff` | plain AIFF | 256 B | negative control (`FetchPCM`) |

Each file is `FORM` + `AIFC`/`AIFF` + `FVER` + `COMM` + `SSND`. `COMM` declares
mono, 8-bit, 8000 Hz (80-bit SANE frequency bytes `40 0c 7d 00 00 00 00 00 00
00`); the A-law/mu-law compression type selects `FetchALaw`/`FetchULaw` in the
real parser. `SDL_AUDIO_FRAMESIZE` is 4, so `AIFF_decode`'s 1024-byte buffer
gives `buflen=1024`, `length=256`, `out = &buffer[1020]`, and 1020 bytes of
out-of-bounds stores. File SHA-256s are in `REAL.sha256`.

## Driver and commands

The driver is the committed `harness/realwav/realwav_driver.c` (unmodified):
`MIX_CreateAudioDecoder(path)` + `MIX_GetAudioDecoderFormat` +
`MIX_DecodeAudio` in `decode` mode, and `MIX_CreateMixerDevice` +
`MIX_LoadAudio` + `MIX_PlayTrack` (dummy device) in `play` mode. Build line
(from the checkout root, same as `REALWAV.md`):

```sh
L=lab/frontier/sdlmixer2shell; D=$L/deps; E=$L/harness/aiff/evidence
for k in vuln-asan fixed-asan vuln-nossp; do
  case $k in
    vuln-asan)   s=$D/SDL_mixer-vuln-src;       b=$D/mixer-aiff-vuln-asan-build/libSDL3_mixer.a;  san=-fsanitize=address;;
    fixed-asan)  s=$D/SDL_mixer-aiff-fixed-src; b=$D/mixer-aiff-fixed-asan-build/libSDL3_mixer.a; san=-fsanitize=address;;
    vuln-nossp)  s=$D/SDL_mixer-vuln-src;       b=$D/mixer-aiff-vuln-nossp-build/libSDL3_mixer.a; san=;;
  esac
  clang -g -O0 -fno-omit-frame-pointer $san \
    -I"$s/include" -I"$D/SDL-release-3.4.0/include" \
    -I"$D/SDL3-3.4.0-build/include-revision" \
    "$L/harness/realwav/realwav_driver.c" "$b" \
    -L"$D/SDL3-3.4.0-build" -lSDL3 -Wl,-rpath,"$(pwd)/$D/SDL3-3.4.0-build" \
    -lm -lpthread -ldl -o "$E/aiff-driver-$k"
done
sh $L/harness/aiff/check-real.sh
```

`check-real.sh` runs 15 decode invocations (3 builds x 5 files), the two play
invocations and the gdb probe; `ASAN_OPTIONS=detect_leaks=0:abort_on_error=0`,
`ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-18/bin/llvm-symbolizer`.

## Observed evidence (author-observed, three identical runs)

- `decode` on the real mixer, vulnerable ASan: `alaw256.aifc` and
  `ulaw256.aifc` both give `AddressSanitizer: stack-buffer-overflow`, `WRITE of
  size 4`, top frame `FetchXLaw ... decoder_aiff.c:95:16`, via
  `FetchALaw`/`FetchULaw` -> `AIFF_decode` (`decoder_aiff.c:541`) ->
  `MIX_DecodeAudio` (`SDL_mixer.c:3190`). ASan names `[32, 1056) 'buffer'
  (line 535)` and `overflows this variable`; access frame offset 1180.
- `decode` controls: `alaw8.aifc`, `raw256.aifc`, `pcm8_256.aiff` are clean on
  every build. The fixed ASan build returns `RESULT=OK total=1024` on both
  attack files. Vulnerable no-stack-protector build exits non-zero (SIGSEGV)
  on both attack files, clean on the controls.
- `play` mode: vulnerable ASan reports the same `WRITE of size 4` at
  `decoder_aiff.c:95` on **thread T1**, through `AIFF_decode` -> `DecodeMore`
  (`SDL_mixer.c:306`) -> `TrackGetCallback` -> `MixerCallback` -> SDL playback
  thread; fixed build is clean. Safe input is clean in both.
- Rung 4, gdb on `aiff-driver-vuln-nossp`, breakpoint `decoder_aiff.c:95 if
  i == 1`: `length=256 i=1 out=buffer+1020`; the store address is `buffer+1024`
  and afterwards `buffer+1020..1027 = 00 00 00 00 c0 01 e0 ba`, i.e. the real
  A-law LUT word `0xbae001c0` derived from input byte `buffer[1]=0x56` at the
  first out-of-bounds offset. The written value is a conversion-table float
  bit pattern selected by an input byte — not an address derived from input.
- `check-real.sh`: **51 PASS / 0 FAIL** on three runs, normalized trace
  `4d96b2b63ce8c86e73375d8c8ab685a494bea3b8de6a9d61d5ad18d101f9ffc8`
  (`evidence/real-trace.txt`). Raw logs in `evidence/real-*.out`.

## Ceiling and grade

Real file-path reachability and real decoder/consumer execution are now
author-observed for the AIFF sibling: rungs 1-3 in the real mixer, rung 4 as a
chosen LUT word at the chosen OOB offset. Still no wire delivery, no live
request-facing listener (the advisory is `AV:L/UI:P`), no pointer or
instruction-pointer control, no benign marker, no command, no witness verdict
and no rung 5. The primitive writes a fixed conversion-table word chosen by an
input byte, so control-flow steering is not claimed. Independent replay has
been requested on the chat tape; this author result is not acceptance.
