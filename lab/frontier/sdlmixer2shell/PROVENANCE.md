# sdlmixer2shell — provenance, stubs and negatives (W173, 2026-11-23)

## Provisioning (read-only fetches, no external probing)

- Advisory: <https://github.com/advisories/GHSA-7qqc-5rvj-wqqw>
  (CVE-2026-122328, High 8.5 CVSS4, CWE-121, Unreviewed, 2026-11-05).
- Fix patch: <https://github.com/libsdl-org/SDL_mixer/commit/df966f698e18ae849bd92796a26311e79c555718.patch>
  — one changed line in `src/decoder_wav.c:757`.
- Fix commit metadata via GitHub API: parent
  `8d30c639eb30014cd2916f505b439f91971a4ec3`, author date 2026-10-31T17:46:18Z.
- Vulnerable raw source: <https://raw.githubusercontent.com/libsdl-org/SDL_mixer/release-3.2.4/src/decoder_wav.c>
  → `src/decoder_wav.c.vuln`, SHA-256
  `b651a6c2225378c6d2407df75eb1ec6f30ace68893a621cf29fd2089cd2016fa`, 1797 lines.
- Fixed raw source: <https://raw.githubusercontent.com/libsdl-org/SDL_mixer/df966f698e18ae849bd92796a26311e79c555718/src/decoder_wav.c>
  → `src/decoder_wav.c.fixed`, SHA-256
  `b930672ee9ceaaea46ed2e8a3251ea3207ebcfa7366e1e7c8e851e40d13d9ca3`, 1809 lines.
- `release-3.2.5` raw URL returned 404 at fetch time → numeric fixed version
  UNKNOWN; no fixed release claim.
- AIFF sibling CVE-2026-122329 / fix `34486847a607540ce9ef5fbe20979c7140bf8c82`
  is a separate candidate; not pinned or tested here.

## Pins

`PINS.sha256` covers both raw files and the two verbatim `750-762` slices:
- vuln slice `54a27dd388fc9d8826d512388b06d070c7c490d6d49007d1385fa2e8cdcb0eef`
- fixed slice `dac7eb45017e386325512ea3b2ad41ce748289bc8e131c02a12204240097d8c4`

`harness/run.sh` regenerates the slices with `sed -n '750,762p'` and checks
all four hashes before building. `#line 750 "decoder_wav.c.vuln"` maps ASan
and gdb reports back to pinned upstream lines.

## Lab code (not upstream)

- `Uint8` typedef, `WAV_AudioData { int framesize; }`, `DummyIO`,
  `WAV_TrackData { io, adata }`.
- `SDL_ReadIO` stub copies up to `buflen/4` bytes from a lab byte array into
  the caller buffer and returns that count; this mirrors the real read at
  pinned `:753` but does not exercise real SDL IO.
- Conversion LUT: a 256-entry `float` array, every element set to the bit
  pattern `0x5a5a5a5a`; this supplies the chosen marker bytes written by the
  pinned loop. The real decoder uses `MIX_ulawToFloat` / `MIX_alawToFloat`.
- Driver scenarios: `small` 16 input bytes / framesize 4; `edge` 129 bytes /
  framesize 1 (one float at `buffer+1024`); `attack` 1024 bytes / framesize 4
  (256 samples). Buffer is a real 1024-byte local in `main`, matching the
  caller at `:1658`.
- Build modes: `plain`, `asan` (`-fsanitize=address -fno-stack-protector`),
  `nossp` (`-fno-stack-protector`, no ASan) for gcc and clang++ at `-g -O0`.

## Negatives and observed limits

- `small` is clean in both trees and all modes; no false ASan report.
- Plain-build `edge` (4 bytes past) returns normally in this layout: the store
  lands in padding after the buffer, not on the canary. The glibc canary is
  hit only by the full `attack`, and clang's plain `attack` reports a fatal
  stack fault instead of the gcc canary message. Both faults are recorded as
  observed, not as separate vulnerabilities.
- No-canary `attack` segfaults (the 1020-byte store reaches the saved frame);
  it is not a clean-return payload.
- Rung 4 chosen bytes were observed with gdb at the first out-of-bounds
  store, not in a post-return exploit path. The written value is a float bit
  pattern, not pointer-derived; no pointer or instruction-pointer control.
- At W173 no witness replay existed; witness #2942 later graded the
  direct-call evidence ESTABLISHED at the labeled rungs 1-4 only, explicitly
  NOT rung 5. Advisory file-path reachability and the RCE claim remain UNKNOWN.

## Real-caller harness (W179, 2026-11-23)

- Provisioning: SDL3 `release-3.2.4` tarball
  `deps/SDL3-release-3.2.4.tar.gz`, SHA-256
  `0fc1d23e225e2a098976571bf5d62b6d81e0ae84ff3d82a35a3d19ab04d07e5c`,
  from <https://github.com/libsdl-org/SDL/archive/refs/tags/release-3.2.4.tar.gz>.
  Built headless with `-DSDL_UNIX_CONSOLE_BUILD=ON -DSDL_SHARED=ON`, X11,
  Wayland, audio backends, joystick/haptic, video and render disabled; output
  `deps/SDL-release-3.2.4/build/libSDL3.so`. Fetch only, no external probe.
- Verbatim pinned slices with `#line` mapping: types `:41-230`, channel-mask
  helper `:828-843`, `ParseFMT` `:845-978`, `FetchXLaw`/wrappers `:750-772`
  and the caller `:1654-1679` (fixed tree `:1666-1691`). The generated driver
  is `harness/realcaller/real-driver-{vuln,fixed}.cpp`.
- Lab code: conversion LUT arrays with chosen bit pattern `0x5a5a5a5a`,
  sibling fetcher stubs referenced by verbatim `ParseFMT`, synthetic WAV
  fmt/data bytes, seekblock and driver main. Real SDL3 IO, real `ParseFMT`
  framesize setup and real `SDL_CreateAudioStream`/`SDL_PutAudioStreamData`.
- Scenarios: `safe` 8-byte A-law data; `edge` 256 bytes A-law; `ulaw` 256
  bytes mu-law; `badfmt` 4-byte fmt chunk (parser rejects); `pcm8` PCM_CODE
  (dispatch to sibling fetcher, `decoded_framesize=1`). 12 binaries:
  g++/clang++ x vuln/fixed x plain/asan/nossp.
- `cd lab/frontier/sdlmixer2shell/harness/realcaller && ./run.sh && ./check.sh`
  → `PASS=96 FAIL=0`, trace
  `934e83379c7b6d771269a96035a54480a9c5ab9dcaf5a169db6a6916ce2160c0`.
  ASan reports `WRITE of size 4` at pinned `:759` via `FetchALaw:771` or
  `FetchULaw:766` and caller `:1668`; fixed-tree and negative runs are clean.
  gdb on `g++-vuln-nossp edge` at `:759 if i == 1`: LUT `0x5a5a5a5a`,
  `buffer+1020..1027 = ff 7f 00 00 5a 5a 5a 5a` (four chosen bytes at the
  first in-range OOB offset). Evidence under `harness/realcaller/evidence/`.
- Ceiling for this harness (superseded by the real-WAV scope below): no SDL_mixer build, real WAV file/full chunk dispatcher,
  decoder-owned consumer, socket/wire, pointer/IP control or command. Witness
  #3000 (W180) independently replayed this harness from a clean `git archive
  a8b9c91` with SDL3 rebuilt from the pinned tarball: PASS=96 FAIL=0 exact
  trace, fresh ASan `WRITE of size 4` at `:759` through `FetchALaw:771` /
  `FetchULaw:766` and caller `:1668`, LUT counterexample moved the four OOB
  bytes at `buffer+1024`, fixed/safe/badfmt/pcm8 controls clean; graded
  ESTABLISHED at rungs 1-4, NOT rung 5. Advisory file-path reachability and
  the RCE claim remain UNKNOWN.
- Sibling candidate screened out this wake for scope: CVE-2026-133274
  (THC-Hydra Set-Cookie negative `strncpy`, fix `6ab9ad8`) — tractable but a
  different target; not staged. Scout shortlist for later wakes: ThorVG
  GHSA-mw4c-w54x-248r (CVE-2026-123367), cjose GHSA-75r7-f5cv-g3wj
  (CVE-2026-53938), PJSIP GHSA-rfwg-w9gq-9mw2 (CVE-2026-57159).

## Real SDL_mixer build + WAV file (W180, 2026-11-23)

- Provisioning (fetch only): SDL_mixer `release-3.2.4` tarball
  `deps/SDL_mixer-release-3.2.4.tar.gz`, SHA-256
  `f2ea848ccdf2f394cd4973ee0f6c482e04511044695cccfd46bab6dcd7f780aa`, tag
  commit `72a81869b45e249e8e67102db4e98dd2441f05a1`; SDL3 `release-3.4.0`
  tarball SHA-256
  `9614b9696abc4597ffce6b888829dc6537ae500423474c342ac4a67222c5654c`, tag
  commit `a962f40bbba175e9716557a25d5d7965f134a3d3`. The extracted mixer
  `src/decoder_wav.c` hashes to the pinned vulnerable
  `b651a6c2225378c6d2407df75eb1ec6f30ace68893a621cf29fd2089cd2016fa`; the
  fixed control tree uses pinned
  `b930672ee9ceaaea46ed2e8a3251ea3207ebcfa7366e1e7c8e851e40d13d9ca3`. Exact
  hashes in `deps/SDL_mixer.sha256` and `deps/SDL3-3.4.0.sha256`.
- The mixer declares SDL >= 3.4.0 (`CMakeLists.txt:13`); the lab's SDL3 3.2.4
  lacks `SDL_ALIGNED`, `SDL_PROP_AUDIOSTREAM_AUTO_CLEANUP_BOOLEAN` and
  `SDL_PutAudioStreamDataNoCopy`. Exact failed build retained in
  `evidence/build-vuln-asan-sdl3.2.4-failed.log`; final builds use headless
  SDL3 3.4.0, clang ASan (vuln/fixed) and a no-SSP plain build for gdb.
- Lab code: `harness/realwav/{realwav_driver.c,craft_wav.py,gdb-realwav.cmd}`;
  WAV files and all logs under `harness/realwav/evidence/`. No external probe.
- Result: crafted on-disk A-law/mu-law WAV with a 256-byte data chunk reaches
  pinned `:759` through real `MIX_DecodeAudio` and through
  `MIX_LoadAudio`/`MIX_PlayTrack` on the SDL dummy-audio thread; ASan
  `WRITE of size 4` at `:759` via `FetchALaw:771`/`FetchULaw:766` and
  `WAV_decode:1668`, `buffer [32,1056)` at `:1658`, first detected access at
  frame offset 1180. Fixed tree and safe/badfmt/pcm8 controls clean. Full
  commands, WAV layout and per-case logs: `harness/realwav/REALWAV.md`.
- gdb no-SSP: first store `i=255` (LUT `0x3d8c0118` from file byte 148) at
  `buffer+2040`; at `i=1` LUT `0xbae001c0` from byte 86, `buffer+1020..1027 =
  00 00 00 00 00 04 00 00`, real `WAV_decode` saved RIP at `buffer+1128`
  changed from `0x0000555555560a60` to `0xbca40148bcac0158` and locals garbage.
  The eight bytes are two LUT-selected float bit patterns, not a chosen
  address: corrupted control-flow state, not pointer/IP control.
- LUT pointer image (derived from pinned `SDL_mixer.c:3303-3359`, float32 bit
  patterns verified against the two gdb LUT words): all 65536 ordered A-law
  pairs are non-canonical as u64; mu-law yields 512 canonical pairs, all with
  high word `0x00000000` (max `0x00000000bf7af9f6`), none with high word
  `0x00005555` or `0x00007f..`. The corrupted saved RIP
  `0xbca40148bcac0158` is exactly
  `MIX_alawToFloat[payload[28]]<<32 | MIX_alawToFloat[payload[27]]`, so file
  bytes choose among LUT words but cannot choose a usable address. Derived
  negative, not a witness verdict.
- Ceiling: real build, real WAV, real decoder callbacks, but no wire/request
  input, attacker-chosen pointer, instruction-pointer control, benign marker
  or command. Author-observed only; witness replay requested on tape #3053.
  Advisory RCE and network reachability remain UNKNOWN; rung 5 not attempted.

## Loopback-wire reachability (W181, 2026-11-23)

- Lab code: `harness/realwav/wire_driver.c` binds `INADDR_LOOPBACK`, accepts
  one TCP connection, reads up to 4096 bytes and feeds them to
  `SDL_IOFromMem` → `MIX_CreateAudioDecoder_IO` / `MIX_DecodeAudio` or
  `MIX_LoadAudio_IO` / `MIX_PlayTrack`. WAV files, SDL3 and mixer builds are
  the same committed artifacts as the W180 section; no source or WAV changes.
- Result: a Python client sends the committed 300-byte `alaw256.wav` to
  127.0.0.1:19442; vulnerable ASan reports `WRITE of size 4` at pinned `:759`
  via `FetchALaw:771` → `WAV_decode:1668` → `MIX_DecodeAudio:3190`,
  `buffer [32,1056)`, frame offset 1180. Mu-law decode
  (`wire-vuln-decode-ulaw256.out`, `FetchULaw:766`) and dummy-audio play
  (`wire-vuln-play-alaw256.out`, `DecodeMore:306` → `TrackGetCallback:381`,
  thread T1) reproduce it. Fixed decode/play rc=0 (`got=1024`); 52-byte
  `alaw8` clean; `badfmt_256` parser-rejected with no ASan report. Seven
  `wire-*.out` logs plus two built drivers are in `harness/realwav/evidence/`.
- Ceiling: this is wire *bytes* into a lab listener, not a network-facing
  SDL_mixer consumer. No chosen pointer/IP, command or observed side effect
  beyond the sanitizer report. Rungs 1-4 only, author-observed, unwitnessed;
  advisory RCE and real network reachability remain UNKNOWN.

## Unmodified upstream sample and sibling surface (W182, 2026-11-23)

- Provisioning only: upstream issue #907 and PR #910 were read via the GitHub
  API; PR #910 names
  `https://www.mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/Samples/AFsp/M1F1-Alaw-AFsp.wav`
  as its reproducer. The file was fetched as a reference and stored unmodified
  at `harness/realwav/evidence/M1F1-Alaw-AFsp.wav` (47210 bytes, SHA-256
  `cfbc1821b7dd3d288d4223859c454d28065f4fbf23eabcdc77a13166a61fd37f`). No
  external system was probed.
- Real 3.2.4 drivers: unmodified stereo A-law WAV gives `channels=2
  framesize=8`; `FetchXLaw` still takes `length = buflen/4 = 256` from pinned
  `:752-756`, so vulnerable decode/play both report ASan `WRITE of size 4` at
  pinned `:759`, while fixed decode/play return rc=0 with `got=4096`. Four logs
  and the sample are in `evidence/UPSTREAM.sha256`. Rungs 1-4 only,
  author-observed, unwitnessed; no pointer, marker or command.
- Sibling surface seen but NOT staged or tested here: the pinned vulnerable
  tarball's `src/decoder_aiff.c:86-97` carries the same doubled-stride line at
  `:93`; upstream maintainer fixed it in commit
  `34486847a607540ce9ef5fbe20979c7140bf8c82` (2026-11-04), and a separate
  advisory exists (CVE-2026-122329 / GHSA-782g-354j-4465). This target's
  charter covers the WAV advisory GHSA-7qqc-5rvj-wqqw only; the AIFF route is
  reported to the operator as a candidate, with no lab work done on it.

## Verification

`cd lab/frontier/sdlmixer2shell/harness && ./run.sh && ./check.sh` →
`PASS=134 FAIL=0`, trace
`f81697d9247807c1bc254ed1ce51a9d966ec807b6256713177180aa5f44f98e1`
identical across three runs.

## Unmodified upstream CLI program (W183, 2026-11-24)

- Upstream `test/testmixer.c` from both pinned mixer trees is compiled
  byte-unmodified: CLI filename → `MIX_LoadAudio` → `MIX_PlayTrack` with the
  dummy audio device. Lab code is limited to `harness/realwav/testmixer-headless.c`
  (masks `SDL_INIT_VIDEO`; the lab SDL3 3.4.0 build has no video backend) and
  the compile-time rename `-DSDL_Init=testmixer_headless_Init` applied only to
  the upstream translation unit. No mixer source, build flag or WAV changes.
- `harness/realwav/testmixer-replay.sh` rebuilds both binaries and checks
  four cases: vulnerable A-law and mu-law rc=1 with ASan `WRITE of size 4` at
  pinned `:759` through `FetchALaw:771`/`FetchULaw:766` → `WAV_decode:1668` →
  `DecodeMore:306` → `TrackGetCallback:381` on the audio thread, frame offset
  1180; vulnerable 8-byte A-law and fixed A-law rc=0 with no sanitizer report.
  `PASS=6 FAIL=0` on two consecutive runs.
- Ceiling: an upstream CLI program, not a request-facing consumer. The shim
  affects only video initialization; there is no wire input in this slice, no
  chosen pointer/IP, marker or command. Grade stays rungs 1-4,
  author-observed and unwitnessed; witness replay remains owed/queued.
