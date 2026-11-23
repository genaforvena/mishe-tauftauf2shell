# Frontier brief: SDL_mixer `FetchXLaw()` doubled output stride (sdlmixer2shell)

**STAGED 2026-11-23 W173; advanced W179** — this brief, a direct-call rung-1..4 harness and a
registered two-pane window exist. Clean git-archive replay at commit `7e7f1d6`
(65 files, 4/4 pins, 12 binaries, exact trace) is in
`lab/frontier/sdlmixer2shell/REPLAY.md`. Byte-exact pins and hashes:
`lab/frontier/sdlmixer2shell/PINS.sha256`; harness provenance, stubs, negatives
and commands: `lab/frontier/sdlmixer2shell/PROVENANCE.md`. Window 123, inner
socket, two live panes verified at 18:26Z; registry 124/124, seed wall
`.mishe-tauftauf/walls/sdlmixer2shell.md`, staging DM #2907. Operator admission
and independent witness replays are complete: witness #2942 graded ESTABLISHED
at the labeled direct-call lab scope, rungs 1-4 only, explicitly not rung 5;
witness #3000 (W180) graded the W179 real-caller / from-source SDL3 scope
ESTABLISHED at the same rungs, explicitly not rung 5.

## 1. Verified ground truth

- Source claim: GHSA-7qqc-5rvj-wqqw / CVE-2026-122328, GitHub Advisory
  Database, Unreviewed, High CVSS4 8.5
  (`CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`), CWE-121,
  published 2026-11-05; origin issue libsdl-org/SDL_mixer#907, PR #910. It
  describes a stack-based buffer overflow in `FetchXLaw()` decoding A-law or
  mu-law WAV, with claimed code execution. The RCE claim is **not reproduced
  here**. The AIFF sibling CVE-2026-122329 / fix `3448684` is a separate
  candidate and is not mixed into this target.
- Affected: SDL_mixer 3.1.2 through 3.2.4 (advisory prose). The pinned
  vulnerable source is tag `release-3.2.4`, raw
  `src/decoder_wav.c` SHA-256
  `b651a6c2225378c6d2407df75eb1ec6f30ace68893a621cf29fd2089cd2016fa`.
- Fix: commit `df966f698e18ae849bd92796a26311e79c555718` (2026-10-31,
  `decoder_wav.c: fix stack overflow in FetchXLaw()`); parent
  `8d30c639eb30014cd2916f505b439f91971a4ec3`. Fixed-tree raw source SHA-256
  `b930672ee9ceaaea46ed2e8a3251ea3207ebcfa7366e1e7c8e851e40d13d9ca3`.
  No `release-3.2.5` tag exists at fetch time (raw URL 404), so the numeric
  fixed version is **UNKNOWN**. Advisory version fields are Unknown too.
- No external probe. Advisory, commit, patch and source fetches were
  provisioning only.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; pinned bytes live in
`lab/frontier/sdlmixer2shell/src/` and are sliced verbatim under `#line` by
`harness/run.sh`.

```
int length = buflen;                                             // :752
length = (int) SDL_ReadIO(tdata->io, buffer, (size_t)(length/4)); // :753
if (length % tdata->adata->framesize != 0) length -= ...;         // :754-756
float *out = (float *) &buffer[(length - 1) * 4];                 // vuln :757
for (int i = length - 1; i >= 0; i--) out[i] = lut[buffer[i]];    // :758-759
return length * 4;                                               // :761
```

`out` is already offset by `(length-1)*4` bytes, then indexed as a `float *`
with stride 4 again, so the last store lands at byte `8*length-4` in a buffer
the real caller declares as `Uint8 buffer[1024]` (pinned `:1658`, `buflen`
1024 at `:1659`, fetch call at `:1668`). With a full 256-sample read the
stores span bytes 0..2043: 1020 bytes past the 1024-byte stack buffer. Fix
`df966f6` replaces the pointer line with `float *out = (float *) buffer;`,
keeping the loop and the LUT index untouched.

## 3. Cheapest local experiment

Slice pinned lines `750-762` from both trees into a driver with lab stubs for
`Uint8`, `WAV_TrackData`, `SDL_ReadIO` (delivers a fixed sample count from a
lab byte array) and a 256-entry conversion LUT whose 32-bit bit pattern is
chosen by the driver (`0x5a5a5a5a`). Scenarios: `small` (4 samples, in-bounds),
`edge` (129 samples, framesize 1 — exactly one 4-byte store at `buffer+1024`),
`attack` (256 samples, framesize 4 — 1020 bytes past). Build g++ and clang++
in `plain`, `asan` and `nossp` (no stack canary, for post-store byte
inspection) modes: 12 binaries. From `lab/frontier/sdlmixer2shell/harness/`:
`./run.sh` verifies four pins and builds; `./check.sh` runs 36 invocations plus
a gdb chosen-byte probe and prints a normalized trace hash.

## 4. Observed evidence (W173, direct-call harness)

- Rung 1 / determinism: `small` returns `rc=64` with `buffer[1023]=11`
  (untouched) in all 12 binary/scenario combinations.
- Rung 2: `edge` returns `rc=516` (`129*4`); `attack` returns `rc=1024`
  (`256*4`) — the fetch loop completes while writing past the object. All
  fixed-tree runs return the same codes with every in-bounds byte written to
  the chosen value and no sanitizer or canary report.
- Rung 3: gcc and clang ASan both report `stack-buffer-overflow`, `WRITE of
  size 4`, top frame `decoder_wav.c.vuln:759`. For `edge` ASan names `buffer`
  `[32,1056)` and `Memory access at offset 1056 overflows this variable` —
  exactly 1024 bytes into the 1024-byte object.
- Rung 4: gdb on `g++-vuln-nossp edge`, breakpoint at pinned `:759`, first hit
  `I=128`, `LUT=5a5a5a5a`, `OUT = buffer+512`; after stepping the store, bytes
  at `buffer+1020..1027` are `11 11 11 11 5a 5a 5a 5a` — chosen bytes at the
  chosen first out-of-bounds offset. Plain `attack` hits the glibc stack
  canary (`stack smashing detected` on gcc, fatal stack fault on clang);
  the no-canary `attack` build segfaults, preserved as an edge/negative.
- `harness/check.sh`: **134 PASS / 0 FAIL** on three identical runs, trace
  `f81697d9247807c1bc254ed1ce51a9d966ec807b6256713177180aa5f44f98e1`.

## 4b. Real-caller replay (W179, 2026-11-23)

`lab/frontier/sdlmixer2shell/harness/realcaller/` compiles verbatim pinned
slices for the WAV fetch-dispatch types (`:41-230`),
`StandardSDLWavChannelMask` (`:828-843`), `ParseFMT` (`:845-978`),
`FetchXLaw`/`FetchULaw`/`FetchALaw` (`:750-772`) and the real caller's fetch
block (`:1654-1679`; fixed tree `:1666-1691`). SDL3 `release-3.2.4`
(tarball SHA-256 `0fc1d23e...`, pinned in `deps/SDL3.sha256`) supplies real
`SDL_IOFromMem`/`SDL_ReadIO`, real `ParseFMT` sets `framesize=1` and
`decoded_framesize=4` from a synthetic mono 8-bit A-law/mu-law fmt chunk, and
the caller consumes through real `SDL_CreateAudioStream`/`SDL_PutAudioStreamData`.
The conversion LUT arrays and the seekblock/tooling around the caller remain
lab code; there is no SDL_mixer build or full WAV chunk dispatcher.

- gcc and clang ASan on `edge` (256-byte A-law data payload) and `ulaw`
  report `stack-buffer-overflow`, `WRITE of size 4`, top frame
  `decoder_wav.c.vuln:759`, then `FetchALaw:771` / `FetchULaw:766` and real
  caller `:1668`. ASan places `buffer` at `[32,1056)` in `RealGetAudio` and
  the access at offset 1180 (124 bytes past the object at the first reported
  store, `i=255`; later stores walk back toward offset 1024).
- gdb on `g++-vuln-nossp edge`, breakpoint `:759 if i == 1`, reads `I=1`,
  `OUT=buffer+1020`, LUT bit pattern `0x5a5a5a5a`; after the store
  `buffer+1020..1027 = ff 7f 00 00 5a 5a 5a 5a` — four chosen bytes at the
  first in-range out-of-bounds offset, reached through the real dispatch.
- Fixed-tree ASan runs are clean with `rc=1`, all scenarios; `safe` (8-byte
  data), `badfmt` (4-byte fmt chunk, parser rejects) and `pcm8` (PCM dispatch,
  `decoded_framesize=1`, no `FetchXLaw`) are negatives with no false ASan
  report.
- `harness/realcaller/check.sh`: **PASS=96 FAIL=0**, trace
  `934e83379c7b6d771269a96035a54480a9c5ab9dcaf5a169db6a6916ce2160c0`
  over 12 binaries x 5 scenarios; evidence in `harness/realcaller/evidence/`.

- Independent replay: witness #3000 (W180) rebuilt SDL3 3.2.4 from the pinned
  tarball in a clean `git archive a8b9c91` and reproduced PASS=96 FAIL=0 with
  the exact trace; a LUT counterexample (`0x5a5a5a5a` → `0x37373737`) moved the
  four OOB bytes at `buffer+1024`, and fixed/safe/badfmt/pcm8 controls stayed
  clean. Graded ESTABLISHED at rungs 1-4, explicitly NOT rung 5.

## 5. Next distinct rung move

The real-caller slice above is now measured; the sample count comes from real
SDL IO and real `ParseFMT`, not a lab stub. The next distinct slice is a real
SDL_mixer build fed an actual WAV file, to learn whether a crafted fmt/data
chunk reaches `FetchXLaw()` with attacker-controlled length and what adjacent
object the 1020-byte store hits. Beyond that, a consumer path, socket/wire
delivery and pointer/IP control remain UNKNOWN. No pointer-sizing primitive
was demonstrated: the written value is a float bit pattern chosen as a marker,
not an address read from the input.


## 6. Honest ceiling

Direct call and real-caller slice, both against pinned source bytes, with a
1024-byte stack buffer matching the real caller. The real-caller harness uses
real SDL3 IO, real `ParseFMT` and a real SDL audio stream, but the conversion
LUT and the seekblock/tooling are lab code. No SDL_mixer build, no real WAV
file or full chunk dispatcher, no decoder-owned consumer path, no socket or
wire, no pointer/IP control, no command execution. Witness #2942 graded the
direct-call evidence ESTABLISHED at rungs 1-4 only; witness #3000 (W180)
independently replayed the real-caller harness from a clean archive with SDL3
rebuilt from the pinned tarball and graded it ESTABLISHED at rungs 1-4,
explicitly NOT rung 5. Advisory file-path reachability and the claimed code
execution remain **UNKNOWN**. Rung 5 not attempted.
