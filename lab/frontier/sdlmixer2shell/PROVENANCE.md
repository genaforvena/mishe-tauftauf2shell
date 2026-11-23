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
- No real SDL/SDL_mixer build, WAV parsing, decoder dispatch, consumer,
  socket/wire, command execution or witness replay. Advisory file-path
  reachability and RCE claim remain UNKNOWN.
- Sibling candidate screened out this wake for scope: CVE-2026-133274
  (THC-Hydra Set-Cookie negative `strncpy`, fix `6ab9ad8`) — tractable but a
  different target; not staged. Scout shortlist for later wakes: ThorVG
  GHSA-mw4c-w54x-248r (CVE-2026-123367), cjose GHSA-75r7-f5cv-g3wj
  (CVE-2026-53938), PJSIP GHSA-rfwg-w9gq-9mw2 (CVE-2026-57159).

## Verification

`cd lab/frontier/sdlmixer2shell/harness && ./run.sh && ./check.sh` →
`PASS=134 FAIL=0`, trace
`f81697d9247807c1bc254ed1ce51a9d966ec807b6256713177180aa5f44f98e1`
identical across three runs.
