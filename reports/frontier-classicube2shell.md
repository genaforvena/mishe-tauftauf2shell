# Frontier brief — ClassiCube PNG decode (SCREENED OUT, rungs 1–3 observed)

**Decision (2026-11-21 17:22Z): SCREEN OUT of the X2Shell chosen-byte lane on
class fit, not on exploitability.** The consumer is a ClassiCube **game client**
fetching a skin or texture pack from a malicious multiplayer server (CVSS
`UI:P`/`UI:R`), not a server-side listener; frontier precedent screens out
purely client-side consumers (reSIProcate). Raw primary claims and the tagged
fix were verified, and a local ASan harness reached rungs 1–3 for both CVEs.
Rung 4 was NOT reached. Fixed side is **tagged release 1.4.0** (standing #6).
No window and no admission requested; the operator may broaden the class.

## Verified ground truth

- **CVE-2026-133307** — MITRE CVE API,
  <https://cveawg.mitre.org/api/cve/CVE-2026-133307>, state PUBLISHED,
  published 2026-11-19T16:32:29.937Z, updated 2026-11-20T20:19:06.880Z.
  `Png_Decode` in `src/Bitmap.c`, heap OOB write from a **duplicate IHDR**
  chunk: the unreset `bufferIdx` underflows the remaining-space calculation so
  following IDAT decompresses past the heap buffer. CVSS 4.0 8.7 HIGH
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`;
  CVSS 3.1 8.8 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`; CWE-787.
- **CVE-2026-133308** — MITRE CVE API,
  <https://cveawg.mitre.org/api/cve/CVE-2026-133308>, state PUBLISHED,
  published 2026-11-19T16:32:29.255Z. `Png_Reconstruct` AVERAGE/PAETH on a
  **zero-width PNG** writes past the heap buffer. CVSS 4.0 5.3 MEDIUM
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N`;
  CVSS 3.1 5.4 MEDIUM `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L`; CWE-787.
- **Affected/fixed**: all versions `< 1.4.0` affected, `1.4.0` unaffected in
  both MITRE records. Tarball sha256: 1.3.9
  `5bb62dbb3ad27e1fbb09842f0cb1f4802b2686553b017e0b67ce09b36f908246`,
  1.4.0 `8f249f435fcce4dac083664c43077073c32c5382a485de3bcd81badf1816143f`.
  GitHub release API for tag `1.4.0`: published 2026-11-18T20:52:20Z, notes
  "There is a vulnerability in earlier versions of ClassiCube ... Fixed:
  Vulnerabilities in PNG decoding".
- **Patch**: commit `c461fa759f218e3c6bda4642b9af79a98dc84a43`, commit date
  2026-11-18T20:39:04Z, message "Fix some invalid PNGs still being parsed
  ... Cyrex". Raw `.patch` sha256
  `3e0b9b1933ddb8db5cdb33589d3d9cc059c027ce7ed5fa11f13c0d74eb6ba6ba`.
  Fixed tag `1.4.0/src/Bitmap.c` sha256
  `7b37f36ce1b73c105e5a1f873c58c50fc2f5b86e2821a76ca0902b42b93b424c`.
- **Third-party claim** (not independently trusted): VulnCheck advisories
  linked from both MITRE records repeat the same two mechanisms.

## Source-bound mechanism (raw pinned bytes)

Pinned `1.3.9/src/Bitmap.c` (sha256
`de9d89d46c9f5d3818fb5d2480ba67831f2c3d96f2c51998d21fa68b6586d5d6`):

- `Png_Decode` at `:377`; IHDR branch `:434–464`. Width/height are checked only
  for `< 0` or `> PNG_MAX_DIMS` at `:442–443` — **zero passes**.
- `:459` allocates `height * max(scanlineBytes, width*4)`; `:463` sets
  `bufferLen = height * scanlineBytes`. A second IHDR reassigns `data` and
  `bufferLen` without freeing the old buffer or resetting IDAT state.
- IDAT branch `:518–583`: `:529` computes `left = bufferLen - bufferIdx` in
  `cc_uint32`; `:531` inflates into `&data[bufferIdx]` with that length. If a
  prior IDAT advanced `bufferIdx` past a later, smaller IHDR's `bufferLen`,
  `left` wraps and the inflate destination runs past the new allocation.
- `:457` sets `scanlineBytes = scanlineSize + 1`. With `width == 0` this is 1,
  yet `Png_Reconstruct` AVERAGE (`:171–178`) and PAETH (`:180–197`) each begin
  with `for (i = 0; i < bytesPerPixel; i++) { line[i] += ...; }` — four bytes
  for RGBA written into one byte per row.

The patch adds exactly two guards on that path: `width <= 0 || height <= 0`
→ `PNG_ERR_TOO_SMALL`, and `if (bmp->scan0) → PNG_ERR_MULTI_HDRS`. Both are
present in tagged `1.4.0/src/Bitmap.c` at `:442` and `:451`.

## Honest rung-4 feasibility assessment

- **Class fit — WEAK, decisive for screen-out.** Both CVE records describe a
  malicious *server* feeding skins/texture packs to a *client*; the CVSS
  vectors require passive/user interaction. This plant's X2Shell lane targets
  memory-safety bugs in runtimes and web-facing **servers**. Accepting a
  client-side media decoder would broaden the charter beyond the operator's
  standing mandate; that call belongs to the operator.
- **Rung 1 — reproducible trigger: ESTABLISHED.** Deterministic PNG byte
  streams reach the real pinned `Png_Decode`; tagged 1.4.0 emits the two new
  error codes for the same inputs.
- **Rung 2 — observed state failure: ESTABLISHED.** `width=0` gives a 2-byte
  allocation against `scanlineBytes=1` and a four-byte AVERAGE/PAETH prefix
  write. Duplicate IHDR leaves `bufferIdx=1000` against a recomputed
  `bufferLen=15`; `left` wraps to `4294966311`.
- **Rung 3 — ASan-confirmed corruption: ESTABLISHED at the sink level.** Both
  paths fault the pinned decoder with real allocation stacks; exact frames
  and sizes below.
- **Rung 4 — demonstrated security impact: NOT REACHED.** The duplicate-IHDR
  write lands 985 bytes past a 15-byte allocation, i.e. in ASan redzone, not a
  live neighbour; the decompressed byte written there is zero in this input.
  No chosen byte in a live object, pointer control, control-flow diversion,
  marker execution or code execution was observed. RCE claims stay claims.

## Local experiment (offline, no network, no listener)

Harness `lab/frontier/classicube2shell/`: `harness.c` calls the **unmodified**
pinned `src/Bitmap.c`, `src/Deflate.c` and `src/Stream.c`; `stubs.c` supplies
only malloc/free, memcpy/memset, byte-order helpers and abort/logging — no
stub parses PNG or inflates data, so it cannot fabricate either primitive.
`-DCC_BUILD_MANUAL` plus `--gc-sections` drop unreachable platform-specific
code. Built with clang 18 `-fsanitize=address -g -O0` (`build.sh`), inputs
generated by Python stdlib zlib (`gen_inputs.py`, exact bytes and sha256 under
`inputs/`). Full provenance in `PROVENANCE.md`.

- **CVE-2026-133308**: `zero_width_avg.png` / `zero_width_paeth.png` (w=0,
  h=2, RGBA, filter 3/4 on row 1). Pinned 1.3.9: ASan heap-buffer-overflow at
  `Png_Reconstruct Bitmap.c:173` (AVERAGE) / `:183` (PAETH) ← `Png_Decode
  Bitmap.c:549`, 0 bytes after a **2-byte** region allocated at `Bitmap.c:459`.
  ASan labels the read-modify-write `READ of size 1`. Tagged 1.4.0: clean,
  `RESULT=0xCCDED074` (`PNG_ERR_TOO_SMALL`).
- **CVE-2026-133307**: `dup_ihdr_underflow.png` (IHDR 100×100, partial IDAT of
  a Z_SYNC_FLUSH zlib stream yielding 1000 bytes, IHDR 1×3, final IDAT).
  Pinned 1.3.9: ASan `WRITE of size 1` at `Inflate_Process Deflate.c:699` ←
  `Inflate_StreamRead Deflate.c:759` ← `Png_Decode Bitmap.c:531`, **985 bytes
  after a 15-byte region** allocated at `Bitmap.c:459` — the byte-level proof
  that `bufferIdx` was not reset. Tagged 1.4.0: clean,
  `RESULT=0xCCDED075` (`PNG_ERR_MULTI_HDRS`).

**Negatives preserved:** valid `benign.png` (NONE/UP) and
`benign_avg_paeth.png` (AVERAGE/PAETH) decode cleanly on both builds;
`zero_width_h1.png` (w=0, h=1) leaves `Png_Reconstruct` uncalled and is clean
on 1.3.9 (1.4.0 rejects at the header); an earlier duplicate-IHDR input with
an unbuffered zlib split produced no output bytes and did not trigger — the
SYNC_FLUSH variant above is the working trigger, not a substitute. Leak
detection is disabled because the decoder intentionally leaks the superseded
buffer on duplicate IHDR; irrelevant to OOB detection.

**Replay:** `cd lab/frontier/classicube2shell && bash run.sh /tmp/cc-replay`.
Two clean-outdir runs on 2026-11-21 gave **55 PASS / 0 FAIL**, identical trace
sha256 `e2ffd73365a944ef0b2f95de1cb7a1c5170caca6ed2bef33e16c6d30bd392cb3`
(PID, addresses and host paths excluded).

## What would change my mind

An operator decision to admit client-side media consumers into the X2Shell
family, or an observed chosen-byte overwrite of a live neighbour (not an ASan
redzone) through the duplicate-IHDR path.
