# W15 — no live code pointer in the negative-glyph write window (2026-11-25)

## Question and decision rule

W14 reached a chosen **mapped address** in a non-PIE lab build, but only as
`BDFChar.bitmap` data dereferenced at `sfd.c:1671`. This wake asks the next
question: can the same file-chosen negative write reach a **live function
pointer** in the real process, so that a later call would branch to a chosen
address? That would be a rung-4 widening (a branch at a chosen mapped
address), still not r5 without a benign marker or command.

Decision rule: break at `fvimportbdf.c:1751` with `glyph<0`, dump the whole
address range reachable by a negative 16-bit glyph, and look for 8-byte
aligned words whose value lies in the executable's `r-xp` mapping at that
moment. Keep a positive only if a candidate is a real code pointer in a live
object that the process later calls; otherwise record a negative and leave
the grade unchanged.

## Source-bound reach

`fvimportbdf.c:1749` reads `glyph = getformint16(...)`, a signed 16-bit
value, and `:1750` accepts every `glyph != 0xffff && glyph < glyphcnt`.
After truncation the file controls one index in `-32768..-1`, so the single
store at `:1751` reaches byte offsets `encs-131072 .. encs-4` (later EOF
indices are `-1` and hit the `encs` chunk header). W14's `-50` write is
`encs-200`, inside this window.

## Method

`replay-w15.sh` runs both existing headless builds on pinned
`truncated.pcf`:

1. `gdb -q -batch -x gdb-w15-<mode>.cmd ./<build>/bin/fontforge`, breaking
   at `fvimportbdf.c:1751 if glyph < 0` and dumping
   `(char*)encs-131072 .. (char*)encs` into `/tmp/ff2s-w15-<mode>.bin`,
   with `info proc mappings` in the same transcript.
2. `scan-w15.py` parses the build's `r-xp` mapping from that transcript and
   reports every aligned 8-byte word in the dump whose value falls in it.
   Each candidate is printed with its raw bytes so ASCII fragments can be
   separated from pointers.

- Default PIE build (`build-plain`, r-xp mapping observed in this run
  `0x5555555bc000..0x55555593c000`): `CAND_COUNT 0`, `RESULT NONE`.
- Local non-PIE build (`build-nopie`, r-xp mapping observed in this run
  `0x405000..0x785000`, `.text` section `0x407010..0x7847c6`):
  `CAND_COUNT 6`, `RESULT ASCII_ONLY`. All six are ASCII string fragments,
  not code pointers — raw bytes at the candidate offsets read
  `.mo\0`, `nis\0`, `ENT\0`, `ell\0`, `DESC\0`, `ASCE\0` (from
  `FontForge.mo`, gettext strings, `FONT_DESCENT`, `truncated.pcf` and
  `FONT_ASCENT`). gdb's `info symbol` resolves their numeric values to
  arbitrary nearby `.text` symbols, which is why the byte context matters.

`sh replay-w15.sh` asserts 6/6 PASS and ends `REPLAY_W15_OK: 6 checks, 0
failed` with rc 0. Receipt on this host (2026-11-25 04:4xZ):

The two raw dumps contain heap addresses and are not byte-stable across
runs (first receipt: `cc9560da…d42d86` non-PIE, `934edf76…31fad00e` PIE;
after rerun: `ecfeaacc…651766`, `802f76d1…48ed4a75`). The normalized scan
outputs are stable across both runs:

```
a5f2d77ad9364a7761aa4fe2a25888110b8479be89395e065a3330622fb8d270  scan-w15-nopie.out
313c4ce473482b43b8e7d2e0dadc4c6a6d28896b3c36de94a7efde1f9e75db76  scan-w15-pie.out
```

Build prerequisites: `sh replay-real.sh` (PIE tree) and
`sh replay-nonpie.sh` (non-PIE tree) first; the scan script itself builds
nothing and needs no network or loopback service.

## Disposition

No function pointer is reachable in the negative-glyph window at write time
in either measured build. W14's mapped address stays a data pointer. No
branch at a chosen address, no marker, no command, no r5, grade unchanged.
The negative is limited to these two headless builds, this import state and
the instant of the vulnerable store. Another build, another allocation
state (e.g. a PCF that changes the heap before `encs`), or a later-created
object could differ; those remain UNKNOWN. A real code pointer candidate
followed by an observed call/branch at a chosen address would change the
decision and goes to `witness`.
