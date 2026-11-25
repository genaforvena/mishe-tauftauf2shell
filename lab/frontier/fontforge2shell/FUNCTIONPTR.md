# W15 — no live code pointer in the negative-glyph write window (2026-11-25)

## Question and decision rule

W14 reached a chosen **mapped address** in a non-PIE lab build, but only as
`BDFChar.bitmap` data dereferenced at `sfd.c:1671`. This wake asks the next
question: can the same file-chosen negative write reach a **live function
pointer** in the real process, so that a later call would branch to a chosen
address? That would be a rung-4 widening (a branch at a chosen mapped
address), still not r5 without a benign marker or command.

Decision rule as executed: break at `fvimportbdf.c:1751` with `glyph<0`,
dump the then-assumed negative range, and look for aligned words in the
executable's `r-xp` mapping. W26 corrected the range assumption; the dump
was a superset, so the observed bytes remain valid.

## Source-bound reach (corrected by W26)

`fvimportbdf.c:1749` reads `glyph = getformint16(...)`, but
`getformint16()` (`:1354-1363`) does **not** sign-extend. A complete
two-byte index is `0..65535`; EOF yields `-1`, and a present low byte with a
missing high byte yields `low-256` (`-256..-1`). The vulnerable guard
therefore accepts negative indices only in `-256..-1`, and the store at
`:1751` reaches `encs-1024 .. encs-4`. W14's `-50` write is `encs-200`,
inside that actual window. See `LATESTATE.md` for the two-build gdb
discriminator and the corrected all-executable-mapping later-state scan.

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

- Default PIE build (r-xp mapping in this run
  `0x5555555bc000..0x55555593c000`): `CAND_COUNT 0`, `RESULT NONE` in
  both the live tree and the clean archive.
- Local non-PIE build (r-xp `0x405000..0x785000`, `.text`
  `0x407010..0x7847c6`): `RESULT ASCII_ONLY` in both trees. Live:
  `CAND_COUNT 6` (`.mo`, `nis`, `ENT`, `ell`, `DESC`, `ASCE`); clean
  archive: `CAND_COUNT 5` (`nis`, `ell`, `ENT`, `ENT`, `ENT`). The exact
  count is build-path sensitive, like W9's consumer rc, because gettext
  string fragments move with the build path. No candidate in either tree
  is a code pointer: every one is a short printable string fragment.
  gdb's `info symbol` on those numeric values resolves to unrelated
  nearby `.text` symbols, so byte context is decisive.

`sh replay-w15.sh` asserts the invariant that survives that layout
change: both breakpoints reached, PIE `CAND_COUNT 0` / `RESULT NONE`,
non-PIE `RESULT ASCII_ONLY` with a bounded count (0..8), script rc 0 and
`REPLAY_W15_OK: 6 checks, 0 failed`. It first ran with an exact-count
assertion, which failed on the clean archive at 5 vs 6 (negative
preserved); the assertion now checks the path-independent invariant and
both trees pass 6/6. Raw dumps contain heap addresses and are not
byte-stable; the normalized scans are stable within each tree:

```
a5f2d77ad9364a7761aa4fe2a25888110b8479be89395e065a3330622fb8d270  scan-w15-nopie.out (live, 6 hits)
313c4ce473482b43b8e7d2e0dadc4c6a6d28896b3c36de94a7efde1f9e75db76  scan-w15-pie.out (both trees)
9042720820e44f8837a86afdff7a3b26d31f05e4592c11f3e03ad4d6a2176094  scan-w15-nopie.out (clean, 5 hits)
```

Build prerequisites: `sh replay-real.sh` (PIE tree) and
`sh replay-nonpie.sh` (non-PIE tree) first; the scan script itself builds
nothing and needs no network or loopback service.

## Disposition

No function pointer was observed in the bytes W15 scanned, and W26 found
none in the actual `encs-1024..encs` window at the measured surviving-free
later-consumer state when every executable mapping was included. W14's
mapped address stays data only. No branch at a chosen address, no marker,
no command, no r5, grade unchanged. The negative is limited to these
headless builds and measured states; another heap state that places a live
called pointer inside the actual 1 KiB window remains UNKNOWN. A real code
pointer candidate followed by an observed call/branch at a chosen address
would change the decision and goes to `witness`.

## W27 follow-up: called-pointer lane closed for these builds

`CALLEDPATH.md` measures the heap `Encoding` object at `encs-768`: its
`tounicode_func`/`fromunicode_func` slots (offsets 88/96) are NULL with no
assignment site, and a file-derived write of `0x414243` into the live
`tounicode` descriptor reaches `iconv(cd=0x414243)` but faults in glibc
`__gconv` at `gconv.c:45` before any indirect call. The chosen address is
dereferenced as data, not called. No branch at a chosen address; the
UNKNOWN in this disposition stays open only for GUI, other loaders, other
build configurations and second-stage overflows.
