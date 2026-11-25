# W18 — changed allocation state: still no live code pointer (2026-11-25)

## Question and decision rule

W15 swept the full negative-glyph write window `encs-131072 .. encs-4` in the
two real headless builds and found no live code pointer at the vulnerable
store, but limited that negative to "this import state". This wake tests the
open alternative named in `FUNCTIONPTR.md`: a PCF import *before* the
truncated one changes the heap state. If a code pointer then appears in the
window and a later call reaches it, that would widen rung 4; otherwise the
negative extends to this state too.

Decision rule: break at `fvimportbdf.c:1751 if glyph < 0`, require the same
`glyph=-1, i=3` store, prove `encs` moved against the W15 baseline, and scan
every aligned 8-byte word in the window for a value in the build's `r-xp`
mapping. Keep a positive only if the bytes are a real function pointer in a
live object that the process later calls.

## Inputs and method

`w18-import.ff`: `New()`, `Import(complete.pcf)`, then
`Import(truncated.pcf)`. The first import is the in-bounds control PCF already
pinned in `REPLAY.md`; the second is the unchanged pinned attack PCF. The
breakpoint therefore fires on the second `PcfReadEncodingsNames()`, after the
first import has allocated and freed its own PCF objects.

`replay-w18.sh` checks both existing builds (`build-plain`, `build-nopie`),
regenerates `w18-import.ff` and the two gdb command files, dumps 131072 bytes
from `encs-131072` to `encs`, reuses `scan-w15.py` against each build's `r-xp`
line from `info proc mappings`, and calls `check-w18-alloc.py` to compare the
`encs` address with W15's single-import transcript.

## Measured result (live tree, 09:2xZ)

| build | W15 `encs` | W18 `encs` | delta | scan |
| --- | --- | --- | --- | --- |
| default PIE (`build-plain`) | `0x555555c48240` | `0x555555c48970` | `+0x730` | `CAND_COUNT 0`, `RESULT NONE` |
| local non-PIE (`build-nopie`) | `0xa92030` | `0xa92760` | `+0x730` | `CAND_COUNT 6`, `RESULT ASCII_ONLY` |

Both breakpoints report `glyph=-1 i=3`. The non-PIE candidates are the same
short printable fragments as W15 (`.mo`, `nis`, `ell`, `ENT`, `ell`, `ENT`),
not pointers. `replay-w18.sh`: 7/7 checks, rc 0, final line
`REPLAY_W18_OK: 7 checks, 0 failed`. Normalized hashes:

```
fb1b4ea80db30fa4c3a0cd79e1abc94e4f7c4b381af2fdc48290bebf5bd6df7a  alloc-w18.out
971214f7bf5ecf59499721e15787a3d72dde8433f5fac4cad14adafafc7b8e4d  scan-w18-nopie.out
313c4ce473482b43b8e7d2e0dadc4c6a6d28896b3c36de94a7efde1f9e75db76  scan-w18-pie.out
```

Raw dump hashes (volatile heap bytes; recorded for provenance only):
`3a45cfb4…641664c8` (non-PIE), `e6079d07…9bbe468e` (PIE).

## Clean-archive receipt (09:32Z)

`git archive 42e0f33f lab/frontier/fontforge2shell` into
`/tmp/ff2s-w18-clean-I5iWW8`, with the pinned tarball copied in, rebuilt
both offline builds and the W15 baseline, then ran `sh replay-w18.sh`:
`REPLAY_REAL_OK: 17/17`, `REPLAY_NONPIE_OK: 15 checks, 0 failed`,
`REPLAY_W15_OK: 6 checks, 0 failed`, `REPLAY_W18_OK: 7 checks, 0 failed`,
script chain rc 0. The PIE scan hash is byte-identical to the live tree
(`313c4ce4…6a2176094`, i.e. no candidates in either). The non-PIE scan has
three printable fragments instead of six (`8e08198c…60aca650de`), and the
`encs` delta is `+0x7b0` instead of `+0x730`
(`0x555555c48430` -> `0x555555c48be0`, `0xa92220` -> `0xa929d0`) — the same
build-path sensitivity W9 and W15 recorded for this headless path. Both
transcripts still report `glyph=-1 i=3`; the decision is unchanged.

## Disposition

The changed allocation state still puts no live code pointer in the negative
glyph write window in either build. No branch at a chosen address, no marker,
no command, no r5, no grade change. This extends W15's negative from one
import state to one specific two-import state; it does not close other heap
states, later-created objects, other FontForge builds or a GUI process. A
real function-pointer candidate followed by an observed call/branch at a
chosen address would change the decision and goes to `witness`.
