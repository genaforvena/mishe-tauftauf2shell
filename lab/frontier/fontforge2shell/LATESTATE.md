# W25 — late-allocation state in the real builds (2026-11-25)

## Question and decision rule

W15/W18/W23/W24 scanned the negative-glyph write window at the instant of the
vulnerable store. All explicitly left a **later-created object** UNKNOWN: after
`encs[-1]` is overwritten, a later allocation could place a live function
pointer inside the same window, which a later call might branch to. That would
be a rung-4 widening (a branch at a chosen mapped address), still not r5
without a benign marker or command.

Decision rule: stop at `fvimportbdf.c:1751 if glyph < 0`, save `encs`, continue
to a later source breakpoint (`sfd.c:1671` in `Save()`), and scan the same
`(char*)encs-131072 .. encs` window at that later moment. A candidate in the
executable `r-xp` mapping that belongs to a later-called object is a positive
and goes to `witness`. An abort before the later breakpoint, or an ASCII-only /
empty window, is an author-side negative with no grade change.

## Method and observed result

`replay-w25.sh` generates an in-tree `w25-late.ff`
(`New(); Import("<tree>/truncated.pcf"); Save("/tmp/ff2s-w25-late-<lane>.sfd")`)
and a per-build gdb command. Both real headless builds are required:
`build-plain` from `replay-real.sh` and `build-nopie` from `replay-nonpie.sh`.

Both runs hit the vulnerable store with `glyph=-1 i=3`, then the process
aborts at the corrupted free with glibc's `double free or corruption (out)`
**before** `sfd.c:1671` is reached. The dump is therefore taken at the abort,
not at a genuine later-object state; that is the honest limit of this lane.
No PCF variant in this lab was measured to survive to a later breakpoint.

- PIE (`build-plain`, `encs=0x555555c48280`, r-xp
  `0x5555555bc000..0x55555593c000`): `CAND_COUNT 0`, `RESULT NONE` —
  `scan-w25-pie.out` hash
  `313c4ce473482b43b8e7d2e0dadc4c6a6d28896b3c36de94a7efde1f9e75db76`,
  byte-identical to W15/W23's write-time PIE scan.
- non-PIE (`build-nopie`, `encs=0xa92070`, r-xp `0x405000..0x785000`):
  `CAND_COUNT 5`, `RESULT ASCII_ONLY` (`nis`, `ENT`, `ell`, `ENT`, `ENT`) —
  `scan-w25-nopie.out` hash
  `2c980b3dbe6842de7666460e55bbd1ce886ec91ff9c50cb3ece659aad77f63c0`.
  All five words are short printable fragments, not code pointers; the count
  is build-path sensitive as in W15/W18/W23.

`sh replay-w25.sh` asserts 8 path-independent checks: the negative store, the
abort message, absence of a hit on the later `Save()` breakpoint and no
`RESULT CODE_POINTER_CANDIDATES` in each lane. Live-tree result: 8/8 PASS,
rc 0, `REPLAY_W25_OK: 8 checks, 0 failed`.

## Disposition

No live code pointer appears in the window, and with this trigger the process
never reaches a later allocation state: the corrupted free aborts first. Grade
unchanged — witness #3309 ESTABLISHED rungs 1-4 only at direct-call scope, no
r5. This is an author-side negative, not a witness verdict. A PCF/grooming
variant that survives the free, a GUI callback, or a deliberately planted
function pointer that is later called remains UNKNOWN; any of those with an
observed branch at a chosen address changes the decision and goes to
`witness`.

Build prerequisites: `sh replay-real.sh` and `sh replay-nonpie.sh` first. No
network, no loopback service, no external probe. Raw heap dumps are not
byte-stable; the normalized scans and gdb transcripts are the stable evidence.
