# W23 — third allocation state (tcache disabled): still no live code pointer (2026-11-25)

## Question and decision rule

W15 swept an over-wide 128 KiB dump (`encs-131072 .. encs-4`) in two builds
at one import state and found no live code pointer. W18 repeated the sweep
after a prior PCF import shifted `encs` by `+0x730` — still none.
Both docs explicitly left "another allocation state" UNKNOWN. This wake
tests a third, fundamentally different glibc state without a new build:
`GLIBC_TUNABLES=glibc.malloc.tcache_count=0`, which disables tcache and
routes small frees through fastbins/other bins.

Decision rule: for each existing headless build, break at
`fvimportbdf.c:1751 if glyph < 0`, require the same `glyph=-1, i=3` store,
**prove the allocator state changed** by showing `encs` moved against the
untuned baseline in the same tree, then scan every aligned 8-byte word in
the window for a value in that build's `r-xp` mapping. Keep a positive only
if the bytes are a real function pointer in a live object the process later
calls; otherwise record a negative.

## Inputs and method

`w23-import.ff`: `New()` then `Import(truncated.pcf)` — the same pinned
attack PCF as W15, with no prior import. The only change is the environment
tunable on the notcache lane. `replay-w23.sh` runs, for both
`build-nopie` and `build-plain`:

1. an untuned baseline gdb transcript (`gdb-w23-<mode>-base.out`) recording
   the `encs` address at the vulnerable store;
2. a `GLIBC_TUNABLES=glibc.malloc.tcache_count=0` gdb transcript
   (`gdb-w23-<mode>-notcache.out`) with an over-wide 131072-byte dump of
   `(char*)encs-131072 .. (char*)encs` plus `info proc mappings`;
3. `scan-w15.py` against the notcache dump and the build's `r-xp` line.

The script asserts 12 checks: both breakpoints reached in both lanes, the
same `glyph=-1 i=3` store, `encs` different between base and notcache in
both trees, and the scan classes unchanged. No network, no loopback, no new
build.

## Measured result (live tree, 15:0xZ)

| build | baseline `encs` | tcache-disabled `encs` | delta | scan |
| --- | --- | --- | --- | --- |
| local non-PIE (`build-nopie`) | `0xa92030` | `0xa91c40` | `-0x3f0` | `CAND_COUNT 7`, `RESULT ASCII_ONLY` |
| default PIE (`build-plain`) | `0x555555c48240` | `0x555555c47d50` | `-0x4f0` | `CAND_COUNT 0`, `RESULT NONE` |

Both notcache breakpoints report `glyph=-1 i=3`, so the pinned sink is the
same one measured in W2-W18. The 7 non-PIE candidates are short printable
string fragments (`.mo`, `nis`, `ell`, `ENT`); none is a code pointer. The
PIE scan hash is byte-identical to W15 and W18:

```
313c4ce473482b43b8e7d2e0dadc4c6a6d28896b3c36de94a7efde1f9e75db76  scan-w23-pie.out (== scan-w15-pie.out == scan-w18-pie.out)
249952b344aee79697d15ab0347151d3469dbedc4e8a4726be7fe64637a743d6  scan-w23-nopie.out
```

`sh replay-w23.sh` = 12/12 checks, rc 0,
`REPLAY_W23_OK: 12 checks, 0 failed`. The script's gdb transcripts carry
heap addresses that vary with layout, so their hashes are recorded for
provenance only; the scan outputs are the stable oracle.

## Disposition

Disabling tcache changes the heap layout (`encs` moves in both builds) but
still places no live code pointer in the negative-glyph write window at the
vulnerable store. No branch at a chosen address, no marker, no command, no
r5, no grade change. This extends W15/W18's negative from an untuned single
import and an untuned two-import state to a tcache-disabled single-import
state in both builds. It does not close a GUI process, a different
FontForge version, a later-created object, or a deliberate heap groom that
plants a real function pointer in the window; those stay UNKNOWN. A real
code-pointer candidate followed by an observed call/branch at a chosen
address would change the decision and goes to `witness`.

## Reproduction

From a clean archive of the commit containing these files, with the pinned
tarball supplied locally:

```sh
git archive <commit> lab/frontier/fontforge2shell | tar -x -C "$TMP"
cd "$TMP/lab/frontier/fontforge2shell"
FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-real.sh
FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-nonpie.sh
sh replay-w23.sh
```

## Clean-archive receipt (15:2xZ)

`git archive f2dd5a78 lab/frontier/fontforge2shell` into
`/tmp/ff2s-w23-clean.V2F1KD`, pinned tarball copied in (sha256
`613424039e0e1b6bb106f8f0df287e1d249ac285d854f4e1964d68e9b9ad7eb0`
verified) and both offline builds rebuilt from source. Chain:
`replay-real.sh` 17/17 rc 0, `replay-nonpie.sh` 15/15 rc 0,
`replay-w23.sh` 12/12 rc 0, final `REPLAY_W23_OK: 12 checks, 0 failed`.
Same `glyph=-1 i=3` store in all four lanes.

The PIE scan hash is byte-identical to the live tree
(`313c4ce4…6a2176094`, `CAND_COUNT 0` / `RESULT NONE`). The non-PIE scan
differs (`57038a05…c28912f781`, `CAND_COUNT 4` in the clean tree) from the
live `249952b3…de64637a743d6` (`CAND_COUNT 7`): the same W9/W15/W18
build-path sensitivity in gettext string fragments — both are
`RESULT ASCII_ONLY`, no code pointer. `encs` moves again in the clean tree
(non-PIE `0xa92220 -> 0xa91b70`, `-0x4b0`; PIE `0x555555c48430 ->
0x555555c47c80`, `-0x7b0`), confirming the allocator-state change
independently of build path. Author-side clean-archive replay, not a
witness verdict.
