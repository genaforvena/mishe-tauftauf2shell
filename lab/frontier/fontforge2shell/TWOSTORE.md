# W29 — one table, two negative stores, still one chosen offset (2026-11-25 23:4xZ)

Author-side negative. No grade change, no witness verdict, no r5.

## Source structure

Pinned `fvimportbdf.c` (tag `20251009`):

- `pcfReadTOC()` copies every TOC entry, but `pcfSeekToType()` stops at the
  first entry whose `type` matches. A duplicate `PCF_BDF_ENCODINGS` TOC
  entry cannot supply a second table offset: one import calls
  `PcfReadEncodingsNames()` once and reads the first entry only.
- `getformint16()` calls `getc()` twice with no EOF check. With one trailing
  index byte `b`, iteration `j` reads `b|(EOF<<8) = b-256`; iterations
  `j+1..tot-1` read `EOF|(EOF<<8) = -1`. So `tot>1` performs two distinct
  negative writes in one import: `encs[(b-256)*4]` and then `encs[-4]`.
- The RHS at `fvimportbdf.c:1751` is
  `(i/(max2-min2+1)+min2)*256 + (i%(max2-min2+1)+min1)`. With both file
  bytes nonnegative, the `i=1` value exceeds the `i=0` value by exactly 1
  (divisor > 1) or 256 (divisor == 1). The second offset and its value are
  therefore dependent, not independently chosen.

## Experiment

`make-twostore-case.py` takes the pinned `truncated.pcf` prefix (291 bytes,
one trailing byte at `0x122`), sets `min2=0,max2=1,min1=max1=0` → `tot=2`,
divisor 2, and sets the trailing byte to `0xFE` (`glyph=-2` at `i=0`).
`gdb-w29-twostore.cmd` breaks at the store and at loop exit; both real
headless builds show the same two stores with one `encs` allocation:

```
W29S1 i=0 glyph=-2 tot=2 encs=0xa92070 value=0 word[-8]=0x21 word[-4]=0
W29S2 i=1 glyph=-1 tot=2 encs=0xa92070 value=1 word[-8]=0 word[-4]=0
W29POST word[-8]=0 word[-4]=0x1
```

PIE shows the same values with `encs=0x555555c48280`. The first store clears
the low dword of the `encs` chunk size (`0x21 → 0`); the forced second store
sets the high dword to `1`. Both builds then abort in glibc (`SIGABRT`);
plain non-PIE run rc 134. No third store (`tot=2`).

## Decision and limits

One PCF can emit two negative-glyph stores, but the second is always at
`encs[-4]` with a value at least 1 above the first. It corrupts the chunk
size, so no survivable two-offset primitive and no second independently
chosen destination. This refines W27's "one chosen offset per import": the
exception is a forced `encs[-4]` write, not a second controllable offset.
The single-import / two-import lanes stay as measured in W26/W27/W28.
UNKNOWN remains: a build or allocator state where `encs[-4]` is not a live
size word, a GUI process, another loader, or a second-stage overflow.
No branch at a chosen address, marker, command, r5 or replay demand;
#4165 stays queued.

`sh replay-w29.sh` = 16/16 PASS, rc 0, final line
`REPLAY_W29_OK: 16 checks, 0 failed`. Normalized hashes:

```
1894a874b4269a722acfbe0d2cca8decdcd433af1eb1d0b4f069f399eb999441  twostore.pcf
0813bed6b9fd266a854ba547263c033975cd502c6d76574897d601a50620e6a0  gdb-w29-twostore-nopie.out
dd5097e47f8eb809e6910bbae1ee651f2608bb7385723cad6a2ab2e7f3d4267a  gdb-w29-twostore-plain.out
3ad454843f6cde0c364a4168263a46f2a4030a43199211bedcdd6dd1020665ab  W29 normalized gdb lines (^W29S/^W29POST, both builds)
```
