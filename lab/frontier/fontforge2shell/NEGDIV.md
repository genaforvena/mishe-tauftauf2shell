# W16 — negative-divisor limb of the :1751 write (2026-11-25, author-side)

## Question

W10/W11 measured chosen low bytes with `max2==min2` (divisor `d=1`), and
W12 measured the nonnegative maximum `0x01FFFE00`, stating that bits
24..31 are only `0x00` or `0x01`. The pinned arithmetic also permits
`max2 < min2-1`, making `d` negative. This wake asks whether that limb can
put an arbitrary address byte into a live pointer and produce a **mapped**
chosen target — the one lane W11/W14 left open. No new grade is claimed.

Source: `fvimportbdf.c:1742-1753` (pinned sha256
`df766f9c…eb30d`); `getformint16()` at `:1354` is unsigned
`getc() | (getc()<<8)` with no EOF check; the RHS is a C `int` written
through `int*`. With `min2=2, max2=0` (`d=-1`) and
`min1=65534, max1=0` (`e=-65533`), `tot=d*e=65533`: the loop runs and
`i/d = -i`. Supplying 65532 skipped `0xffff` indices followed by a
one-byte-truncated `0xce` (`glyph=-50`) stores at `i=65532`:

```
RHS = (2-65532)*256 + (65532 % -1) + 65534 = 0xff0105fe
```

So byte 3 can be `0xff`; W12's numeric ceiling still holds for nonnegative
RHS, but its wording "bits 24..31 only 0x00 or 0x01" was incomplete.
The reachable byte-3 set across both limbs is bounded by the magnitude of
`(min2 + i/d)*256` (roughly `-0x1000000 .. +0x1010000`): `{0x00,0x01}`
for nonnegative RHS and `0xff` (and extremes near `0xfe`) for negative
RHS. In particular `0x55` (PIE binary/heap) and `0xf4` (library mapping)
are not reachable; this is arithmetic, not a guess from one build.

## Measured cases

All files derive from the pinned 296-byte `truncated.pcf`; only the
BDF_ENCODINGS fields at `0x118` and the index bytes from `0x122` change.

| file | sha256 | final index | i at store | glyph |
|---|---|---|---|---|
| `negdiv-atk.pcf` | `ef118f0a2b49da1c7ddfeaa6fc017aff7377810f308a0abec5fb24edfb1a0473` | `0xce` truncated | 65532 | -50 |
| `negdiv-size.pcf` | `c111e7fbdef7d7d751c0eedd712e34746d52fd4a1f5995a58f8cc01c09955881` | `0xff` truncated | 65532 | -1 |
| `negdiv-complete.pcf` | `1c0cf8138892e9005e283f6bdf1c4db58486a80fb35016cd352f3eba9c56c088` | `0x0001` | 65532 | 1 |
| `negdiv-safe.pcf` | `7958a45d26289fed4dc62bdb28bf4222e3bc1e7b95e6e29d84ee15f87a8ee63c` | all 65533 indices `0xffff` | none | skipped |

`gdb-negdiv.cmd` breaks at `fvimportbdf.c:1751 if glyph < 0`, watches the
live `BDFChar.bitmap` word at `encs-200` identified in W10/W11, and prints
`info proc mappings` in the same transcript.

Default PIE `build-plain` (`gdb-negdiv-plain.out`):

```
HIT glyph=-50 i=65532 encs=0x555555c48240
fields min2=2 max2=0 min1=65534 max1=0 tot=65533
Old value = 93824999368688              (0x0000555555c227f0)
New value = 93827838838270              (0x00005555ff0105fe)
x/4xb encs-200 -> 0xfe 0x05 0x01 0xff
```

Local non-PIE `build-nopie` (`gdb-negdiv-nopie.out`, a lab config, not a
shipped default):

```
Old value = 10929632                    (0x0000000000a6c5e0)
New value = 4278257150                  (0x00000000ff0105fe)
```

Parsing each transcript's own `info proc mappings`, neither address falls
in any mapping (`replay-negdiv-mapping.out`): PIE heap is
`0x555555bc4000..0x555555c68000`; non-PIE heap is near `0xa7…` and
`.text` is `0x40…..0x78…`. The new high byte is chosen but lands in an
unmapped range. No branch, marker, command or r5.

## Controls (`replay-negdiv.sh`, one command, 20 checks, rc 0)

| input | plain | fixed-plain | ASan | fixed | nopie | fixed-nopie |
|---|---|---|---|---|---|---|
| `negdiv-atk.pcf` | 0 | 0 | 1 (`WRITE of size 4` at `:1751`) | 0 | 0 | 0 |
| `negdiv-safe.pcf` (no store) | 0 | 0 | 0 | 0 | 0 | 0 |

The in-bounds-looking `negdiv-complete.pcf` is **not** a clean control:
with `d=-1` its lone in-bounds value is `0xff0105fe`; `figureProperEncoding`
accepts a huge `enc` into `MakeEncChar` at `:210`, and both vulnerable and
patched plain builds fault (rc 139). That is the pinned post-overflow
consumer's behavior for a huge in-bounds encoding, not evidence about the
OOB store; it is preserved as a negative result and excluded from the
matrix. The all-skipped control isolates the divisor effect and is clean
in all six trees.

`sh replay-negdiv.sh` regenerates the cases, reruns both gdb transcripts,
asserts the chosen `0xff` byte, the unmapped-result oracle and the 11
return-code/report checks, then prints `REPLAY_NEGDIV_OK: 20 checks, 0 failed`
with script rc 0. Prerequisites: `sh replay-real.sh` and
`sh replay-nonpie.sh` (builds the six local trees).

## Disposition

W12's numeric maximum (`0x01FFFE00`) stands; the byte-3 statement is
corrected to include `0xff` from the negative-divisor limb. The reachable
range still contains no mapped byte for this process layout, and no called
function pointer is involved. Grade unchanged: witness-established rungs
1-4 at the direct-call scope, real-path results author-side only, NO r5.
A chosen byte at `0x55`/`0xf4` in byte 3, a benign marker execution, or an
independent witness verdict widening the real-path grade would change this.
