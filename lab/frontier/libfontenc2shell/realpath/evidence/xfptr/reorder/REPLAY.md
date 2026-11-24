# W189: reordering mappings cannot make Xvfb invoke the hijacked recode pointer

Negative result. Run from the committed checkout with
`sh lab/frontier/libfontenc2shell/realpath/xlive/run-xfptr-reorder.sh`
(2026-11-24, ~03:33Z and 03:35Z UTC). Two runs; the second added an
env-gated backtrace (`LF_BT=1`) in the test-only interposer.

## Hypothesis and design

W187/W188 overwrote `m5->recode` (a map allocated *after* the 131072-byte
encoding buffer) inside a live Xvfb, but `FontEncRecode` was only ever called
on `m1`, allocated before the buffer. Hypothesis: the recode target is chosen
by map order/charset, so if the buffer were allocated during mapping 1, the
first `cmap 3 1` map in mapping 2 would be allocated after the buffer and
would become the invoked target.

`run-xfptr-reorder.sh` writes: mapping 1 `unicode` with `0xff00 0x1111`
(non-identity code, forces buffer allocation), mapping 2 the only
`cmap 3 1` map, mappings 3..10 unicode decoys, then four `0xfe14..0xfe17`
word mappings. Calibration reads the buffer, marker and live maps from
`LF_*` interposer lines; the four chosen 16-bit words are computed to hit
the first map above the buffer. Controls: vulnerable safe (`SIZE 256 256`)
and fixed `5920c6e` crafted.

## Observed result (both runs identical except the relocated marker address)

First run:
```
buffer=0x555555a52930 target=n5 m=0x555555a72940 marker=0x7ffff7fb9159 idx=65552 from=0xfe14 0xfe15 0xfe16 0xfe17 words=9159 f7fb 7fff 0000
vuln-crafted-a marker_calls=0 target_recode=0x7ffff7fb9159 recode_targets=0x5555559497b0,
vuln-crafted-b marker_calls=0 target_recode=0x7ffff7fb9159 recode_targets=0x5555559497b0,
vuln-safe          marker_calls=0 target_recode=0x7ffff7fb2885 recode_targets=0x5555559497b0,
fixed-crafted      marker_calls=0 target_recode=0x7ffff7fb2891 recode_targets=0x5555559497b0,
```
Second run (`LF_BT=1`, marker `0x7ffff7fb91f9`): same four lines, same
`recode_targets=0x5555559497b0`, `marker_calls=0` throughout. Full raw logs:
`cal.txt`, `vuln-crafted-a.xvfb.txt`, `vuln-crafted-b.xvfb.txt`,
`vuln-safe.xvfb.txt`, `fixed-crafted.xvfb.txt`, `bt-run.log` in this directory
(and `realpath/tmp/xfptr-reorder/162{0,1,2,3,4}.xvfb.log`, gitignored).

Live map layout from calibration (`cal.txt`): n1..4 at `0x5555559497b0` ..
`0x555555949930` (below the buffer), n5..10 at `0x555555a72940` ..
`0x555555a72ba0` (above it), n11..12 at `0x555555841e40`. The crafted runs
set n5's `recode` to the marker and left every other map unchanged. The
recoded map is n1 — a `unicode` map in this layout, not a `cmap` map — so
charset does not select it either.

## Causal check

First `FontEncRecode` backtrace in the crafted run (`LF_BT=1`):
```
interpose.so(FontEncRecode+0xb6)
/lib/x86_64-linux-gnu/libXfont2.so.2(+0xfd05)
/lib/x86_64-linux-gnu/libXfont2.so.2(+0x1dad9)
/lib/x86_64-linux-gnu/libXfont2.so.2(+0x21adc)
/lib/x86_64-linux-gnu/libXfont2.so.2(+0xd40b)
Xvfb(+0x13543c)
Xvfb(OpenFont+0x16b)
...
```
The library is stripped (`addr2line` gives no symbols), but the call site is
direct. `objdump -d --start-address=0xfcb0 --stop-address=0xfd20
/lib/x86_64-linux-gnu/libXfont2.so.2` shows:
```
fcc7: mov 0x18(%rsi),%rsi     ; map pointer loaded from a stored field
fcd0: mov (%rbx),%eax
fd00: call FontEncRecode@plt ; rdi=code, rsi=that stored map
fd05: mov 0x8(%rbx),%rsi
```
No charset search or map-list walk precedes the call: libXfont2 passes a
map pointer stored in the font object when `OpenFont` resolves the encoding.
That pointer is the first map of the encoding, whose `FontMapRec` is
allocated at `STARTMAPPING` before `setCode()` can allocate the buffer on any
code line. Hence the first map can never lie after this encoding's buffer,
and the out-of-bounds write cannot redirect a recode that libXfont2 invokes
through this path. This is a structural consumer limit, not a lucky layout.

## Clean-archive replay (2026-11-24 03:38Z)

From `git archive HEAD` at `df7918c` into `/tmp/lf2s-w189-clean`,
`LF2S_SRC=/tmp/libfontenc-src sh ./rebuild.sh` rebuilt all eight pinned
libraries (rc 0; live matrix vuln/fixed/safe as in W155/W156). The committed
`run-xfptr-reorder.sh` then produced a third layout — `buffer=0x555555a53540`,
first post-buffer map `n7=0x555555a73590`, `idx=65584` from
`0xfe34..0xfe37` — and the same negative:
```
vuln-crafted-a marker_calls=0 target_recode=0x7ffff7fb91f9 recode_targets=0x555555949720,
vuln-crafted-b marker_calls=0 target_recode=0x7ffff7fb91f9 recode_targets=0x555555949720,
vuln-safe          marker_calls=0 target_recode=0x7ffff7fb2885 recode_targets=0x555555949720,
fixed-crafted      marker_calls=0 target_recode=0x7ffff7fb2891 recode_targets=0x555555949720,
```
The hijacked map moved from n5 (working tree, `idx=65552`) to n7 (clean
archive, `idx=65584`) with the path-length-driven heap shift, but the
recoded map stayed the first one and `marker_calls` stayed 0. This is an
author replay, not a witness verdict. No Xvfb left running.

## Disposition

Hypothesis rejected. Grade unchanged: rung 4 at CODE/HARNESS and public-API
scope; the live Xvfb overwrite is memory control without invoked control
flow. No command, no remote wire input, no privileged process. The lane
"make the invoked map sit after the buffer by reordering mappings" is closed.
No setuid X server or display manager exists on this host, and static 16-bit
word writes cannot absorb ASLR's randomized heap bits 12-15; those two
blockers from W187/W188 remain. No Xvfb was left running.
