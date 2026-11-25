# W24 — third build: no live code pointer in the negative-glyph write window

## Question and decision rule

W15/W18/W23 swept the 128 KiB negative-glyph write window at the vulnerable
store in two headless builds (default PIE `Debug`, local non-PIE `Debug`) at
three allocation states (untuned, prior complete import, tcache disabled).
Each disposition explicitly left **another build** UNKNOWN. W24 tests that
variable with a third build: same pinned vulnerable source, `RelWithDebInfo`
(-O2 with debug info), default PIE.

Decision rule: break at `fvimportbdf.c:1751 if glyph < 0`, dump
`encs-131072 .. encs`, and scan every aligned 8-byte word against that
build's `r-xp` mapping. Any candidate in a later-called object would be a
rung-4 widening (branch at a chosen mapped address), preserved and handed to
`witness`. Zero candidates, or printable string fragments only, is an
author-side negative with no grade change.

## Build (offline, no network or loopback)

From `lab/frontier/fontforge2shell`, using the source tree pinned in
`PINS.md`:

```sh
FLAGS='-DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_GUI=OFF -DENABLE_NATIVE_SCRIPTING=ON -DENABLE_PYTHON_SCRIPTING=OFF -DENABLE_PYTHON_EXTENSION=OFF -DENABLE_DOCS=OFF -DBUILD_SHARED_LIBS=OFF -DENABLE_LIBSPIRO=OFF -DENABLE_LIBGIF=OFF -DENABLE_LIBJPEG=OFF -DENABLE_LIBPNG=OFF -DENABLE_LIBREADLINE=OFF -DENABLE_LIBTIFF=OFF -DENABLE_WOFF2=OFF -DENABLE_HARFBUZZ=OFF -DENABLE_SANITIZER=none'
cmake -S src/fontforge-20251009 -B build-rel $FLAGS > build-rel-configure.log 2>&1
cmake --build build-rel --target fontforgeexe -j2 > build-rel-build.log 2>&1
sh replay-w24.sh
```

Only `CMAKE_BUILD_TYPE` changed from `replay-real.sh`'s `Debug`; the option
set and source tree are identical. The -O2 build still exposes `glyph` and
`encs` at the breakpoint, so the same dump is possible.

## Observed bytes

`gdb-w24-rel.out`: breakpoint 1 at `fvimportbdf.c:1751`, then
`W24 encs=0x555555b2f240 glyph=-1 i=3`. `info proc mappings` gives the
executable `r-xp` range `0x5555555bc000..0x555555824000` (heap
`0x555555aab000..0x555555b4f000`). The same truncated-PCF store as
W15/W18/W23: negative index `-1`, loop index `i=3`.

`scan-w24-rel.out`:

```
RANGE 0x5555555bc000..0x555555824000
CAND_COUNT 0
RESULT NONE
```

`sh replay-w24.sh` = 3/3 checks, rc 0, `REPLAY_W24_OK: 3 checks, 0 failed`.
Normalized hashes (live tree):

```
7ae88797997d429937a2c3913734931805eff22a5ab8847a796a94e39272ce98  /tmp/ff2s-w24-rel.bin
6d3399d2c9d19b36d616325913399fc55a61deeb07d60e09e04d79f418c326be  scan-w24-rel.out
b62b5283622cf2e333cdbe1eb600297ff04b198a0eb6155df4f6e6f2e203882e  gdb-w24-rel.out
```

The raw dump contains heap addresses and is not byte-stable; the scan output
is the normalized artifact.

## Disposition

No aligned word in the writable negative-glyph window holds a live code
pointer in the third build at the instant of the store. Same result class as
W15/W18's PIE lanes and W23's PIE lanes. No branch at a chosen address, no
marker, no command, no r5, grade unchanged. This is an author-side negative
limited to one -O2 PIE headless build, one import state and one instant;
a deliberate function-pointer groom, GUI, later-created objects, other
compiler/flag combinations and an independent verdict remain UNKNOWN. Do not
infer RCE from a heap abort or a tcache entry.
