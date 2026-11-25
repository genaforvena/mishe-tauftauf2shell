# W14 — file-chosen mapped address dereferenced in a non-PIE lab build

CVE-2026-135295, 2026-11-25 04:08-04:1xZ. Author-side, unwitnessed.
Rung 4 widening for one **locally built configuration**; no grade change,
NO r5. The default builds in `REACHABILITY.md` / `DEREF.md` are PIE; this
one adds `-DCMAKE_EXE_LINKER_FLAGS=-no-pie`. No shipped-default claim.

## Prediction and decision rule

The W10/W11 write reaches a live `BDFChar.bitmap` at byte offset `encs-200`
with `glyph=-50`. The pinned RHS `(min2*256 + min1)` replaces the pointer's
low 32 bits; its maximum is `0x01FFFE00` (W12). In the PIE build the high
dword stays `0x00005555`, so every reachable value is below the lowest PIE
mapping `0x555555554000` and the dereference faults (`DEREF.md`).

Prediction: in a non-PIE build the heap pointer's high dword is zero, so the
full low dword is file-chosen; `0x414243` and `0x5a4344` lie inside that
binary's executable image, so `Save()` reads mapped bytes rather than
faulting. Keep only if gdb shows the chosen pointer at the consumer and the
address resolves inside this build's own image; otherwise record a negative.

## Exact build

From `lab/frontier/fontforge2shell`, pinned tarball
`src/fontforge-20251009.tar.gz` sha256
`613424039e0e1b6bb106f8f0df287e1d249ac285d854f4e1964d68e9b9ad7eb0` and
`pinned/fix-65e80b5.patch` sha256
`f2745243789404ed4b6c737362dd963264ba92a848292a71db6c885675e99175`:

```sh
FLAGS='-DCMAKE_BUILD_TYPE=Debug -DENABLE_GUI=OFF -DENABLE_NATIVE_SCRIPTING=ON -DENABLE_PYTHON_SCRIPTING=OFF -DENABLE_PYTHON_EXTENSION=OFF -DENABLE_DOCS=OFF -DBUILD_SHARED_LIBS=OFF -DENABLE_LIBSPIRO=OFF -DENABLE_LIBGIF=OFF -DENABLE_LIBJPEG=OFF -DENABLE_LIBPNG=OFF -DENABLE_LIBREADLINE=OFF -DENABLE_LIBTIFF=OFF -DENABLE_WOFF2=OFF -DENABLE_HARFBUZZ=OFF'
cmake -S src/fontforge-20251009 -B build-nopie $FLAGS -DENABLE_SANITIZER=none '-DCMAKE_EXE_LINKER_FLAGS=-no-pie'
cmake --build build-nopie --target fontforgeexe -j2
# same for src/fontforge-fixed -> build-fixed-nopie (fix patch applied)
```

`readelf -h` reports `Type: EXEC (Executable file)` for both binaries.
`readelf -SW build-nopie/bin/fontforge` places `.text` at
`0x407010` with size `0x37d7b6` (ends `0x7847c6`) and `.rodata` at
`0x785000`; both chosen addresses are inside `.text`.

`make-nonpie-case.py` regenerates the three PCFs and all gdb / script files
from the pinned `truncated.pcf`. Hashes:

| file | sha256 | RHS / glyph |
|---|---|---|
| `value-nonpie-a.pcf` | `8f0da475c8019d1c78a8e851a7e6dab5dbd35ea24754f5fb9b69a99b1b84fd67` | `0x00414243`, glyph -50 |
| `value-nonpie-b.pcf` | `ac7d52474b8d72e018735be90f914cfd4a5ce22ccbf121795aa426a873e86935` | `0x005a4344`, glyph -50 |
| `value-probe.pcf` | `4b37ed447b2709f1170f73c3e3accc333b62d2424ab3406c62aa02704467d7b6` | in-bounds glyph 1 |

## Measured

`gdb-value-nonpie-a.out` and `gdb-value-nonpie-b.out`, breakpoint at
`sfd.c:1671` (the real `SFDEnc85(&encrypt,*pt)` consumer), non-PIE vulnerable
build:

- a: `HIT enc=261 i=0 bfc=0xa91f60 bfc->bitmap=0x414243 pt=0x414243`,
  `0x414243 <TransDStemHints+554>: 0x0f 0x5e 0x45 0xf0 0x48 0x8b 0x45 0xd8`
- b: `HIT enc=261 i=0 bfc=0xa91f60 bfc->bitmap=0x5a4344 pt=0x5a4344`,
  `0x5a4344 <AfmSplineFont+1464>: 0x8b 0x30 0x8b 0x4d 0x10 0x8b 0x55 0x9c`

Both plain runs exit 0 (no fault); the resulting saved SFD files differ in
their encoded bitmap lines (`cmp -l` first differs at byte 361), so the
consumer read differs with the file-chosen address. `gdb-value-probe-nopie.out`:
`PROBE enc=257 i=0 bfc->bitmap=0xa91e30 pt=0xa91e30`, eight zero bytes — the
in-bounds control keeps a heap pointer. `gdb-fixed-nopie.out`: patched build
on case a keeps `bfc->bitmap=0xa91dc0` with zero bytes. Both controls and
the patched plain run exit 0. The original `WRITE of size 4` at
`fvimportbdf.c:1751` in this build is the same pinned write measured in
`REACHABILITY.md`; the new observation is the mapped-address consumer.

Reproduce in one command from a clean archive of the commit containing these
files, with the pinned tarball supplied locally:

```sh
git archive <commit> lab/frontier/fontforge2shell | tar -x -C "$TMP"
cd "$TMP/lab/frontier/fontforge2shell"
FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-nonpie.sh
```

The script builds both non-PIE trees, regenerates the cases, and asserts 15
stable-lane checks, ending `REPLAY_NONPIE_OK: 15 checks, 0 failed` with rc 0.

## Ceiling of this result

- The pointer written is data (`BDFChar.bitmap`), consumed as data at
  `sfd.c:1671`; no function pointer, branch, marker or command. This is not
  rung 5 and not "code execution" from the advisory's phrase.
- Only the low 32 bits are written; the high dword is inherited (zero in
  this non-PIE build, `0x00005555` in the PIE builds). Byte 3 of the chosen
  value is still only 0 or 1 (W12), so the reachable window is
  `0..0x01FFFE00`; it happens to cover this non-PIE image, not the PIE one.
- `-no-pie` is a local lab configuration, not a measured upstream or distro
  build. The default PIE builds remain unmapped at the chosen addresses
  (`DEREF.md`). ASLR/grooming was not studied; no GUI path, no witness replay
  of this lane.
