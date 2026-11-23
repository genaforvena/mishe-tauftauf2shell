# thorvg2shell lab provenance

Wake W181, 2026-11-23 21:35Z–22:35Z. All paths are relative to this
directory. Everything was provisioned read-only from public sources; no
external host was probed, no service started, nothing bound to any port.

## Sources

- `src/v1.1.1.tar.gz` sha256 `59c12500b7c2fc426e89667b3e4f3fdc2ff05a75cc12001a22c5f58fb1cdf592`
  (ThorVG v1.1.1 release, vulnerable).
- `src/v1.1.2.tar.gz` sha256 `cd466f4abf2522a6dcdc1a69a75d04a214b7163c89731fb8481eceaa6cb73842`
  (ThorVG v1.1.2 release, fixed).
- `src/67680c546d38d817e42eb7583dac8d87a4a319b5.patch` sha256
  `bd25d69f570fd0df9c911748cd3ee9f5337b242d8319967dfaf184680d4f5956`
  (upstream fix patch; byte-identical diff text to commits 67680c5 and
  e740313, which share result blob `1ba076c378...`).
- Extracted with `tar xzf … --strip-components=1` into `src/vuln/` and
  `src/fixed/`. Pinned `tvgJpgd.cpp` sha256s are in `PINS.sha256`.

## Harness

`harness/jpgd_asan.cpp` is a 45-line C++ main that reads a JPEG from disk into
a `std::vector<char>` and calls the real public decoder API `jpgdHeader()`,
`jpgdDecompress()` and `jpgdDelete()` from `src/loaders/jpg/tvgJpgd.cpp`.
`harness/config.h` is a minimal stand-in for Meson's generated config (JPG
loader and file IO flags on). No renderer, canvas, SVG/Lottie loader or
network code is compiled.

`harness/build.sh` builds 8 binaries: gcc 13.3.0 and clang 18.1.3, each against
vuln/fixed trees, with and without `-fsanitize=address`, all
`-std=c++17 -g -O0 -fno-omit-frame-pointer`.

Important allocator caveat: pinned `jpeg_decoder::alloc()` (`:802-826`)
suballocates every working buffer from a single 32512-byte `mem_block`. ASan
cannot see overflows from one suballocation into the next. Two complementary
routes were used:

1. `poc/dup4_large.jpg` is a 2048x2048 grayscale frame whose overflow walks
   past the arena into unmapped memory: pristine vulnerable source faults
   (SEGV at pinned `tvgJpgd.cpp:733` under ASan, rc 139 without ASan), fixed
   tree rejects. This is the unmodified-decoder evidence.
2. `harness/tvgJpgd_directalloc.cpp` is a copy of the pinned vulnerable source
   with **only** `jpeg_decoder::alloc()` replaced by direct `std::malloc`
   (documented inline at `:802`). Original file sha256
   `aa1a47b6a0c195a292da6fe666716fc94e0e65cbc26c7437412cb1bf63a448d6`,
   instrumented copy sha256
   `6249413822bb057988d648e0636e6d3b4b679e18ed919356dd8f77757d848b29`.
   Parsing/decoding logic is otherwise byte-identical. `harness/build.sh`
   does not build it; `REPLAY.md` gives the two compile commands. Allocator
   leaks are expected and ASan leak detection is disabled in the runs.

## PoCs

`poc/make_poc.py` (PIL 10.2.0, Python 3.12.3) renders a deterministic 16x16
grayscale gradient, emits `control.jpg`, then byte-splices the SOS marker into
`dup2.jpg`, `dup3.jpg`, `dup4.jpg` (Ns = 2/3/4, repeated selector `01 00`).
`poc/make_large.py` and `poc/make_marker.py` follow the same recipe for a
2048x2048 frame and for four constant blocks encoding chosen DC halfwords.
All generators re-parse their outputs and assert one SOF0 component, correct
SOS length and selectors, unchanged entropy/EOI and unchanged bytes before
SOS. Full hashes in `PINS.sha256`; SOS bytes and roles in
`reports/frontier-thorvg2shell.md`.

## Evidence

`harness/run_matrix.sh` ran 11 binaries x 8 JPEGs = 88 cases; per-case stdout
and stderr are in `harness/evidence/<binary>__<jpeg>.out`, exit codes in
`harness/evidence/matrix.tsv` (53 x rc0, 12 x rc1, 20 x rc6, 3 x rc139).
Additional gdb transcripts for rungs 2 and 4 were observed live this wake and
are quoted in the brief; no synthetic consumer or wire endpoint was used.

Rebuild and replay from `REPLAY.md`.
