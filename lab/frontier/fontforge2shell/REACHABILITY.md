# REACHABILITY — real FontForge 20251009 Import() path (2026-11-24 06:3xZ)

Real headless build, real PCF file, real scripting `Import()` consumer. This
extends the witness-established rungs 1-4 from the direct-call harness to the
actual parser path; it is still not a pointer/IP or command primitive.

## Provisioning and build

- Source tarball `src/fontforge-20251009.tar.gz`, sha256
  `613424039e0e1b6bb106f8f0df287e1d249ac285d854f4e1964d68e9b9ad7eb0`
  (GitHub tag `20251009`; fetch only, no external probes).
- Fixed tree `src/fontforge-fixed` is a copy with the pinned patch applied:
  `patch -p1 < ../../pinned/fix-65e80b5.patch` succeeds at :1747 with
  offset -13; the changed line :1750 is `glyph>=0 && glyph!=0xffff && ...`.
- Both builds: cmake `-DCMAKE_BUILD_TYPE=Debug -DENABLE_GUI=OFF
  -DENABLE_SANITIZER=address -DENABLE_NATIVE_SCRIPTING=ON
  -DENABLE_PYTHON_SCRIPTING=OFF -DENABLE_PYTHON_EXTENSION=OFF
  -DENABLE_DOCS=OFF -DBUILD_SHARED_LIBS=OFF`, optional image/spiro/harfbuzz
  deps OFF; target `fontforgeexe` in `build-asan/` and `build-fixed/`.
  Binaries and build trees are untracked lab artifacts.

## Inputs

- `truncated.pcf` (296 bytes, sha256
  `0c8dc0fe33eafe6fe631716771eb16f7447070a3f22c8480c54c44559d528703`):
  PCF magic `\x01fcp`, four TOC tables (PROPERTIES, METRICS, BITMAPS,
  BDF_ENCODINGS), four 8x8 glyphs, and a 20-byte BDF_ENCODINGS table at
  offset 276 ending exactly at EOF: format 0, `min2=max2=0x5346`,
  `min1=0x4d`, `max1=0x50`, def 0, glyph indices 0,1,2. The fourth
  `getformint16()` reads EOF twice and yields `glyph == -1`.
- `complete.pcf` (298 bytes, sha256
  `149f03de680225a482172484235d80fc19dc908b12668cca194c48ec8eaa1526`)
  adds a fourth in-range glyph index 3.
- Scripts `import-pcf.ff` / `import-complete.ff`: `New()` then
  `Import("<absolute path>")`.

## Measured results

`ASAN_OPTIONS=detect_leaks=0 ./build-asan/bin/fontforge -script import-pcf.ff`
exits 1 with one ASan report (`real-import-asan.out`, sha256
`8c199e9e1299dd628a004cff7df50085eca2ca8c1b01a9b12b96831d115e0f8c`):

    ERROR: AddressSanitizer: heap-buffer-overflow
    WRITE of size 4 ... 4 bytes before a 16-byte region
    #0 PcfReadEncodingsNames fvimportbdf.c:1751
    #1 PcfParse fvimportbdf.c:1831
    #2 SFImportBDF fvimportbdf.c:2164
    #3 _SFImportBDF fvimportbdf.c:2226
    #4 FVImportBDF fvimportbdf.c:2329
    #5 bImport scripting.c:2306
    ...
    allocated by PcfReadEncodingsNames fvimportbdf.c:1726

Controls, both zero ASan reports and exit 0:

- `./build-fixed/bin/fontforge -script import-pcf.ff` — same truncated file,
  patched source: `real-import-fixed.out` (sha256
  `48d87e242e1aa8d623ef3b066ee056756d49b9dc249516bb6d16130cf43c93c5`).
- `./build-asan/bin/fontforge -script import-complete.ff` — vulnerable
  source, complete table: `real-import-safe.out` (sha256
  `c1ac99c903a1e4e484f2ef236806c40c58c60da4381acf95bb53c04673a19fe5`).

## Scope

Headless CLI scripting `Import()` on this host. The GUI `Import()` menu,
other loaders, plain (non-ASan) real-build behavior, chosen-byte inspection
in the real process, pointer/IP control, command execution, ASLR/grooming
and independent witness replay of this real-build path are UNKNOWN.
