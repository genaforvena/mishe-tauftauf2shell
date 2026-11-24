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

## W3 (2026-11-24 08:0xZ) — consumer of the overwritten slot

`CONSUMER.md` records the answer for this host's 64-bit glibc: the four
bytes at `encs-4` are the high half of the **size word of the same malloc
chunk** (`malloc(16)` gives chunk size `0x21`, header at `encs-8`).
`gdb-consumer-plain.out` (sha256
`53630de80fc3ebc8d370095fe650b3550c4a2e19e38606e8e7add5f23d96f6b5`)
measured `size=0x21` before the store, `size=0x0053494d00000021` after,
then caught `__GI___libc_free(mem=encs)` from `fvimportbdf.c:1770` with the
same corrupted header, followed by `double free or corruption (out)` and
SIGABRT. Patched build / truncated file and vulnerable build / complete
file controls both showed `size=0x21` at line 1770 and exited normally
(`gdb-header-fixed.out`, `gdb-header-complete.out`). The consumer is the
allocator's own metadata check, not an observed second application object.
The value dependence was then measured: an empty-table `zero-write.pcf`
(290 bytes, sha256 `f20ef994…8bf08b5d`) writes zero at `encs[-1]`, leaving
the size word `0x21`; the vulnerable plain build exits 0 while ASan still
reports `WRITE of size 4` at :1751. `gdb-zero-write-post.out` confirms RHS
`0x0`, bytes `00 00 00 00` at `encs-4` and `size=0x21` at `free(encs)`.
`CONSUMER.md` preserves the failed `0xfffd` attempt (no sign extension in
`getformint16()`) and a too-short truncation. Some other plausible size
value remains UNKNOWN; no pointer/IP or command control.

## W4 (2026-11-24 10:3xZ) — file-chosen negative glyph index

`getformint16()` at :1354 is `getc() | (getc()<<8)` with no EOF check.
Truncating a glyph index after **one** byte makes `glyph = low-256`, i.e.
a file-chosen negative index `encs[-256]..encs[-1]`, instead of the fixed
EOF `-1` of W1-W3. Four PCF inputs (`idx-fc/f8/f0/01.pcf`, each
`truncated.pcf` cut at 0x122 with one low byte appended) drove the real
plain process at `glyph=-4/-8/-16/-255, i=0` in `gdb-idx-*.out`; with -4 a
hardware watchpoint on `encs-16` caught `0 -> 0x53464d`, bytes
`4d 46 53 00` at `0x555555c48230` (`gdb-half-watch.out`). ASan reports
the steered write as heap-buffer-overflow (-4), heap-use-after-free in a
chunk freed by `PcfReadBitmaps` (-8) or `SFSetFontName` (-255), and a
later -1 write for -16; all four inputs exit 0 on the patched build and
134 on the vulnerable plain build (`steer-controls.txt`). Details, hashes,
the failed one-byte-offset attempt and the limits are in `STEERING.md`.
This steers the same four-byte write to chosen offsets before `encs`;
no pointer/IP, command, ASLR/grooming or witness verdict, NO r5.

## W5 (2026-11-24 14:0xZ) — low half of the chunk size word

`SIZE.md` records a second measured consumer, distinct from W3's
high-half metadata check. Crafting `min2=max2=0`, `min1=max1=0x91` makes
`tot=1`, so the pinned RHS is exactly `0x91`; truncating the sole glyph
index after low byte `0xfe` gives `glyph=-2`, writing `encs[-2]` =
`encs-8`, the low half of `encs`'s own size word. In `gdb-size-word.out`
the hardware watchpoint reported `Old value = 33`, `New value = 145`,
`x/gx (char*)encs-8` read `0x91`, and that word was still `0x91` at
`free(encs)` from `fvimportbdf.c:1770`. After the free,
`tcache->entries[7] = encs`: glibc accepted the corrupted size and put
the 16-byte-usable chunk in the bin for `0x90`-byte chunks. Vulnerable
plain build exits 0 on this input, while the high-half (`glyph=-1`) and
zero-value controls exit 134; patched build exits 0 on all four inputs;
ASan reports `WRITE of size 4` at :1751 for all three negative inputs
(`8 bytes before` for -2, `4 bytes before` for -1) and nothing for the
complete-table control. A conditional `__libc_malloc` breakpoint for
requests `0x71..0x88` after the free never hit, so no later consumer of
the tcache entry was observed on this path. No pointer/IP, command, ASLR
study, GUI `Import()` menu or witness verdict, NO r5. A GUI build was not
attempted: `gtk+-3.0` is not installed on this host and the existing
builds are `ENABLE_GUI=OFF`.

## W6 (2026-11-24 19:2xZ) — real consumer of the poisoned tcache entry

`CONSUME.md` closes W5's "no observed consumer" gap at the labeled
real-headless path. A second `Import()` in the same process makes
`FVImportBDF:2317` emit a localized notice; glibc gettext's
`_nl_make_l10nflist` calls `malloc(128)`, which returns the `encs` chunk
poisoned by `size-91.pcf` (size word `0x21 -> 0x91`, physically a 0x20
chunk in tcache bin 7). `gdb-real-consumer.out` shows the returned
pointer equal to the corrupted chunk and a subsequent `memcpy` with
`__len=91` whose watchpoint caught the following chunk's size word
changing from `-1` to `0x62616c2f6c6c6568` ("hell/lab"), beyond the
physical 24-byte usable area. Vulnerable plain and patched builds both
exit 0 on the two-import script; vulnerable ASan still reports the
`WRITE of size 4` at :1751, patched ASan and the complete-table control
are clean. The overflow bytes are the host's locale path, not
file-derived; the file controls the corrupted size value and hence the
poisoned size class. No pointer/IP, command, ASLR study or witness
verdict, NO r5. Negative lanes are preserved in `CONSUME.md`.

## W7 (2026-11-24 20:0xZ) — file-chosen bytes in the overflow

`FILECHOICE.md` closes W6's "overflow content is host-derived" gap at the
labeled real-headless path. `size-71.pcf` writes `0x71` at `encs-8`, putting
the physically 0x20 chunk into tcache bin 5. On the second `Import()` a
notice `smprintf` briefly takes and frees the entry, then
`pcf_properties:1464` takes it for `props = malloc(3*32) = 96` bytes and
copies file-derived property integers into all 96 bytes, 72 past the 24
usable bytes. `gdb-props-consumer.out` shows `props == encs` and word
`0x17` at user offset `0x40`; `choice-4-var.pcf` changes one file byte
(`props[2].name_offset` at file offset 0x62 from `0x17` to `0x1a`) and the
same word in the overflow becomes `0x1a` (`gdb-props-var.out`). Vulnerable
plain and patched plain both exit 0; vulnerable ASan reports `WRITE of
size 4` at :1751, patched ASan and the in-bounds first-import control are
clean. Superseded size-class attempts are preserved in `FILECHOICE.md`.
No pointer/IP, command, ASLR study or witness verdict, NO r5.

## Scope

Headless CLI scripting `Import()` on this host. Chosen bytes at a
file-chosen offset before `encs` are now measured (W2/W4), as are the
plain-build abort, the high-half glibc metadata consumer (W2/W3), a
low-half chunk-size rewrite accepted by `free()` into tcache bin 7 (W5),
and a real gettext consumer of that poisoned entry that writes past the
physical chunk on a second `Import()` (W6), plus FILE-BYTES chosen by a
one-byte PCF variant written 40 bytes past that chunk's usable area by a
real `pcf_properties` allocation (W7). The GUI `Import()` menu
(GTK-3 dev packages absent, `ENABLE_GUI=OFF` builds), other loaders,
pointer/IP control, command execution, ASLR/grooming, and independent
witness replay of the real-build path remain UNKNOWN.
