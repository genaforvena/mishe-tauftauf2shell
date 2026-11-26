# xdgmime2shell — provenance

All sources fetched read-only as provisioning from
`https://gitlab.freedesktop.org/xdg/xdgmime/-/archive/<sha>/xdgmime-<sha>.tar.gz`;
no external system was probed. Nothing in this lane binds a socket.

## Pins (SHA-256)

- `src/vuln.tar.gz`
  `89a376a11797ea0e2629bdfc6803d9344b11ed153e09397900f4740a04a82299`
  — commit `0305e05c8b8efa98e69880597f79c7cd1ba3c150` (parent of the fix).
- `src/fixed.tar.gz`
  `8f53c295a76cb96bf296626470323d59ea87bf0b08b1ef653a133c9ff3bc2a67`
  — commit `1debecbfe5a643dd7bd1a70f40cf86b007edbd43` (fix).
- `src/1debecb.patch`
  `35f7098fbdb7c6b3fcf2f8b747dc9837de035af018d71b84e8c9e027b432cfee`
  — GitLab diff endpoint, four-line write-side parenthesization.
- `src/vuln/src/xdgmimemagic.c`
  `862de6927afe39ae51aa138277f764feff2c3b257646354a1aeac9b6fb8f144c`.
- `src/fixed/src/xdgmimemagic.c`
  `fcb1eafe748d3dc18f7f405d1078c8a32e313d23d2fab86b0f12e609ac2ce742`.
- `poc.c`
  `346647db5535fd1a60d11a3efe8f94fbb9288043b75485b2c733339c13a341a1`.
- `probe.c`
  `eea76d40027e9b51608a71326e7763ebbac40251bd0a218fbf6193456b1cd531`.
- Generated magic inputs: attack2
  `6601bef7afba2398307d3e8d02d14660b78045854282a06033ce7f5036a924a2`,
  attack4 `5ebc0c988653a20b28d81397bfb3efefd03bade0e96fba68c7b99200c04180a0`,
  mask `bc95e8a4e68ea7c17a9048ac27f57611973190d049bba3b227954863e55a616a`,
  safe1 `b56caf85c2ba2c9733fd374646fa81b70e3fd2a16ca3bd3c3c914d607a239d8f`.
- `run-all.sh`
  `f19f15d9f5dcd292353a82030b590dc7aeac48f1fea136e4e872855fd2e17205`
  — RESULT PASS=39 FAIL=0, rc 0, GCC 13.3.0 and Clang 18.1.3.

## Build configuration and limits

Compiles unmodified pinned C sources with
`-D_POSIX_C_SOURCE=200809L -DXDG_PREFIX=xdg_test -DHAVE_MMAP -DLITTLE_ENDIAN=1`.
The standalone project's meson file does not define `LITTLE_ENDIAN`; the flag
selects the branch that GLib's little-endian build config selects and that
the upstream ASan trace shows executing. No source line was edited. The
`probe.c` driver includes the pinned `xdgmimemagic.c` to inspect matchlet
state and uses `__attribute__((no_sanitize("address")))` only for deliberate
readback of ASan-poison bytes. ASan-recover reports are kept in the logs;
they are corruption evidence, not successful parsing.

## Negatives and corrections preserved

- First exploratory run reported no ASan because the crafted magic file had
  not been created (the earlier `&&` chain stopped at a link error): an
  absent file silently produces `extents=0` and a fallback lookup. Fixed by
  generating and SHA-pinning all four magic inputs in the runner.
- Several early link attempts mixed stale object files (duplicate `main` and
  duplicate parser symbols). The runner now cleans `src/out` and links each
  driver against an explicit library object list.
- The first `poc.c` called `_xdg_mime_magic_lookup_data()` without
  initializing GLib's global alias list, causing an unrelated SEGV in a fixed
  build; removed. The public-API claim is file parsing, not MIME lookup.
- `extents` is 5, not 4: the parser's default `range_length` is 1. Assertions
  were corrected before the final 39/0 run; earlier failing logs were
  overwritten by the canonical runner, and the corrected expectation is
  recorded here.
- With `abort_on_error=1`, only the first of the two mask writes is reported;
  the second-write assertion reads the recover-mode probe log.
- No named adjacent object, pointer, wire path, command or r5 was observed.

## Author clean-archive replay

Pending; add the receipt here after replaying the unmodified runner from the
staging commit.
