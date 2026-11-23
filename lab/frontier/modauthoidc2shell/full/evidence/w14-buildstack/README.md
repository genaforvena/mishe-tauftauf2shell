# W14: the "plain" full module is ASan-instrumented (2026-11-23)

Correction to the W9-W13 label "non-ASan plain build". No new exploit result;
no grade change. Commands and verbatim output: `raw.txt` in this directory.

- The exact module pinned by W9-W13 (`sha256
  008990618887dde66e4371d1a354c64dccf29c40d36d17c4ac1d8e5f8b375654`, built
  from pinned `state.c` `ceedb687…5aa`) has `libasan.so.8` in `ldd`.
- `evidence/plain-module-build.log` shows apxs putting `-fsanitize=address`
  into the `state.c` compile command. My explicit `CFLAGS='-O1 -g
  -fno-omit-frame-pointer'` in `build-plain.sh` does not remove it; apxs
  appends its own ASan flags from the httpd build.
- `nm -D` on that module lists `__asan_report_load1` and
  `__asan_report_store1` (and wider variants); the inlined state-cookie caller
  `oidc_state_cookies_clean_expired` contains ASan load/store check calls.
- The serving `httpd-2.4.70-install/bin/httpd` also links `libasan.so.8`, as
  do the other lab httpd builds checked (2.4.71 asanapr, apache2root 2.4.70,
  apache2shell 2.4.69). No non-ASan httpd was available in the lab.

**What changes.** "Plain" means no explicit `-fsanitize` in my CFLAGS and
plain-prefix jansson/cjose — not a non-ASan process. W8-W10's observed NUL
stores and W13's child SIGSEGV (`AH00051 … exit signal Segmentation fault
(11)`) with clean well-formed and released-tag controls stand as measured.
But W13 ran with the ASan allocator active, and `ASAN_OPTIONS=detect_leaks=0`
changed that allocator's behaviour: that is a direct explanation of the
per-start bimodality. No availability effect is established on a production
(non-ASan) allocator. Byte always NUL; no chosen byte, pointer target,
consumer dereference, command or rung 5.
