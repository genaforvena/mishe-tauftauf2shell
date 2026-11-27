# berryformat2shell provenance and observations (2026-11-27 W326)

All fetches were read-only provisioning from public Berry/GitHub URLs. All
execution stayed in this lab directory; no socket, external target, scan or
probe was used. The harness runs the real pinned Berry interpreter and real
`string.format` / lexer code. No vulnerable function is copied or
reimplemented. The only debugger action is reading the saved return slot after
the real overflow; GDB does not write memory or force a call.

## Claim sources and pins

- Related advisory: CVE-2026-3285 / GHSA-92ph-pr79-cv5g,
  https://github.com/advisories/GHSA-92ph-pr79-cv5g and
  https://nvd.nist.gov/vuln/detail/CVE-2026-3285. The advisory claims a local
  one-byte OOB read in `scan_string`, fixed by
  `7149c59a39ba44feca261b12f06089f265fec176`; it does **not** claim the
  `string.format` stack write reproduced here.
- Primary report/fix: https://github.com/berry-lang/berry/issues/509,
  https://github.com/berry-lang/berry/pull/511 and
  https://github.com/berry-lang/berry/commit/7149c59a39ba44feca261b12f06089f265fec176.
  The commit message also changes `get_mode`, but that hunk targets post-1.1.0
  source. No separate CVE/GHSA for the format write was found.
- Vulnerable source: https://codeload.github.com/berry-lang/berry/tar.gz/refs/tags/v1.1.0
  → `pins/vuln.tar.gz`, SHA-256
  `b8eb94a44378ecd2f281cf7e244b8617b99f51d500638622b6126e60e730a693`.
  Tag commit `b5ede66721937533fbf5c286ef44a5111ea30c75`; source blob
  `src/be_strlib.c` = `23fdf978fbc1af80a2d853e16634be9b3d0876cd`.
- Upstream fix source: https://codeload.github.com/berry-lang/berry/tar.gz/7149c59a39ba44feca261b12f06089f265fec176
  → `pins/upstream-fix.tar.gz`, SHA-256
  `96afb4d8ed598e2185e50e66af286543ce8eff5a5e52cb45d171ca9c0f866439`.
  Source blobs `src/be_strlib.c` = `9112b0fb5e1bddc6359c2081e13e83061a1a2925`,
  `src/be_lexer.c` = `43670d730b4f10f855b8b2c6f53ea26260124cef`.
- Upstream patch: https://github.com/berry-lang/berry/commit/7149c59a39ba44feca261b12f06089f265fec176.patch
  → `pins/fix.patch`, SHA-256
  `adbcb8609dc87da273d961be820aec5daf70230edf9449f1321e4abd422bf3df`.
  Its lexer hunk applies to 1.1.0; its `be_strlib.c` hunk rejects because 1.1.0
  has `get_mode(str, buf)` while the fix parent has
  `get_mode(str, buf, buf_len)`.
- Local patches: `pins/lexer-fix.patch` SHA-256
  `0020b5a37724e4a1f341906b92bb82c2d9e4d82f3fb0e492b9914eee76cb01b5`;
  `pins/backport-format.patch` SHA-256
  `c2fc304b47009d11246a1a1d01b5e87f17ab7ef26bf65d42cbdd4c42dfd3c0bd`.
  The latter adds the size argument and the upstream truncation logic to the
  1.1.0 `get_mode`; it is a local backport, not an upstream release.

## Source-bound mechanism

Pinned 1.1.0 `src/be_strlib.c:517-545`: `MAX_FORMAT_MODE` is 32 and `FLAGES`
is `"+- #0"`. `get_mode` advances over an unbounded run of those flag bytes,
then executes `strncpy(buf, str, p - str + 1)` and writes a NUL without the
destination size. `str_format:564-572` supplies `char mode[32]`.

Input `inputs/format-overflow.be` is an ordinary Berry statement with 224
attacker-chosen flag bytes (`#0-+` repeated 56) and conversion `s`. The copy is
225 bytes into `mode+1`. In the O0 ASan frame `mode` is `[32,64)` and `buf` is
`[96,224)`; the first invalid byte is the mode redzone at offset 64. In the O0
plain frame the saved RIP is 215 bytes after the copy start, so the same input
overwrites all eight saved-RIP bytes.

The exact upstream fix bounds `get_mode` and makes this long-`%s` input clean.
It does not bound `mode_fixlen`: `strlen(mode)` can be 31, then appending
`BE_INT_FMTLEN "ll"` writes three bytes at `mode+30`, crossing the 32-byte
array. `inputs/format-numeric-residual.be` uses 29 dashes and `d`; both the
local backport and exact upstream fix commit reproduce this residual ASan
WRITE-3.

## Reproduction

`bash bootstrap.sh` builds seven variants with GCC 13.3.0:

- `vuln-asan`, `patched-asan`, `upstream-fix-asan`: `-O0 -fsanitize=address`;
- `vuln-plain`, `patched-plain`: `-O0`, explicitly no stack protector or
  fortify, to expose overwrite geometry;
- `vuln-hardened`, `patched-hardened`: `-O2` with this host's default compiler
  hardening.

`bash run-all.sh` runs the real interpreter on all attack/safe controls,
checks the ASan classes and sizes, repeats the plain crash five times, and
uses `observe.gdb` to read the saved RIP after the real copy.

Observed 2026-11-27 W326, raw logs in `runs/`:

- Vulnerable 1.1.0 ASan: rc 134, `stack-buffer-overflow`, `WRITE of size 225`,
  `get_mode src/be_strlib.c:542` → `str_format:572`.
- Local backport and exact upstream-fix ASan, same long-`%s` input: rc 0,
  ASan-clean. Equal-length safe format and safe numeric controls are clean on
  vulnerable, backport and exact-fix builds.
- Vulnerable unprotected O0 plain: rc 139 in 5/5; patched plain: rc 0.
- Default hardened vulnerable O2: rc 134, `buffer overflow detected`; patched
  hardened: rc 0. The suite does not isolate canary versus fortify as the
  detector.
- GDB after the real 225-byte copy:
  `SAVED_RIP_BYTES=2b23302d2b23302d`,
  `SAVED_RIP_VALUE=0x2d30232b2d30232b`. This is a noncanonical address. The
  process crashes earlier through corrupted locals; return to this value was
  not observed.
- Local backport ASan numeric residual: rc 134, WRITE-3 in `mode_fixlen`
  `src/be_strlib.c:561`. Exact upstream fix: rc 134, WRITE-3 in `mode_fixlen`
  `src/be_strlib.c:627`.
- Related lexer control: vulnerable ASan rc 134, global-buffer-overflow READ-1
  one byte after static `eos`; backport and exact fix report `unfinished string`
  rc 1; safe source is clean.
- `bash run-all.sh`: `TOTAL: 59 PASS / 0 FAIL`, rc 0. Runner SHA-256
  `8cbda6c37f4a2fcf7ed2e523be8530939c3b3c3ecef2e06f9bf4ff31af111871`;
  log SHA-256
  `41e87d538b28b2dc5336f16e3ee5bd74c65900b3d02d655201d60b19218770a7`.

## Reconciliation and negatives

Unknown wake W325 partially applied the upstream patch: the lexer hunk landed,
but `be_strlib.c` and test hunks rejected. Its `run-vuln-plain.out` was produced
by an ASan binary because plain `make` said `berry` was up to date; it is not
plain-build evidence. W326 rebuilt from clean pins, deliberately split the
applicable lexer hunk, backported the format bound, and produced the real
plain/hardened controls above.

The overwrite alphabet is restricted to flag bytes, at most two width digits,
optional precision digits, and the conversion byte; `%n` is not reachable as a
flag. The observed saved-RIP value is noncanonical, no controlled branch or
chosen executable address was observed, and no real consumer, network path,
pointer dereference, marker or command was exercised. The exact-fix numeric
residual is preserved rather than hidden by an extra local repair.

## Rating and limits

R1 ✓ deterministic local script trigger; R2 ✓ `mode[32]` size invariant broken
with attacker-controlled length; R3 ✓ ASan WRITE-225 plus exact-fix residual
WRITE-3; R4 LIMITED — chosen restricted-alphabet bytes at the saved-RIP slot
in an explicitly unprotected O0 build, no controlled branch; R5 NOT CLAIMED.
The prerequisite is a Berry context that executes attacker-influenced script
or format text. Tasmota and NuttX are plausible consumers from public docs,
not locally verified exposure.
