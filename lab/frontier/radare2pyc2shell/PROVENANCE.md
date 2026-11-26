# PROVENANCE — radare2pyc2shell W243 (2026-11-26)

All fetches were read-only provisioning from public GitHub/NVD sources. No
external target was probed; every run below is local.

## Fetched URLs and full-file SHA-256

- `https://raw.githubusercontent.com/radareorg/radare2/6.1.8/libr/bin/format/pyc/marshal.c`
  → `src/marshal-6.1.8.c`, 1225 lines,
  `41698e7886715b57427b166c90101aa132eadec821de66fccbf477a147cbb51c`.
- `https://raw.githubusercontent.com/radareorg/radare2/838df53eaadc57b72a28bead5d8368f1ae37976d/libr/bin/format/pyc/marshal.c`
  → byte-identical to the 6.1.8 tag (same SHA-256), confirming the fix parent.
- `https://raw.githubusercontent.com/radareorg/radare2/6727454b666b28c33837b219a5f91136461357c0/libr/bin/format/pyc/marshal.c`
  → `src/marshal-fix-6727454.c`, 1232 lines,
  `3d8b2a625a96a750ad2135a32d975715f91a262d6bd71695b5ed9982bcf0c313`.
- `https://raw.githubusercontent.com/radareorg/radare2/6.2.0/libr/bin/format/pyc/marshal.c`
  → `src/marshal-6.2.0.c`,
  `0aedf7fb536fbfeb6c5cdb7804dce6a40e15807cfe107a0ac6c31c7115f4a45c` (guard present).
  No `6.1.9` tag: `https://api.github.com/repos/radareorg/radare2/tags?per_page=30`
  lists `6.1.8` then `6.2.0`.
- `https://raw.githubusercontent.com/radareorg/radare2/6.1.8/libr/util/buf.c`
  → `src/buf-6.1.8.c`,
  `538a6784eeb0e7f673625f73fce58e97c957f2b3dd41b90528d2f4b57493a52f`
  (identical at the fix commit).
- Advisory: `https://github.com/radareorg/radare2/security/advisories/GHSA-9phv-v2w8-56j3`;
  issue: `https://github.com/radareorg/radare2/issues/26222`;
  patch: `https://github.com/radareorg/radare2/commit/6727454b666b28c33837b219a5f91136461357c0.patch`;
  commit metadata (parent `838df53e…`, signed) via
  `https://api.github.com/repos/radareorg/radare2/commits/6727454b666b28c33837b219a5f91136461357c0`.

## Verbatim excerpts (byte-exact lines, no edits)

- `pins/get-bytes-vulnerable.inc` = `marshal.c:78-85`, SHA-256
  `a3f2083495e1e6205fc77934167ae195a3968607bdc5b24f0aa653f6962c396f`.
- `pins/get-bytes-fixed.inc` = fix `marshal.c:78-89`, SHA-256
  `8e41575a6e315364b95e125524db2fa9e28d8347b27dae8bf5c4004c95cff9ba`.
- `pins/ascii-readers.inc` = `marshal.c:615-644`, SHA-256
  `d19406980365f39859bcee067be6a940fcad812ddf23d0db48476484b16ed26e`.
- `pins/buf-sink.inc` = `buf.c:496`, SHA-256
  `4f3e1082ed37fd99f92d010c3b7037ef955583c9b795603d4c1de89892d5c9dd`.
- `harness/driver.c`, SHA-256
  `6995deba366eba8e92523316bf3230470397cce4291538b4912d5290ad485ce3` —
  stand-ins only; `#line` directives label frames and do not alter pinned bytes.

## Commands and observed output (2026-11-26 W243)

`bash lab/frontier/radare2pyc2shell/run-all.sh` from the checkout root:
`TOTAL: 31 PASS / 0 FAIL`, exit 0. It builds five binaries (GCC ASan vuln/fixed,
Clang ASan vuln, GCC plain vuln/fixed), runs eight cases, and checks nine hashes.

`out/gcc-attack.log` and `out/clang-attack.log` both contain
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 4294967295`, at 0
bytes past a 1-byte region (the `calloc(0,1)` request is zero bytes). ASan
frame #0 is `memset`/`__asan_memset`; pinned `r_buf_read pins/buf-sink.inc:496`
is frame #1, `get_bytes pins/get-bytes-vulnerable.inc:3` frame #2. Allocation
frame #0 is `calloc`, pinned `get_bytes pins/get-bytes-vulnerable.inc:2` is
frame #1 (the `R_NEWS0` call site).

`out/fixed-attack.log`: `MODE=attack LEN_FIELD=4294967295 RC=3 SINK=0`, no ASan.
`out/vuln-safe.log` and `out/fixed-safe.log`: `MODE=safe LEN_FIELD=16 RC=0 SINK=0`,
`out/plain-attack.log`:
`SINK_BUF=<addr> SINK_R=0 SINK_LEN=4294967295 SINK_BYTE=ff` then
`MODE=attack LEN_FIELD=4294967295 RC=3 SINK=1 SINK_LEN=4294967295 SINK_BYTE=ff`.
The plain lane logs sink arguments and writes eight bytes through the sink
stand-in; it does not read the written bytes back, and `SINK_BYTE=ff` is the
driver's fixed `b->Oxff_priv` (`harness/driver.c:136`), not stream-chosen.
Changing the crafted length field from `ff ff ff ff` to `fe ff ff ff` in a
throwaway copy moves `SINK_LEN` to `4294967294` with `SINK_BYTE` still `ff`
(W243 witness probe). `out/plain-safe.log` has no `SINK_BUF=`.
`out/plain-fixed-attack.log`: `MODE=attack LEN_FIELD=4294967295 RC=3 SINK=0`.

The plain build bounds the pinned sink to eight bytes so the demonstration is
safe locally; the ASan build executes the full pinned `memset` length and aborts
at the first out-of-bounds byte. This is a synthetic consumer: no radare2
library or binary was built, no `.pyc` was parsed by `rabin2`, and no pointer,
command or loopback service was exercised.
- `run-witness.sh`, SHA-256 `ec1bf9246f8b2f9225d02fe983ca060e6e86a546c8566125aaf4b3a3ab6c3d54`:
  clean `rm -rf out` replay verified all nine pins then `run-all.sh`;
  `REPLAY_PASS=10 REPLAY_FAIL=0`, `WITNESS REPLAY PASS`, inner `TOTAL: 31 PASS / 0 FAIL`.

## Independent witness replay (W243, 2026-11-26 03:46Z)

Frontier DM #4802. Unmodified wrapper (sha256
`ec1bf9246f8b2f9225d02fe983ca060e6e86a546c8566125aaf4b3a3ab6c3d54`) replayed
in the worktree and from clean `git archive cee3588b`: both
`REPLAY_PASS=10 REPLAY_FAIL=0`, `WITNESS REPLAY PASS`, inner `TOTAL: 31 PASS /
0 FAIL`, rc 0. Independent raw GETs reproduced all four full-file hashes and
all four excerpt hashes; the fix-parent fetch at `838df53e` is byte-identical
to 6.1.8. Verdict: ESTABLISHED AS LABELED, no grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w243-radare2pyc2shell/detail.md`.

## Real radare2 6.1.8 consumer probe (2026-11-26 W244, local only)

Provisioning was a read-only public tag fetch:
`https://github.com/radareorg/radare2/archive/refs/tags/6.1.8.tar.gz` →
`upstream/radare2-6.1.8.tar.gz`, SHA-256
`84d0e32af697f720c9f480f6b3e56b08f64251d90cfe2d8f163431c006c0053e`.
Configured with `meson setup build-asan --buildtype=debug
-Db_sanitize=address -Denable_tests=false`; built with
`ASAN_OPTIONS=detect_leaks=0 ninja -C build-asan -j2`. A first bare `ninja`
failed only in a build-time `sdb` helper with LeakSanitizer output; no target
bug. After restoring source backups, both source hashes again matched the
pins (`41698e78…` marshal, `538a6784…` buf) and the clean rebuild succeeded.

`craft_pyc.py` writes `crafted-ascii.pyc` (SHA-256
`0f727b2673622df8c9872c6905a85688cd4485f227b71658056922c6c6714f8a`) and,
with `--length 16`, `safe-ascii.pyc` (`f4567972663bc8a162397d11bec5c4067eb30a
91ab182b5191713dda1c9e05d4`). Layout: magic `2c 0d 0d 0a` (`v3.6.0a2`),
`0x63` code byte at `0x08`, 20 zeroed `ut32` header fields, five filler bytes,
then `0x61` TYPE_ASCII and `ff ff ff ff` at `0x22`. The parser's own
`get_code_object_addr()` returns `r_buf_tell()+5 == 0x22` for that header.

Unmodified ASan build: `bash run-real.sh`, both files `RC=0`, no ASan report;
`rabin2 -I` identifies a `pyc` for Python `v3.6.0a2`, `rabin2 -e` reports
entrypoint `0x22`, `rabin2 -s` prints no symbols. `ASAN_OPTIONS` with
`LD_PRELOAD=libasan.so.8` made no difference (`out-real/attack-preload.log`).
Disassembly of the built `r_buf_read` shows `memset@plt`, not `__asan_memset`,
so ASan is not a reliable detector for this particular sink in the library.

The replayable exact-string helper `instrument_real.py` (smoke-tested on
pristine file copies) added probes to the tagged tree. After rebuild, both
`rabin2 -s crafted-ascii.pyc` (`out-real/sink-probe.log`) and
`radare2 -q -c 'is' crafted-ascii.pyc` (`out-real/r2-probe.log`) logged:
`PROBE get_ascii_object n=4294967295 error=0`,
`PROBE get_bytes size=4294967295 alloc_arg=0 usable=1`, then
`PROBE r_buf_read len=4294967295 r=-1 fill=4294967296`.

Causal diagnosis: `buf_io_read()` (`buf_io.inc.c:52`) calls `iob->fd_read`;
`r_io_fd_read()` takes `int len` (`r_io.h:614`), so the 64-bit `0xffffffff`
truncates to `-1`. The real `r_buf_read()` guard `r >= 0 && r < len` at
`buf.c:495` therefore fails and `buf.c:496`'s `memset` is **never executed**
on this consumer path. The synthetic harness stand-in returned `r = 0`, which
is why it wrote; the real IO-backed consumer is a zero-store path. Preserved
negative: the vulnerable function and undersized allocation are reached, but
no out-of-bounds write occurs. Grade unchanged (rung 3 pinned verbatim, rung 4
PARTIAL synthetic only); no real-consumer rung 4, no pointer, no command, no
rung 5. The fixed-control evidence remains the pinned synthetic fixed build.
