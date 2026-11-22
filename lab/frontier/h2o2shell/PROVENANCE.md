# h2o2shell provenance — frontier W117 (2026-11-22)

## Claim

CVE-2026-55368 / GHSA-m998-r5ww-rqjf, "Out-of-bounds writes in H2O access-log
formatting", published 2026-10-23 by the h2o maintainers, High 8.1. Advisory:
<https://github.com/h2o/h2o/security/advisories/GHSA-m998-r5ww-rqjf>.
Fix patch: <https://github.com/h2o/h2o/commit/48b7ae12107fd2b118e4641da49599e9aac8edd8.patch>
(merge of PR #3757, three commits, all in `lib/core/logconf.c`).

## Pins (provisioned read-only from GitHub)

- vulnerable `4212ce114506a073505fd389db16ad2ba4e582a0`
  (first parent of the fix merge; the advisory's "up to 4212ce1")
- fixed `48b7ae12107fd2b118e4641da49599e9aac8edd8`
  (advisory's "48b7ae1 and above")

Exact commit IDs, `lib/core/logconf.c` sha256 and `git archive HEAD` stream
hashes: `pins/PIN_HASHES.txt`.

## Build

Each pin is a real `libh2o.a` built from its own worktree:

```
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address'
cmake --build build-asan --target libh2o -j4
```

and identically for `build-plain` without ASan. System libs: OpenSSL 3.0.13,
libuv 1.48.0, zlib, brotli, zstd. No edits were made to either pinned tree.

## Harness

`harness/logconf_harness.c` uses the pinned library's own
`h2o_logconf_compile("%{error}x", H2O_LOGCONF_ESCAPE_APACHE, ...)` and
`h2o_log_request()`. The request is a zeroed `h2o_req_t` whose `error_logs`
points at a real `h2o_buffer_t` holding 80 chosen bytes `'A' + (i % 26)`.
The caller buffer is exactly 64 bytes in ASan mode; in plain mode a
`readback_frame` places a 128-byte zeroed `tail` immediately after it.

`harness/run-harness.sh` builds and runs six variants: ASan vulnerable/fixed
with 80 chosen bytes, plain readback vulnerable/fixed, and safe-input
vulnerable/fixed with 8 bytes.

## Observed result

- vulnerable ASan: rc 1, `heap-buffer-overflow`, `WRITE of size 1`, 0 bytes
  after the 64-byte region,
  `append_unsafe_string_apache lib/core/logconf.c:438` ←
  `h2o_log_request lib/core/logconf.c:843`.
- fixed ASan: rc 0, `OUT_LEN=81 REALLOCATED=1`, no report.
- vulnerable plain: `OUT_LEN=81 REALLOCATED=0`, tail `4d4e4f50...5a4142`
  (chosen M..B at offsets 0..15 past the sink plus the `\n` suffix at 16).
- fixed plain: `OUT_LEN=81 REALLOCATED=1`, tail all zero.
- safe 8-byte inputs: rc 0, `OUT_LEN=9`, tail all zero on both pins.

## Replay and hashes

`harness/EVIDENCE_HASHES.txt` holds six normalized sha256 values; the
normalizer `harness/normalize.py` strips PIDs, addresses and absolute build
paths but keeps bytes, sizes, line numbers and exit codes.

`harness/clean-replay.sh` re-exports both pins with `git archive HEAD`,
extracts to a fresh `replay/` tree, rebuilds both libraries and all six
harness binaries there, and compares hashes. Result: all six hashes identical
(`REPLAY_IDENTICAL=yes`); see `harness/clean-replay.log`.

## Scope limits

Direct-call harness only. No live h2o process, loopback socket, wire request,
configured access-log format, allocator-neighbour object, pointer control,
command execution or witness replay was observed. The stock caller
`lib/handler/access_log.c:48` uses a 4096-byte stack buffer; the 64-byte sink
is a harness choice. The two other advisory cases (`%q` empty, numeric NUL)
are source-bound from the fix hunks but not separately harnessed. No rung 5.

## Handoff

Brief: `reports/frontier-h2o2shell.md`. Charter:
`.mishe-tauftauf/charters/h2o2shell.md`. Seed wall:
`.mishe-tauftauf/walls/h2o2shell.md`. Live inner two-pane window index 86;
registry 87 windows, unique. Frontier owns no further work on this lane.
