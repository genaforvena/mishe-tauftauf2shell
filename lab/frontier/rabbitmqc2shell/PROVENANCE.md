# Provenance — rabbitmq-c AMQP BODY frame overflow (CVE-2026-61547)

All artifacts in `src/` were fetched read-only as provisioning on
2026-11-21 ~13:01Z; nothing was sent to any external host. `run.sh` verifies
every SHA-256 with `sha256sum -c src/SHA256SUMS` before extracting or
compiling; pin drift exits 2. Raw source bytes, not rendered web readers, are
authoritative for line numbers.

| Pin | SHA-256 | Source |
| --- | --- | --- |
| `src/0.16.0.tar.gz` | `1298b89a78bb8bc70862f612da6eb3a71ade16b5c3f2fa50ec6e5251803ed08a` | <https://codeload.github.com/alanxz/rabbitmq-c/tar.gz/refs/tags/v0.16.0> |
| `src/0.17.0.tar.gz` | `66c36901178c872565f732468e91688f6280c18810fe8b21a199d46347ba3a0c` | <https://codeload.github.com/alanxz/rabbitmq-c/tar.gz/refs/tags/v0.17.0> |
| `src/cve61547.json` | `6b6025b743f44301eac4536c743a196cc8ce0ee3cd015b281feba19d54425639` | <https://cveawg.mitre.org/api/cve/CVE-2026-61547> |
| `src/ghsa-hfjv-vcp3-39wh.html` | `33968f120d6224ca6aaef90a455979dbd8884a149626e414add2a5596a6c5c87` | <https://github.com/alanxz/rabbitmq-c/security/advisories/GHSA-hfjv-vcp3-39wh> |
| `src/fix-b092711.diff` | `e71ec19afdf7df336c8d4befc8c49b3e7ce50155140a68f000d3139d5b6fdf9c` | <https://github.com/alanxz/rabbitmq-c/commit/b09271180621248dc810f4e48e5adabff35ecee1.diff> |
| `src/pr892.diff` | `e71ec19afdf7df336c8d4befc8c49b3e7ce50155140a68f000d3139d5b6fdf9c` | <https://github.com/alanxz/rabbitmq-c/pull/892.diff> — byte-identical to the fix commit diff |

The fix commit is PR #892 and is contained in tag `v0.17.0`; the fixed release
therefore supplies an independent, released fixed-side build rather than a
harness-applied patch. Cross-checks: <https://mallory.ai/vulnerabilities/CVE-2026-61547>
and <https://github.com/alanxz/rabbitmq-c/releases/tag/v0.17.0>. The GHSA HTML
is a snapshot; GitHub rotates metadata IDs on fresh GETs.

## Copied source and stand-ins

No library source is copied or patched. `run.sh` extracts both pinned release
tarballs into the output directory and builds each with CMake/Ninja exactly as
the maintainer advisory documents (ASan build for 0.16.0, plain builds for both
versions, ASan build for 0.17.0). `driver.c` links the resulting static
`librabbitmq.a` and calls the exported `amqp_send_frame()`; the ASan report
names the pinned library frames directly.

Two harness-only elements, both in `driver.c`:

1. A local `AF_UNIX` socketpair whose write end is shut down. The library's
   serialization completes before `amqp_try_send`; the closed socket makes the
   post-copy send fail immediately instead of asserting on a NULL socket. No
   broker, no loopback/TCP listener, no external host.
2. For the `readback` and `guard` modes only, a link-time `realloc`/`free`
   interposer (`-Wl,--wrap`) supplies the library's real 65536-byte outbound
   frame buffer from a page-aligned `mmap` region. It changes where the bytes
   land, never the library code that writes them. The ASan rung-3 build has no
   interposer and uses the library's own `realloc` allocator.

The hostile body buffer is generated entirely by the driver: every byte is the
caller-chosen value and `len` is the caller-chosen count. No serializer or
library code is modified in any mode.

## Pinned line numbers (raw bytes)

Affected tag 0.16.0:

- `librabbitmq/amqp_connection.c:22` `AMQP_INITIAL_FRAME_POOL_PAGE_SIZE 65536`.
- `:53` `amqp_new_connection` calls `amqp_tune_connection(state, 0, 65536, 0)`.
- `:140` `realloc(state->outbound_buffer.bytes, frame_max)` allocates the
  65536-byte outbound frame buffer.
- `:454` `amqp_frame_to_bytes(const amqp_frame_t*, amqp_bytes_t, ...)`;
  `:467` `memcpy(amqp_offset(out_frame, HEADER_SIZE), body->bytes, body->len)`
  with `HEADER_SIZE=7` (`amqp_private.h:96`) and no capacity check.
- `:521-522` the length and frame-end stores use the same unchecked
  `out_frame_len`, so a second OOB store follows the `memcpy`.
- `:531` `amqp_send_frame` → `:548` `amqp_send_frame_inner` → `:454`.

Fixed tag 0.17.0: `amqp_connection.c:467-473` rejects
`body->len > buffer.len - (HEADER_SIZE + FOOTER_SIZE)` with
`AMQP_STATUS_BAD_AMQP_DATA` before the surviving `memcpy` at `:475`. The
regression test added by the same commit is `tests/test_send_frame.c`.

The maintainer advisory's ASan trace cites `:467`, `:548`, `:531`, `:140` and
`:53` — all five match the pinned v0.16.0 bytes exactly.

## Replay record

Direct run 2026-11-21 ~13:05Z: 10 PASS / 0 FAIL rc 0, two five-run groups both
`sha256=239e11fea9854f993b4d90adae7efa9b1b481013688daeeaa5d524cd02ffeee8`.
ASan 200000: `WRITE of size 200000`, 0 bytes after a 65536-byte region, frames
`amqp_frame_to_bytes:467` → `amqp_send_frame_inner:548` → `amqp_send_frame:531`,
allocation via `amqp_tune_connection:140` ← `amqp_new_connection:53`. ASan
1000000: `WRITE of size 1000000` against the same region. Unsanitized 200000
crashes rc 139; staged guard build faults rc 139; staged readback shows the
chosen value at offsets +65536/+65552/+65584/+65600/+65792/+66048/+67584/+69632.
Fixed 0.17.0 returns `rc=-2` (`AMQP_STATUS_BAD_AMQP_DATA`) with no ASan report;
a body of length 2 is clean on both builds. Determinism lines carry mode,
length, value, return code and offset/value pairs only — no ASan PID, address
or path text.

A clean `git archive f773017 lab/frontier/rabbitmqc2shell` extraction into
`/tmp/rmq-archive`, run with absolute outdir `/tmp/rmq-out-clean`, reproduced
10 PASS / 0 FAIL rc 0 and the same digest in both five-run groups; `pins.log`
showed all six pins OK. Window 56 created on the inner tmux socket at 13:07Z
with both panes capture-verified and registered as entry 58 (58 unique).
