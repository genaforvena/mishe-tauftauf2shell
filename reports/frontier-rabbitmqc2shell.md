# Frontier brief — rabbitmq-c AMQP BODY frame overflow (RabbitMQC2Shell)

**Status: new frontier find, brief + harness COMPLETE (2026-11-21 ~13:06Z) —
pending independent witness replay and operator admission.** Rungs 1/2/3 are
ESTABLISHED on the real, verbatim-pinned upstream library: rung 3 is the ASan
report, rungs 1/2 run unsanitized. Rung 4 shows attacker-chosen bytes at chosen
offsets past the 65536-byte outbound frame buffer through the library's own
`memcpy`, reached through the exported `amqp_send_frame()` API. No messaging
application, broker, network listener, real heap neighbour object, pointer,
control-flow diversion or execution was observed — all stay UNKNOWN.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-61547 / GHSA-hfjv-vcp3-39wh. CNA GitHub, Inc.
  (CVE record `providerMetadata.shortName = GitHub_M`); CVE published
  `2026-11-10T16:21:17.565Z`, updated `2026-11-14T02:52:12.997Z`; the
  maintainer GHSA page reads "published Jul 2, 2026". CNA CVSS 3.0
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 CRITICAL**; GHSA also says
  Critical. CWE-787 (out-of-bounds write). Verbatim CNA description: "A heap
  buffer overflow exists in rabbitmq-c when the public amqp_send_frame() API
  is used to serialize an oversized AMQP_FRAME_BODY. The issue occurs because
  amqp_frame_to_bytes() copies frame.payload.body_fragment.len bytes into the
  connection outbound buffer without validating that the body fragment fits
  within the allocated frame buffer."
- **Affected/fixed**: CVE affected `< 0.17.0`; GHSA `<= 0.16.0`; fixed in
  `0.17.0`. Fix commit `b09271180621248dc810f4e48e5adabff35ecee1` (PR #892),
  contained in tag `v0.17.0`. Both release tarballs and the fix diff are
  pinned, so the fixed side is a released build, not a harness-applied patch.
- **Pins**: `src/0.16.0.tar.gz`, `src/0.17.0.tar.gz`, `src/cve61547.json`,
  `src/ghsa-hfjv-vcp3-39wh.html`, `src/fix-b092711.diff` and the byte-identical
  `src/pr892.diff` — six SHA-256 pins in
  `lab/frontier/rabbitmqc2shell/PROVENANCE.md`. The GHSA HTML is a snapshot;
  GitHub rotates metadata IDs on fresh GETs.
- **This lab**: pinned `0.16.0` sources compiled verbatim with CMake/ASan;
  the driver only supplies the body bytes and count and calls the public API.
  ASan reports `WRITE of size 200000` at pinned
  `amqp_connection.c:467`, called from `amqp_send_frame_inner:548` ←
  `amqp_send_frame:531`, into a 65536-byte buffer allocated at `:140`.
  Chosen `0x5a` and `0xa5` read back at offsets +65536 through +69632; a
  `PROT_NONE` guard page faults at the first past-end store; fixed `0.17.0`
  returns `AMQP_STATUS_BAD_AMQP_DATA` before copying.

## Source-bound mechanism

Line numbers are from raw bytes in the pinned tarballs, tag `0.16.0` unless
marked fixed.

1. `amqp_connection.c:22` sets `AMQP_INITIAL_FRAME_POOL_PAGE_SIZE 65536`;
   `:53` calls `amqp_tune_connection(state, 0, 65536, 0)`, and `:140`
   `realloc`s the outbound frame buffer to that size.
2. `:454` `amqp_frame_to_bytes(const amqp_frame_t*, amqp_bytes_t, ...)` receives
   that `amqp_bytes_t` as its capacity argument. In the `AMQP_FRAME_BODY` case
   `:465` takes `body = &frame->payload.body_fragment` and `:467` executes
   `memcpy(amqp_offset(out_frame, HEADER_SIZE), body->bytes, body->len)` —
   `HEADER_SIZE` is 7 (`amqp_private.h:96`). The copy length is the caller's
   body length; the destination capacity appears nowhere in the case.
3. `:521-522` then store the length and frame-end byte using the same unchecked
   `out_frame_len`, so a second, smaller OOB store follows the `memcpy`.
4. The public path is real: `:531` `amqp_send_frame` → `:548`
   `amqp_send_frame_inner` → `:454`, with the copy completing before any send.
   The advisory's published ASan trace cites `:467`, `:548`, `:531`, `:140`
   and `:53`; all five match the pinned bytes exactly.
5. Fixed `0.17.0`: `amqp_connection.c:467-473` rejects
   `body->len > buffer.len - (HEADER_SIZE + FOOTER_SIZE)` with
   `AMQP_STATUS_BAD_AMQP_DATA`; the surviving `memcpy` is at `:475`. The same
   commit adds `tests/test_send_frame.c` as a regression test.

## Lab evidence

`cd lab/frontier/rabbitmqc2shell && bash run.sh <outdir>`:

- 10 PASS / 0 FAIL, exit 0. Two independent five-run groups both
  `sha256=239e11fea9854f993b4d90adae7efa9b1b481013688daeeaa5d524cd02ffeee8`.
- Rung 1: a 200000-byte body passed through the public API crashes the
  unsanitized pinned library with rc 139.
- Rung 2: the declared `body.len`, not the buffer capacity, drives the copy;
  chosen bytes are observed past the 65536-byte boundary.
- Rung 3 (ASan): `heap-buffer-overflow`, `WRITE of size 200000`, 0 bytes after
  a 65536-byte region, frames `amqp_frame_to_bytes:467` →
  `amqp_send_frame_inner:548` → `amqp_send_frame:531`; allocation via
  `amqp_tune_connection:140` ← `amqp_new_connection:53`. With a 1000000-byte
  body the report is `WRITE of size 1000000` (934464 bytes past).
- Rung 4 (INSTRUMENTED chosen-byte control): with the outbound buffer placed
  in page-aligned memory by the harness allocator, `0x5a` and `0xa5` each read
  back at +65536/+65552/+65584/+65600/+65792/+66048/+67584/+69632 after the
  library's own `memcpy`. A `PROT_NONE` page immediately after the buffer
  faults with rc 139 at the first past-end store.
- Negative controls: fixed `0.17.0` returns `rc=-2`
  (`AMQP_STATUS_BAD_AMQP_DATA`) with no ASan report; a body of length 2 is
  ASan-clean on both builds.

**Harness boundary, stated plainly**: the ASan rung uses the library's own
allocator and reports the upstream copy directly — no shim performs the write.
For chosen-byte observation and the guard proof, a link-time `realloc`/
`free` interposer places the library's real outbound buffer in page-aligned
memory; that changes placement, never the library code that writes them. A
local `AF_UNIX` socketpair, shut down for writing, lets the post-copy send
return immediately without a broker or any network listener. Determinism lines
carry no ASan PID, address or path text.

## Rung-4 feasibility assessment

This is an attacker-controlled-length, attacker-controlled-content heap write
through an exported API, with the fix hunk and both affected/fixed releases
pinned. The write is on the **serialization** side: the application must pass
an oversized body fragment into `amqp_send_frame()`. That is a plausible
trust-boundary crossing (a service republishing an untrusted message body),
but no such application was run here. The remaining gap to unqualified rung 4
is the consumer: which applications forward attacker-sized bodies, their
allocator and heap layout, and whether chosen bytes can reach an object
header, pointer or function pointer. None of that was measured.

**Cheapest rung-raising experiment**: write a loopback-only service that
accepts a length-prefixed message body from a local socket and calls
`amqp_send_frame()` on a pinned `0.16.0` connection under ASan and gdb. Send
the 200000-byte chosen-value body; expect the ASan WRITE at
`amqp_connection.c:467` inside the service process. Then freeze the first
past-end bytes, inspect the real heap neighbour under gdb, and only then
attempt pointer/metadata control. This belongs to a dedicated target mind
after admission, not this extracted-driver lane.

## Next-candidate queue (from this wake's read-only scouting)

Recorded so the evidence is not lost; none has a brief or window yet, and none
was built here. All fields below were fetched from public advisories and raw
source by the three scouts and are claims until a witness or this lab pins them.

- **hnswlib / Spotify Voyager**, CVE-2026-124959: file-loader `loadIndex`
  reads `max_elements_` and `cur_element_count`, allocates `M*S`, reads `C*S`
  bytes (`hnswalg.h:707-708,755,758` at `d9b3608`) — chosen length *and*
  content, no `C<=M` check. Fix commit `280cb597…` exists but is an **unmerged
  PR** (#677); no released fix, so fixed-side evidence would be weaker than
  this find's. Highest-priority next candidate on primitive quality.
- **OpenJPEG**, OSV-2025-219 / GHSA-78g4-xqwv-q3g8: `opj_j2k_read_sod`
  unchecked `tp_index[...]` struct writes (`j2k.c:5085-5092` at v2.5.4), 3-line
  guard in `91d08b11…`, but no tagged release contains the fix and the PoC
  must be regenerated.
- **asn1scc**, CVE-2026-75614 / GHSA-825c-7h77-2jjq: uPER constrained-size
  decode lacks `uv > range` (`asn1crt_encoding.c:796-801`), 2-line fix in
  `fe6ab763…`, fixed 4.7.0.1; needs a generated decoder in the harness.
- **wolfSSL** CVE-2026-6679, **HTSlib** CVE-2026-62257, **Imager**
  CVE-2026-102505, **libIEC61850** CVE-2026-49035, **libexpat**
  CVE-2026-77214: lower tractability (stateful DTLS, pointer-store file
  format, Perl module, or OOB read).

## Scope and boundaries

Loopback-free local process drivers: one `AF_UNIX` socketpair per process, no
broker, server, external probe or network listener. Sources were fetched
read-only as provisioning. Harness stand-ins and exact copied ranges are
enumerated in `PROVENANCE.md`. No nginx or other plant's lane was touched.
