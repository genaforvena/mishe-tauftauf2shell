# accelerator PPP2Shell — frontier brief

**Candidate:** accel-ppp `log_tcp`/`log_syslog`/`log_pgsql` unbounded chunk
unpack, CVE-2026-123205. **Status:** local rungs 1/2/3 established on verbatim
pinned upstream `unpack_msg()` bytes; rung 4 is instrumented chosen-byte
control in the harness only. No live daemon, no real L2TP packet, no RCE.
**Ranking:** high tractability, HIGH advisory severity (CVSS 4.0 8.3, PR:N,
AV:N) but an attack-requires-`AT:P` / verbose-logging configuration gate.

## Verified ground truth

- CNA VulnCheck, CVE-2026-123205, published 2026-11-05, CWE-122,
  `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`.
  Affected `>= 0, < 1.15.0` (OSV lists 1.10.0/1.12.0/1.13.0/1.14.0),
  fixed 1.15.0.
- Claim: unauthenticated peers within client-ip-range send an L2TP
  Start-Control-Connection-Request containing many string AVPs while verbose
  logging is enabled; oversized log lines overflow fixed heap buffers in the
  tcp, syslog and pgsql log targets and crash the daemon.
- Sources: [OSV](https://api.osv.dev/v1/vulns/CVE-2026-123205),
  [VulnCheck advisory](https://www.vulncheck.com/advisories/accel-ppp-before-1.15.0-heap-based-buffer-overflow-via-oversized-log-lines-in-log-tcp-log-syslog-log-pgsql),
  [fix commit 58e3994](https://github.com/accel-ppp/accel-ppp/commit/58e399400c4ef4b71472ab7c2c71c54a677a05a8),
  [PR #374](https://github.com/accel-ppp/accel-ppp/pull/374).
  Credit on the advisory: Deus Rex, Denys Fedoryshchenko.

## Source-bound mechanism

`accel-pppd/log.h:8` sets `LOG_MAX_SIZE 4096`. In 1.14.0 the tcp target
allocates `t->buf = _malloc(LOG_MAX_SIZE + 64)` (`log_tcp.c:269`) and its
`unpack_msg()` (`:55-69`) does:

```c
int pos = strlen(msg->hdr->msg);
strcpy(t->buf, msg->hdr->msg);
list_for_each_entry(chunk, msg->chunks, entry) {
    memcpy(t->buf + pos, chunk->msg, chunk->len);
    pos += chunk->len;
}
t->buf_size = pos;
```

There is no bound: a line flushed only on a trailing newline can be
assembled from arbitrarily many `log_*()` calls, and packet printers emit one
call per AVP. The syslog and pgsql targets have the same unchecked loop into
their own fixed `log_buf`. Fix commit `58e3994` adds two independent layers:
`do_log()` caps the accumulated line at `LOG_MAX_SIZE`, and a shared
`log_unpack_msg(msg, buf, size)` clamps each `memcpy` with
`len = min(chunk->len, size - pos)`; the tcp target now passes
`BUF_SIZE - pos`. Pinned file hashes, URLs and extraction details are in
`lab/frontier/accelppp2shell/PROVENANCE.md`.

## Local evidence (verbatim pinned function)

Harness: `lab/frontier/accelppp2shell/`. `run.sh` verifies all 11 pinned
hashes, extracts `unpack_msg()` verbatim from `log_tcp.c.1.14.0` and 1.15.0
plus `log_unpack_msg()` from `log.c.1.15.0` (padding leading lines so upstream
line numbers are preserved), and compiles them with one driver. Clean replay:
19 PASS, `ALL CHECKS PASS rc 0`, trace SHA-256
`3499f52eef8814e5cc73c5e38f990ca0de3f4f0fc243640452c7806dc9c2b18a`
(three byte-identical runs plus a relative-outdir run).

- **Rung 1** — 66 AVP-like chunks of 64 bytes plus a 30-byte header give
  `total=4254`, `buf_size=4160`, `expected_oob=94`; the upstream function
  reports `pos=4254` with no check.
- **Rung 2** — glibc placed the adjacent 128-byte object at `buf+4176`
  (4160-byte region + 16-byte malloc header). Chosen bytes landed at
  `chosen_offset=4` in that object and were read back byte-exact as
  `chosen_bytes=1122334455667788` (little-endian bytes
  `88 77 66 55 44 33 22 11`). This is the real consumer's observed layout in
  this harness, not an assumed adjacency.
- **Rung 3** — ASan: `heap-buffer-overflow`, `WRITE of size 64`, 0 bytes
  after the 4160-byte region, frame `unpack_msg` at pinned
  `log_tcp.c.1.14.0:63`. ASan redzones isolate allocations, so no chosen-byte
  control is claimed from that run.
- **Rung 4** — chosen `0x1122334455667788` is supplied in the AVP bytes at
  the computed offset and read back byte-exact from the adjacent heap object.
  (`marker=55465450` in the trace is a provenance label, not a planted byte
  pattern.) **INSTRUMENTED only:** no live process, no real AVP parser, no
  useful pointer target and no execution.
- **Fixed control** — pinned 1.15.0 functions: `pos=4160`, neighbour clean,
  rc 0, no ASan run needed.

## Rung-4 feasibility and cheapest next experiment

Feasibility: good. The overflowing bytes are attacker-supplied AVP strings
and the destination is a heap buffer, so this class can reach heap metadata
and adjacent objects. The open questions are the real log-target heap layout,
whether verbose logging is enabled on the target, and whether chosen bytes can
reach a pointer used before the daemon aborts.

Cheapest move up a rung: build vulnerable tag 1.14.0 with `log_tcp` targeting
a loopback collector, start the daemon in a private loopback-only netns, and
drive a real L2TP SCCRQ with N string AVPs into the verbose log path. First
observe crash/ASan at the pinned `unpack_msg:63`; then vary AVP count and
length to map which heap neighbour is hit and whether an 8-byte chosen value
lands in a live pointer field. Repeat the syslog and pgsql targets. All input
stays on 127.0.0.1 addresses this plant starts.

## Unknowns and negatives

- No live accel-ppp build, no L2TP wire traffic, no real AVP decoder and no
  configuration of verbose logging were exercised here. The advisory's
  reachable path and "within client-ip-range" condition remain claims.
- Only the tcp target is exercised locally; syslog and pgsql are source-read
  only. The `do_log()` accumulation cap in the fix is not exercised; this
  replay isolates the final consumer.
- No pointer-sized target in a real object was controlled, and no code
  execution was demonstrated. Stock glibc layout on a real daemon is UNKNOWN.
- No exploit framework claim was consulted; only the CNA/OSV/VulnCheck record
  and upstream patch were used.
