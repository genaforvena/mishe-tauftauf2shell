# h2o2shell — frontier brief

CVE-2026-55368 / GHSA-m998-r5ww-rqjf — out-of-bounds writes in H2O access-log
formatting. Screened in 2026-11-22 (frontier W117). Not on the plant's
do-not-duplicate list; no prior brief, charter, wall or window for h2o existed.

## Verified ground truth

- Claim source: GitHub security advisory
  <https://github.com/h2o/h2o/security/advisories/GHSA-m998-r5ww-rqjf>,
  published 2026-10-23, High 8.1, CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H.
  Cross-checked against the CVE record (published 2026-11-04), Debian and
  Ubuntu trackers.
- Affected: commits up to `4212ce114506a073505fd389db16ad2ba4e582a0`.
  Fixed: `48b7ae12107fd2b118e4641da49599e9aac8edd8` and above (merge of
  PR #3757). Both hashes confirmed via the GitHub commit API: the fix merge's
  first parent is exactly the affected commit named by the advisory.
- Claimed primitive: the access-log formatter can write past its log-line
  buffer when an affected custom access-log format is configured. Three cases:
  `%{error}x` allocation error, `%q` with an empty query string, and numeric
  elements whose temporary terminating NUL reaches the end of the buffer.
  Advisory wording: "The effect of the one-byte NUL overwrite beyond a crash
  has not been established."
- Target shape: H2O is an HTTP/1.x/2/3 web server; the primitive is reachable
  from a request when the operator has configured one of the affected log
  formats. This is a genuine web-facing-server, network-triggered memory
  safety bug — in scope for the plant's X2Shell family.

## Source-bound mechanism (from the pinned fix bytes)

All fix hunks are in `lib/core/logconf.c`, function `h2o_log_request()`.

1. `%{error}x` (the case exercised locally): the vulnerable switch arm at
   `logconf.c:842-843` calls
   `append_unsafe_string(pos, req->error_logs->bytes, req->error_logs->size)`
   with **no preceding `RESERVE`**. Every neighbouring arm reserves
   `len * unsafe_factor` (4 for Apache escaping, 6 for JSON). At APACHE
   escape the helper copies printable bytes 1:1 and escapes others to `\\xHH`,
   so `size` bytes of `req->error_logs` are stored starting at `pos` regardless
   of how much room `line_end - pos` has left. The fix inserts
   `RESERVE(req->error_logs != NULL ? req->error_logs->size * unsafe_factor : 0);`.
2. `%q` with no query: the `if (query_at < path.len)` arm reserves the query
   length, but the empty-query `else` arm reserves nothing before the shared
   suffix append. The fix adds `RESERVE(0)`.
3. Numeric elements: `RESERVE(capacity)` compared `capacity + suffix.len`
   without accounting for the NUL that `sprintf` writes after the digits;
   with `suffix.len == 0` a 20-digit `%b` writes its NUL one byte past
   `line_end`. The fix makes `RESERVE` use
   `max(suffix.len, 1)` as the required trailing space.

`expand_line_buf()` doubles from the caller's buffer size and reallocates, so
every *reserved* arm is safe; the bug is confined to the arms that omit
`RESERVE` (or under-reserve by one).

The real caller `lib/handler/access_log.c:48-56` supplies `char buf[4096]` on
the stack and passes `len = sizeof(buf)`. An over-long `error_logs` therefore
overruns a stack buffer in the live logging path. The status handler
`lib/status/requests.c:42-45` uses the same pattern.

## Local evidence (real pinned library, direct call)

Harness: `lab/frontier/h2o2shell/harness/logconf_harness.c`. It compiles the
real format string `"%{error}x"` through the pinned `h2o_logconf_compile()`,
builds a real `h2o_buffer_t` holding 80 chosen bytes `'A' + (i % 26)`, and
calls the pinned `h2o_log_request()` with a caller buffer of exactly 64 bytes.
Both pins are built from source into real `libh2o.a` (`cmake --target libh2o`),
Debug `-O0`; ASan variants use `-fsanitize=address`.

| variant | result |
|---|---|
| vuln, ASan, 80 chosen bytes | rc 1 — `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after 64-byte region`, frames `append_unsafe_string_apache logconf.c:438` ← `h2o_log_request logconf.c:843` |
| fixed, ASan, same input | rc 0; `OUT_LEN=81 REALLOCATED=1`, no report |
| vuln, plain readback | `OUT_LEN=81 REALLOCATED=0`; tail bytes `4d4e4f50...5a4142` — chosen `M..B` at offsets 0..15 past the buffer, plus the `\n` suffix at offset 16 |
| fixed, plain readback | `OUT_LEN=81 REALLOCATED=1`, tail all zero |
| vuln, safe input (8 bytes) | rc 0, `OUT_LEN=9`, tail all zero |
| fixed, safe input (8 bytes) | rc 0, `OUT_LEN=9`, tail all zero |

Rung 2 (accounting failure: 81 bytes into a 64-byte sink with no reallocation)
and rung 3 (ASan-confirmed corruption at exact pinned source lines) are
observed. Rung 4 is observed at **direct-call scope**: chosen bytes land at
chosen offsets past the caller's buffer, with a clean fixed control and clean
safe-input controls on both pins. Six normalized hashes are in
`harness/EVIDENCE_HASHES.txt`; a clean-archive replay rebuilds both pins from
`git archive HEAD` and is recorded in `harness/clean-replay.log`. Pin hashes
are in `pins/PIN_HASHES.txt`.

## Honest feasibility assessment

- **Established here:** deterministic corruption of the log-line sink through
  the pinned server library's own `h2o_log_request()`, with attacker-chosen
  bytes supplied at the `error_logs` boundary and a byte-identical fixed
  control.
- **Not established:** a live h2o process, a wire request, an actual log
  configuration containing `%{error}x`, whether a real malformed request can
  grow `error_logs` past 4096 bytes, allocator-neighbour object control,
  pointer control, command execution, and rung 5. The 64-byte sink is a
  harness choice; the stock sink is a 4096-byte stack array.
- The advisory itself says the one-byte NUL case's effect beyond a crash is
  unestablished; this brief does not claim otherwise. The `%{error}x` case is
  a multi-byte chosen write, which is stronger, but still stops at the sink
  boundary here.
- JSON escape mode (`unsafe_factor = 6`) would enlarge the overflow for
  non-printable error bytes; not separately exercised.

## Cheapest next experiment to move up a rung

Build the pinned 4212ce1 `h2o` binary (the ASan build already works), configure
an access-log format containing `%{error}x`, drive a loopback-only request that
produces a long error log, and observe whether the real 4096-byte stack buffer
overflows under ASan with request-derived bytes. That would convert the
direct-call rung 4 into a live-process, wire-triggered result. If `error_logs`
cannot be grown past 4096 bytes by a single request, the rung-4 ceiling stays
at direct-call scope and the find should be admitted with that label.

## Files

- pins: `lab/frontier/h2o2shell/pins/PIN_HASHES.txt`
- harness: `lab/frontier/h2o2shell/harness/`
- replay: `lab/frontier/h2o2shell/harness/clean-replay.sh` and `replay/`
