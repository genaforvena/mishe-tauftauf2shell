# h2o2shell — status

Admitted 2026-11-22 ~18:28Z under standing approval #6 as the 77th target
mind and 81st engine route. Charter `.mishe-tauftauf/charters/h2o2shell.md`,
seed wall `.mishe-tauftauf/walls/h2o2shell.md`; staged by frontier at commit
`4cf9784`, brief [reports/frontier-h2o2shell.md](frontier-h2o2shell.md).
Frontier's DM #1517 recorded the existing two-pane window (inner index 86,
registry 87 windows); admission adopted it and added the model route,
wake-failure signal and three units, not a duplicate window.

- Claim: CVE-2026-55368 / GHSA-m998-r5ww-rqjf, "Out-of-bounds writes in H2O
  access-log formatting", GitHub security advisory published 2026-10-23,
  High 8.1, `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`. H2O HTTP server, affected
  commit `4212ce114506a073505fd389db16ad2ba4e582a0` and earlier, fixed
  `48b7ae12107fd2b118e4641da49599e9aac8edd8` (merge of PR #3757). Claim
  URLs, fix patch and build notes in `lab/frontier/h2o2shell/PROVENANCE.md`.
- Primitive: `lib/core/logconf.c:842-843` in `h2o_log_request()` appends
  `req->error_logs->bytes` with no preceding `RESERVE`; the fix adds one.
  The real caller `lib/handler/access_log.c:48` passes a 4096-byte stack
  buffer, so a long `error_logs` can overrun it when `%{error}x` is in a
  configured access-log format. The advisory's other two cases (`%q` empty,
  numeric NUL) are source-bound from the fix hunks but not harnessed here.
- Pins: vulnerable `4212ce11…` and fixed `48b7ae12…` (git archive stream
  hashes `b7a7ac60…` / `0cf7bd8d…`, `lib/core/logconf.c` hashes
  `23dabdc7…` / `f6b0349a…`, fix patch `411c36fa…`). Operator replay from the
  repo root rechecked the commit IDs, both archive hashes, both source hashes
  and the patch hash — all matched `pins/PIN_HASHES.txt`. Running the six
  staged harness binaries and normalizing into a clean temp directory
  reproduced all six `EVIDENCE_HASHES.txt` digests byte for byte (vuln-ASan
  rc 1, other five rc 0). Frontier's clean git-archive rebuild is recorded
  in `harness/clean-replay.log` (`REPLAY_IDENTICAL=yes`).
- Grade at admission: **rungs 1/2 accounting failure, rung 3 natural ASan
  `heap-buffer-overflow WRITE of size 1` 0 bytes after a 64-byte sink at
  `append_unsafe_string_apache logconf.c:438` ← `h2o_log_request :843`,
  rung 4 chosen-byte control at DIRECT-CALL scope only.** Plain readback
  writes chosen `M..B` at offsets 0..15 past the sink plus the `\n` suffix
  at 16; the fixed pin expands and is ASan-clean; safe 8-byte inputs are
  clean on both pins. The 64-byte sink is a harness choice, not the stock
  4096-byte stack array.
- RESOLVED in W1: live process, loopback socket, wire request, configured
  `%{error}x` format, `error_logs` >4096 bytes, and chosen bytes reaching a
  control-flow-relevant stack slot (section below). Still UNKNOWN: command
  execution and rung 5, allocator-neighbour object control beyond that frame,
  live-process proof for the other two advisory cases, and independent
  witness replay.
- First bounded experiment: build the pinned vulnerable `h2o` binary
  out-of-tree with ASan, configure an affected access-log format, drive a
  loopback-only request producing a long error log and observe whether the
  real 4096-byte stack buffer faults; fixed-pin and short-request controls
  stay clean. If a single request cannot grow `error_logs` that far, record
  the direct-call ceiling as the honest grade.

## W1 live-process results (2026-11-22 18:35–18:42Z)

Both pins now build as real `h2o` executables out-of-tree with ASan
(`src/vuln/build-asan/h2o` = `2.3.0-DEV@4212ce114`,
`src/fixed/build-asan/h2o` = `2.3.0-DEV@48b7ae121`). All tests bind to
127.0.0.1 only; configs, logs and helper scripts live in
`lab/frontier/h2o2shell/live/`.

1. **Wire reach of the arm.** `live/vuln-proxy.conf` configures
   `format: '%h %l %u %t "%r" %s %b "%{error}x"'` and a reverse proxy to a
   refused port. One `curl` to 127.0.0.1:17890 returned 502 and wrote
   `[lib/core/proxy.c] in request:127.0.0.1:17890/testpath:connection refused`
   into `live/vuln-access.log`: `h2o_log_request` reaches `ELEMENT_TYPE_ERROR`
   on a real request. ~90 bytes, ASan-clean.
2. **Live stack overflow from wire bytes (pure request, no upstream).**
   `live/vuln-redirect-min.conf` configures `redirect: {status: 302,
   internal: YES, url: '//:'}` and the minimal format `'%{error}x'`. The
   redirect handler's failure message includes the request path
   (`redirect.c:46-53`, `util.c:735-793`), which is attacker-controlled.
   A single `GET /AAAA…` (5000 A's) to 127.0.0.1:17894 returned 503 and
   killed the live process with `AddressSanitizer: stack-buffer-overflow`,
   `WRITE of size 1`, frame `log_access` object `buf` [64,4160), overflow at
   frame offset 4160. Frames:
   `append_unsafe_string_apache logconf.c:438` ← `h2o_log_request :843` ←
   `log_access access_log.c:53` ← `h2o_dispose_request request.c:334` ←
   HTTP/1 cleanup. Evidence: `live/asan-redirect-min.897104`.
   A full log format containing `%r` with a 5000-byte path is *not* a fault:
   its `RESERVE` doubles the buffer to heap first (`live/vuln-redirect.conf`,
   17893, ASan-clean). The minimal format keeps `line == buf` on the stack.
3. **Live chosen-byte control.** Plain pinned binary under gdb
   (`live/gdb-redirect-min.conf`, port 17897, breakpoint `logconf.c:843`,
   pattern `'A' + (i % 26)`): `ERROR_SIZE=5137`, `LINE==POS==buf`, and after
   `h2o_log_request` returned, 64 bytes dumped from `buf+4064` are the chosen
   pattern (`42 43 44 …` = `BCD…`), i.e. request bytes at offsets 0..31 past
   the 4096-byte buffer. `bt 3` frame #1 is `0x4d4c4b4a49484746` = ASCII
   `FGHIJKLM`: chosen bytes reached the saved frame/return-address region.
   Evidence: `live/inspect-run.gdb`, `proc://gdb-live` transcript captured to
   `live/gdb-transcript.txt`.
4. **Controls.** Same 5000-A request on the fixed pin (17895) returned 503,
   wrote a 5138-byte log, produced no ASan report and left the process alive.
   Short request on the vulnerable pin (17894) was clean and left it alive.
   `bash live/replay-live.sh` reproduces all three cases: `vuln-short:
   ASAN=no`, `vuln-long: ASAN=YES` (offset 4160), `fixed-long: ASAN=no`.
5. **Additional-wire-path observation.** A lab fake FastCGI upstream
   (`live/fcgi_payload.py`, type-7 FCGI_STDERR with 5000 bytes) also produced
   a live ASan stack overflow (`live/asan-fcgi.840789`), but its long bytes
   came from a local upstream, not the HTTP request; the redirect path above
   is the stronger purely wire-driven result.

**Grade now:** rungs 1/2, 3 and 4 at live-process, wire-triggered scope;
control-flow-relevant stack slot overwritten with chosen wire bytes. Rung 5
is NOT claimed. The Apache escaper expands any byte outside 0x20..0x7c
(`"` included) to four ASCII bytes, so raw pointer bytes containing NULs or
high bytes cannot be written through `%{error}x` directly; partial overwrite
needs a gadget whose address bytes are all printable, plus argument control.
That feasibility analysis is the next bounded step, not an observed result.
