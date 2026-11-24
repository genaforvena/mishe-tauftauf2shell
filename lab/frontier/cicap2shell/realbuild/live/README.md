# W3 — real c-icap server on loopback (2026-11-24 19:0xZ)

This lane puts a loopback TCP socket in front of the *actual* `c-icap` server
binary built from the pinned `C_ICAP_0.6.5` tag under ASan. Unlike W1/W2, the
request goes through the server's own `ci_read_icap_header()`,
`parse_header()` (request.c:501), `process_encapsulated()` and
`process_request()` (request.c:1722). The ASan allocation stack in every
attack run records that chain explicitly.

## Setup

The two build trees are the W1 vulnerable ASan build and the patch-derived
fixed build described in `../README.md` and `../../PROVENANCE.md`. The build
already contains `c-icap` (libtool wrapper), `services/echo/.libs/srv_echo.so`
and the server's own `request.c` objects. A minimal config needs
`CommandsSocket` (otherwise startup aborts) and `ServicesDir` (not
`ModulesDir`) for the echo service; all paths are under /tmp and all binds
are 127.0.0.1 only. `run.sh` writes that config and starts the server with
`-N -S -D` (foreground, single process, debug on stdout).

## Replay

```
cd lab/frontier/cicap2shell/realbuild/live
sh run.sh /tmp/cicap-real/build-asan 1350 vuln-reqmod attack 90 100
sh run.sh /tmp/cicap-real/build-asan 1351 vuln-options options 4242 100
sh run.sh /tmp/cicap-real/build-fixed 1352 fixed-reqmod attack 90 100
sh run.sh /tmp/cicap-real/build-fixed 1353 fixed-options options 4242 100
sh run.sh /tmp/cicap-real/build-asan 1354 vuln-safe safe x 100
sh run.sh /tmp/cicap-real/build-asan 1355 vuln-valid valid x 100
```

`run.sh` prints client output, sends SIGTERM after the request and reports
`ASAN=YES|NO`. Raw server/client output is in gitignored
`../../evidence/live-*.out`. Sixth argument is
`MaxRequestsReallocateMem`; 100 is the compiled stock default, 0 forces
`ci_request_destroy()` immediately after the request.

## Observed (author-run, 127.0.0.1 only)

- REQMOD, six `req-body` entities, sixth offset 90 or 4242: client receives
  `ICAP/1.0 400 Bad request` (check_request rejects `entities[2]` for
  REQMOD), and the server reports ASan `heap-use-after-free`, `READ of size 4`
  at `destroy_encaps_entity header.c:631` from `ci_request_destroy
  request_common.c:417`. With `MaxRequestsReallocateMem 0` the free pair is
  at `mpmt_server.c:689` (`thread_main`); with the stock 100 it fires on
  graceful shutdown at `mpmt_server.c:211` (`release_thread_i`). Allocation
  stack: `mk_encaps_entity header.c:616` <- `ci_request_alloc_entity
  request_common.c:200` <- `process_encapsulated request_common.c:507` <-
  `parse_header request.c:529` <- `do_request request.c:1584` <-
  `process_request request.c:1730` <- `thread_main mpmt_server.c:639`.
- OPTIONS with six entities, sixth offset 4242 and `Connection: close`:
  client receives `ICAP/1.0 200 OK`, and the same UAF follows on shutdown.
  This is the well-formed success-response variant; OPTIONS skips
  `check_request()`'s REQMOD entity count check.
- OPTIONS with the same six entities but *without* `Connection: close`:
  200 OK and a clean shutdown. The keepalive loop calls
  `ci_request_reset()`, which moves the aliased entity out of `entities[5]`
  before teardown; the alias is no longer double-destroyed. Negative
  preserved, not a contradiction.
- Four-entity REQMOD: 400, clean. One-entity REQMOD with a zero chunk:
  200 OK, clean. Patched fixed build, same attack and OPTIONS inputs: clean
  with both reallocation settings.

## Ceiling

The wire value selects the sixth entity's start offset; W1/W2 measured that
value in the live aliased `trash_entities[0].start` slot. This W3 lane adds a
real server and the full parse path, but the server logs do not print that
slot, so no new value-control observation is claimed here. Still no
pointer/IP/command control, no allocator-metadata shaping, no marker and no
r5. Graceful shutdown or `MaxRequestsReallocateMem 0` is the observed
teardown condition; ordinary long-lived keepalive traffic can clear the
alias first. Witness replay of W1/W2/W3 is outstanding.

## W4 — observe the wire value in the live aliased slot (21:0xZ)

`observe.sh` runs the same unmodified binaries under gdb, breaking just
after the sixth entity store (`request_common.c:513` vulnerable, `:515`
fixed) and printing `entities[5]` and `trash_entities[0]` before continuing.
No memory writes, no forced calls. Example:

```
sh observe.sh /tmp/cicap-real/build-asan 1361 opt4242 options 4242 513 0
sh observe.sh /tmp/cicap-real/build-asan 1362 opt90 options 90 513 0
sh observe.sh /tmp/cicap-real/build-asan 1363 safe safe x 513 0
sh observe.sh /tmp/cicap-real/build-fixed 1364 fixed options 4242 515 0
```

Attack values 4242 and 90 print `alias=1` with matching `t0_start`; both
return 200 OK and then hit the `header.c:631` UAF. Four-entity and
patch-derived fixed runs print `e5=(nil) t0=(nil)` with ASAN=NO. Raw output
is in gitignored `../../evidence/w4-*.out`. This is the rung-4 measurement
missing from W3, still bounded by the ceiling above: no pointer/IP/command
control, no proxy, no r5.
