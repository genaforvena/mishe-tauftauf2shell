# Long value-less state token: intermittent plain-module fault (2026-11-23 W12)

All probes use 127.0.0.1:18090, an unauthenticated `GET /protected`, and the
same pinned parent module as W9 (`state.c`
`ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`, module
`008990618887dde66e4371d1a354c64dccf29c40d36d17c4ac1d8e5f8b375654`).
The fixed control is released `v2.4.19.4` built against the same plain
httpd/APR stack (`state.c` `f02d8ddb60927b9da1402c6430d179e4418ff6751ecda6c78db34424ccf77ce5`,
module `b16278d2a4ee942d900a5712673e40260a7ace2199e00469f85b62adda5b98ff`).

## What was tried

- `probe-plain-crash.sh`: four Cookie regimes (`bare` value-less token,
  `second` with `;tail=value`, `safe` with `=1`, `filler` with six more
  value-less tokens) at token-name lengths 1/16/128/1024/4096/7800, three
  trials each, normal multi-child daemon, no debugger.
- `probe-plain-crash-7800.sh`: 30 bare-7800 requests against a fresh server.
- `probe-plain-crash-gdb.sh` (both with gdb's default ASLR-off and with `set
  disable-randomization off`) and `probe-plain-crash-fork-gdb.sh` (gdb follows
  a forked child, ASLR on) to capture a frame without changing the request.
- `catchsegv.c` + `probe-plain-crash-sigsegv.sh`: a lab-only `sigaction`
  interposer that installs a backtrace handler for SIGSEGV, with
  `libasan.so.8` preloaded first (this httpd links ASan). It changes signal
  handling and allocation layout; it is an instrument, not the unmodified
  module's native behavior.
- `probe-plain-fixed-crash.sh` and `probe-plain-fixed-sigsegv.sh`: released-tag
  controls without and with the same shim.

## Observed

- Unmodified plain module, extended sweep: the 14:06Z run faulted two children
  on bare-7800 (`AH00051 … exit signal Segmentation fault (11)`; see
  `FIRST-RUN-20261123T1406Z.md`). A 14:14Z replay faulted one child on bare
  7800 trial 2: `bare n=7800 trial=2 code=000CURLERR` in the clean 72-line
  `codes.txt`, and `AH00051: child pid 1242672 exit signal Segmentation fault
  (11)` at line 1823 of that run's `error.log`. A second 14:14Z replay faulted
  none. `codes-accumulated-three-runs.txt` preserves the earlier appended
  log. The crash is therefore **intermittent**, not a deterministic primitive.
- Fresh-server bare-7800: 30/30 HTTP 302, zero faults (`freq-*`).
- Under gdb: 6/6 HTTP 302 with ASLR off, 6/6 with ASLR on (`gdb-*`); 40/40
  HTTP 302 following a fork (`fork-*`). No SIGSEGV stop in any debugger run.
- With the SIGSEGV shim: 60/60 bare-7800 requests faulted, each with a
  backtrace; the well-formed `mod_auth_openidc_state_<7800 a's>=1` control on
  the vulnerable module returned 302 on 10/10 (`sigsegv-safe-*`). The top
  module frame is `oidc_state_cookies_clean_expired+0x2b3`, which `addr2line`
  resolves to `oidc_state_cookies_parse_token` at pinned `state.c:219`; the
  live stack continues through `oidc_check_user_id` → `ap_run_check_user_id`
  → `ap_process_request_internal`. This attributes the fault to the pinned
  parser, but the shim's signal interposition and libasan preload are
  required to make it deterministic, so it does not upgrade the native crash
  rate above.
- Released tag: 10 bare-7800 + 10 safe-7800 requests clean without the shim
  (`fixed-*`); 10 bare-7800 requests with the shim returned 302 on 10/10 with
  zero backtraces (`fixed-sigsegv-*`).

## Grade and limits

No change: rung 3 confirmed on a real pre-auth wire path (ASan stack), rung 4
scoped and unwitnessed at live-wire scope. The intermittent native child fault
has no captured frame; the shimmed fault has a frame but changes signal
handling and allocator layout. Byte is still always NUL; no chosen byte,
pointer target, consumer dereference, command or rung 5. gdb disables ASLR in
those runs; absolute addresses are lab-layout facts.

## Replay

```
cd lab/frontier/modauthoidc2shell/full
bash build-plain-fixed.sh
bash probe-plain-crash.sh
bash probe-plain-crash-7800.sh
bash probe-plain-crash-sigsegv.sh
bash probe-plain-fixed-sigsegv.sh
```
