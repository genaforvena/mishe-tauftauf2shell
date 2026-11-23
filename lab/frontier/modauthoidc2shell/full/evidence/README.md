# Live ASan httpd loopback probe — CVE-2026-54789 (2026-11-23)

## What this is

The first probe in this lane that uses a **real Apache httpd process, a real
listener, a real HTTP request and the full pinned parent module**. Earlier
`harness/` and `realobj/` probes called the parser directly or in-process.

## Pinned inputs and builds

- Module source: full upstream clone checked out at
  `4301b5364034191adcba5153e5870405855cb74e` (parent of fix `8017478471cc`).
  `src/state.c` sha256 `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`,
  identical to `../src/SHA256SUMS`.
- Fixed control: released tag `v2.4.19.4` (`cd1534e54875d1723949d1afa48cefef48269832`)
  in a separate git worktree.
- Both modules built with `-fsanitize=address` against the prebuilt ASan stack
  in `../../apache2shell/build/`: APR 1.7.4, APR-util 1.6.3, httpd 2.4.71.
  jansson 2.14 and cjose 0.6.1 were provisioned under `src/` and built with
  ASan into `prefix/`. `ldd` on the module resolves libasan, ASan APR/APU and
  the local jansson/cjose. Module sha256s are in `MODULE_SHA256`.
- Configs: `httpd-asan.conf` (parent) and `httpd-fixed.conf` (released fix),
  both binding `127.0.0.1:18090` only. Static provider config — no metadata
  fetch, no external network. `/protected` uses `AuthType openid-connect` and
  `Require valid-user`, so `oidc_check_user_id` → `oidc_handle_unauthenticated_user`
  → `oidc_request_authenticate_user` → `oidc_request_authorization_set_cookie`
  → `oidc_state_cookies_clean_expired` → `oidc_state_cookies_parse_token`
  runs before any authentication.

## Measured

`bash run.sh` from `full/` (30 value-less-cookie requests, 10 well-formed-cookie
requests per module; see `run-final.txt`):

```
sha256: ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa
vuln: ASan_reports=30 pinned_214=30 empty_reply=30 http302=0 dispatch=0
fixed: ASan_reports=0 pinned_214=0 empty_reply=0 http302=30 dispatch=0
```

Every parent fault is `heap-buffer-overflow` `READ of size 1` at pinned
`state.c:214` in `oidc_state_cookies_parse_token`, with the full native stack
through `ap_run_check_user_id` (see `asan-asan.log.*`). The 8192-byte region
was allocated by `apr_palloc` in `ap_parse_htaccess` — a real APR arena, not
a harness malloc. The child dies and curl gets `000`.

A separate first run (`trial-codes.txt`, `fixed-codes.txt`, `asan.log.*`,
`error_log`) was layout-dependent: 7/30 attacks faulted at pinned `:214` and
23/30 returned 302 after reaching `oidc_state_cookies_process_one` with
`mod_auth_openidc_state_novalue` — the scan had found an `=` in adjacent
arena memory and dispatched from the out-of-bounds region. All 10 safe
controls and all 30 fixed-module attacks were clean. Both outcomes are
consistent with the same dead-NULL-test scan; the fault is not asserted by
the runner because it depends on arena layout.

## Limits and later store probe

- ASan faults on the **read** before the NUL store in the value-only regime;
  `ASAN_OPTIONS=halt_on_error=0` did not continue past that fault (negative in
  `store/halt-on-error-negative.log`). The direct NUL store is measured
  separately in `store/` with a second cookie that places its `=` after the
  value-less token: gdb observed 0x3d → 0x00 at pinned `:219` with offsets 39
  and 63 chosen by 8- and 32-byte name padding. That regime writes inside the
  copied Cookie header, not into a pointer-bearing field.
- The stored byte is always NUL. No pointer control, chosen byte value,
  command execution or rung 5.
- Neither probe is witnessed; W147's ESTABLISHED verdict covers the earlier
  direct-call harness only.
- Grade: rung 3 confirmed on a real pre-auth wire path; rung 4 now also
  observed on that wire path with a wire-chosen offset, unwitnessed at that
  scope. No rung 5.
- W9 adds a `build-plain.sh` build (labelled "plain"; see W14 correction in
  `w13-native/README.md`): on the same value-less
  wire request the OOB store lands in the low byte of pointer `0x7ffff5603d`
  (→ `0x7ffff56000`) with the live pre-auth stack; no consumer read followed.
  Raw evidence and limits: `plain-oob/README.md`. W10's same-connection
  watchpoint probe found no consumer of that word in two later requests on the
  same TCP connection, and the one-off allocator trace found no covered live
  allocation (`plain-oob/keepalive/`, `plain-oob/alloc-trace/`).
- W11 reaches the second pre-auth caller (`handle/response.c:353`) with
  `GET /redirect_uri?code=foo&state=foo`: the NUL lands on the wire-chosen `=`
  of `code=foo` in the copied request line (`=foo&sta` → `\0foo&sta`), no
  watchpoint read of that word. Raw: `plain-oob/response/`.
- No chosen byte, pointer control, command or rung 5 in any regime. None of
  the live probes is witnessed; W147 covers the direct-call harness only.
- W12 swept long value-less tokens (up to 7800 bytes) over the plain module:
  an intermittent child SIGSEGV (2/3, 1/3 and 0/3 across three extended
  sweeps; 0/30 on a fresh server). A SIGSEGV-backtrace shim with libasan
  preloaded attributed the fault to pinned `state.c:219` in
  `oidc_state_cookies_parse_token` (60/60 bare faults; safe token 10/10 302;
  released tag with the same shim 10/10 302). The shim changes signal
  handling and layout; the native crash has no captured frame and no gdb run
  reproduced it. Grade unchanged. Raw and limits: `plain-crash/README.md`.
- W14 correction: the W9-W13 `build-plain.sh` module and serving httpd both
  link `libasan.so.8` (apxs injected `-fsanitize=address`; `nm -D` shows ASan
  report calls), so "plain" is not non-ASan and W13's crash ran the ASan
  allocator. The signal-11 fault and controls stand; no production-allocator
  availability claim. Detail in `PROVENANCE.md` § "Build-stack correction
  (2026-11-23 W14)".


## Re-run

```
cd lab/frontier/modauthoidc2shell/full && bash run.sh && bash probe-store.sh && bash probe-gdb.sh && bash build-plain.sh && bash probe-plain-oob.sh && bash probe-plain-detail.sh && bash probe-plain-keepalive.sh && bash probe-plain-response.sh
```
