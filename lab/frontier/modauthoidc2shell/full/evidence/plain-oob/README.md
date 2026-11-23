# Live pre-auth OOB store lands in a pointer byte (2026-11-23 W9)

Non-ASan full module, built from the pinned parent
`4301b5364034191adcba5153e5870405855cb74e` (`src/state.c` sha256
`ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`,
verified by `build-plain.sh`). The module sha256 is
`008990618887dde66e4371d1a354c64dccf29c40d36d17c4ac1d8e5f8b375654`.
Plain jansson 2.14 / cjose 0.6.1 in `full/plain-prefix`; plain httpd 2.4.70
install from `lab/frontier/apache2shell/build`. Config
`full/httpd-plain.conf`, 127.0.0.1:18090 only.

## Result

`bash probe-plain-oob.sh` with
`Cookie: mod_auth_openidc_state_novalue` on `/protected` breaks at pinned
`state.c:219` with the live pre-auth stack:

```
oidc_state_cookies_parse_token (state.c:219)
oidc_state_cookies_clean_expired (state.c:244)
oidc_request_authorization_set_cookie (handle/request.c:132)
oidc_request_authenticate_user (handle/request.c:239)
oidc_handle_unauthenticated_user (mod_auth_openidc.c:516)
oidc_check_userid_openidc (mod_auth_openidc.c:1325)
```

At the breakpoint the store address is `0x7ffff6de2221` and the byte there
is `0x3d`. The eight bytes at that address are
`3d 60 f5 ff ff 7f 00 00`, i.e. the low byte of the 8-byte pointer
`0x00007ffff5603d`. After `next` the byte is `0x00` and the pointer is
`0x00007ffff56000`. The store is out of bounds: the header copy's token is
NUL-terminated before this address and the scan walked past it until it met
the `0x3d` byte.

`bash probe-plain-detail.sh` shows the pointer's target bytes are all zero
(`x/32cb` at `0x7ffff5602d`) inside the anonymous rw mapping
`0x7ffff5157000-0x7ffff5e00000` (the OIDC shared-memory cache region),
and a hardware watchpoint on the corrupted 8-byte word caught no read or
write after the store before the 60-second gdb timeout. `details.txt` has
the raw output; `live-plain.txt` has the before/after proof.

Non-debugger control: the same request returns HTTP 302 on the plain module,
as does a well-formed `mod_auth_openidc_state_abc=1` cookie. The value-less
request produces an empty reply under gdb only because the debugger stops
the child at the breakpoint.

## Limits / grade

- Plain build, not ASan: the ASan module faults on the READ at pinned `:214`
  before any store, so no ASan WRITE is available here.
- gdb disables ASLR; the absolute addresses are lab-layout facts, not a
  portable primitive. Zero-pool-fill harness `realobj/` showed the same
  pointer-low-byte target shape (script `realobj/probe-oob-target.sh`).
- The byte is always NUL and the pointer target is not wire-chosen; the
  wire chooses only whether the scan runs out of bounds (value-less token).
- No consumer read of the corrupted pointer was observed; no chosen byte,
  no chosen pointer, no command and no rung 5. This is rung 4 scoped,
  observed on a live pre-auth wire path, unwitnessed at that scope.

Replay: `cd lab/frontier/modauthoidc2shell/full && bash build-plain.sh &&
bash probe-plain-oob.sh && bash probe-plain-detail.sh &&
bash probe-plain-second.sh`.

## Second-request check (2026-11-23 W9)

`bash probe-plain-second.sh` arms a hardware watchpoint on the corrupted word
after the store and lets the pre-fork child accept another loopback request.
The watchpoint fires inside `libapr-1.so.0` from `apr_socket_accept` →
`ap_unixd_accept` (`unixd.c:303`), with old value `0x7ffff56000` (exactly the
pointer produced by the NUL store) and new value `0` (`second.txt`). The
corrupted word belongs to the connection's `ptrans` region near
`0x7ffff6de2028`, not to a long-lived config object; the next accept clears
it. No read of the corrupted pointer was observed, and no cross-request side
effect was measured. HTTP codes in that script are timing-dependent because
gdb stops the child; use the non-gdb controls above for request outcomes.

