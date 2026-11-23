# Wire-controlled NUL store in the full module (2026-11-23 W8)

The earlier `full/` probe proved an ASan READ fault at the pinned `:214` scan
before the NUL store at `:219`. This probe reaches the store itself and shows
its offset is chosen by the request's `Cookie` header.

## Input

`Cookie: mod_auth_openidc_state_novalue;<name>=<value>` on an unauthenticated
GET of `127.0.0.1:18090/protected`. `oidc_state_cookies_clean_expired()`
(`state.c:229`) apr_pstrdup's the whole header and `apr_strtok`s it on `;`,
leaving the second cookie's `=` in the copy after the value-less token's NUL.
The scan at `:214` crosses that NUL, stops at the `=`, and `:219` stores NUL
there. `<name>` length chooses the store offset.

## Measured

`gdb-single.txt` (one request with eight `z` padding bytes):

```
HIT addr=0x5250000745b7 before=61 (0x3d)
x/s cookie: "=V8"
AFTER addr=0x5250000745b7 val=0 (0x00)
x/s cookie: ""
#0 ... state.c:219
#1 oidc_state_cookies_clean_expired ... state.c:244
#2 oidc_request_authorization_set_cookie ... handle/request.c:132
#6 oidc_check_user_id ... mod_auth_openidc.c:1388
#7 ap_run_check_user_id ... request.c:84
```

`gdb-dump.txt` shows the arena layout at that hit: 30-byte token starting at
`0x525000074590`, its NUL at `0x…745ae`, eight `z` bytes at `0x…745af`–`0x…745b6`,
`=` at `0x…745b7`. Store offset from token start = **39 = 30 + 1 + 8**.
`gdb-dump-32.txt` with 32 `z` bytes: token at `0x525000074628`, store at
`0x525000074667`, offset **63 = 30 + 1 + 32**. The offsets are wire-chosen;
the stored byte is always NUL.

`bash ../../probe-store.sh` (from `full/`, see `summary.txt`, `codes.txt`):

```
state.c sha256: ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa
vuln dispatch=5 oob_value_peek=5
fixed dispatch=0 oob_value_peek=0
```

All ten requests returned HTTP 302. The five parent requests each dispatched
`oidc_state_cookies_process_one` with the second cookie's `V<n>` value (the
`could not parse first element separated by "."` JWT-peek warning in
`vuln-error.log`); the released-tag module dispatched none
(`fixed-error.log`). No ASan report occurred in the in-bounds second-cookie
regime. The 30-byte value-less token alone still faults on the read as in
`../README.md`.

`halt-on-error-negative.log`: a single value-less request with
`ASAN_OPTIONS=halt_on_error=0:abort_on_error=0` still produced one
`heap-buffer-overflow` READ summary at pinned `:214` and an empty reply; no
WRITE report followed. ASan's continue-after-error does not expose the store
in this build.

## Limits

- The gdb runs use `httpd -X` and exit at the end of the breakpoint command
  list, so their `curl` gets an empty reply; that is a debugger artifact. The
  sweep's 302s are the wire outcome.
- The overwritten `=` lies in the copied Cookie header, which `apr_strtok` has
  already tokenized; no pointer-bearing field is hit. No chosen byte value,
  command, marker side effect or rung 5.
- This probe is unwitnessed. W147's ESTABLISHED verdict covers the earlier
  direct-call harness only.
- Only 127.0.0.1:18090 was contacted; no external system.

Re-run: `cd lab/frontier/modauthoidc2shell/full && bash probe-store.sh` and
`bash probe-gdb.sh`. The raw gdb output is preserved in `gdb-single.txt`,
`gdb-offset-*.txt`, `gdb-base-*.txt`, `gdb-dump*.txt` and `gdb-replay-*.txt`;
the exact `-ex` command lists live in `../probe-gdb.sh`.
