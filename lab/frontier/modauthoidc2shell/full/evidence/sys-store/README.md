# W17 — wire-chosen NUL store on the genuinely non-ASan full module

Date: 2026-11-23 22:16Z. Loopback only, 127.0.0.1:18091; port 18090 untouched.
Same binaries as W15/W16: system Ubuntu httpd 2.4.58
(`8e37d897784a95b8c3402e1457a72d736cc10abf13d9666b78fecbc55849087f`,
system APR, no `libasan`), pinned-parent module
`59d9a2f935654ba6bb2f20509b12e1c598d9246d2237fe92aeb7afda3b116701`
(`state.c` `ceedb687…5aa`) and released-tag control
`704f0d5f…f5375a3`. No shim, `LD_PRELOAD`, `ASAN_OPTIONS` or forced
execution. gdb is used only to read the byte at pinned `state.c:219` before
and after the store.

## Measured (`summary.txt`, raw logs alongside)

Request: `Cookie: mod_auth_openidc_state_novalue;<name>=<value>` on
`GET /protected`. Sweep over `<name>` lengths 1/4/8/16/32: all five returned
HTTP 302 on **both** modules; the vulnerable module logged five
`oidc_state_cookies_process_one` dispatches and five value decodes of the
second cookie, the released tag logged zero of each. No child fault in either
error log. This is the in-bounds regime first measured with the ASan module in
W8, now reproduced on the production-allocator stack.

gdb at pinned `:219` with `Cookie: …novalue;zzzzzzzz=V8`:

```
STORE=0x7ffff7b16287 before=0x3d   cookie printed as "=V8"
AFTER=0x7ffff7b16287 after=0x00
```

The 112-byte dump places the header at `0x7ffff7b16260`, so the store is at
token offset **39 = 30 + 1 + 8**. With 32 `z` bytes the store is
`0x7ffff7b1630f` (token start `0x7ffff7b162d0`), offset **63**. Both stops
carry the live pre-auth stack `ap_run_check_user_id` → `oidc_check_user_id`
(`mod_auth_openidc.c:1388`) → `oidc_check_userid_openidc` →
`oidc_handle_unauthenticated_user` →
`oidc_request_authorization_set_cookie` (`handle/request.c:132`) →
`oidc_state_cookies_clean_expired` (`state.c:244`) → pinned `:219`.
The client chooses the stop byte's offset by padding length; gdb curl requests
report `000CURLERR` because the breakpoint stops the child before it replies.

## Limits

The overwritten `=` is inside the apr_pstrdup'd Cookie header copy: an
in-bounds byte with no pointer-bearing target. The byte written is always NUL;
only its offset is wire-chosen. No chosen byte value, controlled pointer,
consumer dereference, command, marker or rung 5. Addresses are lab-layout facts
under gdb; they are not a claim about non-debugger addresses. Author-only and
unwitnessed at this scope. Replay: `cd lab/frontier/modauthoidc2shell/full &&
bash probe-sys-store.sh` (scripts stop only their own 18091 configs).
