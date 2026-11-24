# W19 — native faulting PC on the response caller (non-ASan stack)

Date 2026-11-24 02:17Z. Loopback `127.0.0.1:18091` only. Same system-httpd /
system-APR non-ASan stack and module hashes as `../sys-response/README.md`.
gdb is attached **only to observe** a fault that the sweep already shows
occurs natively; ASLR left on (`set disable-randomization off`),
`follow-fork-mode child`, `handle SIGSEGV stop print nopass`. No shim,
`LD_PRELOAD` or `ASAN_OPTIONS`. A start that does not fault under gdb is a
negative result, not forced execution.

Replay: `cd lab/frontier/modauthoidc2shell/full && bash probe-sys-response-gdb.sh`.

## Measured

`GET /redirect_uri?code=foo&state=foo` with a bare 7800-byte value-less state
cookie: vulnerable start 1 caught 1 native SIGSEGV (4 requests all failed);
vulnerable starts 2 and 3 caught none (8/8 HTTP 400 each); released-tag control
0 catches (6/6 HTTP 400). The native PC in
`vuln_bare_7800-1-gdb.txt` is `0x7ed17ed2cbc2`, raw symbol
`oidc_state_cookies_clean_expired+265`, with the instruction

```
=> movb $0x0,(%rax)
```

and gdb's line table attributing it to `oidc_state_cookies_parse_token` at
pinned `state.c:219` — the NUL **store**, not the OOB read. Full pre-auth stack:

```
#0  oidc_state_cookies_parse_token          state.c:219
#1  oidc_state_cookies_clean_expired        state.c:244
#2  oidc_response_proto_state_restore       handle/response.c:353
#3  oidc_response_match_state               handle/response.c:426
#4  oidc_response_process                   handle/response.c:614
#5  oidc_response_authorization_redirect    handle/response.c:765
#6  oidc_handle_redirect_uri_request        mod_auth_openidc.c:1056
#7  oidc_check_userid_openidc_redirect_uri  mod_auth_openidc.c:1258
#8  oidc_check_userid_openidc               mod_auth_openidc.c:1309
#9  oidc_check_user_id                      mod_auth_openidc.c:1388
#10 ap_run_check_user_id
```

The stopping `=` byte was at `0x7ed17eb17395`; `info proc mappings` places it
in a read-only `r--p` page of `libcom_err.so.2.1`
(`0x7ed17eb17000-0x7ed17eb19000`). The store faulted because the page is not
writable. That address and byte come from adjacent process memory, not from
the client.

## Limits

The PC is native but debugger-observed; non-debugger crashes remain the
availability claim from the sweep. The byte is always NUL; the client chooses
only the length. No chosen byte, pointer control, consumer dereference,
command or rung 5. Author-only and unwitnessed at this scope; grade unchanged.
