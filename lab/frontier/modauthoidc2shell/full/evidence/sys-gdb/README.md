# W16 — native faulting PC for the non-ASan full-module crash

Date: 2026-11-23 18:03Z. Loopback only, 127.0.0.1:18091. Port 18090 untouched.
No shim, `LD_PRELOAD` or `ASAN_OPTIONS`. `gdb` was attached **only to observe**
a fault that W15 already showed occurs natively (Apache `AH00051` child
SIGSEGV with no debugger); ASLR was left on (`set disable-randomization off`).
A debugger changes process layout, so this is a native PC observed under ptrace,
not a claim about the exact address in a non-debugger run.

## Stack and pins (`summary.txt`, replayed by `probe-sys-gdb.sh`)

- `/usr/sbin/apache2` sha256
  `8e37d897784a95b8c3402e1457a72d736cc10abf13d9666b78fecbc55849087f`
  (Ubuntu 2.4.58), system APR, no `libasan`.
- Vulnerable module from pinned parent worktree `4301b536…`: `src/state.c`
  sha256 `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`,
  module sha256
  `59d9a2f935654ba6bb2f20509b12e1c598d9246d2237fe92aeb7afda3b116701`.
- Fixed control from released tag `v2.4.19.4`: module sha256
  `704f0d5fa55c64308415a8d8b31d92230bbd3cb1f15da580f7108fd2df5375a3`.
- gdb 15.1; `set follow-fork-mode child`, `set detach-on-fork on`,
  `handle SIGSEGV stop print nopass`, `run -f <conf> -DFOREGROUND`.

## Measured

Bare `Cookie: mod_auth_openidc_state_<7800 a>` on `GET /protected` on each
fresh gdb start: **4/4** vulnerable starts stopped on SIGSEGV with a captured
PC; well-formed `<7800 a>=1` on the vulnerable module 0/1 catches (6/6 HTTP
302), bare token on the released tag 0/1 catches (6/6 HTTP 302). The first
request of each vulnerable start got an empty reply; the script issues further
requests until gdb's buffered stop line is visible (4 in each stop). Full
native stack in each `vuln_bare_7800-N-gdb.txt`:

```
#0  oidc_state_cookies_parse_token (...) at src/state.c:219
#1  oidc_state_cookies_clean_expired (...) at src/state.c:244
#2  oidc_request_authorization_set_cookie (...) at handle/request.c:132
#4  oidc_handle_unauthenticated_user (...) at mod_auth_openidc.c:516
#6  oidc_check_user_id (...) at mod_auth_openidc.c:1388
#7  ap_run_check_user_id ()  ...
```

The faulting frame is the **NUL store**, not the OOB read: source line
`state.c:219` (`*cookie = '\0';`), instruction `movb $0x0,(%rax)`. With
`-O1 -g`, gcc inlined the parser into `oidc_state_cookies_clean_expired`, so
the symbol on `$pc` is `oidc_state_cookies_clean_expired+265` while gdb's line
table attributes it to `oidc_state_cookies_parse_token` at pinned `:219`.

The scan stopped at an `=` byte found outside the request token and the write
then faulted. `info proc mappings` in each transcript locates the target:
starts 2 and 3 faulted in read-only `r--p` library pages (`libresolv.so.2`,
`libbrotlicommon.so.1.1.0`) immediately after a writable/shm mapping; starts
1 and 4 faulted in unmapped gaps. The `=` byte and its address come from
adjacent process memory, not from the client. The client chooses only the
token length and the value NUL.

## Limits

The PC is native (no signal shim, preload or sanitizer), but observed with gdb
attached; W15's non-debugger crashes remain the availability claim. The
4/4 catch rate under gdb differs from W15's 5/6 first-request rate — small
samples on a layout-dependent fault, not a contradiction. The byte written is
always NUL; no chosen byte, controlled pointer target, consumer dereference,
command or rung 5. Author-only, unwitnessed at this scope.

Replay: `cd full && bash probe-sys-gdb.sh`. Raw per-start gdb transcripts,
codes, error logs and hashes are in this directory.
