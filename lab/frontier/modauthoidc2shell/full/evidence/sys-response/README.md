# W19 — OOB NUL store through the response caller (non-ASan stack)

Date 2026-11-24 02:16Z. Loopback `127.0.0.1:18091` only; 18090 untouched.
No shim, `LD_PRELOAD`, ptrace or `ASAN_OPTIONS`. This is the first long-token
sweep through the **second** pre-auth caller `handle/response.c:353`; W11
reached that caller only with an in-bounds second cookie and W12-W16 drove OOB
only through `handle/request.c:132`.

Replay: `cd lab/frontier/modauthoidc2shell/full && bash probe-sys-response.sh`.

## Pins (`summary.txt`)

- `/usr/sbin/apache2` Ubuntu 2.4.58 sha256
  `8e37d897784a95b8c3402e1457a72d736cc10abf13d9666b78fecbc55849087f`,
  system APR, no `libasan` in the module (`ldd`: apr, aprutil, libcjose,
  libjansson from `plain-prefix`).
- Vulnerable module sha256
  `59d9a2f935654ba6bb2f20509b12e1c598d9246d2237fe92aeb7afda3b116701`
  (pinned parent `state.c` `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`).
- Released-tag control sha256
  `704f0d5fa55c64308415a8d8b31d92230bbd3cb1f15da580f7108fd2df5375a3`.

## Measured (`*-results.txt`, `*-codes.txt`)

Request `GET /redirect_uri?code=foo&state=foo`. Short value-less token
`mod_auth_openidc_state_novalue`: vulnerable 3/3 and fixed 3/3 HTTP 400, each
with 3 `oidc_response_proto_state_restore: enter` log lines — the response
caller is genuinely reached on both modules.

Bare 7800-byte value-less token: vulnerable start 1 had 7 `AH00051`/exit-signal
child faults and 8/8 failed connections; vulnerable starts 2-4 had 0 faults
and 8/8 HTTP 400 each. Well-formed 7800-byte `...=1` token: 0 faults, 16/16
400 across two starts. Released tag with the bare token: 0 faults, 16/16 400
across two starts. The first-start bimodality matches W15/W16's layout-dependent
rate and is not a contradiction.

## Limits

Fault attribution is not in this sweep (no debugger here); see
`../sys-response-gdb/README.md` for the native PC. The byte written is always
NUL and the stopping `=` comes from adjacent process memory, not the client.
No chosen byte, pointer control, consumer dereference, command or rung 5.
Author-only and unwitnessed at this scope; grade unchanged.
