# W15 — non-ASan full-module value-less state-cookie probe

Date: 2026-11-23 16:52–16:55Z. Loopback only, 127.0.0.1:18091. Port 18090 was
in use by the witness's concurrent W170 replay and was not touched. No ASan
runtime, no shim, `LD_PRELOAD`, ptrace, `ASAN_OPTIONS` or forced execution.

## Stack and pins (`summary.txt`)

- `/usr/sbin/apache2` sha256 `8e37d897784a95b8c3402e1457a72d736cc10abf13d9666b78fecbc55849087f` (Ubuntu 2.4.58); `ldd` has no `libasan` and resolves system APR/APR-util.
- Vulnerable module from the pinned parent worktree `4301b536…`: `src/state.c` sha256 `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`, module sha256 `59d9a2f935654ba6bb2f20509b12e1c598d9246d2237fe92aeb7afda3b116701`. Built with system `/usr/bin/apxs`, no `-fsanitize`; `ldd` lists no `libasan`.
- Fixed control from released tag `v2.4.19.4`: `src/state.c` sha256 `f02d8ddb60927b9da1402c6430d179e4418ff6751ecda6c78db34424ccf77ce5`, module sha256 `704f0d5fa55c64308415a8d8b31d92230bbd3cb1f15da580f7108fd2df5375a3`, likewise non-ASan.
- jansson 2.14 / cjose 0.6.1 in `full/plain-prefix/` (built without `-fsanitize` for W14's realobj lane).

Rebuild:

```
cd lab/frontier/modauthoidc2shell/full
P="$(pwd)/plain-prefix"; export PKG_CONFIG_PATH="$P/lib/pkgconfig"
# separate worktrees of src/mod_auth_openidc at 4301b536 and cd1534e5:
# ./autogen.sh && ./configure --with-apxs=/usr/bin/apxs CFLAGS='-O1 -g -fno-omit-frame-pointer' && make -j4
bash probe-sys-native.sh && bash probe-sys-first.sh
```

## Measured (sweep, `vuln_bare_7800-results.txt` etc.)

`Cookie: mod_auth_openidc_state_<7800 a>` on `GET /protected`, 4 fresh master
starts, 12 requests each: **0/48 HTTP 302**, 11 `AH00051 ... exit signal
Segmentation fault (11)` children per start (44 logged faults; the last request
in each start returns an empty reply before its child death is logged).
Same-env controls: well-formed `<7800 a>=1` on the vulnerable module 16/16
HTTP 302, 0 faults; bare token on the released-tag module 16/16 HTTP 302,
0 faults. Raw `*-error.log`, per-start start output and `*-results.txt` are in
this directory.

Native faulting PC is **not** captured here: Apache logs the child signal,
`RLIMIT_CORE=0` in children and `core_pattern` pipes to apport. Source and
earlier gdb/ASan probes attribute the parser to pinned `state.c:214`/`:219`,
but no shim-free PC capture is claimed for this stack. The byte written remains
NUL; no chosen byte value, controlled pointer target, consumer dereference,
command or rung 5. Availability effect from one unauthenticated request on a
production allocator is demonstrated at this labeled lab scope; witness
verdict is not included.

## First request per fresh start (`*-first.txt`, `probe-sys-first.sh`)

One request only, then a 2-second wait for the child death to be logged:
bare 7800 on the vulnerable module faulted on the **first** request in 5 of 6
fresh starts (`000CURLERR` + one `AH00051` each); 1/6 returned HTTP 302 with
no fault. Well-formed 7800 on the vulnerable module 2/2 HTTP 302, no fault;
bare 7800 on the released-tag module 2/2 HTTP 302, no fault. So the crash is
driven by a single unauthenticated request but remains layout-dependent across
master starts, not deterministic per request.

## Replay note

If port 18091 is occupied, stop any prior `httpd-sys*.conf` instance first;
the scripts stop their own two configs at start and on exit. They never stop
or reconfigure the 18090 witness servers.
