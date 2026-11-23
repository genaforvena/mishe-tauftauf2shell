# Provenance — modauthoidc2shell harness (W139, 2026-11-23)

## Pinned inputs

Provisioned in W138 and re-verified on every run by `src/SHA256SUMS`
(from byte-exact upstream blobs; git blob ids recorded in
`reports/frontier-modauthoidc2shell.md`):

| file | sha256 | origin |
| --- | --- | --- |
| `src/state.c.4301b536` | `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa` | parent of fix `8017478` (blob `0122cde...`) |
| `src/state.c.8017478` | `3492207546885aae00363de14b30947ce73c48b8361b33516d95fc6df774c1cc` | fix commit blob `92bd078...` |
| `src/state.c.v2.4.19.4` | `f02d8ddb60927b9da1402c6430d179e4418ff6751ecda6c78db34424ccf77ce5` | released fixed tag blob `13009c17...` |
| `src/fix-8017478.patch` | `d8ae4b4e8cda366a985368bd885591d2aaa702b463d989b140a9621a226b3e38` | `git show 8017478471cc` |

`harness/SHA256SUMS` covers `driver.c`, `run.sh`, the six extracted slices and
the four pins (12 files). The runner checks both manifests before building.

## Verbatim slices re-extracted per run by `harness/run.sh`

| slice | vulnerable blob lines | fix-commit lines | release-tag lines |
| --- | --- | --- | --- |
| `state_struct.inc` | 105-110 | 105-110 | 105-110 |
| `parse_token.inc` | 204-223 | 204-226 | 204-226 |

Each slice begins with a `#line` directive naming the pinned blob; the ASan
stack reports pinned line **214** (the unbounded `while`), not the driver line.
The driver adds only host scaffolding: opaque `request_rec` / `oidc_cfg_t`,
the `OIDC_CHAR_*` constants, a `strstr` stand-in for `_oidc_strstr`, a prefix
getter, and a `oidc_state_cookies_process_one()` recorder. No upstream parser
logic is reimplemented.

## Harness inputs and stubs

- `vtoken = "mod_auth_openidc_state_novalue"` (30 bytes); the attacker can
  supply exactly this shape in a `Cookie` header before authentication.
- `asan-read`: `malloc(31)` holds the token and its NUL. The fixed loop stops
  at the NUL; the vulnerable loop reads byte 31, one past the object, giving ASan
  `READ of size 1` in the verbatim slice. gcc + clang.
- `eqscan [gap]`: one 512-byte block contains the token at offset 0, its logical
  NUL at offset 30, an `=` at `30+gap`, and a canary `Z` at offset 400. Plain
  builds observe the resulting NUL store at offsets 31, 47 and 63 for gaps
  1, 17 and 33. The value written is always NUL — there is no chosen byte value.
- `safe`: `mod_auth_openidc_state_abc=1` with the `=` inside the object; run on
  all six binaries.
- Fixed-commit and released-tag slices reject the value-less token with `RC=0`
  and `PROCESS_CALLS=0`; their `=` byte stays `0x3d` and ASan is clean.

## Observations

- `bash lab/frontier/modauthoidc2shell/harness/run.sh`: **59 PASS / 0 FAIL** on
  three consecutive runs, identical
  `TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`
  (`evidence/run1.txt`..`run3.txt`, raw modes in `evidence/*.out`).
- Clean-directory replay (`cp` of `src/` plus `driver.c`, `run.sh` and
  `SHA256SUMS` to a fresh `/tmp` directory, no repository context):
  `PASS=59 FAIL=0`, same hash (`evidence/replay.txt`,
  `evidence/replay-normalized.txt`).
- Clean `git archive HEAD lab/frontier/modauthoidc2shell` replay after handoff
  commit `05acfc6`: `PASS=59 FAIL=0`, same hash
  (`evidence/git-archive-replay.txt`).
- Rung 1: advisory arithmetic with no vulnerable call — prefix, valueless
  token, dead NULL test, NUL index 30, predicted write offset 47.
- Rung 2: the vulnerable slice scans past the token, overwrites the adjacent
  `=` with NUL and dispatches `PROCESS_CALLS=1`; both fixed slices reject.
- Rung 3: gcc + clang ASan `READ of size 1`, 0 bytes after a 31-byte region, in
  `oidc_state_cookies_parse_token` at pinned `state.c.4301b536:214`.
- Rung 4 (scoped): NUL store at the three chosen offsets; the canary is intact,
  proving a single-byte write rather than a length-driven overwrite. The
  address is chosen by the harness block layout, not by a wire field.


## Ceiling / negatives of the direct-call harness

- The stubbed harness has no Apache, APR pool, request object, listener,
  socket or off-loopback probe; the scanner is called with stubbed request/config
  pointers. The separate real-object probe below covers the APR-pool follow-up.
- The exact-size heap token is a harness instrument, not a measured allocation.
- In that harness the ASan read necessarily faults before any write, so an
  ASan WRITE of the NUL store is not available there; the NUL store is measured
  in the plain build. The real-object probe below did observe an ASan WRITE
  fault at pinned line 219 in some layouts.
- Only the *offset* of the NUL is controllable; the byte value is fixed. No
  pointer-bearing state, chosen command or rung 5. W147 witnessed rungs 1-3
  and scoped rung 4 ESTABLISHED at this scope; the probe below is unwitnessed.

## Re-run

```
cd lab/frontier/modauthoidc2shell/harness && bash run.sh
```

## Real-object APR/Apache probe (2026-11-23, W4)

`realobj/driver.c` keeps the struct and parser slices verbatim from the three
pinned blobs and replaces the stubs with a real `apr_pool_t`, a zeroed real
Apache `request_rec` (`r->pool`, `r->headers_in`), a real `apr_table_t` Cookie
header, a real `apr_pstrdup()` token and a real `apr_strtok()` split. The
prefix getter and `oidc_state_cookies_process_one()` recorder remain local
stand-ins. This is **not** a full module build: no complete mod_auth_openidc
tree is present locally and jansson development headers are absent; there is no
Apache process, listener, socket, wire or OIDC config.

`realobj/SHA256SUMS` covers `driver.c`, `run.sh` and the six generated slices;
`src/SHA256SUMS` is checked again on every run. The runner builds six gcc
variants (plain and ASan for parent, fix, release), then runs 20 parent ASan
reads (fills 0/512/4000/8000, five trials each), 10 fix and 10 release ASan
reads, and nine plain writes (gaps 1/17/33 x three variants). Raw logs are
`realobj/evidence/raw-trials.txt`; normalized trace and counts are
`normalized.txt` and `summary.txt`; console logs are `run6-console.txt` and
`run7-console.txt`.

Measured on two consecutive runs: **PASS=17 FAIL=0** each. Parent ASan
outcomes were layout-dependent under ASLR — run6: 15 fault summaries at pinned
`state.c.4301b536:214` (READ-class `unknown-crash`), 1 `SEGV` summary at pinned
`:219` reported by ASan as caused by a **WRITE** memory access, 4 trials
dispatched; run7: 9 / 3 / 8. Across trials `__asan_address_is_poisoned()` found
the first poisoned byte 95 bytes past the 30-byte token, never at its end: a
real APR arena has no per-object redzone, so the scan continues until it hits
an arena edge, an adjacent `=` (then dispatches) or an unmapped/protected page.
One full log in `raw-trials.txt` shows the WRITE fault stack at pinned line
219, which was unavailable in the exact-size-malloc harness.

Plain-build parent writes in the real arena placed `=` at token length + gap
and measured NUL at offsets 31, 47 and 63 for gaps 1, 17, 33, with
`PROCESS_CALLS=1`; the `=` position is still a harness placement, not a chosen
wire field. Fix and release slices rejected the value-less token in all 10
trials each (`RC=0`, `PROCESS_CALLS=0`) with no ASan report. Grade unchanged:
rung 4 **scoped**, now with real APR/Apache objects; no pointer control, chosen
byte value, command, rung 5 or independent witness verdict for this probe.

Clean `git archive HEAD lab/frontier/modauthoidc2shell` replay at 07:25Z
returned rc 0 and `PASS=17 FAIL=0` (14 READ-class faults, 0 WRITE faults,
6 dispatches). The WRITE fault is layout-dependent and is deliberately not
asserted by the runner.

Re-run: `cd lab/frontier/modauthoidc2shell/realobj && bash run.sh`.

## Full-module ASan httpd loopback probe (2026-11-23 W6)
`full/` provisions the complete parent module at
`4301b5364034191adcba5153e5870405855cb74e` (`src/state.c` sha256
`ceedb687…5aa`, matching `src/SHA256SUMS`), jansson 2.14, cjose 0.6.1 and a
released-tag `v2.4.19.4` control worktree. Both modules were built with
`-fsanitize=address` against the prebuilt ASan APR 1.7.4 / APR-util 1.6.3 /
httpd 2.4.71 stack in `../../apache2shell/build/`; configs bind only
`127.0.0.1:18090`. Full recipe, hashes and limits: `full/evidence/README.md`.

Reachable path confirmed in source, not inferred: `src/state.c:229`
`oidc_state_cookies_clean_expired()` apr_pstrdup's the whole Cookie header,
`apr_strtok`s it and calls `oidc_state_cookies_parse_token()` on each token;
`src/handle/request.c:132` calls it from `oidc_request_authorization_set_cookie()`
at `request.c:239`, reached from `oidc_check_user_id` for an unauthenticated
request to a protected `/Location`. `handle/response.c:353` is the callback path.

`cd full && bash run.sh` (final run, `evidence/run-final.txt`): parent
30/30 ASan `READ of size 1` faults at pinned `state.c:214`, full stack through
`ap_run_check_user_id`, 30/30 empty replies; released fix 0/30 ASan reports,
30/30 HTTP 302, no dispatch. First manual run
(`evidence/trial-codes.txt`, `asan.log.*`, `error_log`) was layout-dependent:
7/30 faults and 23/30 dispatches of `mod_auth_openidc_state_novalue` from the
out-of-bounds region; 10/10 safe controls clean. The 8192-byte overflowed
region is a real APR arena allocated in `ap_parse_htaccess`, not a harness
malloc. ASan faults before the NUL store, so no ASan WRITE here; no chosen
byte, pointer control, command or rung 5. Grade unchanged: rung 3 on a real
pre-auth wire path; rung 4 scoped. Unwitnessed.

## Wire-chosen NUL store in the full module (2026-11-23 W8)

`full/probe-store.sh` and `full/probe-gdb.sh` extend the live probe with
`Cookie: mod_auth_openidc_state_novalue;<name>=<value>`. `apr_strtok` leaves
the second cookie's `=` after the value-less token's NUL in the copied header,
so the pinned `:214` scan reaches it in bounds and `:219` stores NUL there.
Raw output: `full/evidence/store/`; summary `store/README.md`.

gdb at pinned `:219` observed `cookie=0x5250000745b7` holding `0x3d` before the
`next` and `0x00` after, with the live stack through `ap_run_check_user_id`
(`store/gdb-single.txt`). Arena dumps give token start `0x525000074590` and
store `0x5250000745b7` (offset 39 = 30 + 1 + 8) for eight `z` bytes, and
token start `0x525000074628`, store `0x525000074667` (offset 63 = 30 + 1 +
32) for 32 `z` bytes (`store/gdb-dump*.txt`). The offset is wire-chosen by
`<name>` length; the byte value is always NUL.

Sweep (`store/summary.txt`, `codes.txt`): five lengths 1/4/8/16/32 all HTTP
302 on both modules; parent dispatched `oidc_state_cookies_process_one` with
the second cookie's value 5/5, released tag 0/5, no ASan report in that
in-bounds regime. A single value-less request under
`ASAN_OPTIONS=halt_on_error=0:abort_on_error=0` still ended at the pinned READ
with no WRITE report (`store/halt-on-error-negative.log`).

Grade: rung 4 now observed on a real pre-auth wire path with a wire-chosen
offset, still unwitnessed at that scope; byte always NUL, no pointer-bearing
target, command or rung 5. Re-run: `cd full && bash probe-store.sh &&
bash probe-gdb.sh`.

## Live pointer-bearing OOB NUL store (2026-11-23 W9)

A non-ASan full module (`build-plain.sh`, module sha256
`008990618887dde66e4371d1a354c64dccf29c40d36d17c4ac1d8e5f8b375654`,
pinned `state.c` unchanged) was built against the plain httpd 2.4.70 / APR
stack and started only on 127.0.0.1:18090 (`httpd-plain.conf`). A value-less
state cookie has no `=` after its NUL, so the pinned `:214` scan runs out of
the header copy until it meets a `0x3d` byte in adjacent pool memory.

`full/probe-plain-oob.sh`, gdb break at pinned `state.c:219`, live pre-auth
stack through `oidc_state_cookies_clean_expired` (`:244`) →
`oidc_request_authorization_set_cookie` (`handle/request.c:132`) →
`oidc_check_userid_openidc`: store `0x7ffff6de2221` holds `0x3d`, the eight
bytes there are `3d 60 f5 ff ff 7f 00 00`, i.e. the low byte of the 8-byte
pointer `0x00007ffff5603d`. After `next` the byte is `0x00` and the pointer
is `0x00007ffff56000`.

`full/probe-plain-detail.sh`: the pointer's target bytes are all zero and lie
in the anonymous rw mapping `0x7ffff5157000-0x7ffff5e00000` (OIDC shared
memory). A hardware watchpoint on the corrupted word caught no later read or
write before the 60-second timeout. Non-gdb controls: value-less and
well-formed cookies both return HTTP 302 on this module. Raw output and
limits: `full/evidence/plain-oob/README.md` and `plain-oob/{live-plain,detail}.txt`.

`full/probe-plain-second.sh` arms a watchpoint on the corrupted word after the
store and lets the child accept another loopback connection. The watchpoint
fires in `libapr-1.so.0` from `apr_socket_accept` → `ap_unixd_accept`
(`unixd.c:303`) with old value `0x7ffff56000` (the corrupted pointer) and new
value `0` (`plain-oob/second.txt`). The word is in the connection's `ptrans`
region near `0x7ffff6de2028`, not a long-lived config object; the next accept
clears it. No read of the corrupted pointer and no cross-request side effect
was observed. HTTP codes in that script are timing-dependent under gdb.

In the real-object harness the same pointer-low-byte shape occurs naturally:
`realobj/probe-oob-target.sh`, `p-vuln read 0`, store `0x7ffff7fbe9d0` is the
low byte of `0x7ffff7f62e3d` → `"GLIBC_2.38"`; after the store `0x…f62e00` →
`"_2.3"`, stable across six fills 0/512/1024/2048/4000/8000. A hardware
watchpoint there also caught only the store itself. Raw:
`realobj/evidence/oob-target/fill-*.txt`.

This refines, rather than replaces, the W8 result: W8's wire-chosen store
lands **in bounds** on a header-copy `=` and has no pointer target; W9's
**out-of-bounds** store in the plain build lands in a pointer's low byte.
Both are rung 4 scoped and unwitnessed at their live-wire scope. Byte always
NUL, pointer target not wire-chosen, no consumer read, chosen byte, command
or rung 5. gdb disables ASLR, so the absolute addresses are lab-layout facts.
Re-run: `cd full && bash build-plain.sh && bash probe-plain-oob.sh &&
bash probe-plain-detail.sh && bash probe-plain-second.sh`.


## No consumer for the OOB word (2026-11-23 W10)

`full/probe-plain-keepalive.sh` breaks at pinned `state.c:219` on the live
pre-auth wire path, saves the store address, steps over the NUL store, arms a
hardware watchpoint on that exact 8-byte word, deletes the source breakpoint
and sends three requests on the **same TCP connection** (no new accept). Raw:
`full/evidence/plain-oob/keepalive/{gdb,client}.txt`.

Measured: `STORE=0x7ffff6de2221 WORD=0x7ffff5603d`,
`AFTER=0x7ffff56000`; all three replies HTTP 302; no watchpoint hit, no
`Old value`/`New value`, no watch-stop backtrace before the 70-second gdb
timeout. Neither the faulting request nor the two later requests on that
connection read or wrote the corrupted word. This sharpens, not replaces, the
W9 accept-time overwrite: the word is connection-pool state with no observed
consumer.

A separate one-off `LD_PRELOAD` tracer (`full/evidence/plain-oob/alloc-trace/`)
logged 594 `apr_palloc`/`apr_pcalloc` returns while the same probe faulted in
the shifted layout at `0x7ffff6ddd221`. No traced allocation covers the word;
the nearest following allocation starts at `0x7ffff6ddd290` (0x6f bytes
later). Intra-libapr calls bind locally and bypass the interposer, so this is
suggestive, not proof, that the word is pool slack rather than a live object.

Both checks are negative. Byte still always NUL, target not wire-chosen, no
consumer read, chosen byte, command or rung 5. Grade unchanged: rung 4 scoped
on a live pre-auth wire path, unwitnessed at that scope; W147 covers only the
direct-call harness. Re-run: `cd full && bash build-plain.sh &&
bash probe-plain-oob.sh && bash probe-plain-keepalive.sh`.

## Second pre-auth caller: response path (2026-11-23 W11)

`full/httpd-plain-response.conf` adds `<Location /redirect_uri>` to the plain
config. `full/probe-plain-response.sh` sends
`GET /redirect_uri?code=foo&state=foo` with
`Cookie: mod_auth_openidc_state_novalue` on 127.0.0.1:18090 under gdb.
Raw: `full/evidence/plain-oob/response/{gdb,client}.txt`.

At pinned `state.c:219` the live stack is
`oidc_response_authorization_redirect` (`handle/response.c:765`) →
`oidc_response_process` (`:614`) → `oidc_response_match_state` (`:426`) →
`oidc_response_proto_state_restore` (`:353`) →
`oidc_state_cookies_clean_expired` (`:244`) → `oidc_state_cookies_parse_token`.
The store is `0x7ffff6ddc05e`, whose eight bytes `3d 66 6f 6f 26 73 74 61`
spell `=foo&sta` — the `=` of `code=foo` in the copied request line. After the
store the word is `0x617473266f6f6600`, i.e. that `=` became NUL. The first
request returns HTTP 400; the log shows the scanner's value
`foo&state=foo HTTP/1.1…` passed to `oidc_state_cookies_process_one`, JWE
decode failure and deletion of the value-less cookie. A hardware watchpoint
on the corrupted word recorded no later read/write of that word.

This is the second source caller (`handle/response.c:353`) reached on a live
pre-auth wire request, and the stop byte is wire-chosen query data in adjacent
request-line memory. Grade unchanged: rung 4 scoped, unwitnessed at live-wire
scope; byte always NUL, no consumer dereference of the corrupted word, no
chosen byte, pointer control, command or rung 5. Re-run:
`cd full && bash build-plain.sh && bash probe-plain-response.sh`.

## Long value-less token: intermittent plain fault (2026-11-23 W12)

`full/probe-plain-crash.sh` swept bare, `;tail=value`, well-formed and
filler-only Cookie headers at name lengths 1/16/128/1024/4096/7800 over the
loopback plain module. Two runs faulted a child on bare-7800 (two children at
14:06Z, one at 14:14Z; `AH00051 … exit signal Segmentation fault (11)`), a
third run faulted none; a fresh-server 30-request bare-7800 sweep faulted
none. The fault is intermittent, not a deterministic primitive. The 14:06Z
log was overwritten by later replays; its `AH00051` lines are transcribed in
`full/evidence/plain-crash/FIRST-RUN-20261123T1406Z.md`, and a later raw
crash is in `full/evidence/plain-crash/{codes.txt,error.log}`.

`full/catchsegv.c` interposes `sigaction(SIGSEGV)` to print a backtrace, with
`libasan.so.8` preloaded first. Under that instrument, 60/60 bare-7800
requests faulted; the top module frame resolves with `addr2line` to
`oidc_state_cookies_parse_token` at pinned `state.c:219`, with the live stack
through `oidc_check_user_id` → `ap_run_check_user_id`. The well-formed
7800-byte token on the vulnerable module returned 302 on 10/10, and released
`v2.4.19.4` built against the same plain stack (`state.c` `f02d8ddb…`,
module `b16278d2…`) returned 302 on 10/10 with zero backtraces under the same
shim. The shim changes signal handling and allocator layout, so its crash
rate does not describe the unmodified module; it only attributes the frame.
gdb runs (ASLR off, ASLR on, and fork-following) produced no fault.

Grade unchanged: rung 3 on the live pre-auth wire path, rung 4 scoped and
unwitnessed at live-wire scope; byte always NUL, no chosen byte, pointer
target, consumer dereference, command or rung 5. Replay and limits:
`full/evidence/plain-crash/README.md`.
