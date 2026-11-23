# modauthoidc2shell — status

Admitted 2026-11-23 ~06:2xZ under standing approval #6 as the 103rd engine
route. Frontier staged this lane in W139 with byte-exact pinned upstream blobs,
a real fix commit and a released fixed version. Brief:
`reports/frontier-modauthoidc2shell.md`; pins, verbatim slices, hashes and raw
evidence: `lab/frontier/modauthoidc2shell/PROVENANCE.md`. The two-pane inner
tmux window 107 was already live and registered (frontier verified both panes
at 06:16Z), so admission created no second window and changed no registry
entry. The hy4-flash `max_parallel: 3` route was added; the path, debounce and
`@modauthoidc2shell` slice drop-in were minted with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@modauthoidc2shell.service` and
`m2shell-wake-modauthoidc2shell.path` were added to the site's owner resolver
map. The pinned full-flag doctor returned rc 0, `PASS local plant out of Git` /
`GREEN`, and `check-omp-only.py` returned GREEN with 103 declared roles.
Admission changes no grade.

- Claim: CVE-2026-54789 / GHSA-vgr5-qcpp-x2pr (CNA GitHub_M, HIGH 7.5
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-125 + CWE-787);
  mod_auth_openidc `< 2.4.19.4`, fixed by upstream commit
  `8017478471cc071c49aa073c5c9be652a73a8630` and released in `v2.4.19.4`.
  Byte-exact pinned blobs: parent `state.c.4301b536`
  `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`, fix
  `state.c.8017478`
  `3492207546885aae00363de14b30947ce73c48b8361b33516d95fc6df774c1cc`, release
  `state.c.v2.4.19.4`
  `f02d8ddb60927b9da1402c6430d179e4418ff6751ecda6c78db34424ccf77ce5`.
- Primitive: an unauthenticated client sends a `Cookie` token beginning with
  `mod_auth_openidc_state_` but containing no `=`. In
  `oidc_state_cookies_parse_token()` the loop `while (cookie != NULL && *cookie
  != OIDC_CHAR_EQUAL) cookie++;` (pinned parent lines 214-215) can only exit on
  `=`, because the pointer is never reassigned to NULL; line 219 then writes
  NUL at that out-of-bounds offset. Callers `handle/request.c:132` and
  `handle/response.c:353` run before state validation.
- Evidence: `lab/frontier/modauthoidc2shell/harness/run.sh` re-extracts the
  record struct and the whole parser verbatim from all three pinned blobs on
  every run, checks two SHA-256 manifests (12 files), and builds plain plus
  gcc/clang ASan variants. Frontier recorded 59 PASS / 0 FAIL three times plus
  a clean-directory replay and a clean `git archive HEAD` replay. Operator
  replay from `git archive HEAD lab/frontier/modauthoidc2shell` in a fresh
  `/tmp` directory returned rc 0, `PASS=59 FAIL=0` and exactly
  `TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`.

## Current grade — W147 witness ESTABLISHED (direct-call scope)

Rung 3 is confirmed in the verbatim pinned slice: gcc and clang ASan
`heap-buffer-overflow` `READ of size 1` at `state.c.4301b536:214`, 0 bytes past
a 31-byte exact-size token. The vulnerable slice scans past the token,
overwrites an adjacent `=` and dispatches the downstream cookie processor with
`PROCESS_CALLS=1`. Rung 4 is **scoped**: in the plain build the single NUL
store lands at chosen offsets 31, 47 and 63 with an intact canary. Only the
offset is chosen; the byte value is always NUL. Both the fix-commit and the
released `v2.4.19.4` slices reject the value-less token with `RC=0`, no
dispatch, the `=` byte intact and no ASan finding; a well-formed
`mod_auth_openidc_state_abc=1` token is clean on all six binaries.

## Ceiling

The direct-call harness uses stubbed request/config pointers and a recorder;
it has no Apache, APR pool, request object, listener, socket or wire. Its
exact-size heap token is an instrument; the ASan read faults before the write,
so no ASan WRITE is available in that build. W147 ESTABLISHED rungs 1-3 and
scoped rung 4 at that direct-call scope. Later probes add real APR/Apache
objects, a full module on a loopback wire, and a live NUL store with a
wire-chosen offset; none gives chosen-byte or pointer control: rung 3 is
confirmed on a live pre-auth wire path and rung 4 is observed on that path
too. W170 independently replayed W6/W8-W11/W13/W14 and found no counterexample,
ESTABLISHED at those labeled scopes; W15 (production-allocator crash), W16
(its native faulting PC) and W12's shim experiment remain unwitnessed. No
chosen command or rung 5.

## Real-object follow-up (2026-11-23)

`lab/frontier/modauthoidc2shell/realobj/driver.c` runs the verbatim parser
slice against a real `apr_pool_t`, a real Apache `request_rec` with an
`apr_table_t` Cookie header, a real `apr_pstrdup()` token and `apr_strtok()`.
`realobj/run.sh` re-extracts and hash-checks the slices/pins on every run and
builds six gcc variants. Two consecutive runs gave **PASS=17 FAIL=0**
(`realobj/evidence/run6-console.txt`, `run7-console.txt`; raw trials in
`raw-trials.txt`, counts in `summary.txt`). In 20 parent ASan trials per run,
the outcome was layout-dependent under ASLR: run6 saw 15 fault summaries at
pinned `state.c.4301b536:214`, 1 ASan-reported WRITE `SEGV` at pinned `:219`,
and 4 dispatches; run7 saw 9, 3 and 8. The first ASan-poisoned byte was 95
bytes past the token, never at its end: APR arena allocations have no
per-object redzone, so the scan continues to an arena edge, an adjacent `=`
or an unmapped page. Plain-build parent runs stored NUL at offsets 31, 47
and 63 with dispatch; fix and release slices rejected all 10 trials each with
no ASan report. No full module (no parent tree, jansson headers absent), no
Apache process, socket or wire; the `=` position is still harness-placed and
the probe has no witness verdict. A clean `git archive HEAD
lab/frontier/modauthoidc2shell` replay gave `PASS=17 FAIL=0` with 14
READ-class faults, 0 WRITE faults and 6 dispatches: the WRITE fault is
layout-dependent, not asserted. Full-module/loopback work would need those
provisioned dependencies; only a measured controlled pointer or command side
effect can change the grade. What would change the mind: the pre-auth call path
is unreachable on a real configuration, or the released fix misses the live
path. Do not relabel harness mechanics as remote compromise.

## Witness verdict (W147, 2026-11-23)

The witness replayed the lane from a clean `git archive HEAD` into two `/tmp`
trees, rebuilt with its own gcc/clang and ran `bash run.sh` three times
unmodified: rc 0, PASS=59 FAIL=0 and
`TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`
each time; the normalized trace was byte-identical across both tree paths. Its
separate full-block driver over token-to-`=` gaps 1, 2, 8, 16, 17, 33 and 64
found exactly one changed byte per vulnerable run (0x3d→0x00 at token length
+ gap, canary 0x5a intact); fixed and release slices changed 0 bytes with no
dispatch, and `abc=1` dispatched in bounds on all six binaries. Rungs 1–3 and
scoped rung 4 are ESTABLISHED at the labeled direct-call scope; no repair owed
and no rung 5. The external advisory text and the two pre-auth caller lines
were not source-bound in this lane and were not reproduced by the witness —
UNKNOWN, not upgraded.


## Witness verdict (W170, 2026-11-23 16:58Z)

The witness closed the consolidated replay request (#2705/#2804/#2836) from
a full `/tmp` copy at HEAD `10fdd31`, with tracked scripts hash-matched and
pinned `state.c` `ceedb687…5aa` and module `00899061…5654` verified.
ESTABLISHED at the labeled scopes, no counterexample, no grade change, NOT
rung 5: W6 30/30 ASan READ at pinned `:214` with the full live stack
(`ap_run_check_user_id` → `handle/request.c:132` → `state.c:244`), fixed
0/30 with 30 HTTP 302; W8 `:219` byte 0x3d→0x00 at two wire-chosen offsets;
W9 pointer-low-byte store with no later consumer read; W11 second caller via
`handle/response.c:353` with `=foo&sta` stop byte; W13 bimodal child SIGSEGV
with clean well-formed and fixed controls; W14 non-ASan harness faults with
layout-dependent rate, matching the claim. Source-bound pinned `:214` scan
and `:219 *cookie=NUL`; fixed `:217` adds the NUL guard. The witness found
no chosen byte, pointer target, consumer dereference, command or marker.
W12's shim experiment and W15's non-ASan full-module crash were not part of
this verdict and stay author-only/unwitnessed. No further witness action
owed on those replayed scopes.

## Full-module ASan loopback result (2026-11-23 W6) — W170 ESTABLISHED

The real full-module wire path is now measured. `full/` provisions the
complete parent module at `4301b5364034191adcba5153e5870405855cb74e`
(`src/state.c` sha256 `ceedb687…5aa`, matching the pin), jansson 2.14 and
cjose 0.6.1, and builds it with ASan against the local ASan APR 1.7.4 /
APR-util 1.6.3 / httpd 2.4.71 stack. A released-tag `v2.4.19.4` module is
the control. Both serve only `127.0.0.1:18090`; static provider config means
no metadata fetch or external contact.

The caller is source-bound and live: an unauthenticated GET of
`/protected` (protected by `AuthType openid-connect` / `Require valid-user`)
passes `oidc_check_user_id` → `oidc_handle_unauthenticated_user` →
`oidc_request_authorization_set_cookie` (`handle/request.c:132`) →
`oidc_state_cookies_clean_expired` (`state.c:229`) →
`oidc_state_cookies_parse_token`. With `Cookie:
mod_auth_openidc_state_novalue`, `cd full && bash run.sh` gave parent
30/30 ASan `heap-buffer-overflow` READ at pinned `state.c:214`, full native
stack through `ap_run_check_user_id`, 30/30 empty replies; released fix 0/30
reports, 30/30 HTTP 302, zero OOB dispatches. A first layout-dependent run
gave 7/30 faults and 23/30 dispatches of `mod_auth_openidc_state_novalue`
from the out-of-bounds region; all safe controls were clean. The overflowed
8192-byte region is a real APR arena from `ap_parse_htaccess`. Evidence:
`lab/frontier/modauthoidc2shell/full/evidence/README.md`, `run-final.txt`,
`asan-asan.log.*`, `trial-codes.txt`, `error_log`.

This upgrades rung 3 to a **real pre-auth wire path in a live Apache
process**. It does not upgrade rung 4: ASan faults on the read before the NUL
store, the byte value is always NUL and its offset is chosen by adjacent
arena memory, not by the client; there is no pointer control, command or
rung 5. W170 ESTABLISHED this probe at the labeled live pre-auth wire scope;
no counterexample to the mechanism, no chosen byte or pointer control. What
would change the grade: a measured controlled pointer or command side effect.

## Wire-chosen NUL store (2026-11-23 W8) — W170 ESTABLISHED

The store itself is now observed in the live full module. A request carrying
`Cookie: mod_auth_openidc_state_novalue;<name>=<value>` leaves the second
cookie's `=` in the apr_pstrdup'd header copy after the value-less token's
NUL; the pinned `:214` scan finds it in bounds and `:219` writes NUL there.
gdb on the ASan child recorded `0x3d` → `0x00` at
`0x5250000745b7` with the live stack through `ap_run_check_user_id`
(`full/evidence/store/gdb-single.txt`). Arena dumps put the store at token
offset **39** with eight `z` padding bytes and **63** with 32, i.e.
`30 + 1 + <name length>`: the offset is chosen by the wire input
(`store/gdb-dump*.txt`). `full/probe-store.sh` sent five lengths (1/4/8/16/32):
all 302, parent dispatched `oidc_state_cookies_process_one` with the second
cookie's value 5/5, released `v2.4.19.4` 0/5, no ASan report in that regime.
`ASAN_OPTIONS=halt_on_error=0` did not continue past the value-only READ fault
(negative preserved in `store/halt-on-error-negative.log`).

This lifts rung 4 from harness-only to **observed on a live pre-auth wire path
with a wire-chosen offset**, ESTABLISHED by W170 at that scope; the byte is
always NUL, the overwritten `=` is in the already-tokenized header copy, and no
pointer-bearing target, command or rung 5 is measured. Replay: `cd
lab/frontier/modauthoidc2shell/full && bash probe-store.sh && bash probe-gdb.sh`;
evidence and limits in `full/evidence/store/README.md`.

## Live pointer-bearing OOB store (2026-11-23 W9) — W170 ESTABLISHED

A `build-plain.sh` full module (labelled "plain", not non-ASan — see the W14
correction below) built from the same pinned parent, module sha256
`008990618887dde66e4371d1a354c64dccf29c40d36d17c4ac1d8e5f8b375654`,
serves 127.0.0.1:18090 on the httpd 2.4.70 / APR stack (ASan runtime; see below). A value-less state
cookie has no `=` after its NUL, so the pinned `:214` scan runs out of the
header copy into adjacent pool memory. gdb at pinned `state.c:219` on a live
pre-auth request (full stack through `oidc_state_cookies_clean_expired:244` →
`oidc_request_authorization_set_cookie` `handle/request.c:132` →
`oidc_check_userid_openidc`) measured the store at `0x7ffff6de2221`: the
byte is `0x3d` and the eight bytes there are
`3d 60 f5 ff ff 7f 00 00`, i.e. the low byte of pointer `0x7ffff5603d`.
After the store the byte is `0x00` and the pointer `0x7ffff56000`.

The pointer's target lies in zeroed bytes of the OIDC shared-memory mapping
`0x7ffff5157000-0x7ffff5e00000`; a hardware watchpoint on the corrupted word
caught no later read or write. Non-gdb controls: value-less and well-formed
cookies both return HTTP 302 on this module. The real-object harness shows
the same shape naturally (`realobj/probe-oob-target.sh`: store at the low
byte of `0x7ffff7f62e3d` → `"GLIBC_2.38"`, stable over six pool fills; the
watchpoint again caught only the store).

`probe-plain-second.sh` armed a watchpoint on the corrupted word: the next
`apr_socket_accept` wrote `0` over it (old value `0x7ffff56000`). The word
is in the connection's `ptrans` region near `0x7ffff6de2028`, so the
corruption is connection-scoped; no consumer read or cross-request side
effect was observed (`plain-oob/second.txt`).


This refines W8 rather than replacing it: W8's **in-bounds** store overwrites
a header-copy `=` chosen by the wire and has no pointer target; W9's
**out-of-bounds** store in the plain build corrupts a pointer's low byte.
Grade is unchanged: rung 4 scoped, now with a pointer-bearing target on a
live pre-auth wire path, ESTABLISHED by W170 at that scope. The byte is always
NUL, the pointer target is not wire-chosen, no consumer read, chosen byte,
command or rung 5 is measured; gdb disables ASLR, so the addresses are
lab-layout facts. Replay: `cd lab/frontier/modauthoidc2shell/full &&
bash build-plain.sh && bash probe-plain-oob.sh && bash probe-plain-detail.sh`;
raw evidence and limits `full/evidence/plain-oob/README.md`.

### W10 no-consumer check (2026-11-23) — W170 ESTABLISHED

`full/probe-plain-keepalive.sh` arms a hardware watchpoint on the corrupted
word at pinned `state.c:219`, removes the source breakpoint, and sends three
requests on the **same TCP connection**, avoiding the W9 accept-time overwrite.
It measured `STORE=0x7ffff6de2221 WORD=0x7ffff5603d` →
`AFTER=0x7ffff56000`; all three returned HTTP 302 and no watchpoint hit,
`Old value`/`New value` or watch-stop backtrace occurred within 70 seconds
(`full/evidence/plain-oob/keepalive/`). A one-off `LD_PRELOAD` APR allocator
trace found no traced allocation covering the word (nearest starts 0x6f bytes
later), though intra-libapr calls bypass interposition
(`plain-oob/alloc-trace/`).

No consumer of the corrupted word was observed in the faulting request or the
two later same-connection requests. "Pointer-bearing" describes the 8-byte
shape, not a demonstrated dereference. Grade unchanged: rung 4 scoped on a
live pre-auth wire path, ESTABLISHED by W170 at that scope; byte always NUL, no chosen
byte, pointer target not wire-chosen, no command or rung 5. Replay: `cd
lab/frontier/modauthoidc2shell/full && bash build-plain.sh &&
bash probe-plain-oob.sh && bash probe-plain-keepalive.sh`.

### W11 response-path store (2026-11-23) — W170 ESTABLISHED

`full/httpd-plain-response.conf` enables `<Location /redirect_uri>`;
`full/probe-plain-response.sh` sends an unauthenticated
`GET /redirect_uri?code=foo&state=foo` with the value-less state cookie. gdb
at pinned `state.c:219` shows the live stack through
`oidc_response_proto_state_restore` (`handle/response.c:353`), the second
source caller. The store at `0x7ffff6ddc05e` holds `=foo&sta` before and
`\0foo&sta` after: the scan left the copied Cookie header and stopped at the
wire-chosen `=` of `code=foo` in the copied request line. HTTP 400 followed;
`oidc_state_cookies_process_one` received the adjacent request-line text and
failed JWE decode. A hardware watchpoint on the corrupted word recorded no
later read/write of that word (`full/evidence/plain-oob/response/`).

Grade unchanged: rung 4 scoped on a live pre-auth wire path, ESTABLISHED by W170 at
that scope. The second caller is now source-bound and reached on the wire, and
the stop byte is wire-chosen, but the byte written is always NUL with no
dereference of the corrupted word, chosen byte, pointer control, command or
rung 5. Replay: `cd lab/frontier/modauthoidc2shell/full && bash build-plain.sh
&& bash probe-plain-response.sh`.

### W12 long value-less token: intermittent fault — unwitnessed

`full/probe-plain-crash.sh` swept Cookie headers of length 1/16/128/1024/
4096/7800 over the plain parent module on 127.0.0.1:18090 with no debugger.
Two extended sweeps faulted a child on a bare (value-less) 7800-byte token
(`AH00051 … exit signal Segmentation fault (11)`); one sweep and a fresh-
server 30-request bare-7800 sweep did not. `full/evidence/plain-crash/`
preserves the raw codes and logs, plus a transcription of the first run's
log, which a later replay overwrote. This is an intermittent observation,
not a deterministic crash primitive.

A lab-only `sigaction(SIGSEGV)` interposer (`full/catchsegv.c`) with
`libasan.so.8` preloaded first made the bare-7800 request fault on 60/60
trials and print a backtrace whose top module frame resolves via `addr2line`
to `oidc_state_cookies_parse_token` at pinned `state.c:219`; the live stack
passes through `oidc_check_user_id` → `ap_run_check_user_id`. The same-length
well-formed token returned 302 on 10/10, and released `v2.4.19.4` built on
the same plain stack returned 302 on 10/10 with zero backtraces under the
same shim. The shim changes signal handling and allocator layout, so it
attributes the frame but does not raise the native crash rate. gdb runs with
ASLR off, ASLR on and fork-following reproduced no fault.

Grade unchanged: rung 3 confirmed on the live pre-auth wire path, rung 4
scoped and unwitnessed at that scope. Byte always NUL; no chosen byte,
pointer control, consumer dereference, command or rung 5. Replay: `cd
lab/frontier/modauthoidc2shell/full && bash build-plain-fixed.sh &&
bash probe-plain-crash.sh && bash probe-plain-crash-7800.sh &&
bash probe-plain-crash-sigsegv.sh && bash probe-plain-fixed-sigsegv.sh`.
Raw and limits: `full/evidence/plain-crash/README.md`.


### W13 native child SIGSEGV, bimodal per server start — W170 ESTABLISHED

The child fault was reproduced without the W12 shim, `LD_PRELOAD` or ptrace:
the pinned plain module on the plain httpd/APR stack, started with
`ASAN_OPTIONS=detect_leaks=0`, is bimodal by master start. Six identical fresh
starts gave 12/12 HTTP 302 with zero faults, then four starts of 0/12 HTTP 302
with 11 `AH00051` SIGSEGV children each, then 12/12 clean. A 60-request A/B
run gave 60/60 clean under default `ASAN_OPTIONS` and 59/60 crashing under
`detect_leaks=0`; an earlier 240-request run in a crashing state logged 240
faults. The first A/B crash follows the logged 7800-`a` value-less Cookie on
the live pre-auth path by 0.98 s. Fork-inherited allocator/ASLR layout is the
likely reason a start is safe or crashing; no fault address was measured.

Controls in the same env over four fresh starts each: well-formed 7800-byte
token on the vulnerable module and bare 7800-byte token on released
`v2.4.19.4` gave 8/8 HTTP 302 with zero faults in every start. strace and gdb
remained clean (54, 250 and 120 requests), so ptrace lands in the safe layout
and no native frame was captured; W12's shim remains the only `:219` attribution.
Apache zeroes child `RLIMIT_CORE` without `CoreDumpDirectory` and the core
pattern pipes to apport, so no usable core was captured.

Grade unchanged: rung 3 confirmed on the live pre-auth wire path, rung 4
scoped and ESTABLISHED by W170 at that scope. This adds a **native** availability
observation from one unauthenticated request, but it is bimodal across
restarts, not a deterministic primitive. Byte always NUL; no chosen byte,
pointer target, consumer dereference, command or rung 5. Replay: `cd
lab/frontier/modauthoidc2shell/full && bash probe-plain-native.sh`; raw
transcripts and limits in `full/evidence/w13-native/README.md`.

**W14 build-stack correction.** The "plain"/"non-ASan" label on W9-W13 is
wrong: the pinned module `00899061…5654` and the serving httpd both link
`libasan.so.8`, apxs injected `-fsanitize=address` into the module compile,
and `nm -D` shows ASan report calls. W13's crash had no added shim/preload but
still ran the ASan allocator, so `ASAN_OPTIONS=detect_leaks=0` is a change to
that allocator's layout, not to a production heap. The signal-11 child fault,
store bytes and clean controls stand; no availability claim on a non-ASan
stack. Grade unchanged. Detail: `lab/frontier/modauthoidc2shell/PROVENANCE.md`
§ "Build-stack correction (2026-11-23 W14)".

**W14 long-token plain-allocator result.** `realobj/evidence/longtoken/`:
`driver_long.c` plus `probe-long-token.sh` built a genuinely non-ASan driver
(no `-fsanitize`, no libasan in `ldd`) with the verbatim pinned parser. A
value-less token faults 5/5 at 32000/48000 in both runs, but 3/5 at 65000
and 4/5 at 100000 in a clean-archive replay (first run 5/5 at both; rc 139,
SIGSEGV 11), 4/5 at 29000-31000, and is clean with dispatch at <= 28000;
fixed and release drivers are clean with no dispatch at all lengths, and the
well-formed control is clean and dispatched at 7800/65000. gdb caught the
plain-process SIGSEGV at pinned `state.c.4301b536:219` (the NUL store), no
libasan/preload/shim. Harness availability only — no full module, listener,
socket or wire; no grade change, no rung 5. Full evidence in `PROVENANCE.md`
§ "Long value-less token faults a non-ASan real-APR process (2026-11-23 W14)".

**W15 non-ASan full-module crash on the wire — unwitnessed.** The pinned
parent module and the released tag were rebuilt with system `/usr/bin/apxs`
against Ubuntu httpd 2.4.58 / system APR and non-ASan jansson/cjose; `ldd`
shows no `libasan` in the server or either module. On loopback 18091 (18090
was the witness's port), a bare 7800-byte value-less state cookie returned
0/48 HTTP 302 across four fresh starts with 44 logged `AH00051 ... exit
signal Segmentation fault (11)` children; well-formed and released-tag
controls were 16/16 HTTP 302 with zero faults. With one request per fresh
start, 5/6 bare requests faulted on the **first** request (1/6 clean), so the
effect is driven by one unauthenticated request but is layout-dependent
across starts. No native faulting PC is captured on this stack; the written
byte is still NUL, with no chosen byte, pointer target, consumer dereference,
command or rung 5. This replaces the W14 caveat "no availability claim on a
non-ASan stack" with a measured one at this labeled wire scope; grade and
witness status unchanged. Raw: `full/evidence/sys-native/README.md`; replay
`cd lab/frontier/modauthoidc2shell/full && bash probe-sys-native.sh &&
bash probe-sys-first.sh`.

## Native faulting PC on the non-ASan full module (2026-11-23 W16)

W15's production-allocator crash had no captured PC because children have
`RLIMIT_CORE=0` and core_pattern pipes to apport. `full/probe-sys-gdb.sh`
attaches gdb **only to observe** (no shim, `LD_PRELOAD` or `ASAN_OPTIONS`;
ASLR left on) to the same non-ASan system-httpd stack on 127.0.0.1:18091.
A bare `Cookie: mod_auth_openidc_state_<7800 a>` on each fresh start caught
SIGSEGV in **4/4** vulnerable starts (first request per start); well-formed
6/6 HTTP 302 and the released tag 6/6 HTTP 302 caught nothing. All four stops
are at pinned `state.c:219`, the `*cookie = '\0'` **store**, with faulting
instruction `movb $0x0,(%rax)` and the live pre-auth stack
`ap_run_check_user_id` → `oidc_check_user_id` → `handle/request.c:132` →
`state.c:244` → `:219`. gcc inlined the parser into
`oidc_state_cookies_clean_expired`, so the symbol on `$pc` is
`oidc_state_cookies_clean_expired+265`. Transcripts place the `=` stop byte
in read-only library pages or unmapped gaps past a writable/shm mapping.

The PC is native but observed with a debugger attached; W15's non-debugger
crashes remain the availability claim. The byte is always NUL and its address
is chosen by adjacent memory, not the client; no chosen byte, controlled
pointer target, consumer dereference, command or rung 5. Grade unchanged;
author-only/unwitnessed at this scope. Raw: `full/evidence/sys-gdb/README.md`;
replay: `cd lab/frontier/modauthoidc2shell/full && bash probe-sys-gdb.sh`.
