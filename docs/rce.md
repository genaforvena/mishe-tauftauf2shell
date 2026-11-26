# Rung 5 — working remote command execution

Rung 5 is an additive plant goal, approved by the owner on 2026-11-21. It
does not replace rung 4 and does not make every target an RCE target. A mind
attempts it only when a measured rung-4 primitive leaves a credible bounded
path; a measured structural blocker is a valid negative result.

## Acceptance contract

A rung-5 claim requires all of the following:

1. **Real target and input path.** Attacker-controlled wire or request input
   reaches a live affected target process started by this plant on loopback.
   An extracted harness, synthetic consumer or debugger-forced call remains
   rung-4 mechanics.
2. **Chosen command execution.** That input makes the target execute a
   lab-chosen benign command. The proof command only creates a unique marker
   file under `lab/` or prints a unique marker through the target process.
   A pointer fault, a call to a pre-existing benign marker, or a marker address
   alone is not command execution.
3. **Observed side effect.** The harness checks the marker directly and binds
   it to the triggering request, not to the client or a debugger action.
4. **Differential controls.** The fixed target rejects or survives the same
   input without the marker, and a safe input on the affected target also
   leaves the marker absent. The vulnerable positive is repeatable.
5. **Exact conditions.** The report names source pins, build flags,
   configuration and authentication gates, ASLR state, address provenance,
   grooming, debugger involvement, process survival and all remaining UNKNOWNs.
6. **Independent witness.** A fresh witness replays the committed harness from
   a clean checkout and varies the command or another attacker byte to exclude
   a fixed side effect. Author observation is not ESTABLISHED.

No persistence, external connection, credential access or off-loopback action
is approved. ASLR-disabled experiments remain permitted when labeled. A failed
hypothesis stays in the target report; it is not retried into existence.

## First lane — FreeSWITCH

FreeSWITCH already has a witness-replayed live rung-4 primitive: an
unauthenticated WebSocket upgrade to the opt-in `mod_xml_rpc` endpoint reaches
`SSL_shutdown` with `wsh->ssl` equal to eight attacker-chosen bytes. The first
bounded R5 experiment is a forged `SSL` and `SSL_METHOD` in that same frame.
The intended chain is an indirect `ssl_shutdown` method call with the forged
object as its first argument, redirected to a lab-known command function.
ASLR-disabled calibration is allowed; final execution must come from the wire
payload, not debugger writes.

The alternative Datasketches lane has a genuine indirect call, but only in a
synthetic consumer, so it is not R5. Ruby's natural called target is the
untyped CRuby `T_DATA` `dfree(data)` finalizer, used by the established lane
below.

FreeRDP's wake-20 result supplies a chosen indirect call target in a live
stock 3.32.0 rdpsnd log path: `s_wLog` at `out_buffer+8880` has `custom +112`
set to libc `system()` and `context +120` to a command string at
`out_buffer+12000`, and real `WLog_Layout_GetMessagePrefix` code
(`Layout.c:211-213`) calls `log->custom(log->context)`. Two benign marker
touches were observed; no-call, upstream-style format-guard and safe-input
controls leave the marker absent. This stays rung 4 lab mechanics, not R5:
the pointer, argument and command are server-side synthetic playback bytes,
the client chooses only the wrap and target offset, there is no wire-derived
command and no witness replay (`lab/freerdp2shell-src/call_target_stock.txt`,
`reports/freerdp2shell-status.md`).

The libIEC61850 lane is different: a wire-supplied chain already calls real
libc `system` in the live unsanitized server with a target-written marker
(`3777729`), so it is a second witness-ESTABLISHED R5 lane (#1127), not a
blocked one.

Current status: **FreeSWITCH R5 ESTABLISHED, with labeled conditions.** Commit
`462e887` connects a forged `SSL`/`SSL_METHOD` carried in the same WebSocket
frame to `system()` in a live loopback target, with a target-written marker, a
`system(rdi=forged SSL)` trace, and absent-marker safe and fixed controls.
Witness #1118 replayed the committed harness from clean blobs (matching script
digests and source pins), reproduced the marker and varied the command
(`id>r5` → `pwd>p1`) for a different side effect; safe and pinned-fixed runs
left the marker absent. ASLR-off calibration and trigger, opt-in
`mod_xml_rpc`/websocket config, lab build shims, a sudo-root netns and
127.0.0.1-only traffic remain required; ASLR-on reachability stays UNKNOWN.
The README R5 cell is filled for this build only. Evidence and recipe in
`reports/frontier-freeswitch2shell.md` and the 2026-11-21 addenda of
`docs/reproducibility.md`.

Ruby2Shell is witness-ESTABLISHED at its labeled host/harness conditions:
commit `8b9d8f97f0ec1237fe1fb2bc30339d1a32db1341` converts the existing
Sinatra Stage C poison into an untyped CRuby `RData` whose real GC finalizer
calls libc `system` with the multipart request's benign `touch` command. The
author's final matrix is 3/3 attacks plus clean safe/fixed controls; a
fresh-context independent clean-archive replay reproduced two varied-command
attacks and both controls, independently scanning target pops and checking
that no harness code directly calls `system` or creates the marker. ASLR stays
enabled, but mtrace/ObjectSpace.dump//proc/self/maps oracles and custom
grooming/GC middleware are required; the affected process can abort after the
HTTP 200/marker, and stock-app oracle-free RCE and persistence remain UNKNOWN.
Use `bash lab/repro/ruby2shell-rung5-http.sh attack|control|fixed <tag>`;
evidence and exact conditions are in `reports/ruby2shell-investigation.md` and
`docs/reproducibility.md`.

The 2026-11-22 follow-up against unmodified classic Sinatra/Puma is a bounded
NEGATIVE for stock/oracle-free/persistent RCE. N=828 aborts 3/3 pre-response;
N=556 completes a later GET in only 2/3 runs and faults on teardown; safe and
fixed controls survive. Its corrupted chunk is fastbin, not tcache, and the
0x30→0x50 class change is source-closed for consolidation. Filler/order and
safe-primer sweeps found no stable valid unsorted expansion, expanded headers
held invalid Ruby data, and tested multipart errors disclosed no addresses.
No stock command, oracle, reliable survival or second command was achieved.
Stock Rails remains UNKNOWN; Veria's PoC is still unpublished. See the Ruby
report's bounded-negative section and `ruby2shell-stock-baseline.{ru,sh}`.

The 2026-11-24 stock Rails follow-up advances allocator evidence but does not
change that verdict. `ruby2shell-stock-rails{,-setup}.sh` uses an unmodified
`rails new` app. N=524 with 32 fake-header multipart parts produced a traced
`0x200→0x250` expansion and a `0x230` second mapping-buffer allocation; four
trailing invariant bytes changed the original remainder's size to `0x251`.
No useful physical consumer, `0x3f0` tcache neighbor or address disclosure
followed, including in a separate seeded 512-layout search. Final
uninstrumented attacks aborted 3/3 pre-response; safe affected and fixed
controls survived 3/3. No command or persistent second-request execution was
achieved, so the established host/harness-specific rung-5 result remains the
only Ruby2Shell RCE claim. Veria's stock Rails PoC remained unpublished at
2026-11-24T04:11Z.

The IEC61850 lane is also witness-ESTABLISHED at the labeled conditions
(verdict #1127, W89): `bash lab/frontier/libiec61850/r5_system.sh <abs-outdir>`
drives a wire-supplied chain through ObtainFile staging to real libc `system`,
creating a target-written `R5_IEC_MARKER_49035` marker with benign-file and
fixed-build controls. W89 replayed it from a clean git-archive tree (6/6 pins,
15 PASS / 0 FAIL), varied the command for a distinct marker side effect and
also replayed `r4_real.sh` (13 PASS / 0 FAIL). ASLR is disabled, addresses are
host-measured and the command is lab-chosen; ASLR-on reachability stays
UNKNOWN and the rung-4 grade is unchanged. Recipes and expected bytes for
both lanes are in the 2026-11-21 addenda of `docs/reproducibility.md`.

PHP2Shell is witness-ESTABLISHED at its labeled conditions (2026-11-25,
message #4556, witness W221). The unmodified W66 harness at commit `33b6840d`
was replayed from a clean `git archive` with fresh attacker bytes
(`SID=0badc0de00112233445566778899beef`, filler `Z`): an unauthenticated
loopback upload-progress producer under per-worker `RLIMIT_FSIZE=1024` leaves
an exact-tail session splice while the producer worker stays alive; a second
unlimited FPM master with upload progress off consumes it, tinyfilemanager
accepts the promoted admin session, and its designed upload makes the live
consumer worker print a unique marker and `uid=1000` into a PID-bound marker
file. Fixed 8.4.28 and safe-input runs leave the marker absent; a second
affected run with different bytes reproduced the positive. Two FPM masters,
shared session directory, ASLR=2, K=1024, the permissive app config and the
size limit remain required; stock/default reachability is UNKNOWN. Recipe and
evidence: `reports/php2shell-investigation.md` W66/W69 and
`.mishe-tauftauf/artifacts/witness-w221-php2shell/detail.md`.
