# Research task: investigate how far rung 4 goes

General goal: for memory-safety vulnerabilities in language runtimes and
web-facing servers — the "X2Shell" class — reproduce the failures in a
local, isolated laboratory and investigate how far **rung 4 (demonstrated
security impact: chosen bytes at chosen offsets, pointer control, benign
marker execution, per-build labeled)** can be pushed for each target.

Rungs are not boxes to touch. They are a depth investigation: each rung
states what evidence is strong enough to support, and the lane records the
exact boundary where the evidence stops. A negative result, a harness-only
grade, or an UNKNOWN is part of the answer — it says how far rung 4 goes
on that build, not that the lane failed. Preserve failed hypotheses and
contradictory results; treat unknowns as unknowns.

## Stalled-lane doctrine

An idle wake is not work. When a target has no owed experiment, the mind
must either (a) push the same target deeper toward rung 4 with a bounded,
falsifiable experiment that could change a grade — a new consumer, a
wire-pure version of a debugger-assisted step, stock-allocator placement,
a live process, a stronger marker, or a counterexample to an existing
claim — or (b) if rung 4 is genuinely closed on this host/build, mine an
**adjacent vulnerability in the same target/runtime**: same source tree,
same subsystem, a descendant CVE, or the next bug in the same fix series.
Adjacent work keeps the same evidence ladder and is logged as a named
lane; a distinct product or runtime goes to frontier/operator for a new
mind, never a silent scope drift. A wake that only re-reads a page for a
timestamp with no new claim is a watch, not an experiment: do not
self-schedule it; wait for a signal or a dated trigger.

All triggering, listeners, debuggers and test consumers stay on this
machine, bound to loopback or local containers. Never contact external
systems or scan public infrastructure. Read-only provisioning from official
source homes and public advisories is the sole exception, and it never
sends a trigger off this machine. Publish reproducible reports.

## Targets (verified ground truth, 2026-11-20)

Read from the vendor/researcher pages and the CVE records. Starting
claims, not conclusions.

### PHP2Shell — CVE-2026-109618 / CVE-2026-109619 (php2shell.com)

- OOM-handling corruption (618) and stale global state across requests
  (619) in core PHP; CVSS 9.2 both; pre-auth RCE demonstrated on
  WordPress/Drupal/Joomla; application-agnostic memory disclosure.
- Affected/fixed: 8.2<8.2.35, 8.3<8.3.36, 8.4<8.4.27, 8.5<8.5.12.
- 2026-10-23 update: a circulating PoC vector needs
  `session.serialize_handler` set to `php_binary`/`php_serialize` and
  changed to `php` at runtime before `session_start()`, with
  `session.upload_progress` enabled — the same family as the public
  `murrez/php2shell` framework's CVE-2026-115560 claims. PHP recommends
  `session.upload_progress.enabled = 0` pending the next bugfix release.
- 2026-11-20 reopened lane (**CVE-2026-126714** / GHSA-fm2m-fjf5-v3cp,
  CVSS 9.2, from the 2026-11-19 vendor release): `ps_files_write()` does
  not clear the old session before writing the replacement; an interrupted
  write can leave new prefix + old tail that decodes as a third session.
  Affected 8.2<8.2.36, 8.3<8.3.37, 8.4<8.4.28, 8.5<8.5.13; both pinned
  8.4.26 and 8.4.27 are affected. Both halves are reproduced on both
  ASan builds (commits 741c677, 8440254): a real session write interrupted
  at a syscall boundary leaves the spliced file on disk and the next
  request promotes the object. The kill is shim-simulated (the advisory's
  hard-OOM worker death), not a demonstrated remote trigger. Fix VERIFIED
  on 8.4.28 (pinned in `lab/php2shell/provision.sh`, commits ab3ee16 and
  02bd370): unconditional `ftruncate(0)` first leaves the same interrupted
  write as a 100-byte new prefix with no object promoted
  (`aftershell-producer-8.4.28-asan.log`). Hand-assembled splice bytes still
  decode on 8.4.28, but a fixed handler cannot produce them.
- 2026-11-20 new descendant lane (**CVE-2026-129481** /
  GHSA-g3vh-838c-65v7): an incomplete fix for 109619. A fatal in a user
  stream wrapper's `stream_close()` interrupts session shutdown, leaving
  the recorded script-filename pointer live into the next request on the
  same FPM worker. Affected 8.4.27-fpm-asan; no ASan on fixed 8.4.28 or on
  a benign-close control. `lab/repro/php2shell-cve129481-fpm.py` observes an
  ASan 4-byte use-after-free read at
  `php_session_cleanup_filename (session.c:128)`. Rung 3 CONFIRMED, no
  rung 4 and no pre-auth reachability claim. Wake 29 reproduced the
  129474 stale-argument read on 8.5.12 CLI from the vendor's own regression
  case. Wake 31 added a bounded loopback FPM harness for 129182
  (`lab/repro/php2shell-cve129182-fpm.py`, with release-ASan build support in
  `lab/php2shell/build-fpm-release.sh`); the debug ASan build preserves a
  negative. Wake 45 finished the release-ASan
  8.5.12 replay: both vendor diagnostics reproduce but
  `VERDICT=CLEAN_NO_UAF` with zero ASan markers, also with fast shutdown
  forced, in ZendMM mode and under `--control`. Wake 46 root-caused it under
  gdb; wake 47 corrected the label and fixed the ordering: the 8.5.12 → 8.5.13
  fix is two `if (EG(active))` guards at `zend.c:1509` (dtor) and `:1534`
  (repop). Request 1's fatal repopulates the array; its own
  `zend_shutdown_executor_values()` then clears `EG(active)` and UNDEFs the
  global at `zend_execute_API.c:440` while the type is still `IS_ARRAY`
  (`type=775`), leaving only `value.arr`. Request 2's PHP_VALUE warning sees
  `active=0, flags=7, type=IS_UNDEF`, so `zval_ptr_dtor` is a no-op and the
  `:1534` branch is unreachable; `zend_activate()` was wake 46's wrong label
  for the `:440` site. Grade stays UNKNOWN with a fully ordered measured
  cause; no fixed 8.5.13 release build was started for that lane.
  129289 remains untested (smuggling, not memory corruption).
- 2026-11-21 new adjacent lane (**CVE-2026-129538** /
  GHSA-5j3f-64r7-f564), named by 8.5.13's NEWS (`NEWS:49-51`): "PHP-CGI
  out-of-bounds read and write during PATH_INFO correction". The
  8.5.12→8.5.13 `sapi/cgi/cgi_main.c` diff is exactly the `pilen > slen`
  guard on the `env_path_info + pilen - slen` computation and a `path_info
  &&` guard on its use; 8.4.28 carries the same fix, 8.4.27/8.5.12 do not.
  Vendor regression `ghsa-5j3f-64r7-f564.phpt` supplied three shapes.
  Committed harness `lab/repro/php2shell-cve129538.py` (direct php-cgi
  calls, loopback only) replays them on 8.5.12-asan vs 8.5.13-asan:
  affected 8.5.12 long-suffix `PATH_INFO="xxxx"` and PATH_TRANSLATED shape
  `"cted"` (fixed `"/x"`, ORIG NULL); a sweep n=1..20 leaks the
  `PATH_INFO=` name tail for n=2..11, is empty at n=12 and leaks the SECRET
  value tail for n=13..20 (n=20 → `"23456789"`), fixed clean for all 20;
  gdb at `cgi_main.c:1294` shows the store 15 bytes before
  `getenv("PATH_INFO")`, byte `47`→`0`. 8.4.27-asan also yields `"xxxx"`.
  ASan stays silent (the environment block is not redzoned); the proof is
  the gdb byte observation plus the patch-sensitive output difference.
  Grade **rung 3 CONFIRMED** for this lane: an observed OOB write and an
  attacker-offset OOB read with a server-visible leak of neighbouring
  bytes. No arbitrary write, pointer control, marker execution, pre-auth
  reachability or RCE claim, and no other lane's grade changes.
  `lab/repro/php2shell-cve129538-fcgi.py` then reaches the same shape through
  loopback FastCGI params (php-cgi as a 127.0.0.1 FastCGI responder,
  FCGI_PARAMS with `has_env=1`): long suffix yields `PATH_INFO=".0.1"` on
  8.4.27-asan and 8.5.12-asan but `"/x"` on fixed 8.5.13, short suffix clean
  on all three. A steering leg with the SECRET param before or after
  PATH_INFO leaks `"23456789"` / `"27.0.0.1"` respectively (fixed 8.5.13
  `"/x"` both), so the attacker chooses the offset (suffix length) and the
  adjacent value (param order); the leak destination is
  `$_SERVER['PATH_INFO']`. Wake 50 closed the HTTP reachability UNKNOWN:
  `lab/repro/php2shell-cve129538-nginx.py` runs a real loopback nginx 1.24
  FastCGI responder against 8.5.12-asan and 8.5.13-asan. The standard
  `fastcgi_split_path_info` mapping is clean on both builds (suffix only in
  PATH_INFO, `pilen >= slen`); a naive non-default mapping with the full URI
  in SCRIPT_FILENAME and `PATH_INFO=/` leaks adjacent param bytes on 8.5.12
  (`xxxxx` / `xxxxxxxxx` at n=16/20, and `6789` / `23456789` with a SECRET
  param before PATH_INFO) while 8.5.13 stays clean — verdict
  `HTTP-REACHABLE OOB READ CONFIRMED` in gitignored
  `lab/build/evidence/w50-nginx/verdict.txt`. The 8.5.12→8.5.13 cgi_main.c
  diff is exactly the 129538 guard, so the split is patch-sensitive; with
  ORIG_PATH_INFO set the transient OOB NUL write also fires (GDB byte proof
  from wake 48; ASan silent, no sanitizer claim). The naive mapping is not
  the nginx default and no stock-config claim is made. The lane is at its
  natural stop: offset-controlled OOB read plus a fixed-zero NUL write, no
  chosen-byte write, pointer control, marker execution, pre-auth or RCE;
  grade stays rung 3.
- 2026-11-21 new adjacent lane (**CVE-2026-129501** /
  GHSA-x8r7-mg3g-74hg), named in 8.5.13's NEWS:82/85, "Double free during
  DOM XML serialization". The exact 8.5.12→8.5.13
  `ext/dom/xml_serializer.c` diff has two hunks: hunk 1 marks values in a
  `zend_array_dup()`'d prefix-candidate list `DOM_Z_UNOWNED` so the two lists
  do not both `efree()` the same prefix; hunk 2 serializes a shallow `xmlDoc
  declaration_doc` copy instead of NULLing the real document's children
  around `xmlSaveDoc()` (a TRY bailout left them NULL).
  `bash lab/php2shell/build-dom.sh 8.5.12` built ONE dom-enabled 8.5.12
  ASan/UBSan CLI (`lab/build/php-8.5.12-asan-dom`, clang, libxml 2.9.14
  compat path); the first make hit a 1500s tool deadline at 524 objects and
  a 28s resume finished. No full 8.5.13 build: the "fixed" binary is that
  same binary relinked after swapping in the byte-identical 8.5.13
  `xml_serializer.c` (`diff -q` clean), so the claim is patch-sensitivity,
  not a version-pair build. `lab/repro/php2shell-cve129501-dom.py` runs the
  vendor regression body and an XMLDocument-only shape with
  `USE_ZEND_ALLOC=0`: affected rc=1 `ASAN_DOUBLE_FREE` for both, fixed rc=0
  CLEAN with output matching the vendor `--EXPECT--` byte for byte, clean
  control CLEAN on both; 4-byte prefix freed twice at
  `dom_xml_ns_prefix_map_destroy (xml_serializer.c:126)`. Default ZendMM
  exits 0 with ASan silent, so no default-allocator ASan claim. Wake 52 ran
  hunk 2's two 8.5.13 DOM regression bodies via
  `lab/repro/php2shell-cve129501-dom-hunk2.py` on the same vuln/fixed pair:
  affected loses children and orphans comments with rc=0 and no sanitizer
  report, fixed matches vendor EXPECT. That is a DOM-state fault, not an
  allocator fault; the grade stays **rung 3 CONFIRMED** from hunk 1.
  Tcache escalation is CLOSED NEGATIVE — the only owned prefix is `"ns"+%u`
  (13 bytes max, glibc 0x20 bin) and a PHP `zend_string` is at least 32 bytes.
  No chosen-byte write, pointer control, marker, pre-auth or web reachability;
  no other lane's grade changes. Raw evidence is gitignored
  (`lab/build/evidence/w51-129501-dom/`, `.../w52-129501-hunk2/`), regenerated
  by the commands in `reports/php2shell-investigation.md`.
- 2026-11-21 new adjacent lane (**CVE-2026-129291** /
  GHSA-jm4m-qfqx-967m), "PHP-FPM epoll use-after-free can lead to local
  privilege escalation" in 8.5.13 NEWS. The exact 8.4.27→8.4.28
  `sapi/fpm/fpm/fpm_children.c` diff calls `fpm_event_del()` on the child's
  stdout/stderr events and sets the fds to -1 before closing them.
  `lab/repro/php2shell-cve129291-fpm.py` embeds the new 8.5.13 vendor phpt and
  runs it against FPM ASan builds: 8.4.27 FAIL (`bool(false)`, no child-exit
  warning or replacement), 8.4.28 PASS (`bool(true)`), 8.5.12 FPM also fails —
  verdict CONFIRMED, rung 2 fix-sensitive functional fault, no ASan/UBSan
  report. Swapping only 8.5.13 `fpm_children.c`, or that plus
  `zend_builtin_functions.c`, into 8.5.12 left the test FAILing, so it is not
  isolated to the epoll hunk. No pointer control, chosen byte, marker, LPE
  demo or web path; no other lane's grade changes. Gitignored evidence
  `lab/build/evidence/w52-129291-fpm/`; do not repeat the single- or dual-TU
  swaps if reopened.
- Rung-4 angle: the disclosed RCEs are runtime-level; the lab reproduces
  the memory-safety failures (OOM longjmp path; stale-state UAF) in
  ASan/UBSan builds of an affected PHP, then attempts placement and
  control exactly as in the staged plan below.

### Ruby2Shell — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5 (verialabs.com/ruby2shell/)

- **One-byte heap overflow** in Ruby's single-byte-encoding case
  conversion: upcasing `ß` writes two bytes (`SS`) while the loop
  bounds-checks only one; output buffer is input length + 20, so 21 `ß`
  overflow by one byte. Written byte is fixed (`S` on upcase, `s` on
  fold); attacker controls the buffer size through input length. In the
  loop for several ISO-8859 and Windows-125x encodings since Ruby 2.4.0;
  reached by `upcase`, `swapcase`, `downcase(:fold)`, `casecmp?`; UTF-8
  unaffected. Rails and classic Sinatra exposed in default configs.
- Affected/fixed: 3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; 3.2 and older EOL.
  Fix commit `ruby/ruby@d582f8f`.
- Vendor claim: Veria Labs demonstrated RCE on stock Rails and publishes a
  PoC on **2026-11-25**. That RCE is the vendor's claim, not a lab finding;
  the PoC is still unpublished and the lab's own RCE is not demonstrated.
- **Lab position (2026-11-21): rung 4 — demonstrated impact,
  request-reachable, every rung-4 claim witness-ESTABLISHED.** Chosen bytes
  at a chosen offset on stock glibc (5/5 + clean control); the same chain
  driven by one multipart POST through a default-config classic Sinatra app
  and a default `rails new` app (5/5 + control each, before
  routing/CSRF/auth); Stage C tcache poisoning handing out an
  attacker-nominated address. Witness tapes #51 (in-process), #65 (both
  HTTP sections) and #89 (Stage C) independently re-ran the committed
  scripts. Evidence: `reports/ruby2shell-investigation.md`.
- **Depth results, 2026-11-21 (no ladder grade change).** (a) HTTP Stage C
  ran on the Sinatra request thread: 3/3 attacks read the nominated address's
  chosen bytes back in the HTTP response, 2/2 controls clean, but the
  process then aborts in WEBrick worker-thread tcache teardown — no
  persistence or surviving stock-process foothold is claimed. (b) The
  vendor's copy-out one-byte over-read was separately reproduced under
  valgrind as a second observed invalid access (rung 3 class): the byte read
  back is the same `0x53` the overflow wrote and the returned string is
  correct, so it is not an information leak and not rung 4.
- **Remaining gaps (UNKNOWN):** request-shaped grooming (the groom and
  marker are lab middleware, not an attacker's request), control-flow
  hijack, the target nominated inside attacker-controlled string content,
  and GC disabled between frees and readback. Next trigger: the vendor's
  PoC (dated 2026-11-25, or later while major vendors lag); compare its
  mechanics against these honest gaps. A timestamp-only advisory re-check
  is a watch, not an experiment.

### Node2Shell — CVE-2026-123828 (admitted 2026-11-20, standing approval #6)

- **Two one-byte heap overflows** in Node.js HTTP/2 `session.altsvc()`
  (`src/node_http2.cc`): the origin buffer is sized to the origin length and
  the null terminator is written one byte past its end; the fix removes
  `kNullTerminate` from **both** `WriteOneByteV2` calls in `AltSvc`, so the
  app-supplied ALT/value buffer has the same one-byte overflow when it exceeds
  1024 bytes and its length is ≡ 8 (mod 16). Remote unauthenticated
  single-request trigger: a long valid `:authority` that an application
  forwards to altsvc. Attacker controls the allocation size through the
  authority length — same class as Ruby2Shell.
- Affected 24.x, 26.x per the official advisory; fixed 24.22.3 /
  26.13.1 (2026-11-11); fix commit `nodejs/node@ae9ab37d62`
  (nodejs-private#1035). Snyk also claims 22.x<22.23.5, but the fix
  is absent from the 22.23.5 release notes — backport unverified;
  check the 22.x source before building it.
- **Lab position (2026-11-21): rung 3, two independent triggers; rung 4 not
  demonstrated.** Wake 33 isolated the value-side terminator (v24.22.2,
  loopback, one request, ALT 1048 → 4/4 then 3/3 SIGABRT rc=134 `malloc():
  invalid next size (unsorted)`; ALT 1200 and ALT 10 controls 2/2 each with
  the ALTSVC echo). Its pre-write sizefield was never captured, so neither
  magnitude shrink nor flag-only clear is claimed for that lane. Wake 34 ran
  both terminators on-class in one request: 8/8 aborts rc=134 split
  `mismatching next->prev_size` 2/8, `invalid next size` 3/8, `double free or
  corruption (!prev)` 3/8; the origin write dominates, no combination
  primitive appears and the third `WriteOneByteV2` in the subsystem is safe
  (shipped JS appends a NUL). Reproduce: `sh
  lab/repro/node2shell-valnul/run.sh 3`. Witness notification failed (chat
  tape 510); no independent verification is assumed.

### Similar things (operator's standing mandate)

The operator actively watches for new X2Shell-class public claims and
advisories (runtime-level memory-safety failures with pre-auth web
reachability), proposes targets with evidence, and admits them to the
plate under the standing approvals. Each admission records: the claim
source, the CVE/GHSA, affected and fixed versions, the claimed primitive,
and why a rung-4 attempt is plausible in this lab.

#### Admitted 2026-11-20 ~17:10Z: Brotli2Shell (CVE-2026-111497 / GHSA-9v8h-qqgm-4m35)

Claim source: the CVE record, Envoy advisory GHSA-3wvj-j6qm-62mr and upstream
fix `google/brotli@0ed4268`. Affected C library 1.0.3–1.0.9, 1.1.0 and
1.2.0; fixed 1.0.10 / 1.1.1 / 1.2.1, with downstream Node.js, Python
`Brotli`, Bun and Envoy copies. Claimed primitive: a crafted stream writes
attacker-chosen bytes past the decoder's 8-byte `buffer.u8` into adjacent
state; CVSS 4.0 9.2 (`PR:N`). Frontier observed rungs 1/2/3 on a standalone
file-only harness: v1.2.0 stage-1 spin plus stage-2 SIGSEGV, v1.2.1 hard
error `-17`, 20 chosen bytes at indices 8..27 setting three state fields to
`0x7fffffff`. Small C target, exact tags, public patch and no hardware
gate make a rung-4 attempt plausible. Rung 4 is NOT demonstrated; network
reachability and public RCE claims stay unverified, and the
`ikow/brotli2crash` non-exploitability claim is preserved. Evidence:
`reports/frontier-brotli2shell.md` (commits `fb821a2`, `02d34fa`). The
dedicated `brotli2shell` mind owns this lane; details in
`.mishe-tauftauf/charters/brotli2shell.md`.

#### Admitted 2026-11-20 ~17:45Z: Freeradius2Shell (CVE-2026-127030)

Claim source: the cve.org record and Red Hat CVE page for CVE-2026-127030
(CNA Red Hat, published 2026-11-12, CVSS 3.1 7.5 `AV:N/AC:L/PR:N/UI:N/A:H`,
CWE-787) plus upstream fix `064567a08f3b` against vulnerable parent
`3f802d74deef`. Affected RHEL 10/9/8/7 per Red Hat; the exact fixed release
tag is UNKNOWN — the fix commit is the version boundary. Claimed primitive:
a remote unauthenticated oversized EAP-FAST SessionTicket drives
`hdr.length`-sized AES-GCM decrypt bytes into a 152-byte stack struct before
tag verification, overwriting the saved return address. Frontier observed
rungs 1/2/3 and a harness-only rung 4 on a standalone file-only harness:
chosen `0x4242…` at the saved-RIP slot, canary abort rc 134, chosen marker
executes rc 42, fixed build rejects `PAC is too long` rc 0; ASan is honestly
blind because the write occurs inside libcrypto. Small C module, exact
vulnerable/fixed commits, public diff, no hardware gate and unauthenticated
network framing make a rung-4 attempt plausible. Rung 4 is harness-only:
live `radiusd`, network reachability, real stack layout and the key-unknown
byte-control case remain UNKNOWN. Evidence: `reports/frontier-freeradius2shell.md`
(commit `2d708ec`, witness replay tape #227). The dedicated `freeradius2shell`
mind owns this lane; details in `.mishe-tauftauf/charters/freeradius2shell.md`.

#### Admitted 2026-11-20 ~18:12Z: FalkorDB2shell (CVE-2026-107909 / GHSA-x67x-q5pm-p9h7)

Claim source: the CVE record and GitHub advisory for CVE-2026-107909 /
GHSA-x67x-q5pm-p9h7 (NVD-sourced, published 2026-10-09, CVSS 4.0 8.8,
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H`, CWE-787). Claimed primitive: a
remote unauthenticated WebSocket frame with a 64-bit extended payload length
to the Bolt port drives `buffer_apply_mask()` past the receive buffer
because the only bounds check is an `ASSERT()` compiled out of release.
Affected FalkorDB before 4.20.0; upstream fix `0b11a00b34b25c4d4fdfe55f0a35c8a00593bd7d`
(2026-07-08, PR #2170) deletes the entire Bolt/WebSocket subsystem, so there
is no patched `ws_read_frame()` to diff; the lab `FIXED` build is a local
length guard, not the upstream fix. Bolt is disabled by default. Frontier
observed rungs 1/2/3 on a standalone extracted-C harness: declared length
4144 with zero payload bytes gives 525 OOB XOR writes, a chosen mask flips a
zero canary to `0x4242…` or `0x4141…`, the in-bounds control gives zero OOB
writes, and ASan names `buffer_apply_mask_single` under a short-chunk lab
layout. Small C subsystem, exact vulnerable parent, public fix commit, no
hardware gate and unauthenticated framing make a rung-4 attempt plausible.
Rung 4 is NOT demonstrated: every 8-byte word is the repeating 4-byte mask
(`K:K`), not a chosen pointer; live `BOLT_PORT` reachability, handshake path,
real heap layout and the first OOB `chunks[]` pointer remain UNKNOWN.
Evidence: `reports/frontier-falkordb2shell.md` (commit `b140144`). The
dedicated `falkordb2shell` mind owns this lane; details in
`.mishe-tauftauf/charters/falkordb2shell.md`.

#### Admitted 2026-11-20 ~17:52Z: Freeswitch2Shell (CVE-2026-116785 / GHSA-jj89-q47c-gh94)

Claim source: GitHub advisory GHSA-jj89-q47c-gh94 and the CVE record for
CVE-2026-116785 (CNA GitHub, CVSS 3.1 9.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`, CWE-122/681/787). Claimed primitive:
an unauthenticated WebSocket frame on an enabled `mod_xml_rpc` endpoint uses
the 8-byte extended length field; `ws_read_frame()` swaps only its low 32 bits
into signed `int plen`, so `FF FF FF FF` gives `plen=-1`, the signed guard
passes and the unbounded `size_t` copy writes sender-chosen bytes from
`buffer+14` across `wbuffer` into the handle's tail fields, including
`SSL *`. Affected `<= 1.11.1`, fixed `>= 1.11.2`; upstream fix
`d557ca6d29e6da4f10824dc158100906a592b91a` against vulnerable parent
`fbac12b451a1` adds `ws_get_be64()` and an unsigned length guard. Both
`mod_xml_rpc` and `enable-websocket` are off by default; where enabled the
endpoint is HTTP/WebSocket, not SIP (the separate, earlier FreeSWITCH decline
was the SIP-facing GHSA-f73w-xph4-pjp3). This candidate is distinct from the
screened-out GHSA-294g-hq4w-c275, whose overflow bytes are the configured
credential's base64 tail and not sender-chosen.

Small single-file subsystem, exact vulnerable/fixed commits, no hardware gate
and unauthenticated HTTP framing make a rung-4 attempt plausible. Operator
reproduction 18:28Z (throwaway copy of digests-pinned sources) observed
rungs 1/2 placement, an ASan `heap-buffer-overflow` `WRITE of size 132146` in
`memcpy` from `ws_raw_read`, and a chosen 8-byte value at
`offsetof(wsh_t, ssl)=131112` executing a marker with `rc=42`; in-bounds and
fixed-build controls pass and five repeats are identical. Frontier repaired
the harness accounting and exit codes at 19:02Z; the driver now prints
`ALL CHECKS PASS` (rc 0) with pinned sources `ws_overflow.c` `75433b5d…` and
`run.sh` `637cfa36…`. The earlier 2928 OOB-write count was double the real
extent because a zero-byte read underflowed `trace_copy()`; 1464 is correct.
This is a harness-only rung 4 for marker execution. Two real-source checks
compiled the unmodified pinned `ws.c` with Abyss type stand-ins over a
127.0.0.1 socket (`lab/freeswitch2shell/live/`). With the advisory's
`FF FF FF FF` frame (`plen=-1`) ASan reports `negative-size-param (size=-5)`,
the plain build aborts rc 134 and the fixed source returns `rc=-1009` with
`wsh->ssl` untouched. `bash lab/freeswitch2shell/live/run_pos.sh` adds a
positive length, `7F FF FF FF 00 00 00 00` (`plen=INT_MAX`): the guard's
signed add overflows, the real `ws_raw_read` copies sender bytes verbatim,
and the plain build writes `0x4142434445464748` to `wsh->ssl`
(`ssl_bytes=4847464544434241`, `RESULT=PASS`, rc 0); fixed `rc=-1009` with
`ssl=(nil)` and ASan `WRITE of size 4096` at the end of a 131136-byte region.
Chosen-pointer control is therefore demonstrated in the real function over
loopback, not just in the extracted harness.
Wake 4 (20:29Z) closed the live gap: a full vulnerable FreeSWITCH ran in a
private `unshare -n` netns with `mod_xml_rpc` + `enable-websocket`, bound
`127.0.0.1:18080`, completed a WebSocket `101` upgrade and took a crafted
unmasked extended-127 frame. GDB captured `wsh->ssl=0x4847464544434241` and
the same value in `$rdi` at the SIGSEGV in `SSL_shutdown` from `ws_destroy
(ws.c:367)` ← `websocket_hook (mod_xml_rpc.c:703)`. Fixed-source and
in-bounds-frame controls both survive. The opt-in module/flag gate, lab-only
build shims and 127.0.0.1-only scope stay in the claim; the sentinel is not
executable code. Evidence: `lab/freeswitch2shell/live/logs/live_gdb/`,
`live_fixed/`, `live_safe/`, scripts `run_live_gdb.sh` / `run_live.sh`.
Durable evidence:
`reports/frontier-freeswitch2shell.md` (reproduction section), harness
`lab/frontier/freeswitch2shell/{ws_overflow.c,run.sh}`. The dedicated
`freeswitch2shell` mind owns this lane; details in
`.mishe-tauftauf/charters/freeswitch2shell.md`.

#### Admitted 2026-11-20 ~19:32Z: Freerdp2Shell (CVE-2026-114045 / GHSA-3m9q-g533-rqjq)

Claim sources: the GitHub advisory GHSA-3m9q-g533-rqjq, the CVE/OSV and NVD
records for CVE-2026-114045, FreeRDP's 3.32.1 release notes and the 3.32.0 to
3.32.1 diff, read as provisioning, not lab findings. CWE-122 via CWE-190;
CVSS 3.1 8.8 High post-auth (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), 9.8
Critical only in no-auth deployments. Affected `master <= 8ec6d3923b…` and
stable `<= 3.32.0`, fixed `>= 3.32.1` (tag `bf217a5`); lineage: a bypass of
the CVE-2026-63117 fix (`b7ca093`). Claimed primitive: a client
`WAVE_FORMAT_DVI_ADPCM` `SNDC_FORMATS` record with `nBlockAlign=4,
nChannels=2` passes the scalar `>= 4` floor but violates the unchecked codec
relation `nBlockAlign >= 4*nChannels`; `select_format()` wraps a UINT64 block
size to `0xfffffffffffffff0`, commits it to `out_frames`, fails the `realloc`
without rollback, and `send_samples()` then `CopyMemory`s client audio bytes
into the still-8820-byte buffer at monotonically advancing offsets — an
unbounded sequential heap write of client-chosen bytes. Default posture is
**post-authentication (`PR:L`)**: keep that gate prominent in every impact
claim. This is a native C RDP server component, in the plant's admitted
"similar things" class alongside FreeSWITCH, FreeRADIUS and Brotli.

Small single-subsystem diff, exact vulnerable/fixed commits, no hardware gate
and a full bulk `memcpy` of client-supplied bytes (no reliance on glibc
tail-first/store-first zero-store windows) make a rung-4 attempt plausible.
The operator re-ran the digests-pinned harness at 19:30Z from committed
sources: `ALL CHECKS PASS`, rc 0, digests `d0a31487…` / `c5186500…`; rungs
1/2/3 with `out_frames=0xfffffffffffffff0`, `oob_writes=7564` starting at
offset 8820, chosen bytes at offsets 8820/12000, and ASan
`heap-buffer-overflow` `WRITE of size 16384` `0 bytes after an 8820-byte
region`; rung 4 places chosen `de`/`ad` at offsets 8820/21384 with
`out_pending_frames=8192`; benign PCM and the 3.32.1 guard are clean and five
vulnerable traces are byte-identical. Wake 4 drove the crafted PDU through
the real `rdpsnd_server_recv_formats()` parser on source-built 3.32.0
library bytes: ASan `WRITE of size 16384` 0 bytes after an 8820-byte region
from `rdpsnd_server_send_samples`, and a sanitizer-free replay placed `de`
at OOB offset 8820 and `ad` at 21384, fixed-guard control rc 3 with no
wrap. This was a chosen-byte rung 4 on real library bytes, still in-process at
wake 4: MCS/channel setup, rdpsnd over the wire, live-process corruption,
stock allocator layout and a full RDP session were UNKNOWN then; wake 8 below
moves the transport and live-server items to observed.
Wake 5 framed a complete SNDC_FORMATS PDU and drove the real exported
`rdpsnd_server_handle_messages()` dispatcher (rdpsnd_main.c:1204-1298) with a
stub WTS read callback, including body reassembly across reads and msgType
demux. A read-only source survey corrected the earlier implication that the
DVI record was shadow-reachable: `select_format()` is called from the server's
`Activated` callback, and shadow's default format list has no DVI_ADPCM
(tag `0x11`), so that variant is a library-level path only. A
WAVE_FORMAT_ADPCM record (tag `0x02`, `nBlockAlign=8`, `nChannels=2`) wraps
`out_frames` to `0xfffffffffffffffc`. Wake 6 then replaced the stub with
libfreerdp's real WTS reader (`FreeRDP_WTSVirtualChannelRead`), a real
`wMessageQueue` and the shadow `Activated` selection logic, and corrected the
reachability claim again: `freerdp_dsp_supports_format()` leaves only PCM in
the FFmpeg-off builds tested here, so neither wrap-capable tag is selected
from the stock server list. The positive rung 4 supplies an ADPCM server
record through `subsystem->rdpsndFormats`; with that condition explicit,
chosen-byte readback and the ASan `WRITE of size 16384` hold through the real
reader, dispatcher, activation and parser. Wake 7 ran a real 3.32.0
`freerdp-shadow-cli` on 127.0.0.1:13890 and the committed probe completed
X.224 / RDP_NEG_REQ over real TCP: protocol selection `0x08`/`0x02`/`0x00`,
and a TLS handshake that stops at `CONNECTION_STATE_NEGO` when CredSSP is
withheld under default NLA, while standard-RDP local-peer mode advances
without credentials. Wake 8 completed MCS CONNECT / ERECT DOMAIN / ATTACH
USER / three CHANNEL JOIN confirms via `live_mcs_join_probe.py` and drove a
headless `sfreerdp` to `CONNECTION_STATE_ACTIVE`; `SNDC_FORMATS` crossed the
wire and a subsystem-supplied ADPCM record made the live server log
`realloc failed!` / `SelectFormat failed with 12`. A synthetic playback
event then gave the live ASan server `WRITE of size 16384`, 0 bytes after an
8820-byte region, from `rdpsnd_server_send_samples`, with client-chosen
`0xDE` at offset 8820. No-auth posture, subsystem-supplied format table,
ASan build and synthetic audio are explicit conditions; stock allocator
layout, a real audio source and an FFmpeg-enabled build stayed UNKNOWN
then; wake 9 closed the stock-allocator item: the live chosen-byte overwrite
under stock glibc wrote 7564 OOB bytes at offsets 8820..16383 with the first
OOB byte client-chosen, did not fault at the write and produced glibc
`double free or corruption (!prev)` on teardown; a benign control stayed in
bounds. Wake 10 made that live result one command:
`bash lab/freerdp2shell-src/verify_live.sh` applies five committed patches
to pinned 3.32.0, builds a plain shadow server and `client/Sample sfreerdp`,
and asserts over real loopback TCP readiness: 17 PASS / 0 FAIL warm and
18 PASS / 0 FAIL clean-room, rc 0, in
`lab/freerdp2shell-src/verify_live_run.txt`. The vulnerable session logs
`WAKE9_COPY ... b8820=de ... b21384=00` before glibc corruption and the
`FR_BENIGN_ONLY=1` control keeps `b8820=00`. Witness W31 independently
re-ran the unmodified script from clean HEAD b25d025 in its own clean room:
18 PASS / 0 FAIL, RC 0, verdict ESTABLISHED with no corrections (#532). The
one-command harness uses post-auth credentials, so it does not re-assert the
no-auth 9.8 case. Wake 12 measured the live stock glibc layout in three
loopback sessions (ports 23143-23145, byte-identical apart from the ASLR
arena base): requested 8820 → usable 8824 → chunk size 8832, next size field
at `out_buffer+8824`, and a 64-byte chunk at `out_buffer+9056` holding two
live heap pointers at +9072/+9080 (`base+0x2340`) that the chosen-0xDE write
replaces byte-for-byte. Pointer-bearing heap data in the write path is
OBSERVED. Wake 13 identified that object as the wLog for
`com.freerdp.channels.rdpsnd.server` (144-byte wLog struct at
`out_buffer+8880`, `Names` field at `+8904`, pointer array at `+9072`), and showed
that a configured `WLOG_FILTER` plus a scratch log call injected immediately
after the real `CopyMemory` makes `WLog_GetFilterLogLevel` execute
`mov (%rax,%r15,8)` with `rax` equal to the eight chosen `0x41` bytes at
`+8904`. The dereference base is exactly the chosen value; `+9072..+9119`
chosen bytes alone did not move the fault. Wake 14 removed the scratch server
log call: on the unmodified server, FreeRDP's own `SNDC_QUALITYMODE` receive
path reaches the clobbered wLog after the write; with a scratch client-side
delay the live stock server faults at the same instruction with
`rax=0x4141414141414141` (`natural_log_trigger_stock.txt`, raw logs under
`verify-live-out/wake14/`). Limits: chosen playback bytes are lab-supplied,
the object was identified after the fact with no grooming, only one object
was controlled, a client-side delay and `WLOG_FILTER` are required, and the
no-filter control stays clean. Arbitrary heap targeting stays UNKNOWN.
Evidence: `reports/frontier-freerdp2shell.md`, extracted harness
`lab/frontier/freerdp2shell/{rdpsnd_overflow.c,run.sh}`, real-library
harness `lab/freerdp2shell-src/{run.sh,*.c}` with committed traces, seed
status `reports/freerdp2shell-status.md`, the wake-12 layout capture
`lab/freerdp2shell-src/heap_layout_stock.txt`, the wake-13 chosen-pointer
capture `lab/freerdp2shell-src/pointer_control_stock.txt` and the wake-14
natural-trigger capture `lab/freerdp2shell-src/natural_log_trigger_stock.txt`.
The dedicated
mind owns this lane; details in `.mishe-tauftauf/charters/freerdp2shell.md`.
Wake trigger units and the presentation.json entry are owed from the
person's full-flag sync, never a bare `mishe sync`.

#### Admitted 2026-11-20 ~20:27Z: Xrdp2Shell (CVE-2026-44178 / GHSA-hh7r-2rmq-q4g4)

Claim sources: the GitHub advisory GHSA-hh7r-2rmq-q4g4, the CVE/OSV/NVD
records for CVE-2026-44178, xrdp's v0.10.6.1 release notes and the
`v0.10.6...v0.10.6.1` diff, read as provisioning, not lab findings. CWE-122;
CVSS 3.1 8.8 High post-auth (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), 9.8
Critical only in no-auth deployments. Affected `< 0.10.6.1`; fixed in
`0.10.6.1` (tag `v0.10.6.1`, fix commit
`43dc9c3b71e5e46733d70ec0239c482ee264cd9f`). Claimed primitive: an
authenticated client's reassembled DYNVC virtual-channel message exceeds the
fixed 8192-byte xrdp→chansrv out stream; all three writers ask
`trans_get_out_s(trans, 8192)` on an exactly-8192-byte stream, `init_stream`
keeps that buffer, and `out_uint8a` is a plain `g_memcpy` with a bounds check
gated behind `USE_DEVEL_STREAMCHECK`, absent in ordinary builds. The client
controls the length (`drdynvc_process_data_first()` checks only
`total_bytes >= 1590 && bytes <= total_bytes`; DYNVC reassembly stages a
client-sized stream), so a multi-chunk message drives the copy far past the
8164/8168/8166-byte thresholds. Default posture is **post-authentication
(`PR:L`) with a dynamic channel open**: keep that gate prominent in every
impact claim. Native C RDP server component, in the admitted "similar things"
class alongside FreeRDP, FreeSWITCH, FreeRADIUS and Brotli.

Exact vulnerable/fixed tags, a public single-file subsystem diff, no hardware
gate and a full bulk `memcpy` of client-supplied bytes (no reliance on glibc
tail-first/store-first zero-store windows) make a rung-4 attempt plausible.
The operator re-ran the digests-pinned harness at ~20:25Z from committed
sources: `ALL CHECKS PASS`, rc 0, digests `46735a43…` / `2da4d3ea…`; rung 1
28+20000 bytes gives `oob_writes=11836 first_oob=8192 last_oob=20027`
(static 26-byte path 11834), rung 2 chosen `ab`/`cd` at OOB offsets
8228/12028, rung 3 ASan `heap-buffer-overflow` `WRITE of size 20000` 0 bytes
after the 8192-byte region via `do_copy` -> `drdynvc_data_first`, rung 4
`de`/`ad` at OOB offsets 8228/12024 across two messages; exact-size 0.10.6.1
and benign controls show `oob_writes=0` and 5/5 traces are byte-identical.
The claimed harness-only boundary was advanced on 2026-11-21: a second driver
(`lab/xrdp2shell-real/`, digests `a05ba8ac…` / `ecfe9f7e…`) links the real ASan
xrdp 0.10.6 `libxrdp.a` / `libcommon.a` and calls `xrdp_channel_process()` →
real `drdynvc_process_data_first()` → real `out_uint8a` on the `trans_create`
buffer: ASan `WRITE of size 20000` 0 bytes after the 8192-byte region, 8164
clean / 8165 OOB, 5/5 identical. A non-ASan reader plants an adjacent canary
chunk and reads chosen `DEADBEEF-CR` / `C0FFEE00-CR` back at offsets 84/484,
8208 bytes past the buffer start; no pointer-sized field or control-flow
target was controlled, and a `free()` variant aborts `malloc(): corrupted
top size`. The 8128-byte cap is a synthetic control, not the real 0.10.6.1
  fix. A wire-format driver (`lab/xrdp2shell-real/wire_drdynvc_driver.c`)
  now feeds a full TPKT/X.224/MCS SendDataRequest/channel/DYNVC_DATA_FIRST
  PDU to the real `xrdp_rdp_recv()`: ASan `WRITE of size 8191` 0 bytes after
  the 8192-byte `trans_create` region at payload 8191 (8164 clean), while
  the 20000-byte harness payload is rejected by `xrdp_mcs_recv()`'s 16K
  userData limit — only 8165–~16375 bytes are wire-reachable in one PDU.
  It is still in-process: a completed RDP logon, chansrv-negotiated
  dynamic-channel open, socket-level network PDU trace, stock live-session
  allocator layout and the auth gate stay UNKNOWN; loopback COTP
  reachability of the lab listener is the only network observation.
  Witness W33 (#548) found both the wire-PDU and real-code claims ESTABLISHED
  as claimed, with the disclosed limit that it compiled against the existing
  lab build tree rather than a clean-room rebuild; the committed real driver
  needed `-include config_ac.h` and an earlier `-I` on this host, a RUNBOOK
  correction owed to the xrdp2shell mind. Evidence:
`reports/frontier-xrdp2shell.md`, harness
`lab/frontier/xrdp2shell/{xrdp_overflow.c,run.sh}`, real-path drivers and
runbook `lab/xrdp2shell-real/{real_drdynvc_driver.c,chosen_bytes_real_path.c,RUNBOOK.md}`,
status `reports/xrdp2shell-status.md`. The dedicated `xrdp2shell` mind owns this
lane; details in `.mishe-tauftauf/charters/xrdp2shell.md`. Wake trigger units
and the presentation.json entry are owed from the person's full-flag sync,
never a bare `mishe sync`.

#### Admitted 2026-11-20 ~20:52Z: Gst2Shell (CVE-2026-111183 / GHSA-62fg-53h6-6f68)

Claim sources: GHSA-62fg-53h6-6f68 / CVE-2026-111183 / ZDI-26-775
("GStreamer rtpL16depay Heap-based Buffer Overflow Remote Code Execution",
2026-10-15), the NVD/GHSA and ZDI advisories, and the fix commit
`80c184b4c5ee8ba28b2540ba58f40b8d44b61622` (2026-10-08) against vulnerable
parent `0b70c356345335dacc0acdc45d07a8a33bdf5eab`, read as provisioning, not
lab findings. CWE-122, CVSS 3.0 **9.8 Critical**
(`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) — pre-auth by the vector; a loopback
RTSP server → `rtspsrc` caps path was later demonstrated locally (see below),
but whether any public service accepts attacker SDP and the claimed RCE stay
UNKNOWN. Claimed
primitive: caps `encoding-params` is parsed into `channels` with no upper
bound (`gstrtpL16depay.c:181-189`), stored in the heap-embedded
`GstAudioInfo`; for `channels > 8` no channel order exists, so
`:201-216` calls `gst_rtp_channels_create_default (channels, info->position)`,
whose loop at `gstrtpchannels.c:301-310` writes
`GST_AUDIO_CHANNEL_POSITION_NONE` to `posn[0..channels-1]` with no bound.
`info->position` holds 64 elements, so `channels=1000` writes 936 elements /
3744 bytes out of bounds. The fix adds `gsize n_posn = G_N_ELEMENTS
(info->position)` and clamps with `channels = MIN (channels, n_posn)`.

An exact vulnerable/fixed commit pair, a pure length-check omission in one
small C function with a three-line fix, no hardware gate and a pre-auth
vector make a rung-4 attempt plausible. The operator re-ran the digests-pinned
harness at 20:47Z from committed sources: digests `3d2b8e06…` / `7dde5da7…`
match, `ALL CHECKS PASS`, rc 0. Rung 1 `channels=1000 position_capacity=64
oob_writes=936 first_oob=256 last_oob=3999` with 3744 counted zeroed OOB
bytes; rung 2 a caps value of 200 clobbers OOB offset 768 but not 1792, a
value of 1000 clobbers both; rung 3 ASan `heap-buffer-overflow`, `WRITE of
size 4`, 0 bytes after a 256-byte region in `vuln_create_default`; the
`MIN`-clamped fixed control gives `oob_writes=0` and 5/5 traces are
byte-identical. The extracted harness's `NONE=0` model was wrong: pinned
`audio-channels.h:101` defines `NONE=-3`, so the OOB writes store
`fd ff ff ff` and index 73 corrupts the low half of the `order` pointer from
NULL to `0x00000000fffffffd`. A live GStreamer 1.24.2 ASan harness
(`bash lab/gst2shell-src/run_live.sh`) faults at the real `depay.c:267`
`order->pos` dereference; the shipping `rtpL16depay` plugin
(`bash lab/gst2shell-src/run_real.sh`) faults rc 139 for `encoding-params`
86/87/100/1000, with a second glibc `free()` fault mode at N=86. A 2026-11-21
pass symbolicated the N=1000 shipping fault by gdb debuginfod to `srcpad->g_class`
of a heap-adjacent GstPad, and `bash lab/gst2shell-src/run_sdp.sh` drove
`a=rtpmap:96 L16/44100/N` SDP text through GStreamer's own SDP parser into the
fault at N=86/1000 (the harness explicitly models the RTP structure name); the
`sdpdemux` file path reached PLAYING without instantiating `rtpL16depay` and
fails at benign N=8 too, a bounded negative. A loopback RTSP server then fed a
real `rtspsrc ! rtpL16depay ! fakesink` victim pipeline with no auth challenge
(`rtsp_server.py` digest `f812d844…e0668`, `run_rtsp.sh` digest
`9841c920…2a5d`): N=8 is clean, N=1000 faults rc 139 four times with the
corruption in GLib's `block_source` (`rbx = 0xfffffffdfffffffd`); stock
`uridecodebin` auto-plumbing selects the same depay and aborts rc 134 with
`malloc(): invalid size`, removing the explicit-link step. This is a
count-controlled rung-4 effect, not chosen bytes: strong rung 4; whether a
public service ingests attacker SDP, RCE and allocator layout stay UNKNOWN.
The same loopback server was run across the whole advisory family
(`rtsp_server_codec.py` `1493f137…cb45c`, `run_rtsp_family.sh`
`54e8331e…786e`, evidence `family_evidence.txt`): decodebin auto-plugs
`GstRtpL8Depay`, `GstRtpL16Depay` and `GstRtpL24Depay`, and N=1000 faults each
— L8 `malloc(): unaligned tcache chunk detected` rc 134, L24 `malloc():
invalid size (unsorted)` rc 134, L16 `Caught SIGSEGV` rc 124 at the timeout —
against clean N=8 controls. The exact glibc message and rc vary between runs,
so the asserted claim is only "attacker-chosen count faults the victim". The
same L8 path under memcheck shows three 4-byte invalid stores 0/4/12 bytes
past a 1016-byte GObject allocation; the shipping plugin has no debug info,
so that write is not symbolicated to a function name in that run. One command
replays every driver: `bash lab/gst2shell-src/verify_all.sh` (add
`VERIFY_VALGRIND=1` for the memcheck lane). An independent witness replay
contradicted the earlier "43 PASS / 0 FAIL at HEAD 3b07571" assertion on its
host: 42 PASS / 1 FAIL, rc 1, with only `L8 N=1000 faults victim` failing on
`malloc_consolidate(): invalid chunk size` / `dumped core` (rc 134), a family
the old regex did not admit. `checkfault` now accepts that fault family or a
nonzero per-leg rc recorded by the family runner, keeping 43 checks. From
repaired HEAD 31e7243 the author's `VERIFY_VALGRIND=1` replay reported
43 PASS / 0 FAIL, rc 0 (`verify_all_clean_head_run.txt`); a docs-side run
without that flag reported 39 PASS / 0 FAIL, rc 0. Both are author-side
replays, not independent acceptance. Witness W33 (#552) re-ran the
unmodified `VERIFY_VALGRIND=1` replay from clean HEAD 2a78ee6: 43 PASS /
0 FAIL, rc 0, REPAIR ESTABLISHED and the 42/1 contradiction closed.
Chosen-byte rung 4 stays NOT DEMONSTRATED.
Evidence:
`reports/frontier-gst2shell.md`, harness
`lab/frontier/gst2shell/{rtp_channels_overflow.c,run.sh}`, seed status
`reports/gst2shell-status.md`; the SDP harness `lab/gst2shell-src/sdp_caps.c`
and `run_sdp.sh` (digest `6ba2e707…c4f`), the gdb trace
`lab/gst2shell-src/gdb_symbolicated_1000.txt`, the RTSP driver
`lab/gst2shell-src/{rtsp_server.py,run_rtsp.sh}` and its tracked
`rtsp_evidence.txt` / `rtsp_gdb_1000.txt` are tracked. The dedicated
`gst2shell` mind owns this lane;
details in `.mishe-tauftauf/charters/gst2shell.md`. Wake trigger units and
the presentation.json entry are owed from the person's full-flag sync, never
a bare `mishe sync`.

#### Admitted 2026-11-20 ~22:2xZ: Babelfish2Shell (CVE-2026-119923 / GHSA-vq28-vgj3-r26w)

Claim sources: CVE-2026-119923 / GHSA-vq28-vgj3-r26w / AWS bulletin
2026-166-AWS, the AWS/GHSA/NVD advisories, and the fix commit
`ab820bddaffa540af82f2f689c3e535f82f14d89` (backports
`66fe10002e37`/5.6, `f0b8bd54aad1`/6.1) against vulnerable tag
`BABEL_4_8_0`, fixed tag `BABEL_4_10_0`, read as provisioning, not lab
findings. CWE-122, CVSS 3.1 **9.8 Critical**
(`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), CVSS 4.0 9.3 — a remote
unauthenticated crafted prelogin packet to the TDS port (default 1433); the
claimed RCE is a claim, not a demonstration. Claimed primitive:
`tdslogin.c:342-363` `ParsePreLoginRequest` reads an unbounded 16-bit
network-order `length`; `initStringInfo` allocates exactly 1024 bytes;
`tdslogin.c:377-383` calls `TdsGetbytes(prev->val.data, prev->length)` and
`tdscomm.c:634-659` `memcpy`s `length` sender bytes verbatim into that
buffer with no resize — both copy count and written bytes are
attacker-controlled. The fix rejects `length > 4096` and calls
`enlargeStringInfo` before the copy.

An exact vulnerable/fixed tag pair, a pure missing-bounds-check, no hardware
gate or credentials for rungs 1–3 and a pre-auth vector make a rung-4
attempt plausible; unlike Gst2Shell's fixed `-3` write pattern, the OOB bytes are
sender-chosen. Frontier re-ran the pins-pinned harness at handoff: pins
`c5559f08…` / `d4b09e8c…` match the brief and `ALL CHECKS PASS`, rc 0. Rung 1
`length=4096 si_capacity=1024 oob_writes=3072 first_oob=1024
last_oob=4095`; rung 2 lengths 1050/1150/2100 clobber neither/first/both
neighbour stamps; rung 3 ASan `WRITE of size 4096`, `0 bytes after
1024-byte region` in `wire_getbytes`; rung 4 sender bytes `de ad be ef ca fe
ba be` and `41 42 43 44` land byte-exact at OOB offsets 1100/2000; the fixed
control gives `rc=0 oob_writes=0`, clean under ASan, and 5/5 traces are
byte-identical. Rungs 1/2/3 are established only in the extracted harness;
rung 4 shows chosen bytes at chosen offsets there, **not** in a live
process. No real Babelfish/PostgreSQL process, TDS endpoint, `palloc`/heap
layout, real neighbouring object, pointer control or marker execution was
observed — the consumer-reality check is still owed. Distinct from the
`postgres2shell` FDW lane and CVE-2026-119924. Evidence:
`reports/frontier-babelfish2shell.md`, harness
`lab/frontier/babelfish2shell/{prelogin_overflow.c,run.sh}` with raw sources
and `PROVENANCE.md` under `src/`, seed status
`reports/babelfish2shell-status.md`. The dedicated `babelfish2shell` mind
owns this lane; details in `.mishe-tauftauf/charters/babelfish2shell.md`. The
two-pane window (inner socket, window 21), registry entry and seed wall are
already live from frontier; wake trigger units and the presentation.json
entry are owed from the person's full-flag sync, never a bare `mishe sync`.

#### Admitted 2026-11-21 ~00:5xZ: Bzfs2Shell (CVE-2026-130849 / GHSA-9q5f-g948-c95m)

Claim sources: CVE-2026-130849 / GHSA-9q5f-g948-c95m / EUVD-2026-127253 (CNA
VulnCheck, published 2026-11-17), "BZFlag bzfs before 2.4.32 Heap
Out-of-Bounds Write via NetHandler::tcpReceive()", CWE-122, CVSS 4.0 **9.3
Critical** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/...`), read as
provisioning, not lab findings. Affected `< 2.4.32` (including v2.4.30), fixed
`2.4.32`; fix commit `8e501d685aef549090b363260979a4eb93484ea1` (OSV also
resolves the tag to `f11f05485d7406c78159aac00ace3c58b4b17ec2`), vulnerable
tag `v2.4.30`. Claimed primitive: a TCP body length of exactly 1024 passes a
guard that rejects only `len > MaxPacketLen`, so `recv(fd, tcpmsg + 4, 1024)`
writes four body bytes past `tcpmsg[1024]` into the adjacent `int tcplen`;
choosing those bytes negative leaves `tcplen` below zero after `tcplen +=
size`, so the next `receive()` writes chosen bytes before the object. The fix
bounds the body to `MaxPacketLen - 4` and rejects a bad offset or length
before `recv`.

Scope: `bzfs` is a dedicated C++ game server, not a language runtime or HTTP
server; it is admitted as an X2Shell-class extension under the same precedent
that admitted FreeRADIUS, Brotli and FalkorDB — a pre-auth network-reachable
heap OOB write with sender-chosen bytes, exact tags and an advisory RCE claim.
The judgment is recorded, not buried; revisit this lane first if the class is
later narrowed. Distinct from every other admitted lane.

One off-by-header bound in one function, a 13-line fix diff, a one-packet-pair
unauthenticated trigger and OOB bytes that are the tail of the attacker's own
body make a rung-4 attempt plausible. Frontier re-ran the digests-pinned
harness at handoff: `bash lab/frontier/bzfs2shell/run.sh out` printed `ALL
CHECKS PASS`, rc 0; pins `1a16963f…` / `f2686d5b…`. Rung 1 `tcplen=-1024` with
the chosen tail at `tcpmsg+1024`; rung 2 destination 936 bytes before the
object, next length 1028; rung 3 ASan `heap-buffer-overflow`, `WRITE of size
64`, `recv` → `traced_recv` → `receive_msg`; rung 4 `DEADBEEFCAFEBABE` and
`0123456789ABCDEF` read back byte-exact from chosen preceding members; fixed
controls reject at the first bound and are ASan-clean, five runs byte-identical
(`sha256=cea3b92e…`). Rungs 1/2/3 are established only in the extracted
harness; rung 4 is INSTRUMENTED CHOSEN-VALUE CONTROL — a real syscall writes
chosen bytes at a chosen harness member offset, but the prefix stand-in is not
the stock `NetHandler` layout. No live `bzfs` process, player socket, real
object layout, allocator neighbour, function pointer or execution was
observed; the advisory's RCE claim is untested here, and the consumer-reality
check is owed before any stock-build rung-4 claim. Evidence:
`reports/frontier-bzfs2shell.md`, harness `lab/frontier/bzfs2shell/` with
`PROVENANCE.md`, seed status `reports/bzfs2shell-status.md`. The dedicated
`bzfs2shell` mind owns this lane; details in
`.mishe-tauftauf/charters/bzfs2shell.md`. The two-pane window (inner socket,
window 22), registry entry and seed wall are already live from frontier; wake
trigger units and the presentation.json entry are owed from the person's
full-flag sync, never a bare `mishe sync`. Witness replay was requested
separately (#429).

#### Admitted 2026-11-21 ~02:2xZ: Kamailio2Shell (CVE-2026-106803)

Claim sources: OSV and cvelistV5 records for CVE-2026-106803 (CNA MITRE,
published 2026-11-02), upstream issue #4954, fix PR #4958 and fix commit
`21261436492f0014930e804e20586e3833bb91b9` with patch, and raw `notify.c` /
`save.c` at tags `6.1.4` and `6.1.5` (hashes and URLs in
`lab/frontier/kamailio2shell/PROVENANCE.md`). CWE-121, CVSS 3.1 **9.8
Critical** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Affected 6.1.3/6.1.4,
fixed 6.1.5, which enlarges `bufport`/`portbuf` to 6 bytes and adds a bound
check. Claimed primitive: a crafted `application/reginfo+xml` NOTIFY Contact
URI supplies `alias=<host>~<port>~<proto>`; `process_contact()` uses the
tilde distance as the `memcpy` length into `char bufport[5]` and then stores
an unchecked NUL, while `update_contacts()` has the same flaw with
`portbuf[5]`. The advisory claims unauthenticated process termination; its
`C:H/I:H` vector is a separate claim, not a lab result.

Scope: `ims_registrar_pcscf` is an IMS P-CSCF SIP module that must be loaded
and configured, not a default-on HTTP path. It is a C network-facing server
component, admitted as an X2Shell-class extension under the same precedent
that admitted FreeRADIUS, FreeSWITCH and Bzfs2Shell; the judgment is recorded
in `.mishe-tauftauf/charters/kamailio2shell.md` and this is the second lane
to revisit if the class is narrowed.

The overwrite length is a URI distance, not the numeric port, so long chosen
writes pass the 5-byte buffer; exact affected/fixed tags, a patch, no
hardware gate and a claimed unauthenticated trigger make a rung-4 attempt
plausible. The operator replayed the committed harness at ~02:1xZ: 16 PASS,
`ALL CHECKS PASS rc 0`, deterministic trace
`sha256=94ef79641b081f850cb04f95d0f0945e7de7f84f9505462f23bf8aa054fa1cb8`.
Rung 1 `len=80` with `oob=75`, rung 2 chosen function pointer and stamp
overwritten byte-exactly, rung 3 ASan `stack-buffer-overflow` `WRITE of size
80` from `memcpy` ← `parse_alias`, rung 4 `MARKER EXECUTED` through the
instrumented pointer only; the pinned 6.1.5 rule rejects `len=80` before the
copy. Rungs 1/2/3 are established in the extracted harness; rung 4 is
INSTRUMENTED chosen-value control. No live Kamailio, real frame layout,
stack protector, return-address control or execution was observed.
Evidence: `reports/frontier-kamailio2shell.md`, seed status
`reports/kamailio2shell-status.md`, harness `lab/frontier/kamailio2shell/`.
The dedicated `kamailio2shell` mind owns this lane. Its two-pane window
(inner socket, window 24), registry entry and seed wall were live from
frontier's handoff; wake trigger units and the presentation.json entry are
owed from the person's full-flag sync, never a bare `mishe sync`.

#### Admitted 2026-11-21 ~02:2xZ: Iperf2Shell (CVE-2026-101283 / GHSA-pwcx-5qh6-2pxc)

Claim sources: cvelistV5 record
`https://cveawg.mitre.org/api/cve/CVE-2026-101283` (CNA Anthropic, analyst
Ada Logics, published 2026-09-30), GitHub advisory GHSA-pwcx-5qh6-2pxc, the
esnet 3.22 release page and tag
`926bd905501b792bd082d2200d1d1a84aa543e3a`, the fix commit
`d08588aceee48fa45832cae5e32616abb33cb0fc` and raw `iperf_auth.c` at tags
3.20, 3.21 and 3.22 (hashes in `lab/frontier/iperf2shell/PROVENANCE.md`).
CWE-122, CVSS 4.0 **9.2 Critical**
`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`. Affected 3.20 and
3.21, fixed 3.22; the one-line fix turns the warn-only length guard into a
rejection before `BIO_read`. Claimed primitive: the base64-decoded client
`authtoken` length is passed as the `BIO_read` size into a 256-byte RSA heap
buffer, so the overflow length and bytes are attacker-chosen. The server
must have RSA auth enabled, but the oversized token is the input being
parsed, so the write is still pre-auth. Preserved conflict: 3.22 release
notes call this CVE a use-after-free in `iperf_server_api.c` and name a
separate CVE for the `iperf_auth.c` overflow; the CVE record, GHSA and fix
commit point at `decrypt_rsa_message()`.

Scope: `iperf3` is a C network-listening daemon, admitted as an X2Shell-class
extension under the same "similar things" precedent as FreeRADIUS,
FreeSWITCH and Bzfs2Shell; the judgment is recorded in
`.mishe-tauftauf/charters/iperf2shell.md`.

The write consumer is a real OpenSSL 3 `BIO_read` → `memcpy`, so the
nginx-plant zero-store lesson does not apply; a pre-auth network input,
exact tags and an exact patch make a rung-4 attempt plausible. The operator
replayed the committed harness at ~02:1xZ: 17 PASS, `ALL CHECKS PASS rc 0`,
trace
`sha256=bd3efc4cb4720e7fe5cc2e83e79cc7e89010f75a7e93579360a215eb5f029caf`.
Rung 1 decoded length 336 against a 256-byte modulus (`oob_bytes=80`), rung 2
glibc aborts at `free(): invalid size` from the next chunk's overwritten
metadata, rung 3 ASan `heap-buffer-overflow` `WRITE of size 336` from
`BIO_read` ← `decrypt_rsa_message` at `iperf_auth.c.3.21:324`, rung 4 chosen
`IPERF2SHELL!` and `0x1122334455667788` supplied in the write buffer only;
the pinned 3.22 rule rejects before `BIO_read`. Rungs 1/2/3 are established
on the real pinned upstream function; rung 4 is INSTRUMENTED chosen-byte
control, not pointer control in a stock binary. No live `iperf3`, stock heap
layout, useful-pointer control or execution was observed. Evidence:
`reports/frontier-iperf2shell.md`, seed status
`reports/iperf2shell-status.md`, harness `lab/frontier/iperf2shell/`. The
dedicated `iperf2shell` mind owns this lane. Its two-pane window (inner
socket, window 25), registry entry and seed wall were live from frontier's
handoff; wake trigger units and the presentation.json entry are owed from
the person's full-flag sync, never a bare `mishe sync`.

#### Admitted 2026-11-21 ~02:4xZ: Uftpd2Shell (CVE-2026-59964 / GHSA-vqhc-mmjf-972h)

Claim sources: the authoritative cvelistV5 record
`https://cveawg.mitre.org/api/cve/CVE-2026-59964` (CNA GitHub_M, published
2026-11-18, updated 2026-11-19), maintainer advisory GHSA-vqhc-mmjf-972h,
fix commit `f5552a8c6a5f14691f51bef1f3373747259d7ac8` and its patch, and
raw `src/common.c` at tags `v2.15` and `v2.16` (hashes and URLs in
`lab/frontier/uftpd2shell/PROVENANCE.md`). CWE-121, CVSS 3.1 **5.9 MEDIUM**
`AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H`. Affected `< 2.16`, fixed `2.16`;
the fix adds an 11-line bound before the `memmove`. CISA ADP SSVC:
Exploitation `poc`, Automatable `no`, Technical Impact `partial`. The
advisory claims memory corruption and a reliable crash; RCE is not
demonstrated and is not claimed here. Claimed primitive: without chroot,
a logged-in FTP client sends a near-`PATH_MAX` path; `compose_path()`
shifts the `strlcat`-capped `dir[PATH_MAX]` right by the configured home
length and writes that many bytes past the stack buffer. CWD/RETR/STOR/LIST
reach it. The `PR:L` and no-chroot gates stay in every impact claim.

Scope: uftpd is a C network-facing file server, admitted as an X2Shell-class
extension under the same "similar things" precedent that admitted
FreeRADIUS, FreeSWITCH, Bzfs2Shell, Kamailio2Shell and Iperf2Shell; the
judgment is recorded in `.mishe-tauftauf/charters/uftpd2shell.md`. Frontier
ranked the lane high tractability, MEDIUM priority; every pin needed for a
rung-4 attempt exists, which is the admission basis, not a RCE claim.

The write consumer is a real libc `memmove`, so the nginx-plant
structural-zero-store lesson does not apply; the overflow length and bytes
are attacker-influenced and the vulnerable/fixed bytes and 11-line patch
pin the intended semantics. The operator replayed the committed harness at
~02:38Z: 23 PASS, `ALL CHECKS PASS rc 0`, deterministic trace
`sha256=ad11094aa03e898df6c3b00a83b6b8ba8a9b049e0a0a18bf5fd952475d09d33b`.
Rung 1 `path_len=4095` / `home_len=128` / `expected_oob=128`, rung 2 plain
build aborts with `*** stack smashing detected ***`, rung 3 ASan
`stack-buffer-overflow` `WRITE of size 4096`, victim `dir` `[256, 4352)`
at pinned `common.c.v2.15:61`, rung 4 chosen `UFTPD2SHELL!` and
`0x1122334455667788` written by the upstream `memmove` only; pinned v2.16
leaves `returned=null`. Rungs 1/2/3 are established on verbatim pinned
upstream code; rung 4 is INSTRUMENTED chosen-byte control. No live uftpd,
stock frame layout, useful-pointer control or execution was observed;
whether the default `/srv/ftp` home's 9-byte overflow reaches a control
datum is UNKNOWN. Evidence: `reports/frontier-uftpd2shell.md`, seed status
`reports/uftpd2shell-status.md`, harness `lab/frontier/uftpd2shell/`. The
dedicated `uftpd2shell` mind owns this lane. Its two-pane window (inner
socket, window 26), registry entry and seed wall were live from frontier's
handoff; wake trigger units and the presentation.json entry are owed from
the person's full-flag sync, never a bare `mishe sync`.

#### Admitted 2026-11-21 ~03:1xZ: Accelppp2Shell (CVE-2026-123205)

Claim sources: the VulnCheck CNA record for CVE-2026-123205 (published
2026-11-05, PR #374), the OSV entry, the VulnCheck advisory and fix commit
`58e399400c4ef4b71472ab7c2c71c54a677a05a8`; pinned source hashes and URLs in
`lab/frontier/accelppp2shell/PROVENANCE.md`. CWE-122, CVSS 4.0 **8.3 High**
`AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`. Affected
`>= 0, < 1.15.0` (OSV lists 1.10.0/1.12.0/1.13.0/1.14.0), fixed 1.15.0.
The advisory claims memory corruption and a crash only; RCE is not claimed.
Claimed primitive: `unpack_msg()` in the tcp/syslog/pgsql log targets concatenates
unbounded chunk `memcpy`s into a fixed `LOG_MAX_SIZE 4096`-derived heap buffer;
in 1.14.0 the tcp target allocates 4160 bytes and a flood of L2TP string AVPs
under verbose logging assembles an arbitrary-length line before the trailing
newline. The `AT:P` logging gate and "within client-ip-range" condition stay
in every impact claim.

Scope: accel-ppp is a C network-facing PPP daemon, admitted as an X2Shell-class
extension under the same "similar things" precedent that admitted FreeRADIUS,
FreeSWITCH, Bzfs2Shell, Kamailio2Shell, Iperf2Shell and Uftpd2Shell; the
judgment is recorded in `.mishe-tauftauf/charters/accelppp2shell.md`. Frontier
ranked the lane high tractability, HIGH advisory severity; every pin needed
for a rung-4 attempt exists, which is the admission basis, not an RCE claim.

The write consumer is a real `memcpy` into a heap buffer, so the
nginx-plant structural-zero-store lesson does not apply; the overflow bytes
are attacker-supplied AVP strings. The operator replayed the committed harness
at ~03:07Z: 19 PASS, `ALL CHECKS PASS rc 0`, trace
`sha256=3499f52eef8814e5cc73c5e38f990ca0de3f4f0fc243640452c7806dc9c2b18a`.
Rungs 1/2/3 are established on the verbatim pinned upstream `unpack_msg()`
from `log_tcp.c.1.14.0`: 66 64-byte chunks plus a 30-byte header give
`pos=4254` into a 4160-byte region, `expected_oob=94`; chosen
`0x1122334455667788` reads back byte-exact at offset 4 in the adjacent
harness heap object; ASan reports `heap-buffer-overflow`, `WRITE of size 64`,
0 bytes after the region at pinned line 63. Rung 4 is INSTRUMENTED
chosen-byte control only; pinned 1.15.0 stops at `pos=4160` with a clean
neighbour. No live daemon, real L2TP AVP path, verbose-logging configuration,
stock heap layout, useful-pointer control or execution was observed. Evidence:
`reports/frontier-accelppp2shell.md`, seed status
`reports/accelppp2shell-status.md`, harness `lab/frontier/accelppp2shell/`.
The dedicated `accelppp2shell` mind owns this lane. Its two-pane window (inner
socket, window 27), registry entry and seed wall were live from frontier's
handoff and were capture-verified at admission; wake trigger units and the
presentation.json entry are owed from the person's full-flag sync, never a
bare `mishe sync`.

#### Admitted 2026-11-21 ~03:18Z: Indiserver2Shell (CVE-2026-71979)

Claim sources: the VulnCheck CNA record for CVE-2026-71979 (published
2026-08-17), the CVE record, OSV, upstream issue #2472 and fix commit
`96bbd7f564bbb128a129019e44eadd40dd49cff9` (fix parent `3220880`, pinned as
affected); pinned source hashes and URLs are in
`lab/frontier/indiserver2shell/PROVENANCE.md`. CWE-121, CVSS 4.0 **8.7 High**
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` — availability only,
no RCE claimed. Affected `0` through `2.2.4.2`, fixed at the commit; the
advisory also names `v2.2.4` / `3371faeb` as reproduced. Claimed primitive:
`indiserver` listens on TCP/7624 without authentication or transport
encryption; a ~1.2 KB packet with mismatched XML tag names exceeding 1024
bytes drives unbounded `sprintf()` into `err[1024]` in
`MsgQueue::readFromFd()`, the shared read path for every client and driver.
No configuration gate and no auth.

Scope: INDI is a C instrument-control daemon, admitted as an X2Shell-class
extension under the same "similar things" precedent that admitted FreeRADIUS,
FreeSWITCH, Bzfs2Shell, Kamailio2Shell, Iperf2Shell, Uftpd2Shell and
Accelppp2Shell; the judgment is in
`.mishe-tauftauf/charters/indiserver2shell.md`. The advisory's
availability-only ceiling stays in every impact claim.

The write is a single large `vsprintf` of attacker-chosen alphanumeric bytes
onto the stack, so saved-frame placement is structurally plausible and a
rung-4 attempt is warranted; no structural-zero-store blocker was found. The
operator replayed the committed harness at ~03:16Z: 19 PASS, `ALL CHECKS PASS
rc 0`, trace
`sha256=2c446e0f1b1beecee5aa437d5a15818ad0c951d72fbcdb2cb545a656925ca85c`.
Rungs 1/2/3 are on the verbatim pinned upstream `oneXMLchar()` /
`parseXMLChunk()` from `3220880`: a 1206-byte `<A*600>x</B*600>` packet
formats 1237 bytes into `err[1024]` (`expected_oob=213`), the first byte past
the buffer changes, and ASan reports `stack-buffer-overflow`, `WRITE of size
1237`, with frames at pinned `lilxml.cpp:1281` / `:348`. Rung 4 is
INSTRUMENTED chosen-byte control only: token-safe `INDI2SHELL` read back
byte-exact at requested adjacent-stack offsets 0 and 64; fixed `96bbd7f`
bounds the format with `snprintf(..., XML_ERROR_SIZE, ...)` and the neighbour
is clean. No live daemon, real TCP/7624 path, stock stack layout,
canary/NX measurement, useful-pointer control or execution. Evidence:
`reports/frontier-indiserver2shell.md`, seed status
`reports/indiserver2shell-status.md`, harness `lab/frontier/indiserver2shell/`.
The dedicated `indiserver2shell` mind owns this lane. Its two-pane window
(inner socket, window 28), registry entry and seed wall were live from
frontier's handoff and were capture-verified at admission; wake trigger units
and the presentation.json entry are owed from the person's full-flag sync,
never a bare `mishe sync`.

#### Admitted 2026-11-21 ~03:4xZ: Shairport2Shell (GHSA-6g79-wrcj-h8xw)

Claim source: the maintainer advisory GHSA-6g79-wrcj-h8xw, published
2026-09-04 by `mikebrady` at
`https://github.com/mikebrady/shairport-sync/security/advisories/GHSA-6g79-wrcj-h8xw`,
with no CVE assigned. CWE-121, CVSS 3.1 **7.5 High**
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — availability only, no RCE claimed.
Affected `< 5.5`; patched `5.5` and `5.6-dev`. Fix history: development PR
#2263 merged 2026-08-26 (`74d59d8f83538c03852d51f953a2ca7716340fc2`), master
backport PR #2267 merged 2026-08-31
(`a5d8f46a54c0440bdd5290d385fe8a740c636d36`). Fix parent
`a50f18469143b9dbe599b8333d228a586dc29e67` is pinned affected and fix
`c1c41c4ec9937eb7d2f8819dadd5bc45f65ab3f4` pinned fixed; source hashes and
URLs are in `lab/frontier/shairport2shell/PROVENANCE.md`.

Claimed primitive: an AirPlay-2 receiver accepts an RTSP request whose method
is not in `method_handlers[]` and hex-dumps the request body into a fixed
4096-byte stack buffer. The length is clamped to 4096 **bytes**, but each byte
becomes two hex characters plus a final NUL, so up to 8193 bytes are written
into `char obf[4096]` at `rtsp.c:4208`. The fill loop runs regardless of log
verbosity; a fresh connection defaults to `airplay_type = ap_2`, which the
advisory says bypasses the RTSP authentication check. That auth-bypass and
pre-auth reachability stay advisory claims until observed on a live daemon.

Why a rung-4 attempt is plausible: the overflow is a single loop of small
`snprintf(obfp, 3, "%02X", ...)` writes of attacker-chosen bytes (within a
token-safe hex alphabet) onto the stack, so a saved-frame overwrite is
structurally plausible and no structural-zero-store blocker was found.
Vulnerable and fixed bytes, exact commits and a public patch pin the intended
semantics. Rung 4 is INSTRUMENTED chosen-byte control only in harness stack
storage: no live daemon, socket, auth-bypass observation, stack layout, useful
pointer or execution.

Operator replay 2026-11-21 ~03:44Z from committed HEAD:
`bash lab/frontier/shairport2shell/run.sh <outdir>` printed 21 PASS lines,
`ALL CHECKS PASS rc 0`, trace
`sha256=b87176f5891ef547eef69a11176fd3e0a3a3c367fd19fdf80d30fa9b733e9c86`,
byte-identical to the brief. Evidence:
`reports/frontier-shairport2shell.md`, seed status
`reports/shairport2shell-status.md`, harness `lab/frontier/shairport2shell/`.
The dedicated `shairport2shell` mind owns this lane. Its two-pane window
(inner socket, window 29), registry entry and seed wall were live from
frontier's handoff and were capture-verified at admission; wake trigger units
and the presentation.json entry are owed from the person's full-flag sync,
never a bare `mishe sync`.

#### Admitted 2026-11-21 ~04:2xZ: Asterisk2Shell (CVE-2026-57201 / GHSA-x348-j6c9-77f3)

Claim source: the maintainer advisory GHSA-x348-j6c9-77f3 (2026-06-25,
CVSS 3.1 8.1, `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) and the CVE record
(2026-10-27, CVSS 3.1 7.5, availability only). The two authoritative
sources disagree on attack complexity and C/I impact; the conservative
availability-only reading is kept and the discrepancy is not resolved.
Affected Asterisk <=20.20.0 / <=21.12.2 / <=22.10.0 / <=23.4.0 and two
Certified branches; patched 20.20.1 / 21.12.3 / 22.10.1 / 23.4.1 and the
matching Certified releases. The `chan_ooh323` addon must be explicitly
compiled, installed and reachable, so no stock-deployment claim is made.
The defect is an unbounded `vsprintf` into `logMessage[2048]` at
`ootrace.c:50`; fix `2d7b8c8dc13d9ead8b6f36cc38b6dd91cd4abd3a` replaces
it with `ast_vasprintf`. The affected parent `661d6a2f…` is byte-identical
to release 23.4.0. Frontier's harness (`lab/frontier/asterisk2shell/run.sh`)
compiles the verbatim pinned lines and reports 24 PASS, rc 0: rung 1
`written=2433` bytes into the 2048-byte buffer; rung 2 a caller object
2272 bytes away changes; rung 3 ASan `stack-buffer-overflow`,
`WRITE of size 2433`, frame `ooTrace` at pinned `ootrace.c:50`; rung 4
chosen `AST2SHELL` bytes read back at harness-victim offsets 0 and 64 with
a clean fixed control — instrumented only, no live daemon, socket,
useful-pointer control or execution. Cheapest next rung: build Asterisk
23.4.0 with `chan_ooh323` under ASan and drive a loopback H.323 field into
the real `ooTrace` format arguments. Admitted by the operator ~04:2xZ under
standing approval #6 on #550: the two-pane window (30, inner socket), registry
entry and seed wall were live from handoff and were capture-verified; the
charter and status file are now in place. Operator replay ~04:22Z from
committed HEAD: 24 PASS, `ALL CHECKS PASS rc 0`, trace
`sha256=51b5ff1b82684092340d5bd93105efed76e453681e552eb0bb84103eb74feee0`,
byte-identical to the brief. Wake trigger units and the presentation entry are
owed from the person's full-flag sync, never a bare `mishe sync`. Evidence:
`reports/frontier-asterisk2shell.md`, seed status
`reports/asterisk2shell-status.md` and the pinned hashes in
`lab/frontier/asterisk2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~05:0xZ: Netatalk2Shell (CVE-2026-45698 / GHSA-5443-v9xg-mqgv)

Claim source: the Netatalk maintainer advisory GHSA-5443-v9xg-mqgv
(2026-05-28) and the CVE record (2026-08-17). Both grade High 7.5
`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`. Affected `>=3.1.19, <4.4.3`
(project advisory 3.2.0–4.4.2); fixed 4.4.3. The pinned 4.4.2 source contains
the vulnerable expression, so 4.4.2 is affected despite the GHSA range
contradiction. Reachability requires an authenticated AFP session (`PR:L`)
and a cross-device rename path inside a share (`AC:H`), so no stock-default
claim is made. The defect is `remain = strlen(path) - len - 1` at pinned
`etc/afpd/directory.c:168`, which underflows to `SIZE_MAX`; the guard at line
176 cannot reject a filename and `strcpy(path + len, de->d_name)` at line 181
writes an attacker-chosen 255-byte name into `char path[MAXPATHLEN + 1]`.
Fix `33dbda708cd38ee4ffa568cc5dde1fda4f900dfe` uses `sizeof(path)`.
Frontier's harness (`lab/frontier/netatalk2shell/run.sh`) compiles the
verbatim pinned lines 147–203 and reports 24 PASS, rc 0: rung 1 a 256-byte
`strcpy` into `path[1025]`, rung 2 the first saved-return-slot byte changed,
rung 3 ASan `stack-buffer-overflow`, `WRITE of size 256`, frame `deletedir`
at pinned `directory.c:181`, rung 4 chosen `NET2SHEL` bytes read back at
write offsets 0/64 and in the saved-return slot at offset 56 with a clean
fixed control — instrumented only, no live daemon, socket, AFP session,
mount, useful-pointer control or execution. Cheapest next rung: build 4.4.2
afpd under ASan, serve a loopback-only AFP share with a nested cross-device
mount point, authenticate, create a 255-byte filename and trigger the
`deletedir()` path. Admitted by the operator ~05:0xZ under standing approval
#6 on #574: the two-pane window (31, inner socket), registry entry and seed
wall were live from handoff and were capture-verified. Operator replay
~05:05Z from a clean `git archive HEAD` extraction of `c37e96d`: 24 PASS,
`ALL CHECKS PASS rc 0`, trace
`sha256=c1bba7fb17b2a2b0cf6de7c76725974f005192648287245f5ba3b8aac08339d0`,
byte-identical to the brief. Wake trigger units and the presentation entry are
owed from the person's full-flag sync, never a bare `mishe sync`. Evidence:
`reports/frontier-netatalk2shell.md`, seed status
`reports/netatalk2shell-status.md` and the pinned hashes in
`lab/frontier/netatalk2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~05:28Z: Iondtn2Shell (GHSA-gmhw-vmwr-wrxh / CVE-2026-123999)

Claim sources: maintainer GHSA-gmhw-vmwr-wrxh (2026-11-07, High 7.5
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) plus a VulnCheck advisory and
CVE record CVE-2026-123999 (CVSS v4 8.7, also availability-only). The GHSA
"No known CVE" metadata vs VulnCheck's assignment is a preserved claim
conflict; neither is a lab observation. Affected `3.6.2 <= 4.2.0`, patched
`4.2.1-a.2`. Fix `4b158b64211ad399a00be4215dd81de2f4767d1e` changes only
`nm/mgr/nm_mgr_print.c`. Claimed primitive: in `ui_str_from_ac()`, rendered
AMP values are appended with two unbounded `strcat()` calls into a
1024-byte `STAKE` heap allocation (pinned 4.2.0 lines 548 function start,
550 allocation, 557/558 concatenations); a long or deeply nested value list
writes past the end. The fix uses `istrlen()`/`istrcat()` capacity checks and
returns NULL when capacity is exhausted. Reachability gate from the advisory:
the remote UDP CLA/AMP path needs non-default `-l -r` file and parsed-report
logging; otherwise only interactive local UI rendering is claimed. Impact
claimed is availability-only (crash of `nm_mgr`).

Frontier's harness (`lab/frontier/iondtn2shell/run.sh`) extracts the verbatim
pinned lines 548–563 / 543–588 under `#line` directives with stubbed
collaborators and reports `ALL CHECKS PASSED rc 0`: rung 1 `18 × 81 = 1458`
bytes written into a 1024-byte region (`overflow=434`); rung 2 the first byte
underbound changes and the returned string is longer than the allocation;
rung 3 ASan `heap-buffer-overflow`, `WRITE of size 81`, frame
`ui_str_from_ac` at pinned line 557; rung 4 the 8-byte token `ION2SHL!` read
back byte-exact at chosen write offsets 1024/1088/1152/1280/1408, while the
patched build returns NULL before overflowing and leaves the neighbour
unchanged. Rung 4 is INSTRUMENTED only — chosen bytes land in the harness
allocator's adjacent region; no live `nm_mgr`, socket, UDP CLA/AMP payload,
UI, useful pointer or execution. Cheapest next rung: build 4.2.0 `nm_mgr`
under ASan, start loopback-only with `-l -r`, send a deeply nested AMP report
whose rendered list exceeds 1 KiB, capture the real ASan frame at pinned line
557 and the wire bytes, then measure real heap adjacency and pointer control.
Admitted by the operator ~05:28Z under standing approval #6 on the
`fefc2b7` / `de67924` handoff: the two-pane window (32, inner socket),
registry entry and seed wall were live from handoff and were capture-verified.
Operator replay ~05:26Z from a clean `git archive HEAD` extraction of
`d4267283` into two separate absolute output directories: `ALL CHECKS PASSED
rc 0` in both, byte-identical trace
`sha256=e9bc1ffffb7ba2bc39b5c3c26cf29a4c1cf0f8f96160a92cc979326f29d38f71`
(brief records 26 PASS; the harness printed 27 `PASS` lines including
`PINNED_SOURCE_BYTES`). Wake trigger units and the presentation entry are
owed from the person's full-flag sync, never a bare `mishe sync`. Evidence:
`reports/frontier-iondtn2shell.md`, seed status
`reports/iondtn2shell-status.md` and the pinned hashes in
`lab/frontier/iondtn2shell/PROVENANCE.md`.

#### Held 2026-11-21 ~01:12Z: Gdbserver2Shell (CVE-2026-121997 / GHSA-jq36-9pw3-8r4v) — not admitted under #6

Frontier handed this find over on tape #448 after committing
`reports/frontier-gdbserver2shell.md` (5261154) and the harness
`lab/frontier/gdbserver2shell/`. Claim sources: the CVE record (CNA Red Hat,
published 2026-11-05), the GHSA API and RHBZ 2565679 comment 0; CWE-122, CVSS
3.1 **8.1 High** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`. Claimed primitive:
`cmd_qtdpsrc` allocates `slen+1` from the packet's declared length but calls
`hex2bin` on the actual hex length, so a declared/actual mismatch writes
sender-chosen bytes past the heap buffer; a following `qGetTLSAddr` packet is
claimed to call through the overwritten `td_ta_map_lwp2thr_p` pointer.
Affected products are Red Hat names (RHEL 6-10, gcc-toolset-14/15, hardened
images); **upstream version range, fixed version and fix commit are UNKNOWN**.
Upstream sourceware gitweb returned 503; no upstream bytes were pinned.

The operator replayed the committed harness independently at 01:0xZ: 14 PASS,
`ALL CHECKS PASS rc 0`, `sha256=c81092bd…`. That digest differs from
frontier's `61826865…` because `run.sh` hashes ASan text, not a deterministic
five-run trace; no harness pins, ASan log or PROVENANCE.md are committed.
Rungs 1/2/3 are ESTABLISHED only for the extracted model, and rung 4 calls a
pointer inside a `process_info_private` struct the harness itself invented —
no live gdbserver, stock layout, real function pointer, RIP control or shell
execution. The window's claimed `01:21Z`/`01:22Z` creation and capture times
contradict the files' `00:58:5xZ` mtimes and #448's `00:59:06Z` tape stamp;
those timestamps stay UNKNOWN.

Decision: **held, not admitted** under standing approval #6. That approval
lists "affected/fixed versions" among the evidence required for admission;
a debugger daemon with no upstream version, no fix, no pinned source bytes,
AC:H and instrumented-only rung 4 sits further outside this plant's
runtime/web-server class than Bzfs2Shell, already recorded as the first lane
to revisit if the class is narrowed. No charter, status file, docs/README
admission entry or engine route is created, and none is requested from the
person for this candidate. Frontier's two-pane window 23, registry entry
(status file still the brief) and seed wall remain a **frontier dashboard,
not a declared target**; no wake unit or presentation entry is owed.

Revisit trigger: a reachable mirror supplies pinned vulnerable upstream bytes
and a fixed version/commit, the real `gdbserver/tracepoint.cc` handler is
compiled into the ASan harness, and the stock `process_info_private` layout
and `qGetTLSAddr` dispatch are exercised. Until then this is an examined
candidate, not a mind.

#### Examined 2026-11-20: GHSA-87fm-7w84-j2px (Ruby case-conversion integer overflow)

Flagged by ruby2shell on tape #84. Claim source: the vendor's
2026-11-18/19 batch advisory and the GHSA; affected Ruby
3.3 <=3.3.13, 3.4.0-3.4.12, 4.0.0-4.0.9, fixed 3.3.14/3.4.13/4.0.10; CWE-190
`rb_str_casemap` intermediate `int` length overflows to a small positive
value, so `rb_str_new` allocates a tiny string and ~4 GiB of converted
data is written past it; vendor says RCE-proving PoCs exist. This is
**not a new target** — it is Ruby, already admitted as Ruby2Shell, so no
new mind, charter, window or trigger unit is owed. **Lane not opened**
under the current guard: the published minimal reproduction is
`"\u0390" * 715_827_883` (~1.4 GiB input, ~4 GiB output, Rack <=3.2.1
for the Rails path), while a plant wake service is capped at
`memory.max=2 GiB`, `memory.high=1.5 GiB` inside a slice capped at 5 GiB
and already holding ~2.5 GiB. This is the same structural-limit lesson
as the nginx2root consumer check: no amount of grooming changes a budget
that cannot hold the input. Revisit only if a person-owned guard or
dedicated larger-budget lane changes that ceiling. The other five GHSAs
in the batch are triaged in the next section (seven total; two handled here).

#### Triaged 2026-11-20: remaining five GHSAs in the 2026-11-18 Ruby batch

Claim source: ruby-lang.org's 2026-11-18 advisory
`multiple-vulnerabilities-in-regexp-and-string/`, which states **seven**
bugs (all Ruby, affected <=3.3.13 / 3.4.0-3.4.12 / 4.0.0-4.0.9, fixed by
3.3.14/3.4.13/4.0.10) and says PoCs prove RCE for some of them. The note
above said "six other" — corrected: seven total, two handled
(34m4-m9fh-gqp5 admitted as Ruby2Shell, 87fm-7w84-j2px examined above),
five remaining:

- GHSA-7x2q-68qv-6p8x — double free in Regexp compilation, RCE PoCs;
  vendor conditions impact on applications that compile
  attacker-controlled patterns.
- GHSA-wpqw-5qxg-m68r — out-of-bounds read in case-insensitive Regexp
  matching with attacker-controlled patterns; claimed
  attacker-controlled memory corruption.
- GHSA-3p8q-wmhx-vm2w — CWE-190 integer overflow in Regexp compilation
  causing a heap overflow, RCE PoCs; attacker-controlled patterns.
- GHSA-7whj-cfh7-xgm4 — CWE-787 heap overflow in `Regexp#to_s`,
  disclosure/RCE PoCs; attacker-controlled patterns.
- GHSA-pvgc-g7gj-pv6h — out-of-bounds read in case-insensitive
  backreference matching; disclosure or crash only, no RCE claim;
  trigger is a crafted string against a pattern.

Decision: **no new target** (all Ruby, already admitted) and **no lane
opened**. Reachability is the blocker, not the memory budget: the admitted
CVE-2026-132825 is default-reachable in Rails/Sinatra through ordinary
case conversion of user strings, whereas four of these five need the
application to compile attacker-controlled regex patterns — a specific
application behavior, not a default web-framework path. The fifth is a
read-only disclosure/crash bug with no write/control primitive for rung 4.
Repro sizes for the regexp bugs are UNKNOWN — not measured, so no budget
claim is made. No new mind/charter/window/trigger is owed; ruby2shell owns
any decision to open a secondary lane (noted to it on tape).

#### Examined 2026-11-20: NGINX HTTP/2 RCE cluster (CVE-2026-123007 / CVE-2026-123633)

Claim sources: Wiz Research's 2026-11-18 post
(`wiz.io/blog/nginx-http2-rce-vulnerabilities`), Rapid7's 2026-11-18
analysis (updated 11-20) and F5 advisory K000163926. Both are CVSS 9.2,
pre-auth, and need `http2 on`; Wiz reports RCE confirmation for both in
its own labs. **CVE-2026-123007** (CWE-191):
`ngx_http_v2_filter_cleanup()` refunds queued DATA beyond
`NGX_HTTP_V2_MAX_WINDOW`, the next connection WINDOW_UPDATE's unsigned
subtraction underflows, the excessive `h2c->send_window` becomes a
negative `off_t` length, and buffered TLS output performs an out-of-bounds
`memcpy`. Affected 1.9.5-1.31.8; fixed 1.30.7 stable / 1.31.9 mainline.
**CVE-2026-123633**: HTTP/2 connection use-after-free when a partial
HEADERS frame leaves a connection on the reusable list and free-slot
pressure closes it mid-request; proxy configuration required. Affected
1.19.7-1.31.8; fixed 1.30.7 / 1.31.9.

Decision: **no new target admitted, no lane opened.** The published
CVE-2026-123007 RCE handoff (`sfewer-r7/CVE-2026-123007`,
`NGINX_HTTP2_STANDALONE_REPRODUCTION.md`) states its calibrated profile
requires `avx512f` and `avx512vl`, a Debian glibc 2.41 nginx 1.31.8
image, and about 119.02 GiB plaintext per attempt (about 60 GiB for the
standalone crash trigger). This host is an AMD Ryzen 7 5700X with
**avx2 only** and glibc 2.39: the published copy consumer is structurally
unavailable here, the exact consumer-reality failure the staged plan
screens for first. Wiz's RCE claim for this CVE used an undisclosed
method, so an alternative route is UNKNOWN, not established.
CVE-2026-123633 has no public PoC and is the dedicated mission of the
sibling `nginx2root` plant; cross-plant scope is reserved to the person.
Revisit 123007 only with a different consumer or a person-owned larger
budget; revisit 123633 only on a person's cross-plant decision. Tape
#105/#106. No mind, charter, window or trigger unit is owed.

#### Scanned 2026-11-20: Java4Shell (CVE-2026-114938) — screened out here

Claim sources: JFrog and Wiz (both 2026-11-17), CCB Belgium. OpenJDK's
x86-64 AVX-512 VBMI Base64 decoder intrinsic underflows its tail mask on
input such as 64 `A`s plus `=` (JDK 17): `(len/4)*3 - padding` wraps to
-1, `BZHI` reads 255, and a 64-byte masked store starts at offset 48 of
a 50-byte output array, writing ~62 bytes past it. Affected 17.0.6
through 17.0.21.0.3, 21 through 21.0.13.0.3, 25 through 25.0.5.0.3,
27 through 27.0.1.0.3 (and the Java 8 Enterprise Performance Pack);
fixed 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1. Claims of pre-auth
RCE in default-configured Keycloak, Jira, Confluence, Artifactory,
Jenkins and PingFederate are vendor/researcher claims, not lab findings.
**Decision: no admission, no lane.** All four flags `avx512f`,
`avx512bw`, `avx512vbmi`, `bmi2` are required; observed 2026-11-20
12:19Z that this host's Ryzen 7 5700X (Zen 3) exposes **zero** avx512
flags, so the vulnerable assembly path cannot run here. Same
structural-consumer screen that ruled out nginx CVE-2026-123007.
Revisit only on a person-owned AVX-512-capable lane.

#### Frontier brief 2026-11-20: Apache2Root (CVE-2026-119618)

Claim sources: Apache's 2.4.71 advisory (released 2026-11-11), the CVE
record (CWE-362) and Red Hat's CVE page. Unauthenticated heap
corruption/RCE claim in mod_http2's `assign_headers()` when HTTP/2 is
negotiated (`h2`/`h2c`); affects httpd 2.4.55-2.4.70 and mod_h2
2.0.8-2.0.42, fixed in 2.4.71. The one-line fix
`apache/httpd@824beab` changes `apr_table_setn(req->headers,
"Content-Length", "0")` to `apr_table_setn(r->headers_in, ...)`, i.e.
the buggy path mutates the shared stream table after cloning it into
the request. Red Hat reports a reliable exploit against a default
event-MPM server; Wiz and CSA could not locate that primary research,
and CVE.org scores `AC:H` against Red Hat's `AC:L` — reliability stays
UNVERIFIED. No CPU blocker on this host, so this is the top tractability
candidate. Full source-bound mechanism, unknowns and the cheapest
loopback h2c experiment are in `reports/frontier-apache2root.md`.
Admitted as the dedicated `apache2shell` mind under standing approval #6;
rung 3 is confirmed and the main lane is closed at Stage A — Stage C pointer
control is UNREACHABLE on this build and host (the wire-byte alphabet rejects
the bytes a canonical pointer needs, Huffman-coded HPACK does not bypass
validation, and a 15-capture fault-site census plus a heap-layout check found
only pointer slots). A second, adjacent same-subsystem lane L1 covers httpd
2.4.71's `CHANGES` entry "Fix a crash creating an HTTP/2 session with
`H2PushDiarySize 0` and debug logging enabled": `h2_push_diary_create(pool, 0)`
returns NULL (`h2_push.c:549-555`) and `h2_session_create()` reads
`session->push_diary->dtype` under `APLOGcdebug(c)`; 2.4.71 guards it at
`h2_session.c:1068-1069`. On 2.4.70 with `H2PushDiarySize 0` and debug
logging, the h2c handshake fails (server rc=1) with UBSan `member access
within null pointer of type 'struct h2_push_diary'` and ASan `SEGV on unknown
address 0x00000000000c` in `h2_session_create`; 2.4.71 answers rc=0 with no
sanitizer report. Grade: rung 2 only — a fixed-offset NULL read requiring
operator-set config, no chosen-byte, chosen-offset or scalar-steering
primitive and no route to rung 4; the main lane's Stage A closure stands.
Reproduce: `python3 lab/apache2shell/pushdiary-lane.py`. Evidence:
`reports/apache2shell-investigation.md`, "Adjacent lane L1"; raw logs are
gitignored under `lab/apache2shell/logs/`.
Adjacent lane L2 (CVE-2026-23918) is a second same-subsystem crash, not a
reopen of the main CVE: the 2.4.70 build already carries mod_http2 2.0.42,
so `lab/apache2shell/build-l2.sh` builds pristine ASan/UBSan httpd 2.4.66
(mod_http2 2.0.35; source SHA-256
`94d7ff2b42acbb828e870ba29e4cbad48e558a79c623ad3596e4116efcfea25a`) and
2.4.67 (2.0.39; SHA-256
`66cd206637b0d5c446fa7dabe75fe03525da8fb55855876c46288cd88b136aa4`). The
fix replaces three unguarded `APR_ARRAY_PUSH(m->spurge, ...)` sites
(`h2_mplx.c:134/167/183` in 2.4.66) with a duplicate-refusing
`add_for_purge()`. `python3 lab/apache2shell/l2-lane.py` drives h2c HEADERS
plus RST_STREAM (fill 0, 8 connections × 100 streams) on loopback
7266/7267: 2.4.66 gives 800 sent / 18 responses with child aborts or SEGVs
in both pristine runs (assertion message varies, child failure does not),
while 2.4.67 answers 800/234 and 800/248 with zero assertions, aborts or
SEGVs. Grade: rung 2 — reproducible crash on unmodified vendor builds with
a clean fixed control, no confirmed attacker-controlled corruption and no
route to rung 4; the main lane's Stage A closure stands.
Adjacent lane L3 (CVE-2026-57941, shared `session->bbtmp` re-entrancy) is a
third same-subsystem crash, not a reopen of CVE-2026-119618. The 2.4.70
`CHANGES` record names the issue and `CHANGES:137-142` gives the affected
range 2.4.0 through 2.4.68. `lab/apache2shell/build-l3.sh` builds pristine
ASan/UBSan httpd 2.4.68 (SHA-256 `68c74d4df38c26bed4dfbdb8f3baf1eb532f3872357becc1bba5d136f6b63c06`)
and 2.4.69 (`c5e6ebc66e349b87d7fc6916ae7cc2a808ed348003de134cf9e9d89d3e2cc73d`)
with pinned nghttp2 1.64.0. `python3 lab/apache2shell/l3-lane.py 10 8 20`
drives h2c GETs of 512 KB, 32 KB POST bodies, immediate RST_STREAM and client
GOAWAY over loopback 7268/7269: pristine 2.4.68 produced child SEGVs in three
runs (one repeat clean) and forced-ASan (`handle_segv=1`,
`allow_user_segv_handler=0`) produced `SEGV on unknown address`,
`Hint: PC is at a non-executable region. Maybe a wild jump?` and frame 1
`h2_c1_read (h2_c1_io.c:502)` in 3 of 8 GOAWAY runs, while 2.4.69 stayed clean
in every variant. The first forced-ASan attempt failed with
`RuntimeError: can't start new thread` from leftover httpd children and is
preserved INVALID, not a pass; gdb follow-ups missed the crashing child.
Grade: rung 3 confirmed in the input path the fix changes. Rung 4 is NOT
demonstrated: the race is intermittent and the jump target is not
attacker-chosen. A body-canary pass added `L3_BODY_BYTE` and `L3_VERSIONS`
to `lab/apache2shell/l3-lane.py`: twelve forced-ASan 2.4.68 runs per byte at
8 connections × 20 streams gave wild-jump PCs in 8/12 runs for `0x42` and
6/12 for `0x5a`; the PC low 12 bits came from
`{0x048, 0x228, 0x2c8, 0x7c8, 0x868}` and no body-byte pattern appeared in
any PC. Instrumenting `read_and_feed()` found one input filter whose
`in_func` low 12 bits stayed `0xa86` in 744 calls across eight runs while
the PC varied, including jumps to `0x...7c8` and `0x...048`; the first probe
used `%p`, which httpd renders `bogus`, and was changed to hex. This is
evidence against a body-steered jump, not proof of which slot held the bad
target (the race can corrupt between log and call or in a deeper frame).
Pristine source was restored byte-for-byte, the module rebuilt with no
`L3PROBE` string, and the wild jump reproduced in 1 of 2 smoke runs
(`l3-restore-smoke-0446-2.log`, PC `0x7dc388d172c8`). L3 is CLOSED at rung
3 with no reopen condition; no chosen bytes, chosen offset, pointer control
or marker were obtained. The main lane's Stage A closure and do-not-retry
list are unchanged.

Adjacent lane L4 (CVE-2026-56154, mod_rewrite UAF via `%{LA-U:HTTP:...}`) is a
fourth same-subsystem lane, not a reopen of CVE-2026-119618. The 2.4.68→2.4.69
`modules/mappers/mod_rewrite.c` diff duplicates `ctx->vary_this` into the
parent request pool before `ap_destroy_sub_req()` destroys the subrequest
pool that owned it; `apr_table_merge()` at `mod_rewrite.c:4701` then
dereferenced the stale string. `lab/apache2shell/rw-lane.py` on the L3 ASan
builds with `mod_rewrite.so` and `MaxMemFree 1` gives 2.4.68 12/12 child
SIGSEGV against 2.4.69 0/12; both the plain-header and absent-header controls
are 0/12. `rw-gdb.py` frames the fault as `strlen` → `apr_pstrdup` →
`apr_table_merge` at the exact merge line, with the dangling `ctx->vary` in
`rdi`/`rsi`; ASan prints no use-after-free because libapr is uninstrumented.
Grade rung 3 confirmed; no chosen bytes, offset, pointer control or marker,
and L4 closes there. Raw logs are gitignored; reproduce with
`RW_VARIANT=lau RW_HEADER=yes RW_N=12 ./rw-lane.py 2.4.68 2.4.69` from
`lab/apache2shell/` plus the two controls and `python3 rw-gdb.py`.

## Staged rung-4 plan (per target, revised from the nginx2root experience)

These stages are successive depth probes, not checkboxes. Stop at the first
observed limit and document it; a lane that reaches Stage C on one build
and only Stage A on another reports both boundaries separately.

1. **Consumer reality first.** Before exploitation mechanics, determine
   the consumer's behavior on this host's hardware and glibc (for
   memcpy-style consumers: dispatch order, store-first vs tail-first,
   zero-store windows). A structural zero-store consumer kills the path —
   record it and move to the next consumer or target.
2. **Rungs 1–3.** Suspected → reproducible crash → confirmed corruption,
   ASan/UBSan builds of affected and fixed versions, patch diff read as a
   specification first.
3. **Stage A — placement control.** Heap-groom the lab process and prove
   chosen bytes at a chosen offset via a canary. LD_PRELOAD
   synthetic-memcpy experiments are approved for mechanics but labeled
   synthetic; no stock-build rung-4 claim derives from them.
4. **Stage B — wire-pure trigger** where the debugger was used to force
   ledger or state values; bulk local traffic is approved with the
   operator's purpose gate.
5. **Stage C — control-flow hijack.** Pointer control / benign marker
   execution, ASLR disabled where needed, honestly labeled per-build.

## Deliverable

`reports/<target>-investigation.md` per target plus committed
reproduction scripts; a failed stage is preserved as a negative result
and per-build boundaries are part of the deliverable.

## Frontier finding — Mosquitto CVE-2026-110486 (2026-11-20 15:40Z)

`frontier` selected the next candidate after the Apache handoff and drove
it locally: **Mosquitto 2.1.0–2.1.2 built-in WebSocket "MASKerade"**,
CVE-2026-110486 / GHSA-6j8m-r32v-4h38 (Critical), fixed 2.1.3. A masked
zero-length frame makes `net__read_ws()` return 4 while copying 0 bytes;
`packet__read_single()` underflows `to_process` and advances `pos` past a
1-byte allocation. Full source-bound mechanism, claim sources and honest
rung grading are in `reports/frontier-mosquitto2shell.md`.

Observed on gcc ASan/UBSan builds under
`lab/frontier/mosquitto2shell/` (`build.sh`, `trigger.py`, `run.sh`,
`placement.sh`): rung 1 deterministic 3-frame pre-auth trigger over a
loopback WS upgrade; rung 3 ASan `WRITE of size 256` 3 bytes past a 1-byte
region on 2.1.2 (`logs/differential-run1.log`), clean on 2.1.3; Stage A
placement control — the write offset grows exactly 4 bytes per empty
frame (0 → in-bounds, 1 → +4, 2 → +8, 4 → +16, 8 → +32) with chosen
payload bytes (`logs/placement-run1.log`). Rung 4 (the published
tcache → dlsym → shell chain) is NOT demonstrated locally and stays a
claim; ASan's allocator cannot host the glibc tcache chain.

Handed to the operator with evidence for a decision on a dedicated
`mosquitto2shell` mind; frontier does not duplicate that lane. Next cheap
rung: non-ASan `-O0 -g` build under gdb, reproduce the PONG-adjacency
groom and confirm a controlled `malloc()` return before claiming rung 4.
