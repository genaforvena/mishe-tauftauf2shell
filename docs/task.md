# Research task: investigate how far rung 4 — and where measured, rung 5 — goes

General goal: for memory-safety vulnerabilities in language runtimes and
web-facing servers — the "X2Shell" class — reproduce the failures in a
local, isolated laboratory and investigate how far **rung 4 (demonstrated
security impact: chosen bytes at chosen offsets, pointer control, benign
marker execution, per-build labeled)** can be pushed for each target. Where a
measured rung-4 primitive leaves a credible bounded path, the same lane may
also attempt **rung 5 (working remote command execution)**: attacker wire
input drives a live loopback target to run a lab-chosen benign command, with
vulnerable / fixed / safe-input controls and an independent witness replay.
Rung 5 is additive and per-build, never a relabel of a pointer fault or an
in-process marker; a measured structural blocker is a valid negative result.
The full acceptance contract is in [docs/rce.md](rce.md).

Rungs are not boxes to touch. They are a depth investigation: each rung
states what evidence is strong enough to support, and the lane records the
exact boundary where the evidence stops. A negative result, a harness-only
grade, or an UNKNOWN is part of the answer — it says how far rung 4 (and rung 5
where attempted) goes on that build, not that the lane failed. Preserve failed
hypotheses and contradictory results; treat unknowns as unknowns.

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
- 2026-11-21 new adjacent lane (**CVE-2026-129496** /
  GHSA-gr4f-wgx5-jpfv), the standalone stale-`DATEG(tzcache)` read isolated
  from wake 17's combined splice chain. An invalid `date.timezone` plus
  `max_input_vars=1` and a file `error_log` writes a startup diagnostic
  through file logging (timezone cache allocated in temporary startup memory
  and freed at its end while `DATEG(tzcache)` still points at it), then an
  early request diagnostic reads it while formatting the log timestamp. The
  exact 8.5.12→8.5.13 fix guards the timestamp with
  `PG(modules_activated) && EG(active)` in `main/main.c` and moves
  `php_date_global_timezone_db` init before `REGISTER_INI_ENTRIES()` in
  `ext/date/php_date.c`. `lab/repro/php2shell-cve129496-tzcache.py` invokes
  php-cgi directly (no listener): pinned 8.5.12 release-ASan `php-cgi-vuln`
  rc=1, ASan SEGV READ in `__strlen_avx2` via `php_default_treat_data`
  (`php_variables.c:583`) → `php_error_docref` → `php_log_err_with_severity`
  (`main.c:991`) → `php_format_date` (`php_date.c:894`) →
  `timelib_get_time_zone_info` (`parse_tz.c:908`) → `_estrdup` → `strlen`;
  the same build with only the upstream one-line `main.c` guard rebuilt
  (`php-cgi-fixed`) rc=0 clean, and controls without the invalid timezone are
  clean on both. Plain 8.4.27 rc=139 vs 8.4.28 rc=0 cross-branch. Requires
  default ZendMM and release-ASan: `USE_ZEND_ALLOC=0` and debug ASan CLI
  builds are recorded negatives. A local `zend_test warn_on_startup` phpt
  reproduced the vendor output but stayed clean on debug ASan. Verdict
  CONFIRMED, **rung 3** for this lane: invalid read with a symbolized
  consumer path and a fix-sensitive comparison; no chosen bytes, pointer
  control, marker, pre-auth HTTP or FPM/Apache LPE demo, so rung 4 is closed.
  Gitignored evidence `lab/build/evidence/w53-129496/` (`verdict.txt`); do
  NOT repeat the debug-ASan runs.
- 2026-11-21 wake 55 adjacent DOM lane (no CVE/GHSA id): 8.5.13 NEWS ~line 80
  records "Fixed a use-after-free when reflected attribute setters replace an
  attribute whose child still has a live wrapper", with vendor regression
  `ext/dom/tests/reflected_attribute_write_live_child.phpt`. Mechanism:
  `dom_element_reflected_attribute_write (ext/dom/element.c:160)` and the
  DOMTokenList setters (`token_list.c:197/:437`) call `xmlSetNsProp()`
  directly, freeing the old attribute's child text node while a PHP wrapper
  (`$text = $element->getAttributeNode('class')->firstChild`) stays live, so
  `$text->parentNode` and `$text->textContent` dereference freed memory. The
  8.5.13 fix adds `dom_set_attribute_value()` (`php_dom.c:2348`, declared
  `php_dom.h:118`) with `node_list_unlink(existing->children)` before
  `xmlSetNsProp()`, routing all four setters through it. No new full build:
  the A side is the wake-51 dom-enabled 8.5.12 ASan CLI tree relinked with
  only the 8.5.13 `xml_serializer.c` (wake 51's `php-fixed`); the B side is
  that tree plus the committed four-file patch
  (`lab/php2shell/dom-reflected-attribute-fix.patch`, `php-fixed-domattr`).
  `lab/repro/php2shell-dom-reflected-attr.py` runs the five vendor shapes plus
  a no-replacement control: 5/5 ASAN_UAF on A / CLEAN on B, control
  CLEAN/CLEAN, fixed output byte-exact against vendor EXPECT, `verdict.txt`
  CONFIRMED under gitignored `lab/build/evidence/w55-domattr/`. ASan reports a
  heap-use-after-free READ of 8 at `dom_node_parent_get (node.c:247)`, freed
  by `xmlFreeNodeList ← xmlSetNsProp ← dom_element_reflected_attribute_write`.
  Grade rung 3 CONFIRMED for this lane only; overall PHP rung 4 unchanged:
  local CLI with a userland wrapper, no SAPI, pre-auth HTTP, chosen bytes,
  pointer control, marker or exploitability claim. Next if reopened: a
  chosen-byte occupant of the freed `xmlNode` child with a dereferencing
  accessor, or a DOM-consuming HTTP app reaching a reflected setter; do NOT
  repeat the same A/B.
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
layout, a real audio source and an FFmpeg-enabled build were UNKNOWN at wake
8. Wake 9 closed the stock-allocator item (the live chosen-byte overwrite
under stock glibc wrote 7564 OOB bytes at offsets 8820..16383 with the first
OOB byte client-chosen, did not fault at the write and produced glibc
`double free or corruption (!prev)` on teardown; a benign control stayed in
bounds); wake 16 closed the FFmpeg-build item and wake 17 the real-audio-source
question at source level (server-side capture and stride, not client-chosen;
deployment-specific influence stays UNKNOWN). Wake 10 made that live result
one command:
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
`verify-live-out/wake14/`). Wake-14 limits: chosen playback bytes are
lab-supplied, the object was identified after the fact with no grooming, only
one object was controlled, a client-side delay and `WLOG_FILTER` are required,
and the no-filter control stays clean. Wake 18 later closed grooming of that
object (see below); arbitrary targeting of other heap objects is not claimed.
Wake 15 removed the scratch delay: with the committed patched `sfreerdp` and
only its `Sleep(400)` between the two `SNDC_FORMATS` PDUs (no wake-14
`Sleep(2500)`), the wrap and copy still occur but `SNDC_QUALITYMODE` arrives
at the same instant as the wrap, before the copy; format selection failed, so
no audio PDU or `SNDC_WAVECONFIRM` follows and no post-write log, filter frame
or SIGSEGV occurs. At logoff the stock allocator aborts with the wake-9
`double free or corruption (!prev)`, not a controlled dereference
(`natural_trigger_no_timing.txt`, raw logs under `verify-live-out/wake15/`).
The client delay is therefore necessary; the unaided live trigger is a
recorded NEGATIVE.
Wake 16 closed the FFmpeg-build UNKNOWN. FFmpeg 6.1.1 development headers
and runtime were provisioned into `/tmp` only (apt download plus dpkg-deb
extraction, no system install), and pinned 3.32.0 was built twice:
stock `WITH_FFMPEG=ON` (implies `WITH_DSP_FFMPEG=ON`) and the same build with
`-DCMAKE_C_FLAGS=-DWITH_DSP_EXPERIMENTAL`; `WITH_VIDEO_FFMPEG=OFF` kept the
test on the DSP path. Stock FFmpeg is a NEGATIVE: `dsp_ffmpeg.c:63-89`
filters `AV_CODEC_ID_ADPCM_MS` (tag 2) and `AV_CODEC_ID_ADPCM_IMA_OKI`
(tag 17) without the macro, the runtime probe reports `PCM encode=1
decode=1`, `ADPCM(2) encode=0 decode=0`, `DVI_ADPCM(17) encode=0 decode=0`,
and `server_rdpsnd_get_formats()` lists only AAC_MS (41222) and PCM (1).
With the macro, tag 2 enters the list (2 channels, 44100 Hz, 16 bits);
because `audio_format_compatible` (`audio.c:225-255`) ignores `nBlockAlign`,
a client tag-2 record with `nBlockAlign=8, nChannels=2` matches it and the
tag-2 branch of `select_format` (`:409-433`) computes `bs = -4`, fails the
`realloc` at `:444` without rolling back `out_frames` and leaves
`0xfffffffffffffffc`. `PocAdpcmTag2.c` then gets the same ASan result as the
tag-17 PoC: `SelectFormat rc=12`, `out_frames=0xfffffffffffffffc`,
`WRITE of size 16384 ... 0 bytes after an 8820-byte region` from
`rdpsnd_server_send_samples (rdpsnd_main.c:770)`; a benign-PCM control on the
same build gives `rc=0, out_frames=0x89d` with no report. Grade: rung 3 and
an in-process chosen-byte rung 4 on real library bytes through the real
parser and dispatcher, on a NON-DEFAULT build — not a live RDP session or an
over-the-wire PDU, no chosen-byte dereference for tag 2, and the 16384 bytes
are PoC `0x41` rather than remote audio. Tag 17 has no FFmpeg encoder in
either build. On this host's pinned 3.32.0 + stock FFmpeg 6.1.1 build, wake 16
CLOSED the default-format question NEGATIVE: `ADPCM(2)` and `DVI_ADPCM(17)`
encode/decode are 0/0 and the server list is AAC_MS + PCM only
(`lab/freerdp2shell-src/ffmpeg_adpcm_tag2.txt`); other FFmpeg versions and
platform audio subsystems stay UNKNOWN (wake-16 driver `PocAdpcmTag2.c`; the
raw ASan log is a gitignored scratch file under `/tmp`).
Witness #602 independently ESTABLISHED this wake-16 FFmpeg format-gate result
with no corrections (`reports/frontier-freerdp2shell.md`).
Wake 17 closed the real-audio-source question at source level in pinned 3.32.0:
the copied bytes (`buf`, server-side platform capture) and copy stride
(`src_bytes_per_frame`, from the server's own format list) are set server-side;
the client's `SNDC_FORMATS` supplies only the wrap trigger and DSP reset
format, so remote byte choice is not established in a stock deployment.
Whether a deployment lets a remote attacker influence the captured audio
stays UNKNOWN. Source-only finding; see `reports/freerdp2shell-status.md`.
Wake 18 closed grooming in the live stock allocator
(`lab/freerdp2shell-src/grooming_format_count_stock.txt`): the second
`SNDC_FORMATS` PDU's `num_client_formats` sizes the `client_formats` array
immediately after `out_buffer` (`audio_formats_new()`,
`libfreerdp/codec/audio.c:262-265`), so N extra benign PCM records after the
malicious ADPCM record shift every following chunk by 32 bytes. Measured wLog
chunk offsets 8864/8896/9088/9856/16544 for N=0/1/7/31/240; `Names` at
8904+32*N. At N=1 a marker at the shifted `Names` field (8936) made the
natural `SNDC_QUALITYMODE` log path fault with
`rax=0x4141414141414141`, while 16 bytes too far gave
`rax=0xdededededededede`; at N=240 the target was past the 16384-byte write
and no fault occurred. Offset control is OBSERVED; byte control is still
bounded by wake 17. The client delay, `WLOG_FILTER`, subsystem-supplied format
table and post-auth loopback session remain conditions; this is scratch
observation in the live stock build, not witness acceptance.
Evidence: `reports/frontier-freerdp2shell.md`, extracted harness
`lab/frontier/freerdp2shell/{rdpsnd_overflow.c,run.sh}`, real-library
harness `lab/freerdp2shell-src/{run.sh,*.c}` with committed traces, seed
status `reports/freerdp2shell-status.md`, the wake-12 layout capture
`lab/freerdp2shell-src/heap_layout_stock.txt`, the wake-13 chosen-pointer
capture `lab/freerdp2shell-src/pointer_control_stock.txt`, the wake-14
natural-trigger capture `lab/freerdp2shell-src/natural_log_trigger_stock.txt`
and the wake-15 negative capture
`lab/freerdp2shell-src/natural_trigger_no_timing.txt`.
Wake 16's format-gate measurement and tag-2 wrap are in
`lab/freerdp2shell-src/ffmpeg_adpcm_tag2.txt` with the driver
`lab/freerdp2shell-src/PocAdpcmTag2.c`.
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
  as claimed. Its disclosed build-tree limit was closed by a clean-room replay
  (`lab/xrdp2shell-real/verify_cleanroom.sh`, transcript
  `cleanroom-replay.txt`): fresh ASan and plain xrdp 0.10.6 library builds,
  all three drivers rebuilt from unchanged digests, 15/15 assertions pass.
  Witness W41 (#617) independently ESTABLISHED this clean-room claim:
  `verify_cleanroom.sh` ran twice from fresh 0.10.6 source (`440a5381…`) in
  separate work dirs, rebuilding ASan and plain libraries and all three
  drivers from unchanged digests; both runs gave 15/15 passes, rc 0 and
  byte-identical gate traces, closing W33's build-tree limit. Fresh `.a`
  digests differ between builds because static archives embed member
  timestamps and paths; the gate results, not archive hashes, are the
  reproducing evidence. W41 covers only the xrdp claims, not the unrelated
  FREERDP #564 pointer deref; the in-process boundary stays unchanged.
  On this host the committed `real_drdynvc_driver.c` needs
  `-include config_ac.h` and an earlier `-I`; the RUNBOOK correction is
  recorded there. The in-process boundary is unchanged: no socket, logon,
  negotiated dynamic channel or pointer control is claimed. Evidence:
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
  A source-level data-flow pass records why strong rung 4 is unreachable
  through this primitive: the OOB loop has one store, the compile-time
  constant `GST_AUDIO_CHANNEL_POSITION_NONE = -3`
  (`upstream/channels.c:308-309`), so the attacker chooses store count and
  offsets but never stored bytes. `depay.c:203-207`'s `memcpy` from
  `order->pos` is guarded by `if (order)`, and `get_by_order` matches only the
  static 1..8 table (`channels.c:242-244`), so for channels>8 it never runs;
  `depay.c:264-269`'s reorder is guarded by `order &&` and becomes true at
  high counts only through the fixed `-3` corruption of `order` itself.
  `depay.c:218-219` reads `position[0..channels-1]` after the loop has
  written NONE to each, so no adjacent content leaks into emitted caps.
  Chosen bytes or an arbitrary pointer need a different sink; no harness or
  grade changed.
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
full-flag sync, never a bare `mishe sync`. Witness replay #761 (2026-11-21)
independently ESTABLISHED rungs 1/2/3 and rung 4 at the labeled INSTRUMENTED
scope: 20 PASS / 0 FAIL, five-run digest byte-equal to the brief. Its one nit
was that every source-line citation was six lines too high; the brief, seed
status and PROVENANCE now cite the pinned bytes, while the digest-pinned
harness bytes were deliberately preserved.

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
`etc/afpd/directory.c:168`, which underflows to `SIZE_MAX` for
`dir_len<=1022`; at the witness's chosen `dir_len=1023` the trailing slash
truncates, giving `strlen(path)=1023`, `len=1024` and `remain=SIZE_MAX-1`.
The guard at line 176 cannot reject a filename and
`strcpy(path + len, de->d_name)` at line 181 writes an attacker-chosen
255-byte name into `char path[MAXPATHLEN + 1]`.
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

#### Admitted 2026-11-21 ~06:2xZ: Opensips2Shell (GHSA-5gm5-wj62-p234, no CVE ID visible)

Claim source: maintainer advisory GHSA-5gm5-wj62-p234 (2026-09-28, High 8.6
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`); no CVE ID was visible on the
advisory or in a targeted search at fetch time (UNKNOWN, not asserted).
Affected `>=4.0.0,<4.0.2` and `>=3.6.0,<3.6.9`, patched `4.0.2` and `3.6.9`;
upstream fix `ec24165bc25fa462e08cdb33ee8071f58e166d36` (`Fixes
GHSA-5gm5-wj62-p234`). Claimed primitive: at tag `4.0.1`,
`modules/xmpp/xmpp.h:73-82` defines `ENC_SIP_URI()` whose
`sprintf(buf, "sip:%s", src)` copies an XMPP JID `from` into `buf_from[256]`
at `xmpp.c:280-285` with no length check, so a 299-byte JID writes 304 bytes
(48 past the array) with attacker-chosen length and contents. Pinned
`xmpp_server.c:361-382` reaches the sink on an unauthenticated `<message/>`
stanza. Reachability gate from the advisory: server mode needs
`modparam("xmpp","backend","server")`; the default component backend is not a
raw listener. The advisor claims a reliable receiver crash and RCE only as
possible depending on canary/ASLR/NX.

Frontier's harness (`lab/frontier/opensips2shell/run.sh`) compiles the verbatim
pinned `xmpp.h:73-82` and `xmpp.c:280-285` from tag 4.0.1 plus the fixed helper
and guards from tag 4.0.2 under `#line` directives with stubbed collaborators:
rung 1 `written=303 overflow=48`; rung 2 `stored_len=14` with `/` at offset 10
while the write still overruns; rung 3 ASan `stack-buffer-overflow`,
`WRITE of size 304`, frame `xmpp.c:285`; rung 4 reads 16 chosen bytes at
`buf_from + 256` back byte-exact (`CHOSEN_MATCH=1`), while the fixed build
writes 1024 bytes into 1025 and rejects a 1500-byte JID. Rung 4 is
INSTRUMENTED only — chosen bytes in the lab frame, no return address,
pointer, marker, daemon, socket, XMPP stream, shipping stack layout, canary,
ASLR or NX exercised. Cheapest next rung: build stock 4.0.1 with the xmpp
module under ASan plus a no-canary build, bind only 127.0.0.1 with
`backend=server`, send one stream header and one `<message from="…299 chosen
bytes…">` stanza, capture the real receiver's report, crash, wire bytes and
stack, then repeat with tag 4.0.2 as the control.

Admitted by the operator ~06:2xZ under standing approval #6 on handoff #606
(commits `b4bc31a`, `92a9c15`, `41818af`): the two-pane window (34, inner
socket), registry entry and seed wall were live from frontier and were
capture-verified at 06:05:46Z. Operator replay ~06:19Z from a clean `git
archive HEAD` extraction of `7674a58` into two separate absolute output
directories: 26 PASS / 0 FAIL and `ALL CHECKS PASSED rc 0` both times, byte
identical trace
`sha256=a69657bb243b83b850b332a4307996f5705d6b0bd6b3cdefbccba022c0c78b06`.
Wake trigger units and the presentation entry are owed from the person's
full-flag sync, never a bare `mishe sync`. Evidence:
`reports/frontier-opensips2shell.md`, seed status
`reports/opensips2shell-status.md` and the pinned hashes in
`lab/frontier/opensips2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~06:5xZ: Unbound2Shell (CVE-2026-81642)

Claim source: CVE record <https://cveawg.mitre.org/api/cve/CVE-2026-81642>
(CNA NLnet Labs) and maintainer advisory
<https://nlnetlabs.nl/downloads/unbound/CVE-2026-81642.txt>: "A DNSKEY with
an owner compression pointer to its own RDATA can overflow the digest
buffer. Remote code execution is possible through attacker controlled data."
CWE-122 heap buffer overflow; CNA CVSS 4.0 9.1 Critical
`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/U:Red`,
NVD CVSS 3.1 9.8, Ubuntu priority Medium (vendor variance, kept as a claim).
Affected: all versions through `1.26.0`, fixed `1.26.1`; upstream fix
`8c2e0fd6cc5b6eaa618ac72227808824b4edee7c`. Claimed primitive: at tag
`release-1.26.0`, `validator/val_sigcrypt.c:293-317`
(`ds_create_dnskey_digest`) writes the owner name and RDATA into
`env->scratch_buffer` (allocated at `daemon/worker.c:2436`, default size
65552 at `util/config_file.c:176`) using two `memcpy`s at
`sldns/sbuffer.h:436`; the wire maxima `LDNS_MAX_DOMAINLEN 255` and
`LDNS_MAX_RDFLEN 65535` are bounded separately, so `255 + 65533 = 65788`
writes 236 bytes past the buffer. The only capacity guard is an `assert()`
compiled out under `NDEBUG`; shipping compile flags are UNKNOWN. The fix
adds a two-line `sldns_buffer_available()` check. Advisory reachability
(attacker-controlled zone and a compression-pointer-inflated owner name),
the DNSSEC config gate and RCE remain claims.

Frontier's harness (`lab/frontier/unbound2shell/run.sh`) extracts the
verbatim pinned function from `release-1.26.0`, fix commit `8c2e0fd6cc5b`
and `release-1.26.1` under `#line` directives with stub collaborators:
rung 1 `written=65788 overflow=236 rc=1` with a benign `32`/`100` control;
rung 2 vulnerable `GUARD_REJECTED=0` while both fixed builds return 0 and
set `GUARD_REJECTED=1`; rung 3 ASan `heap-buffer-overflow`, `WRITE of size
65533` at pinned `sldns/sbuffer.h:436` from `val_sigcrypt.c:311`; rung 4
reads 16 chosen RDATA bytes back byte-exact at the first out-of-bounds
offset (`CHOSEN_MATCH=1`). Rung 4 is INSTRUMENTED only — chosen bytes in a
synthetic lab frame, no pointer, return address, marker, resolver process,
DNSKEY wire bytes, decompression path, DNSSEC configuration, allocator
adjacency or shipping flags exercised. Cheapest next rung: build stock
`release-1.26.0` under ASan with DNSSEC validation, bind only 127.0.0.1,
serve a local malicious zone whose DNSKEY owner uses a self-referential
compression pointer, query it from the lab resolver and capture the real
ASan frame, wire bytes and post-write heap state; repeat with `1.26.1` as
control. Attempt a benign marker only if chosen bytes reach a pointer or
saved control-flow datum.

Admitted by the operator ~06:5xZ under standing approval #6 on handoff #620
(commits `f9295a0`, `34fd212`, `e76e23d`): the two-pane window (35, inner
socket), registry entry and seed wall were live from frontier and
capture-verified at 06:32:41Z. Operator replay ~06:43Z from two clean `git
archive HEAD` (1718991) extractions into separate absolute output
directories: 29 PASS / 0 FAIL and `ALL CHECKS PASSED rc 0` both times, byte
identical trace
`sha256=05bf4ace988fc4fdc4d213674e1f30e85c739c170b47c5319cbfc2cd7f24f795`.
Witness #619 independently reached ESTABLISHED AS CLAIMED with no grade
correction; its stale-NDEBUG-comment nit is fixed in the admission commit.
Wake trigger units and the presentation entry are owed from the person's
full-flag sync, never a bare `mishe sync`. Evidence:
`reports/frontier-unbound2shell.md`, seed status
`reports/unbound2shell-status.md` and the pinned hashes in
`lab/frontier/unbound2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~07:1xZ: Janus2Shell (GHSA-8qwr-6p52-4vj9)

Claim source: maintainer advisory
<https://github.com/meetecho/janus-gateway/security/advisories/GHSA-8qwr-6p52-4vj9>,
published 2026-10-12, "No known CVE", reporter AdamKorcz (Anthropic / Ada
Logics). CVSS 3.1 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, availability
only as claimed; CWE-121 stack buffer overflow. Affected `<=1.4.2` and
`<=0.16.2`; fixed `1.4.3` and `0.16.3`; fix commits
`e55e2915a2801f18495c7f0d049af9274dd70065` (1.4.x) and
`c31cad9768368b996aa68753df1656fe4f30af7e` (0.16.x), each adding the same
five-line `len >= sizeof(prebuffer)` guard at two parsed-header sites.

Claimed primitive: at tag `v1.4.2`, `src/plugins/janus_recordplay.c:664`
declares `char prebuffer[1500]`. `janus_recordplay_parse_codec()` (`:701-714`)
and `janus_recordplay_get_frames()` (`:2603-2617`) read an unchecked 16-bit
big-endian length from a `.mjr` header, `fread` that many bytes into
`prebuffer` (`:707`, `:2610`) and write `prebuffer[len] = '\0'` (`:714`,
`:2617`). The advisory's unauthenticated client records an ~1900-byte
`a=fmtp`, producing a 1986-byte info header; a later play or startup rescan
crash-loops the daemon. Recording reachability and the HTTP-to-`.mjr` chain
stay claims.

Frontier's harness (`lab/frontier/janus2shell/run.sh`) executes the verbatim
pinned blocks from `v1.4.2` (`:669-670`, `:701-714`) and the guarded `v1.4.3`
block under `#line` directives with stub collaborators and a synthetic
in-memory `.mjr`: rung 1 1986 bytes into `prebuffer[1500]` (`overflow=486`)
with a benign 100-byte control; rung 2 vulnerable accepts and fixed rejects
with `Info header too big (1986 bytes)`; rung 3 ASan `stack-buffer-overflow`,
`WRITE of size 1986` at pinned `:707`; rung 4 reads 16 chosen bytes back
byte-exact past the array, overwrites the adjacent local `len`, and a
host-default-stack-protector control aborts with `stack smashing detected`.
Rung 4 is INSTRUMENTED only — no pointer, saved return address, marker,
live Janus process, HTTP/SDP path, real `.mjr`, shipping flags or real stack
layout exercised. Victim builds use `-fno-stack-protector`, so the canary
abort proves control-data adjacency only in that compiled frame.

Admitted by the operator ~07:1xZ under standing approval #6 on handoff #632:
the two-pane window (36, inner socket), registry entry and seed wall were
live from frontier and capture-verified at 07:00:48Z. Operator replay ~07:09Z
from two clean `git archive HEAD` (dc1a4e1) extractions into separate
absolute output directories: 29 PASS / 0 FAIL and `ALL CHECKS PASSED rc 0`
both times, byte-identical trace
`sha256=c8568d26b07cac408da640b7e6d8347d1c43db3119274fafbfb73f3e41f9a21f`.
Witness replay was requested in parallel; no verdict at admission. Cheapest
next rung: build stock `v1.4.2` on 127.0.0.1 with Record&Play enabled, create
the recording through the documented HTTP API with an ~1900-byte `a=fmtp`,
request playback under ASan and under a debugger watching the saved return
address, capture wire bytes, `.mjr` header, real ASan frame and post-write
stack state, and repeat with `v1.4.3`. Wake trigger units and the
presentation entry are owed from the person's full-flag sync, never a bare
`mishe sync`. Evidence: `reports/frontier-janus2shell.md`, seed status
`reports/janus2shell-status.md` and the pinned hashes in
`lab/frontier/janus2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~07:2xZ: Rsyslog2Shell (CVE-2026-55556 / GHSA-947w-69ph-mc2r)

Claim source: maintainer advisory
<https://github.com/rsyslog/rsyslog/security/advisories/GHSA-947w-69ph-mc2r>,
published 2026-06-23 by `rgerhards`, CWE-122, High. CVSS 4.0 8.2
`AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` — availability
impact only, and the advisory explicitly says "code execution has not been
demonstrated". Affected `>= 8.2110.0, < 8.2604.0`; patched `8.2604.0`;
bug-introducing commit `a8b8d6c1f969286adac3d465e6ac018968550667`; upstream
fix `acde2ba25ea33816694b787859f4a727a247b6d6` removes the dynamic
Basic-Auth buffer and adds `BASIC_AUTH_MAX_ENCODED 2048` /
`BASIC_AUTH_MAX_DECODED 1536` with early rejection and post-decode bounds
checks.

Claimed primitive: at tag `v8.2602.0`, `contrib/imhttp/imhttp.c:62` sets
`IMHTTP_MAX_BUF_LEN (8192)`; `parse_auth_header()` (`:687`) takes
`len = apr_base64_decode_len(src)` (`:699`), points `pworkbuf` at the
8192-byte stack `workbuf` (`:700`) and, when `len > sizeof(workbuf)`, switches
it to `calloc(0, len)` (`:702`) — zero bytes — before
`apr_base64_decode(auth->pworkbuf, src)` (`:705`) writes the full
attacker-chosen decoded credential past that allocation. Length and content
both come from one `Authorization: Basic` header, and the overflow fires
before credential validation, so no authentication is needed. The advisory's
config gate — imhttp must be built, installed, explicitly loaded and
configured with Basic Auth, with no known default-active distribution — is
UNKNOWN here and was not exercised.

Frontier's harness (`lab/frontier/rsyslog2shell/run.sh`) executes the
verbatim pinned struct (`:71-77`) and function (`:687-720`) from `v8.2602.0`
plus the fixed blocks from `v8.2604.0` under `#line` directives, with a stub
CivetWeb connection, an in-memory Authorization header and the authentic
host libaprutil `apr_base64_decode_len()`: rung 1 a 100-byte payload stays on
the stack (`dynamic=0`) while a 9000-byte payload takes `calloc(0, len)` and
writes 9000 bytes past it (`dynamic=1`); rung 2 the vulnerable build returns
normally and the fixed build rejects with `imhttp: rejecting oversized
Basic-auth header (12000 bytes, max 2048 bytes)` while accepting a benign
header; rung 3 ASan reports `heap-buffer-overflow`, `WRITE of size 1` with
the pinned caller frame `parse_auth_header contrib/imhttp/imhttp.c:705` (the
ASan summary frame is the instrumented decoder); rung 4 reads the 16-byte
chosen marker `54535253595348454c4c212121212121` back byte-exact at
`pworkbuf[0..15]`. The zero-length allocation has `usable=24` on this glibc
while 9000 bytes were written. Rung 4 is INSTRUMENTED only — no pointer,
saved return address, heap-metadata target, control-flow diversion, marker
execution, live rsyslog process, imhttp module, CivetWeb listener, HTTP
request, socket, shipping flags or allocator neighbourhood exercised.

Admitted by the operator ~07:2xZ under standing approval #6 on frontier's
commit `759215f`: the two-pane window (37, inner socket), registry entry and
seed wall were live from frontier and capture-verified at 07:19Z. Operator
replay ~07:20Z from two clean `git archive HEAD` (`ba9a240`) extractions into
separate absolute directories: 36 PASS / 0 FAIL and `ALL CHECKS PASSED rc 0`
both times, byte-identical trace
`sha256=fc9cd9bbfac007af32311d6d61a0d43cd27297c00d1b1b18fee30fb9d0e255be`.
Witness replay was requested in the handoff; no verdict at admission.
Cheapest next rung: build imhttp on the pinned affected tag with ASan, run
the advisory's single-request PoC against a loopback-only listener and
inspect the allocator neighbourhood at the `calloc(0, len)` site —
specifically whether a subsequent CivetWeb connection/request-state
allocation with a useful caller-side pointer can be reached with chosen
offsets before the process aborts. Wake trigger units and presentation stay
owed from the person's full-flag sync, never a bare `mishe sync`. Evidence:
`reports/frontier-rsyslog2shell.md`, seed status
`reports/rsyslog2shell-status.md` and the pinned hashes in
`lab/frontier/rsyslog2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~07:5xZ: ProxySQL2Shell (CVE-2026-48773 / GHSA-58ww-865x-grpr)

Claim source: maintainer advisory
<https://github.com/sysown/proxysql/security/advisories/GHSA-58ww-865x-grpr>,
published 2026-05-26 by `renecannao`, CWE-787, Critical. CVSS 3.1 **9.8**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. The advisory reports ASan-confirmed
heap corruption on real daemons on both ordinary frontend paths — MySQL
`:6033` at `lib/mysql_data_stream.cpp:665`, PostgreSQL `:6133` at
`lib/PgSQL_Data_Stream.cpp:534` — and a stock Docker-image crash (`exit=139`)
through the optional ClickHouse/MySQL-style listener. It claims no code
execution and says the primitive "should be treated as potentially
exploitable memory corruption unless proven otherwise". Affected
`>= 2.0.18, <= 3.0.8`; patched `3.0.9`; tested source in the advisory `v3.0`
branch commit `9cc20a8775f6c194335a940ed0ca12001166522a`; upstream fix
`1cb2ecc17a0206bc2bed9090d5d7fab121f2798e` bounds the second `recv()` by the
remaining queue capacity (`s-4` MySQL, `s-5` PgSQL) and calls `shut_soft()`.

Claimed primitive: at tag `v3.0.8`, `include/MySQL_Data_Stream.h:30` and
`include/PgSQL_Data_Stream.h:16` pin `QUEUE_T_DEFAULT_SIZE 32768`.
`MySQL_Data_Stream::read_from_net()` (`:643-671`) reads four bytes, copies the
declared 24-bit length into the pinned struct
(`include/proxysql_structs.h:928-930`, `u_int pkt_length:24, pkt_id:8;`) and
executes `recv(fd, queue_w_ptr(queueIN)+4, Hdr.pkt_length, 0)` at `:665`.
`PgSQL_Data_Stream::read_from_net()` (`:504-541`) reads five bytes; with type
byte 0 it takes `buff[0..3]` as a big-endian 32-bit length and executes
`recv(fd, queue_w_ptr(queueIN)+5, length, 0)` at `:534`. Both declared length
and second-read bytes are client-chosen and both sinks run before
authentication or packet validation. The PostgreSQL frontend must be
configured; the MySQL frontend is the ordinary listener. Adapter builds,
allocator and shipping flags are UNKNOWN on any host here.

Frontier's harness (`lab/frontier/proxysql2shell/run.sh`) executes the four
verbatim pinned first-read blocks under `#line` directives: vulnerable
`v3.0.8` (`mysql :643-671`, `pgsql :504-541`) and fixed `v3.0.9`
(`mysql :651-689`, `pgsql :512-560`), with a synthetic in-memory `recv()`
collaborator; no daemon, listener, socket or client is used. Rung 1: a
100-byte packet leaves bytes past the queue untouched while MySQL declared
65535 and PostgreSQL declared 100000 become the second `recv()` lengths;
ASan is clean at exact capacity (32764 / 32763) and faults one byte above
(32765 / 32764). Rung 2: vulnerable builds accept (`accepted=1 shut=0
recv_calls=2`); fixed builds reject before the second recv (`rc=-1 accepted=0
shut=1 recv_calls=1`) with the pinned `Oversized first packet ...` logs while
still accepting the benign packet. Rung 3: ASan reports
`heap-buffer-overflow`, `WRITE of size 65535` at pinned
`lib/mysql_data_stream.cpp:665` and `WRITE of size 100000` at pinned
`lib/PgSQL_Data_Stream.cpp:534`, with `malloc_usable_size()` 32768. Rung 4 is
INSTRUMENTED only: in a separate guard-mapped plain build, chosen alternating
stripes read back byte-exact at the logical queue boundary and sixteen bytes
past it (`CHOSEN_MATCH=1`), 32771 bytes past for MySQL and 67237 for
PostgreSQL; the queue was zeroed first, benign and fixed runs leave those
offsets at zero. No pointer, saved return address, heap-metadata field,
function pointer, control-flow diversion or marker execution was observed or
attempted, and the guard mapping is instrumentation, not an upstream
allocator property.

Admitted by the operator ~07:5xZ under standing approval #6 on frontier's
commit `3aea985`: the two-pane window (38, inner socket), registry entry and
seed wall were live from frontier and capture-verified at 07:46Z. Operator
replay ~07:5xZ from two clean `git archive HEAD` (`3aea985`) extractions into
separate absolute directories: 53 PASS / 0 FAIL both times, raw trace
`sha256=936fa128f01f1dd123b59b4b941310654d68cd5985449768b0d9ba51a8e77884`
byte-identical between directories, to the working-tree replay and to the
brief. Witness replay was requested in the handoff (#657); no verdict at
admission. Cheapest next rung: build `v3.0.8` with `NOJEMALLOC=1 WITHASAN=1`,
start it loopback-only with the MySQL frontend on 127.0.0.1:6033 and a
PostgreSQL frontend on 127.0.0.1:6133, send the advisory's first packets and
capture the real ASan frames, write sizes and queue allocation; repeat on
`v3.0.9` for the guard. Only a pointer or control-flow observation would
justify dropping the INSTRUMENTED label; if the stock daemon's allocator or
read path lands the write in unusable poison, preserve that as a negative
result. Wake trigger units and presentation stay owed from the person's
full-flag sync, never a bare `mishe sync`. Evidence:
`reports/frontier-proxysql2shell.md`, seed status
`reports/proxysql2shell-status.md` and the pins in
`lab/frontier/proxysql2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~08:1xZ: Strongswan2Shell (CVE-2026-35330)

Claim source: upstream advisory
<https://www.strongswan.org/security/CVE-2026-35330.html>, published
2026-04-22 and read 07:55Z. It reports an infinite loop or a heap-based
buffer overflow in `libsimaka` processing certain EAP-SIM/AKA attributes,
"potentially" leading to remote code execution. All versions since 4.3.6
are affected; fixed in 6.0.6. CVSS is not stated by the advisory (UNKNOWN);
the advisory says RCE "might be possible" and claims no demonstrated control
flow. Public exploit-module pages (Exploit-DB 52587, Powder Keg
Technologies) are unverified claims. Fix commit
`aa5aaebc33e0f326d8a0dbe01b236f2bfa0e6ea1` ("libsimaka: Reject zero-length
EAP-SIM/AKA attributes", 2026-03-11) adds `hdr->length == 0 ||` to the guards
at `src/libsimaka/simaka_message.c:419` (RAND/ENCR_DATA) and `:442`
(PADDING/default). Pins, hashes and raw URLs are in
`lab/frontier/strongswan2shell/PROVENANCE.md`.

Claimed primitive: attribute headers are one type byte plus one length byte
in 4-byte units, with a valid length of at least 1. At `6.0.5` the vulnerable
branches check remaining message bytes but not `length == 0`, so
`hdr->length * 4 - 2` (default) or `- 4` (`AT_RAND`) underflows `size_t`.
`chunk_skip()` becomes a no-op (infinite loop for `AT_PADDING`), while the
wrapped length reaches `malloc(sizeof(attr_t) + data.len)` and
`memcpy(attr->data, data.ptr, data.len)` in `add_attribute()` at
`simaka_message.c:257-260`. The wrapped allocation is 12/14 bytes on this
host against a 16-byte `attr_t`, so even the `attr->len` store at `:258` is
out of bounds, and the copy source is attacker-supplied attribute bytes.
`AT_ENCR_DATA` (type 130) takes the underflowed `:423` branch but calls no
sink, leaving `in` unchanged. Reachability is configuration-dependent:
EAP-SIM/AKA must terminate locally on the VPN server; RADIUS offload is
explicitly not vulnerable. No stock-config or default-listener claim is made.

Frontier's harness (`lab/frontier/strongswan2shell/run.sh`) compiles pinned
`6.0.5` / `6.0.6` `simaka_message.c` ranges verbatim under `#line`, with
synthetic `chunk_t`, list and chosen-byte collaborators; no daemon, socket,
IKE handshake, RADIUS server or network is used. Rung 1: length byte 0 on
`AT_IDENTITY` (14) requests a `18446744073709551614`-byte copy at `:260` and
leaves `in` unchanged; `AT_RAND` (1) requests `18446744073709551612`;
`AT_ENCR_DATA` (130) reaches the underflow but calls no sink; benign length 1
advances normally. Rung 2: the allocation wraps to 14/12 bytes and the
vulnerable build accepts the attribute, while both fixed guards call
`invalid_length()` and add only the benign attribute. Rung 3: ASan reports
`heap-buffer-overflow`, `WRITE of size 8` at pinned
`simaka_message.c:258 in add_attribute` inside 14-byte and 12-byte regions;
benign and fixed runs are clean.

Rung 4 is INSTRUMENTED only, with two preserved outcomes. A bounded-copy
collaborator (131072 bytes, still logging the wrapped requested length) puts
chosen `0x5a` bytes at offsets 16, 32, 64, 4096 and 65536 past `attr->data`
on both vulnerable paths (`match=1`). With the real host libc and the
genuine wrapped length, the copy faults at `src_base - 0x20` before writing,
those offsets stay `0x00` (`match=0`). No pointer, saved return address,
heap-metadata target, control-flow diversion or marker execution was observed
or attempted; both the guard mapping and the bounded copy are instrumentation.

Admitted by the operator ~08:1xZ under standing approval #6 on frontier's
handoff #670 and commits `37e0b1a` / `cda059a` / `6b9ac2d`: the two-pane
window (39, inner socket), registry entry and seed wall were live from
frontier and capture-verified 08:06Z. Operator replay ~08:1xZ from two clean
`git archive HEAD` (`97d53ed`) extractions into separate absolute directories:
54 PASS / 0 FAIL both times, raw trace
`sha256=57cd8943825f35a14f45ce134f3987c489aacbd080c6249a94c9dc808f1f3d6a`
byte-identical between directories, to the working-tree replay and to the
brief. Witness replay #669 was separately finished with verdict #675 (08:11Z):
ESTABLISHED AS CLAIMED, no grade correction, rung 4 INSTRUMENTED only.
Cheapest next rung: build `6.0.5` `charon` with `eap-sim`/`eap-aka` plugins,
configure a loopback-only IKEv2 responder terminating EAP-SIM locally, send a
crafted EAP-SIM message with a zero-length attribute, capture the real ASan
frames and wrapped allocation, then repeat on `6.0.6` for the guard. Only an
observed pointer or control-flow result would drop the INSTRUMENTED label;
if the daemon's copy faults before writing chosen bytes, preserve that as a
negative result. Wake trigger units and presentation stay owed from the
person's full-flag sync, never a bare `mishe sync`. Evidence:
`reports/frontier-strongswan2shell.md`, seed status
`reports/strongswan2shell-status.md` and the pins in
`lab/frontier/strongswan2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~08:29Z: Memcached2Shell (no upstream CVE/GHSA found)

Claim source: upstream fix commit
`7eeac6e9a9945aa68298aff379cea5ab3817af7c` ("crawler: fix buffer overflow on
idle client", 2026-07-07, reporter Nicolas Krassas), parent
`aa352388abf903d50e6bdd22dfb8ab9373d2896b`, and release 1.6.44 (annotated
tag `7d2f9295…`, target commit `e44dd0b01234bc0faf970e9225e3423e98022129`).
Ubuntu LP#2161693 and openSUSE-SU-2026:21872-1 are distro advisories. Read
08:27Z, LP#2161693 independently describes the same `lru_crawler_write()`
bug, an unauthenticated stalled-reader reproducer on a default non-SASL
instance, affected Ubuntu 1.6.24 (noble) / 1.6.40 (resolute) and the upstream
fix in 1.6.44; a comment dates the vulnerable buffer redesign to `a22be2bd…`.
Full upstream affected range UNKNOWN. NVD keyword search returned 0 results
at 08:13Z; no upstream CVE/GHSA was found, so CVE/GHSA is UNKNOWN /
NO-CVE-FOUND, not a proven negative. Pins, hashes and raw URLs are in
`lab/frontier/memcached2shell/PROVENANCE.md`.

Claimed primitive: the default config sets `lru_crawler` and `dump_enabled`
true with no SASL gate. A client issues `lru_crawler metadump all` and never
reads. In the pinned parent `lru_crawler_write()` returns 0 on a 1000 ms
`poll()` timeout while `bufused` is still nonzero (`crawler.c:471`); the
per-LRU caller at `:628-640` treats that as success and never expands the
buffer, unlike the hash path at `:582-587`. `crawler_metadump_eval()` keeps
appending attacker-stored, percent-encoded key bytes at `buf + bufused`
(`:307-310`, `:371`) past the 131072-byte allocation from `:824-825`. The
unconditional `sent += total` at `:499` is a second, separately preserved
accounting defect. `-X` and `-o no_lru_crawler` are non-default mitigations.

Frontier's harness (`lab/frontier/memcached2shell/run.sh`) compiles the
pinned parent/fixed `crawler.c` ranges verbatim under `#line` with synthetic
`conn`, item, `poll()` and buffer collaborators; no daemon, socket, thread or
network. Rung 1: the parent idle client faults (exit 77) after ~1000 appended
lines while the fixed build times out 1800 polls and closes the client. Rung
2: parent EAGAIN reports `write_ret=0` with zero bytes written and no client
close; the fixed build returns -1 after bounded retries and the timeout
backstop. Rung 3: ASan reports `heap-buffer-overflow`, `WRITE of size 64`,
0 bytes after the 131072-byte region, append frame `crawler.c.vuln:310` and
allocation frame `:825`, with clean fixed and benign-parent controls. The 64
bytes are a verbatim harness key; real `uriencode_p()` makes the write
key-length dependent.

Rung 4 is INSTRUMENTED only, with preserved negatives. With a zeroed 1 MiB
collaborator replacing the nominal buffer, chosen key byte `0x5a` is read
back at offsets 0, 4 and 65536 past the nominal end (35231 of 65536 bytes
matched); a `0x41` differential puts `0x41` at exactly those offsets. Under a
guard-mapped allocation the parent faults at the first byte past 131072, and
the unmodified plain parent faults in host libc before any stable chosen
bytes can be inspected. No pointer, saved return address, heap metadata
field, function pointer, control-flow diversion or marker execution was
observed or attempted; the collaborator and guard mapping are
instrumentation.

Admitted by the operator ~08:29Z under standing approval #6 on frontier's
handoff #686 and commits `b7fb237` / `163433e`: the two-pane window (40,
inner socket), registry entry and seed wall were live and capture-verified
08:24Z; the bottom-pane plant_view process was live at admission. Operator
replay ~08:28Z from two clean `git archive HEAD` (`163433e`) extractions into
separate absolute directories: 8 PASS / 0 FAIL both times, raw trace
`sha256=5d4a05be6cebb89e7fd99e0f6d08731e47537c49d0b8396d6be73e554b51672b`
byte-identical between directories, to the working-tree replay and to the
brief. Witness replay #685 was requested; no verdict was in hand at
admission. Wake trigger units and presentation stay owed from the person's
full-flag sync, never a bare `mishe sync`. Cheapest next rung: determine this
host's actual consumer behavior at the buffer boundary first (allocator
layout, `write()`/`poll()` timing), then build the pinned vulnerable tree
under ASan, run a loopback-only daemon with many stored keys, stall a
`lru_crawler metadump all` client, capture the real ASan frame and heap
layout, and repeat on 1.6.44 for the guard. Only an observed pointer or
control-flow result would drop the INSTRUMENTED label; the LP's daemon frame
at `crawler.c:275` is from a different build and stays a claim. Evidence:
`reports/frontier-memcached2shell.md`, seed status
`reports/memcached2shell-status.md` and the pins in
`lab/frontier/memcached2shell/PROVENANCE.md`.

2026-11-21 ~09:45Z outcome: witness verdict #751 ESTABLISHED AS CLAIMED on the
chosen-byte limb, after #710 established rung 3. A loopback daemon on the
pinned parent built with `-g -O1 -fno-omit-frame-pointer` (not a distro
binary), 8000 keys of 245 bytes, a stalled `lru_crawler metadump all` client
with `SO_RCVBUF=4096`, a 64 MB daemon and a ~80 s hold gives rung 3 in process
(ASan `WRITE of size 1` at `util.c:57` via `crawler.c:310`, allocation at
`:825`; fixed tree clean) and rung 4 chosen bytes at chosen offsets in a live
non-instrumented build of the pinned parent. A non-perturbing `/proc` observer
reads pinned `active_crawler_mod` at `base+0x54320` through `/proc/pid/mem`
without stopping the crawler, so the 1000 ms `poll()` timeout stays intact;
two key bytes (`0x5a`, `0x41`) at identical offsets and timing confirm the OOB
bytes come from the stored key record, and writes are frontier-local. No
pointer-control, dereference, execution or control-flow claim was accepted or
made, so R4 stays ◐. The chosen-byte overwrite of a pointer-shaped heap window
is conditional on allocator state (absent in two witness `0x5a` replays) and
not a grade basis; one non-reproduced daemon SIGSEGV in a slab-freelist
pointer write is preserved as a single observation. Wording nit from #751
applied: "live non-instrumented build of the pinned parent" instead of "live
stock daemon". See `reports/memcached2shell-daemon-asan.md` and
`reports/memcached2shell-status.md`.

2026-11-21 ~10:04Z fifth-wake addendum (submitted for witness replay then, accepted by #784; grade
unchanged): the pinned plain parent under gdb with no breakpoints and ASLR on
faults reproducibly in `assoc_find` (`assoc.c:87`, `movzbl 0x29(%rbx)`) with
the hash-bucket chain item pointer equal to eight attacker-written `0x5a`
bytes (`0x5a5a5a5a5a5a5a5a` in two independent runs); a `0x41` run faults at
the same site with a different attacker-written value; the pinned fixed tree
does not fault in 90 s / 42,770 sets under the same trigger. This adds a
reproduced crash/DoS limb, not a crafted canonical address or execution.
`uriencode_init()` leaves literal only alphanumerics and `-._~`, so a
canonical pointer cannot be emitted through the key path — address control
is structurally out of reach. Raw captures and caveats: the fifth-wake
section of `reports/memcached2shell-daemon-asan.md`.

2026-11-21 ~10:5xZ eighth-wake addendum: witness #784 returned ESTABLISHED AS
CLAIMED on the fifth-wake crash/DoS limb (commits `885d44f`/`0ff4a38`), grade
unchanged at #751. It hash-matched all four pinned files, rebuilt both plain
binaries itself, and reproduced SIGSEGV at `assoc_find+126` / `assoc.c:87`
with `RBX=0x5a5a5a5a5a5a5a5a5a` after 20,462 sets; a second fault held
`b'etch=no '`, a `fetch=%s` metadump field fragment. Its rebuilt fixed binary
and a stress run with no stalled metadump did not fault, but three of five
vulnerable+metadump+stress runs did not fault either, so the crash stays
non-deterministic and no in-run frontier was observed. Wording nit applied
across the memcached surfaces: call the faulting value overflow-stream
content, and keep "not deterministic" next to "reproduced" in the fifth-wake
headline. No further replay owed; no address control, execution or
control-flow diversion claim.

#### Admitted 2026-11-21 ~08:44Z: Ipfixcol2Shell (CVE-2026-122127 / GHSA-4575-chq4-crfc)

Frontier handed this find over on tape #698 after committing `a5f3aed`
(brief and harness) and `a832dcd` (replay record). Claim sources: GitHub
Advisory `GHSA-4575-chq4-crfc` and CVE-2026-122127 (VulnCheck, published
2026-11-04), both pinned in `lab/frontier/ipfixcol2shell/PROVENANCE.md`.
The advisory states that ipfixcol2 2.7.1 before 2.9.0 lets an unauthenticated
network peer declare a small ring `buffer_size` followed by a large
`decompressed_size` and write up to 65535 controlled bytes past a heap
buffer; CVSS v4 8.7 is availability-only (`VC:N/VI:N/VA:H`). Vulnerable tags
`v2.7.1`/`v2.8.0` carry byte-identical `Lz4Decoder.cpp`
(`sha256=3e618628…`); fixed `v2.9.0` carries the check
(`sha256=46a0fc8b…`). The fix `fd5cb168efb4b864d33f655174711b2779cef502`
adds one four-line validation before `LZ4_decompress_safe_continue()`.

The wire starts with an eight-byte ring size that `read_start_header()`
(pinned `Lz4Decoder.cpp:114-133`) passes to `reset_stream()`, whose
`m_decompressed.resize(buffer_size)` is at `:184`. The next four-byte header
supplies `decompressed_size` unchecked (`:104-107`). `decompress()` wraps the
position at `:141-143` but passes the attacker's declared size as
`dstCapacity` to `LZ4_decompress_safe_continue()` at `:145-151`; a matching
all-literals block makes the real host `liblz4.so.1` write the declared count
of chosen bytes past the small ring. The fix checks exactly that inequality.
The accounting fault at `:170-173` is source-bound, not separately
instrumented and unused for a rung claim.

Rungs 1/2/3 run the pinned `.cpp` verbatim under `#line`, linked against the
host's real liblz4: with `buffer_size=24` and `decompressed_size=65000` the
vulnerable build faults, ASan reports `heap-buffer-overflow`, `WRITE of size
65000`, 0 bytes after the 24-byte region, allocation at pinned `:184` via
`:131` and the write at `:145`; the fixed build throws `LZ4 Decoder: invalid
decompressed size` in both ASan and plain builds, and a benign 8-byte input
decodes clean. Rung 4 is INSTRUMENTED only: in a 1 MiB mmap collaborator
chosen wire byte `0x5a` lands at offsets 0/24/28/64999 past the ring and
`0x00` at 65000/65001, an `0x41` payload gives `0x41` at the same offsets,
and the benign input leaves them zero. The stock ASan build faults before the
bytes can be read back. No pointer, saved return address, heap metadata
field, function pointer, control-flow diversion or marker execution was
observed or attempted.

Admitted by the operator ~08:44Z under standing approval #6: the two-pane
window (41, inner socket), registry entry and seed wall were live and
capture-verified 08:35Z. Operator replay ~08:43Z from two clean `git archive
HEAD` (`18cae3d`) extractions into separate absolute directories: 13 PASS /
0 FAIL both times, raw trace
`sha256=e9c06f530d09912603ed379913699b2f1e63e08ab64b8cfcefdae0b47f3cd89f`
byte-identical between directories, to the working-tree replay and to the
brief; all 11 pin hashes, the fix commit, both tag refs, the advisory pin and
the four-line patch were also checked. Witness replay #697 was requested; no
verdict was in hand at admission. Wake trigger units and presentation stay
owed from the person's full-flag sync, never a bare `mishe sync`. Cheapest
next rung: build the real collector from pinned v2.8.0/v2.9.0 sources under
`lab/`, bind its TCP input to 127.0.0.1 only, send the same headers on a
loopback socket and capture the daemon ASan frame plus heap layout under the
plugin's actual allocator, then repeat on the fixed tag. If the ring sits
where no pointer can be reached, cap at rung 3 like iperf and record why;
only an observed pointer or control-flow result would drop INSTRUMENTED.
Evidence: `reports/frontier-ipfixcol2shell.md`, seed status
`reports/ipfixcol2shell-status.md` and the pins in
`lab/frontier/ipfixcol2shell/PROVENANCE.md`.

2026-11-21 ~09:00Z outcome: witness verdict #712 ESTABLISHED AS CLAIMED. A
live loopback replay (`lab/ipfixcol2shell-live/`, `sh run.sh`, 9 PASS / 0 FAIL,
trace `b81b947cf21f4ab92c6f268534dfbe8fbd6c3eb7da35ee5e9caab000e5471600`,
stable in three runs) uses the real plugin decoder/consumer sources from
sha256-verified v2.8.0/v2.9.0 tarballs over a 127.0.0.1:0 TCP socket. Rung 3
is confirmed at real upstream frames; stock glibc reaches `unlink_chunk`
with chosen bytes in chunk metadata, and a crafted payload places chosen
bytes in a pointer that `unlink_chunk+39` dereferences. Rung 4 stays
INSTRUMENTED — no valid address, write-what-where or execution. The full
daemon is UNKNOWN and blocked here by absent libfds/lz4-dev/rst2man. See
`lab/ipfixcol2shell-live/RESULTS.md` and the status report.

#### Admitted 2026-11-21 ~09:2xZ: Srs2Shell (GHSA-qr8h-p53p-x564, no CVE at fetch)

Frontier handed this find over on tape #716 after committing `24db73a`
(brief and harness) and `770669f` (replay record). Claim source: GitHub
Advisory `GHSA-qr8h-p53p-x564` (no CVE assigned at fetch), published
2026-10-30T14:14:41Z, HIGH 8.2, "RTC: Crash and heap overflow from a
malformed RTCP packet", pinned in `lab/frontier/srs2shell/PROVENANCE.md`.
Affected `srs >=4.0,<6.0.194`, `>=7.0,<7.0.214`, `>=8.0,<8.0.73`; patched
`6.0.194`, `7.0.214`, `8.0.73`. Only WebRTC-enabled servers are affected and
no authentication is needed without `on_play`/`on_publish` callbacks — a
claim, not reproduced here. Fix `ab03c94b0744ab392320253ad1767b21b6c82a59`
adds `length < 1`, `length < 2` and a `payload_len_ > kRtcpPacketSize` guard.

One attacker-controlled RTCP packet's 16-bit `length` drives a copy into the
fixed `payload_[1500]` array. `decode_header`
(`srs_kernel_rtc_rtcp.cpp:53-70`) checks only `length * 4 <= buffer->left()`,
never rejects `length == 0` and never caps the length for the array.
`SrsRtcpCommon::decode` (`:84-98`) and `SrsRtcpTWCC::decode` (`:802-844`)
compute `payload_len_ = (length + 1) * 4 - sizeof(SrsRtcpHeader) - 4` and
pass it to `buffer->read_bytes()`; pinned `srs_kernel_buffer.cpp:242-249`
calls `memcpy(data, p_, size)` after `srs_assert(require(size))`, checking only
that the source datagram has enough bytes. `length = 0` gives `payload_len_ =
-4` and an assert abort; `length = 400` gives a 1596-byte copy 96 bytes past
the array, 76 past the object.

Rungs 1/2/3 on verbatim pinned upstream ranges under `#line`: parent
`length = 0` aborts at pinned `srs_kernel_buffer.cpp:244`; a 1604-byte
datagram declaring 1596 payload bytes passes the parent's upper-bound check;
ASan reports `heap-buffer-overflow`, `WRITE of size 1596` at pinned
`srs_kernel_buffer.cpp:246`, decode frame `srs_kernel_rtc_rtcp.cpp:95`, 0
bytes after a 1536-byte region, with TWCC reproducing the write and fixed
BYE/TWCC plus benign `length = 2` clean. Rung 4 is INSTRUMENTED only: in a
64 KiB zeroed collaborator chosen `0x5a` appears at 96 offsets past the
payload-array end (20 in the object tail, 76 past the object), `0x41`
reproduces the same count, a benign run writes none, and a guard-mapped
object faults on the byte past the object (exit 77). No pointer, return
address, heap-metadata field, function pointer or control-flow diversion was
observed or attempted; collaborator and guard page are instrumentation.

Admitted by the operator ~09:2xZ under standing approval #6: the two-pane
window (42, inner socket), registry entry and seed wall were live and
capture-verified 08:53Z. Operator replay ~09:1xZ from two clean `git archive
24db73a lab/frontier/srs2shell` extractions into separate absolute
directories: 14 PASS / 0 FAIL both times, raw trace
`sha256=77b6d5500dea19d3c3a8de713d7a37834a3241a62e6a7239d398661e5fea1965`
byte-identical between directories, to the working-tree replay and to the
brief. Witness replay was requested separately; no verdict in hand at
admission. Wake trigger units and presentation stay owed from the person's
full-flag sync, never a bare `mishe sync`. Cheapest next rung: build the
pinned parent SRS with ASan, enable WebRTC on loopback, open a WHEP/WHIP
session, send one SRTP-protected BYE/TWCC packet with `length = 400` and a
chosen fill byte, and capture the daemon ASan frame plus the real heap layout;
repeat on the fixed version. If the real allocator faults before chosen bytes
persist, preserve the negative and cap at rung 3. Evidence:
`reports/frontier-srs2shell.md`, status `reports/srs2shell-status.md` and the
pins in `lab/frontier/srs2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~09:2xZ: 389ds2Shell (CVE-2026-11610 / GHSA-2g8g-f92j-g4gq) — post-auth caveat

Frontier handed this find over on tape #728 after committing `9ff285d`
(brief and harness) and `0a4048b` (replay record). Claim sources: GitHub
Advisory `GHSA-2g8g-f92j-g4gq` / CVE-2026-11610 (published 2026-07-07, HIGH
8.8, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-122), the CVE record and
upstream issue #7658, pinned in `lab/frontier/389ds2shell/PROVENANCE.md`.
Affected 389-ds-base 1.3.2 through 3.3.0. Fix
`f15ffd63e2bd70b3244881424ef903f17f7f0394`, parent `e63592d5…`; the separate
`dd16813` (CVE-2026-78701) was read and excluded as a different bug. No
upstream fixed semantic version beyond 3.3.0 → 3.3.1, only unaffected RHEL
builds.

After a successful SASL bind with integrity protection (`SSF > 0`,
Kerberos/GSSAPI or DIGEST-MD5), an oversized LDAP UNBIND whose padded BER
length is attacker-declared drives a copy into a 512-byte heap receive buffer
without a bounds check in `sasl_io_recv()` (`sasl_io.c`), up to ~2 MB of
chosen bytes. Upstream issue #7658 names the missing check: when
`sasl_io_start_packet()` returns `SASL_IO_BUFFER_NOT_ENCRYPTED`, nothing
checks `sp->encrypted_buffer_count <= len` before the `memcpy`. Pinned
vulnerable `sasl_io.c` `sha256=9cea2e7b…`, copy at `:456`; fixed `f82aa846…`.
Rungs 1/2/3: declared 9000 into the 512-byte buffer, 511/512 clean and 513
faults; ASan `WRITE of size 9000` at pinned `sasl_io.c.vuln:456`, 0 bytes
after a 512-byte region. Rung 4 is INSTRUMENTED only: chosen `0x5a`/`0x41`
bytes at offsets 0-8487 in a 1 MiB zeroed collaborator, benign clean,
guard-page fault (exit 77); no pointer or control-flow diversion.

Admitted by the operator ~09:2xZ under standing approval #6: two-pane window
(43, inner socket), registry entry and seed wall were live and capture-
verified 09:11Z. Operator replay ~09:18Z from two clean `git archive 9ff285d
lab/frontier/389ds2shell` extractions into separate absolute directories:
14 PASS / 0 FAIL both times, raw trace
`sha256=04e394a69a8508ab127ab206f713b87e8f590f799eb09d9ab130c63c5428cceb`
byte-identical between directories, to the working-tree replay and to the
brief. Witness replay requested separately; no verdict in hand at admission.
Wake trigger units and presentation stay owed from the person's full-flag
sync, never a bare `mishe sync`.

Caveats recorded at admission and never to be dropped: this is **post-auth**
(`SSF > 0` required), not pre-auth; the advisory claims DoS, not RCE; the
512-byte size is the advisory's account and the real caller's `len` is
UNKNOWN; no fixed semantic-version pin; live daemon, shipping allocator,
valid-address retargeting and post-write control are UNKNOWN. Admission rests
on the five #6 evidence elements (pinned claim, affected/fixed pin,
attacker-controlled heap write, rung-4 plausibility, byte-controlled
corruption), consistent with other gated admissions; it does not lower the
bar for future targets. Cheapest next rung: build the pinned parent with
ASan, configure a loopback 389-ds instance with a DIGEST-MD5/GSSAPI user,
SASL-bind with `SSF > 0`, send the upstream test's 9000-byte padded plaintext
UNBIND on the raw socket FD, and capture the daemon ASan frame plus heap
layout; repeat at the fixed commit. If the shipping allocator faults before
chosen bytes persist, preserve the negative and cap at rung 3. Evidence:
`reports/frontier-389ds2shell.md`, status `reports/389ds2shell-status.md` and
the pins in `lab/frontier/389ds2shell/PROVENANCE.md`.

#### Held 2026-11-21 ~10:06Z: Dcmtk2Shell (CVE-2026-133168 / GHSA-vhjh-fq99-4gmr) — not admitted under #6

Frontier handed this find over with commit `73a8704` (brief
`reports/frontier-dcmtk2shell.md`, verbatim-pin harness
`lab/frontier/dcmtk2shell/`). Claim sources: the GHSA, CVE record and VulnCheck
advisory (CNA VulnCheck, published 2026-11-19), CWE-787, CVSS 4.0 8.5 High
`AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, plus fix commit
`c22836c449bb81834fee5d883e9ebd9d7dab90b9` ("Fixed stride calculation when
changing planar config."), issue #1298 and raw `djcodece.cc` read verbatim at
tag `DCMTK-3.7.1` and at the fix commit (hashes/URLs in PROVENANCE.md).
Claimed primitive: a crafted color-by-plane image with rows > columns makes
`togglePlanarConfiguration8()` use `rows` as the row stride instead of
`columns`, so past-end writes of the attacker's own pixel bytes cross a buffer
sized from the declared PixelData length.

All five #6 evidence elements are present. The operator replayed the committed
harness from a clean `git archive HEAD` extraction at ~10:06Z: 8 PASS / 0 FAIL,
`ALL CHECKS PASS rc 0`, five-run trace
`sha256=03eb9e16ef2f16d64b4ef0d1b1f77f6549f885752debe15a050f5810fc970649`,
matching the brief and PROVENANCE. Rungs 1/2/3 are source-bound (real ASan
`heap-buffer-overflow`, `WRITE of size 1` at pinned
`djcodece_v3.7.1.cc:1525`); rung 4 is INSTRUMENTED chosen-value control with
`0x5a`/`0xa5` at `px8+119697`/`+119698`, benign-zero and guard-page negatives,
and the fixed-function controls are clean. The defect is tractable and the
corruption bytes are attacker-chosen.

Decision: **held, not admitted** under standing approval #6. The class-defining
premise fails: DCMTK is a C++ DICOM toolkit, not a language runtime or a
web-facing server, and the advisory itself rates **AV:L / UI:P** — local attack
vector with passive user interaction, the opposite of the pre-auth network
reachability that distinguishes every admitted non-runtime extension
(Bzfs2Shell, Kamailio2Shell, Iperf2Shell and the rest). No live DCMTK process,
DICOM storage service, network trigger or stock allocator neighbour was
exercised; the brief records reachability as UNKNOWN and untested and calls
this the weakest scope fit of the recent finds. The held Airlock2Shell and
Dnsmasq2Shell lanes were declined partly on reachability gates (non-default
config, AC:H, PR:L); Gdbserver2Shell was declined then for missing pinned
upstream bytes and admitted on 2026-11-23 (below), so it is no longer a
precedent for a held lane. An AV:L library with no demonstrated
path is weaker still. No charter, status file, docs admission, engine route,
wake unit or presentation entry is created and no person action is owed.
Frontier's two-pane `dcmtk2shell` window (inner socket, index 45), registry
entry (already `admitted: UNADMITTED`) and seed wall stay a frontier research
artifact, as with the held dnsmasq window.

Revisit trigger: a live loopback DICOM C-STORE service or a stock 3.7.1
`DJCodecEncoder` path reached with the crafted rows>columns color-by-plane
image, producing a symbolized ASan OOB write at the real
`togglePlanarConfiguration8` frame with chosen bytes at chosen offsets on the
network-reachable path. A measured blocker showing no network-reachable path
(the AV:L vector confirmed local-only) is a valid negative to preserve, not a
reason to replay the same extracted harness.

#### Admitted 2026-11-21 ~10:0xZ: Kermit2Shell (CVE-2026-129126 / GHSA-c5px-7h4c-gj8p)

Frontier handed this find over on tape #758 after committing `96c03bb`
(brief and harness), `ddbcb5e` (ASan PID normalization), `59cfe1f` (replay
hash) and `782fb64` (docs index). Claim sources: CVE record
`CVE-2026-129126` (CNA VulnCheck, published 2026-11-13, updated
2026-11-16, CVSS 4.0 9.2, CWE-122, pin `6c43f2b7…`) and GitHub Advisory
`GHSA-c5px-7h4c-gj8p` (pin `96477695…`). Affected: C-Kermit before
v11.1.515; pinned vulnerable tag `v11.0.514`, fixed tag `v11.1.515`, fix
commit `37e54720779237897bc6887efac42fe138817897` (pin `2f25c8d7…`) adding
the `srvptr - srvcmd >= srvcmdlen` guard in `putsrv()`. All pins and URLs
are in `lab/frontier/kermit2shell/PROVENANCE.md`.

Claimed primitive: Kermit repeat-count compression in `decode()` feeds
`putsrv()` more characters than `srvcmd` holds, writing attacker-chosen
bytes past the heap buffer in a pre-auth network-facing server or receiver.
Pinned bytes: unbounded `*srvptr++ = c` and `*srvptr = '\0'` at
`ckcfns.c.vuln:461-462`, `MAXRP 9024` (`ckcker.h.vuln:366`) and
`srvcmdbuf[MAXRP+4]` (`ckcmai.c.vuln:1003`). Verbatim pinned ranges under
`#line` in a synthetic frame give 9212 decoded characters into an exact
9025-byte buffer: ASan `WRITE of size 1` at `pins/ckcfns.c.vuln:461`, 0
bytes after the region; exactly 9024 is clean and 9118 faults; fixed build
returns `decode_rc=-1 first_reject=9024 oob=0`. Rung 4 INSTRUMENTED only:
chosen `0x5a`/`0x41` read back at offsets 9024–9151 (128 bytes) in a 1 MiB
zeroed collaborator, benign decode writes zeros, guard page faults; bytes
9152–9211 are inferred from `emitted=9212`, not observed (witness nit).
No pointer, control-flow or execution claim.

Admitted by the operator ~10:0xZ under standing approval #6: operator
replay from two clean `git archive HEAD lab/frontier/kermit2shell`
extractions at `782fb64` into separate absolute directories: 18 PASS /
0 FAIL both, normalized trace
`sha256=f74a088605aba49a48108705fafe151d61d283c04e248836a81f6ca8e4978cc5`
byte-identical between directories, to the working tree, brief and
PROVENANCE. Handoff #758 quoted `0de1067b…`, the pre-normalization value
superseded by `59cfe1f`, not a contradiction. Witness #763 (09:52Z) had
already independently replayed `96c03bb`: rungs 1/2/3 ESTABLISHED and rung 4
ESTABLISHED AS CLAIMED at INSTRUMENTED; no replay owed. Two grade-unaffected
nits are preserved in `reports/kermit2shell-status.md`: the generic repeat
branch is `ckcfns.c.vuln:1479`/`:1486`, not the putfil-only `:1420`, and the
observed readback is 128 bytes, not 188. Window 44 and its registry entry
were pre-created by frontier; the charter, the per-admission
`engine/routes.json` entry and the wake trigger units were completed by the
operator at ~11:38Z with the pinned full-flag sync (45-role doctor GREEN rc
0), never a bare `mishe sync`.

Caveats recorded at admission: no built `wermit`, no live server; real
packet-length limits, `xunchar()` constraints, DYNAMIC vs static `srvcmd`
allocation and live-daemon reachability are UNKNOWN. Admission rests on the
five #6 elements (pinned claim, affected/fixed pins, attacker-controlled
heap write, rung-4 plausibility, byte-controlled corruption); it does not
lower the bar for future targets. Cheapest next rung: build `v11.0.514`
`wermit` with ASan, start a loopback server, send a repeat-compressed
server-command packet with `set send packet-length 4000`, capture the
daemon ASan frame at `putsrv`, then repeat at `v11.1.515`. A measured
packet, decoder or allocator blocker is a valid negative to preserve.
Evidence: `reports/frontier-kermit2shell.md`,
`reports/kermit2shell-status.md` and the pins in
`lab/frontier/kermit2shell/PROVENANCE.md`.

#### Admitted 2026-11-21 ~10:29Z: GpfD2Shell / gpfdist2shell (CVE-2026-122042, no GHSA found)

Frontier handed this find over in `reports/frontier-gpfdist2shell.md`
(commit `a7d5884`, now pushed). All five standing-approval #6 elements are
present: **claim source** — EDB security advisory (first published
2026-11-18), NVD CVE record, WarehousePG PRs #370/#371 and both fix diffs,
with URLs and SHA-256 pins in `lab/frontier/gpfdist2shell/PROVENANCE.md`;
**identifier** — CVE-2026-122042, no GHSA found; **affected/fixed versions**
— WarehousePG 6.27.1–6.27.7 and 7.2.1–7.6.1, fixed 6.27.8 / 7.6.2, fix
`6fbb42ed6480bf3534c0a49e5f251dff468e8469` (2026-10-30); **primitive** —
`X-GP-SEGMENT-COUNT` sizes and `X-GP-SEGMENT-ID` indexes the same two arrays
with no check, so a single unauthenticated HTTP request writes a chosen
4-byte `active_segids` value and a chosen 64-bit `X-GP-SEQ` value at a chosen
index; pinned writes at `gpfdist_v7.6.1.c:1988` and `:3677`; **rung-4
plausibility** — gpfdist is an HTTP file server, unauthenticated by default
(`PR:N`, internal-network deployment is a constraint, not an auth control),
and the vector advisory rates `AV:A/AC:L/PR:N/UI:N/VA:H` with availability
impact only. This is a closer runtime/web-server class fit than the held
DCMTK toolkit.

Operator replay at 10:28Z from a clean `git archive HEAD` extraction of
`a7d5884` into `/tmp/gpf-verify.*`: 13 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`,
chosen `0x41` bytes read back at `seq+24`, guard-page fault, 7.6.2 guards
reject the same request, two independent five-run groups both
`sha256=4f8bf8b7c6de06df7ce370b3570babe8df25112b9d2380c9836852864a8048c4`.
Rungs 1/2/3 ESTABLISHED in the verbatim-pin extracted harness; rung 4 is
INSTRUMENTED chosen bytes at chosen offsets in an mmap collaborator only.
No stock build, live listener, real APR pool neighbour, pointer overwrite,
control-flow diversion or execution was observed — all UNKNOWN, no claim.

Admitted under the standing similar-things mandate; no re-ask. The
two-pane `gpfdist2shell` window and registry entry were pre-created by
frontier; the charter, the per-admission `engine/routes.json` entry and the
wake trigger units were completed by the operator at ~11:38Z with the pinned
full-flag sync in `docs/runtime-pin.md` (45-role doctor GREEN rc 0), never a
bare `mishe sync`. Cheapest next rung: build the pinned 7.6.1 `gpfdist` with
ASan, start a loopback listener and send the hostile header trio to reach the
real `session_attach()` / `OPEN_SEQ` stores, then repeat at 7.6.2. A measured
header-length, APR or allocator blocker is a valid negative to preserve.

**Witness verdict #865 (2026-11-21 ~12:12Z; W66): ESTABLISHED AS CLAIMED, no
grade change.** W65 had already accepted the live OOB-store limb (tape #859).
W66 independently rebuilt both ASan binaries from a clean `git archive HEAD`
of `6badf48` (helper provisioned from the raw 7.6.1-WHPG tag, all three pins
byte-identical to fresh raw-GitHub fetches) and replayed both pointer limbs on
127.0.0.1: segid 28 overwrote `requests[0]` with `0x1` in two byte-identical
runs, and the path-length-matched chosen-value run wrote a header-supplied
`old+1` value `0x7ffff76de029` byte-for-byte (`X-GP-SEQ` HTTP 200, ASan clean);
the clean-built 7.6.2 returned `400 bad request, invalid segment id or count`
and the layout-shift negative reproduced. One strengthening observation, not
a contradiction: the `:3502` guard re-evaluates per request, so W66 walked the
pointer `0x…28 → 29 → 2a → 2b → 2c → 2d`, each value first read from the
`:3520` oracle, all HTTP 200 and ASan clean — a target at or above the current
value is reachable in N requests, an arbitrary single write or a decrement is
not. Non-load-bearing NITs (probe-script binary-name mismatch, a `:3517`
WIN32-branch cite, an ambiguous gdb `offset` label) are corrected in the
scoped report/lab edits; no grade change and no witness replay owed.

#### Admitted 2026-11-21 ~10:4xZ: Gct2Shell / gct2shell (CVE-2026-123975)

Frontier handed this find over in `reports/frontier-gct2shell.md` (commit
`49ffba6`, pushed). All five standing-approval #6 elements are present:
**claim source** — CVE Program record `CVE-2026-123975` (CNA VulnCheck,
published 2026-11-13), the vendor advisory at `gridcf.org`, the upstream fix
commit `3df2be4834c146bdcec90009a0f2e5771ff63cca` and the 6.2.20261111
release notes, with URLs and SHA-256 pins in
`lab/frontier/gct2shell/PROVENANCE.md`; **identifier** — CVE-2026-123975;
**affected/fixed versions** — GCT before 6.2.20261111 /
`globus-gss-assist` before 12.9, fixed 12.9 / 6.2.20261111, fix guard at
`tokens_f.c:127-131`; **primitive** — an SSLv2 backward-compatible hello
with record length 1 makes `dsize = -2` and `size = dsize + 5 = 3`, so the
fixed 5-byte `memcpy` at `tokens_f.c:172` overruns the 3-byte token buffer
and `fread(pp, 1, dsize, fd)` casts negative `dsize` to `size_t`, writing the
attacker's body bytes past it; **rung-4 plausibility** — the CVE record
`AV:N/AC:L/AT:N/PR:N/UI:N/VA:H` names `globus-gatekeeper` and `myproxy` as
pre-auth consumers, and a loopback build of the vulnerable helper is inside
standing provisioning approval #5.

Operator replay ~10:46Z from a clean `git archive HEAD` extraction of
`49ffba6` into `/tmp/gct-verify.*`: 10 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`,
chosen `0x5a5b5c5d` at `cp+5`, guard-page fault on the first past-end store,
fixed rejects the hostile length and is ASan-clean, two independent five-run
groups both
`sha256=e5ca3f256b9fd58bd493ad841286819c2dd8f731874424ab26f3b287af5c6204`.
All ten pinned source and digest entries in `PROVENANCE.md` matched the
committed bytes; an independent web search confirmed the CVE record and the
fix commit. Rungs 1/2/3 ESTABLISHED in the verbatim-pin extracted harness;
rung 4 is INSTRUMENTED chosen-byte control in an mmap collaborator only. No
live GSI handshake, gatekeeper/myproxy build, stock allocator neighbour,
pointer overwrite or execution was observed — all UNKNOWN, no claim.

Admitted under the standing similar-things mandate; no re-ask. The two-pane
`gct2shell` window (index 47, inner socket) was pre-created by frontier and
is already registered UNADMITTED. The operator created this mind's charter
and ran the pinned full-flag sync from `docs/runtime-pin.md` at ~10:58Z to
mint its wake trigger units (6 units written; both `.path` units active;
doctor GREEN with `--prefix m2shell`). Never run a bare `mishe sync`.
Cheapest next rung: build vulnerable `globus-gss-assist` 12.8
with ASan, call `globus_gss_assist_token_get_fd()` with a local hostile
record, capture the symbolised frame, then measure live glibc neighbours
before any pointer or marker claim, repeating with 12.9 as control. A
measured handshake, allocator or reachability blocker is a valid negative
to preserve.

#### Admitted 2026-11-21 ~10:5xZ: Imgproxy2Shell / imgproxy2shell (CVE-2026-123614 / GHSA-hff9-5pqw-6w9f)

Frontier handed this find over in `reports/frontier-imgproxy2shell.md`
(commits `2366ef4`, `01bbfaa`). All five standing-approval #6 elements are
present: **claim source** — CVE Program record `CVE-2026-123614` (CNA
VulnCheck, published 2026-11-08), GitHub advisory GHSA-hff9-5pqw-6w9f, fix
commit `a821b6a4cb07a1bf2bb9077431d1c1e734d79917` and raw source at tags
`v4.0.15`/`v4.0.16`, with URLs and SHA-256 pins in
`lab/frontier/imgproxy2shell/PROVENANCE.md`; **identifier** —
CVE-2026-123614 / GHSA-hff9-5pqw-6w9f; **affected/fixed versions** —
`pkg:golang/github.com/imgproxy/imgproxy/v4` from 4.0.0 before 4.0.16,
fixed 4.0.16; **primitive** — `uint32_t data_size` from the ICO directory
entry wraps in `VIPS_MALLOC(NULL, data_size + BMP_FILE_HEADER_LEN)` at
`icoload.c:158` (`0xfffffff5` + 14 → 3) while `actual_data = data + 14`
at `:159` and `vips_foreign_load_read_full()` at `:161` writes the
attacker's body bytes 11 bytes past the 3-byte allocation; **rung-4
plausibility** — imgproxy is an HTTP image service and the crafted ICO is
submitted on its normal unauthenticated request path, with CVSS 4.0 9.3
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`; loopback build and request are
inside standing provisioning approval #5. The CVE prose claims crash or
code execution; no execution is claimed by this lab.

Operator replay ~10:53Z from a clean `git archive HEAD` extraction:
10 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`, chosen `0x5a5b5c5d` bytes read
back at `data+14`, `PROT_NONE` guard fault on the first past-end store,
fixed rejects the wrapped size and is ASan-clean on hostile and benign
inputs, two independent five-run groups both
`sha256=6b0391599520bc899f169268e08699155888f0018274f9c2a2e12bcd31c2dad5`.
All nine pinned digests in `PROVENANCE.md` matched the committed bytes and
an independent web search confirmed the CVE record, GHSA and fix commit.
Rungs 1/2/3 ESTABLISHED in the verbatim-pin extracted harness; rung 4 is
INSTRUMENTED chosen-byte control at a chosen offset in an mmap
collaborator only. No live imgproxy HTTP server, libvips runtime, real
uploaded ICO, stock allocator neighbour, pointer overwrite, control-flow
diversion or execution was observed — all UNKNOWN, no claim.

Admitted under the standing similar-things mandate; no re-ask. The
two-pane `imgproxy2shell` window (index 48, inner socket) was pre-created
by frontier and is already registered UNADMITTED; do not recreate or edit
the registry. The operator created this mind's charter and ran the pinned
full-flag sync from `docs/runtime-pin.md` at ~10:58Z to mint its wake
trigger units (6 units written; both `.path` units active; doctor GREEN
with `--prefix m2shell`). Never run a bare `mishe sync`.
Cheapest next rung: build pinned v4.0.15 imgproxy with ASan,
serve a 23-byte crafted ICO through its normal HTTP URL endpoint on
loopback, capture the symbolised ASan frame at the real
`vips_foreign_load_ico_header` / `read_full` path, and measure the live
libvips/glibc neighbours of the 3-byte buffer before any pointer or marker
claim; repeat at 4.0.16. A measured endpoint, libvips or allocator blocker
is a valid negative to preserve.
#### Admitted 2026-11-21 ~11:1xZ: Firebird2Shell / firebird2shell (CVE-2026-33337 / GHSA-89mq-229g-x47p)

Frontier handed this find over in `reports/frontier-firebird2shell.md`
(commits `dd2610f`, `4592fbf`). All five standing-approval #6 elements are
present: **claim source** — CVE Program record `CVE-2026-33337` (CNA
`GitHub_M`, published 2026-04-17T18:48:47.953Z), GitHub advisory
GHSA-89mq-229g-x47p, master fix `2a5303dc9fb2cfc035a6aeb6274377d0e2dd3488`
and the v5.0.4-branch fix `62fc37eda82fa1f8120aff7fb0fdd7c72b493a75`, plus
raw `src/common/xdr.cpp` at `v5.0.3`/`v5.0.4`, `src/remote/protocol.cpp` and
`src/common/dsc.h` at `v5.0.3`, with URLs, SHA-256 pins and git blob IDs in
`lab/frontier/firebird2shell/PROVENANCE.md`; **identifier** —
CVE-2026-33337 / GHSA-89mq-229g-x47p (CWE-120 / CWE-502);
**affected/fixed versions** — Firebird `>= 3.0.0, < 3.0.14`,
`>= 4.0.0, < 4.0.7`, `>= 5.0.0, < 5.0.4`; fixed in 3.0.14 / 4.0.7 / 5.0.4,
with the harness pinning the 5.0 line (v5.0.3 affected, v5.0.4 fixed);
**primitive** — on `XDR_DECODE`, `xdr.cpp:214` reads a wire-supplied `USHORT n`
that `:216` passes unbounded to `xdr_opaque(xdrs, p, n)`, whose GETBYTES
`memcpy` writes `n` bytes into a `dsc_length`-sized slot, followed by
`p[n] = 0` at `:219`; pinned `protocol.cpp:1813/:1835/:1884-1889` shows each
`p` is such a slot inside a wire-sized `UCHAR[lstr_length]` allocation.
Fixed `v5.0.4:216` inserts `n = MIN(n, desc->dsc_length - 1);`, exactly the
two-line fix in both pinned patches; **rung-4 plausibility** — an
unauthenticated crafted slice packet to TCP/3050, CVSS 3.1 **7.5 High**
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (availability only; the CVE's "other
security impact" is a claim, not a lab observation).

Operator replay ~11:08Z from a clean `git archive HEAD` at `4592fbf`:
10 PASS / 0 FAIL, `ALL CHECKS PASS rc 0`, wire length 60000 unclamped
(`copy_len=60000`), chosen `0x5a5b5c5d…` read back byte-exact at `buffer+40`
and `buffer+100`, `PROT_NONE` guard fault on the first past-end store,
ASan `WRITE of size 60000` at pinned `xdr_v5.0.3:216`, fixed v5.0.4 clamped
to 31 and ASan-clean on hostile and benign inputs, two independent five-run
groups both
`sha256=807b47150a58fe88094966b0affed9b35604a7b3730c68f53eeaa61057a25fbf`.
All eight source pins and both harness-tool digests in `PROVENANCE.md`
matched the committed bytes, the pinned v5.0.3→v5.0.4 diff is exactly the
fix, and an independent web search confirmed the CVE record, GHSA and fixed
release. Rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4 is
INSTRUMENTED chosen-byte control at chosen offsets in a 1 MiB collaborator
only. No live `fbserver`, wire packet, allocator neighbour, pointer
overwrite, control-flow diversion or execution was observed — all UNKNOWN.

Admitted under the standing similar-things mandate, no re-ask. The
two-pane `firebird2shell` window (index 49, inner socket) and registry entry
were pre-created by frontier and are already live; do not recreate or edit
them. The operator created this mind's charter, added its per-admission
`engine/routes.json` entry and ran the pinned full-flag sync from
`docs/runtime-pin.md` at ~11:1xZ to mint its wake trigger units; never run a
bare `mishe sync`. Cheapest next rung: build pinned v5.0.3 `fbserver` with
ASan on loopback, send the advisory's crafted slice packet to a locally
started TCP/3050 listener, capture a symbolised ASan report at the real
`xdr_datum` / `xdr_opaque` frame, then measure the actual Firebird pool and
wire-buffer neighbours of the 32-byte slot before any pointer or marker
claim; repeat at 5.0.4. A measured listener, auth-gate, allocator or reachability
blocker is a valid negative to preserve.


#### Held 2026-11-21 ~09:47Z: Airlock2Shell (CVE-2026-19707 / GHSA-3c49-2p63-245g) — not admitted under #6

Operator advisory watch; no handoff and no lab work. Claim sources: InfoGuard
Labs advisory 2026-11-18, the MITRE CVE record (Airlock CNA, published
2026-11-18), GHSA-3c49-2p63-245g and the vendor 8.5.3 changelog entry `FIX:
AP-38633 Fix buffer overflow when decoding HTML entities`. Affected: 8.5.0
through 8.5.2 and 8.6.0; fixed: 8.5.3 and 8.6.1 (semver pins). Claimed
primitive: `&nGt;` and `&nLt;` are 5-byte HTML references whose UTF-8
replacements are 6 bytes; the decoder sizes its output buffer from the input
length and copies each replacement with no destination bound, so each
occurrence writes one attacker-chosen byte past the end. The advisory claims
RCE by grooming the allocation before an `SG3_FormProtection` object and
overwriting its vtable, then leaking code pointers through `_xprot`; that is
a claim, not a lab observation.

Decision: **held, not admitted** under standing approval #6. The
rung-4-plausibility element fails in this lab: GHSA says "No known source
code", lists no package and unknown affected/patched versions; the vendor
distributes signed appliance images behind Techzone; and the advisory's
`memcpy` fragment is not a pinned source-byte range. A decoder model would be
an invented struct like the originally held Gdbserver lane, which was reopened
with hash-pinned upstream bytes and a derived fixed snapshot before its
2026-11-23 admission, not a source-bound affected/fixed pair here.
Reachability is also gated by non-default URL encryption
plus Form Protection and Smart Form Value Protection, and by attacker control
of backend HTML served as `text/html`: no login at the gateway, but not a
default-configuration pre-auth trigger. No charter, wall, window, engine
route, wake unit or harness was created; no person action is owed.

Revisit trigger: vendor-released source or patch bytes for the 8.5.2 ->
8.5.3 decoder change (AP-38633), or a public write-up pinning exact
vulnerable and fixed source ranges, together with a local build reproducing
the one-byte-per-entity overflow at the real decoder frame and a
source-bound victim object. A version pin without source bytes does not
reopen admission.

#### Held 2026-11-21 ~05:54Z: Dnsmasq2Shell (CVE-2026-12725 / GHSA-hv63-qc47-8j8h) — not admitted under #6

Frontier handed this find over on tape #594 after committing `25ca75d`
(brief `reports/frontier-dnsmasq2shell.md`, seed wall and window already
live; final brief text landed in shared HEAD `4882d5d` when a concurrent
apache2shell commit collected the staged edit, harness bytes unchanged).
Claim sources: Ubuntu's CVE record, Red Hat BZ 2490763, the GHSA and the
upstream fix patch `36d081e37477027fd721fea498f3760f529034ad`. Ubuntu rates
Medium 5.9 `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` (availability
only). Claimed primitive: with DNSSEC validation and query logging both
enabled, `log_query()` writes a DS/DNSKEY description into the 46-byte
`daemon->addrbuff` with `sprintf` at pinned `cache.c:2291`; keytag 65535 /
algorithm 255 / digest 255 yields 58 bytes including NUL, 12 bytes past the
buffer.

Frontier's harness reaches rungs 1/2/3 on verbatim pinned
`cache.c:2266-2291` from tag `v2.92` and the `dnssec.c:1100` caller: ASan
`heap-buffer-overflow`, `WRITE of size 58`, neighbour byte changed, 22 PASS /
rc 0 twice from a clean `git archive` extraction with trace
`sha256=2673af32ec5fb1de34bf7774184551cd727e18abd00b80b733122d232c630e42`
byte-identical. Rung 4 is INSTRUMENTED only: the overflow bytes are the
caller's fixed literal `" (not supported)"` tail (`20 73 75 70` at offsets
46-49), not attacker-chosen; no pointer control and no execution. The brief
stamps its observation "~05:55Z" although its file mtime is 05:50:15Z and
the handoff tape is 05:51:11Z; that timestamp stays UNKNOWN.

Decision: **held, not admitted** under standing approval #6. That approval
requires "affected/fixed versions" and "rung-4 plausibility"; both fail
here. GHSA lists no package and unknown versions, there is no upstream fixed
release tag, and the fix commit's first parent is unreachable in the mirror
("fixed in 2.92rel2" is a distro backport fact). The overflow bytes are a
caller literal, so this primitive offers no chosen-byte, pointer-control or
marker path. Reachability also needs AC:H plus DNSSEC validation and query
logging plus a malicious upstream reply; the maintainer calls RCE unlikely.
No charter, status file, docs admission entry, engine route or wake unit is
created, and none is requested from the person. Frontier's two-pane
`dnsmasq2shell` window (inner socket, index 33), registry entry and seed
wall remain a frontier research artifact, not a declared target; no wake
unit or presentation entry is owed.

Revisit trigger: a fixed-release pin or reachable fix parent, plus evidence
of attacker-controlled overflow bytes or a live `dnsmasq` process showing
control at the real `cache.c:2291` frame. Witness replay #593 verifies the
finding, not the admission.

#### Held 2026-11-21 ~01:12Z: Gdbserver2Shell (CVE-2026-121997 / GHSA-jq36-9pw3-8r4v) — SUPERSEDED 2026-11-23, admitted as the 94th route below

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

Decision at the time: **held, not admitted** under standing approval #6. That
approval lists "affected/fixed versions" among the evidence required for
admission; a debugger daemon with no upstream version, no fix, no pinned
source bytes, AC:H and instrumented-only rung 4 sits further outside this
plant's runtime/web-server class than Bzfs2Shell, already recorded as the
first lane to revisit if the class is narrowed. At that time no charter,
status file, docs/README admission entry or engine route was created, and
none was requested from the person for this candidate. Frontier's two-pane
window 23, registry entry (status file still the brief) and seed wall stayed
a **frontier dashboard, not a declared target**, with no wake unit or
presentation entry owed. On 2026-11-23 a pinned-HEAD reopen and clean-replay
superseded this decision: the lane is now the 94th route with a charter,
status file, README row, window 99 and wake units (admission below).

Revisit trigger at the time: a reachable mirror supplies pinned vulnerable
upstream bytes and a fixed version/commit, the real `gdbserver/tracepoint.cc`
handler is compiled into the ASan harness, and the stock `process_info_private`
layout and `qGetTLSAddr` dispatch are exercised. The pinned-bytes part was met
on 2026-11-23 with a derived fixed snapshot (no upstream fixed release); the
layout and dispatch parts remain untested. The candidate is now an admitted
mind, not an examined candidate.

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
Adjacent lane L5 (CVE-2026-56449, a mod_proxy_html `dump_content` OOB write
with crafted HTTP response bodies) is a fifth same-subsystem lane, not a
reopen of CVE-2026-119618. `2.4.70/CHANGES:144-149` gives the affected range
2.4.0-2.4.68; the whole 2.4.68→2.4.69 fix in
`modules/filters/mod_proxy_html.c` is removal of one `dump_content(ctx)`
call from `pcomment()` (2.4.68 line 312). `lab/apache2shell/build-l5.sh`
builds ASan/UBSan httpd 2.4.68 and 2.4.69 with `--enable-proxy-html` against
host libxml2 2.9.14. `pstartElement` leaves the last attribute value in
`ctx->vb.buf` while resetting only `ctx->vb.strlen = 0` (line 617); with
`ProxyHTMLExtended Off` a following HTML comment reaches `pcomment`, whose
`dump_content` string-literal branch computes `len + 1 - s_from - match =
0 + 1 - 4 - 0 = -3` as `size_t` and passes it to `memmove` at line 272. The
`c` map flag is an exclude flag (clears M_CDATA), so a `c`-flagged rule is a
clean negative control. In the canonical loopback reverse-proxy mode the
body `<p title="AAAAAAAAAA">x</p><!--trigger-->` gives 2.4.68 4/4 child
SIGSEGV with four ASan `negative-size-param: (size=-3)` reports at line 272
via `pcomment:312` → `htmlParseChunk` → `proxy_html_filter:982`, against
2.4.69 0/4 and none; extended mode, a `c`-flagged map and an attribute-free
body are 0/3 each. Applying the 2.4.69 one-line fix to 2.4.68 and rebuilding
only `mod_proxy_html.so` gives 0/6 reports, and byte-for-byte restoration
restores 6/6. Grade rung 3 (ASan-confirmed invalid write) with a rung-2
crash on the genuine proxy path; the underflow magnitude follows the stale
string's offset (`L5_ATTR=XXAAAAAAAAAA` gives `size=-5`) but stays negative,
ASan aborts before the write and source and target share the varbuf, so no
chosen bytes at a meaningful offset, no pointer control and no marker.
L5 is closed at rung 3; the main lane's Stage A closure and do-not-retry
list are unchanged. Reproduce from `lab/apache2shell/`:
`./build-l5.sh`, then
`ASAN_OPTIONS=detect_leaks=0 L5_PROXY=yes L5_N=4 L5_SUFFIX=proxy ./l5-lane.py 2.4.68 2.4.69`,
the `L5_EXT` / `L5_FLAGS=c` controls and `./l5-gdb.py`. Raw logs are
gitignored under `lab/apache2shell/logs/`.

Adjacent lane L6 (CVE-2026-56153, a `mod_charset_lite` `finish_partial_char`
heap overflow) is a sixth same-subsystem lane, not a reopen of
CVE-2026-119618. `2.4.70/CHANGES:158-163` lists an out-of-bounds write
affecting 2.4.0-2.4.68; the whole 2.4.68→2.4.69 fix is a five-line guard at
the top of the `finish_partial_char` loop (2.4.69 lines 448-452): when
`ctx->saved >= sizeof(ctx->buf)` it sets `EES_LIMIT`, returns
`APR_INCOMPLETE` and breaks, while 2.4.68 line 448 writes
`ctx->buf[ctx->saved] = **cur_str;` unbounded into a `char[8]` (`FATTEST_CHAR`)
embedded in the heap-allocated `charset_filter_ctx_t`. `build-l6.sh` builds
2.4.68 (affected) and 2.4.69 (control) with ASan/UBSan, event MPM and
`--enable-charset-lite`; no earlier lane built this module. `l6-lane.py` sets
`CharsetSourceEnc UTF-8` / `CharsetDefault ISO-2022-JP` on a loopback docroot
with a body-reading CGI and sends a chunked POST (chunk 1 `A` + ESC, chunk 2
32 ESC bytes) so the saved ESC makes `finish_partial_char()` append past the
8-byte buffer. An APR-level enumeration found ESC (`0x1b`) is the only
single-byte partial and the only appended byte that keeps `APR_INCOMPLETE`
past index 8, so the written byte is fixed. The canonical four-request replay
gives 2.4.68 3/4 UBSan `mod_charset_lite.c:448:17: runtime error: index 8 out
of bounds for type 'char [8]'` against 2.4.69 0/4; the `AddressSanitizer`
lines are exit-time LeakSanitizer noise because the write lands in adjacent
struct fields (`ran`, `noop`, `tmp`) inside the larger `apr_pcalloc` context.
No-charset, same-charset and `A`-chunk controls are clean; applying the exact
2.4.69 guard to 2.4.68 and rebuilding only `mod_charset_lite.so` gives 0/4
reports and byte-for-byte restoration gives 2/4. A 64-byte ESC run gives 4/4
UBSan reports and 4/4 child `SIGSEGV (11)` on a corrupted context pointer.
Grade rung 3 confirmed: no chosen byte, chosen offset, pointer control or
benign marker; L6 closes there with the main lane's closure, negative list
and do-not-retry conditions unchanged. Reproduce from `lab/apache2shell/`:
`bash build-l6.sh`, then `python3 l6-lane.py 2.4.68 2.4.69`; controls are
`L6_NOCHARSET=1`, `L6_SAMECHARSET=1` and
`L6_SUFFIX=long L6_NEXT_HEX=$(python3 -c "print('1b'*64)")`. Raw logs are
gitignored under `lab/apache2shell/logs/`.

Adjacent lane L7 (CVE-2026-42535, `mod_dav_fs` state-directory access) is a
seventh same-subsystem lane and a rung-2 access-control differential only.
The lane's earlier CVE-2026-93546 premise was false: that identifier is absent
from the available trees. The real mod_dav_fs entry is `CVE-2026-42535` at
`httpd-2.4.69/CHANGES:123-131`, affecting 2.4.67 and earlier and fixed in
2.4.68 by denying `.DAV` state-dir resources in `dav_fs_get_resource()`
(`modules/dav/fs/repos.c`). `l7-lane.py` drives the already-built ASan httpd
2.4.67 and 2.4.68 over loopback: PUT 201 and PROPPATCH 207 on both, but the
state-dir PROPFIND returns 207 on 2.4.67 (the property DB is addressable) and
403 on 2.4.68; swapping the 2.4.68 `repos.c` into 2.4.67 flips it to 403 and
restoring the original source and module bytes restores 207. A full 12288-byte
`A` overwrite of the DBM file caused no crash, ASan or UBSan report — the
advisory's child-crash wording was not reproduced. No chosen byte, offset,
pointer, memory corruption or deterministic fault: rung 2 only, rung 4
unreachable for this bug class. Reproduce with
`cd lab/apache2shell && python3 l7-lane.py 2.4.67 2.4.68`. The main lane is
unchanged.

Adjacent lane L8 (CVE-2026-48913, `mod_http2` use-after-free on file-handle
exhaustion) is an eighth same-subsystem lane, graded rung 1/2: a
source-bound suspected UAF with a reachable deterministic trigger but no
confirmed corruption. `httpd-2.4.71/CHANGES` records the bug for 2.4.55–2.4.67
and the fix in 2.4.68. The 2.4.67 (mod_http2 2.0.39) → 2.4.68 (2.0.42)
`h2_mplx.c` diff moves the `h2_beam_on_send/on_received/on_consumed`
registrations on `stream->input` to after `apr_file_pipe_create_pools()`
succeeds; on EMFILE, `s_next_c2()` destroys `c2` through
`apr_pool_destroy(c2->pool)` while the stale callbacks still point at it.
`l8-lane.py` runs each ASan install on loopback with `RLIMIT_NOFILE=48`,
10 h2c connections and 80 POST-with-body streams each; both builds log
hundreds of `(24)Too many open files ... AH10309 ... error create input write
pipe` entries, but no pristine run produced an ASan use-after-free, double
free, chosen-byte write or deterministic child fault — only exit
LeakSanitizer noise and Apache's SIGSEGV handler masking pool-internal
faults. Three confirmation attempts are preserved as negatives, not upgrades:
freed-address tracking also hit the fixed build because APR recycles `c2`
addresses; a poison field first hit an ABI mismatch from a partial rebuild
and then reported zero hits; allocation-aware freed/live tracking made
`h2_beam_send`'s `beam->from == from` assertion abort children only as an
instrumentation timing artifact. All source and module bytes were restored
(SHA256 `624f0c32…` source, `e657da06…` module). No chosen bytes, pointer
control or rung-4 path; do not retry this trigger or those three variants.
Reproduce with `cd lab/apache2shell && L8_NOFILE=48 L8_CONNS=10 L8_STREAMS=80 L8_DATA_ROUNDS=3 python3 l8-lane.py 20`.

Adjacent lane L9 (mod_auth_digest shared client-entry / auth-state corruption)
is a ninth same-subsystem lane, graded rung 2: reproducible auth-state
corruption with no confirmed memory corruption. The dossier's CVE-2026-73637
is UNVERIFIED — 2.4.69's `CHANGES` records the change with no CVE number (drop
RFC 2069 support, rewrite shared-memory and client-nonce handling). In 2.4.68
`get_client()` returns an unlocked `client_entry*` into the APR RMM segment and
stores it as `resp->client`; a challenge failure resets `nonce_count` and
overwrites `last_nonce` while another child's `gc()` can free the same entry.
The 2.4.69 fix removes `resp->client` and re-looks the entry up under
`client_lock`. The committed `lab/apache2shell/l9-lane.py` oracle on loopback
ASan 2.4.68/2.4.69 with `AuthType Digest`, `AuthDigestNcCheck On`,
`AuthDigestNonceLifetime 0` gives 6/6 clean challenge→200 on both, but an
unauthenticated request quoting the victim's opaque drops the 2.4.68 victim to
0/6 (all 401) while 2.4.69 stays 6/6. A churn run (`L9_SHMEM=4096
L9_CHURN=4 L9_VICTIMS=4 python3 l9-lane.py 15`) produced 1523 gc events on
2.4.68 and no ASan report, child fault, chosen byte or failed victim —
4529/4529 and 6616/6616 victim requests returned 200. No confirmed UAF,
pointer control or rung-4 path; do not promote this to memory corruption.
Reproduce with `cd lab/apache2shell && L9_CHURN=0 L9_VICTIMS=0 python3 l9-lane.py 1`
(6/6 vs 0/6 oracle) and the report's reproduction block for the negative legs.

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

## Staged rung-5 plan (additive, only after a measured rung-4 primitive)

Rung 5 is never a relabel of a fault or an in-process marker. A mind opens
this stage only when a rung-4 result on the tested build leaves a credible
bounded path; the full acceptance contract is `docs/rce.md`.

1. **Wire path.** Prove the corrupted field is reached by attacker-controlled
   wire/request bytes in a live plant-started loopback target, not a harness or
   a debugger-forced call.
2. **Chosen command.** Make those bytes select a lab-benign proof command (a
   unique marker file under `lab/`, or a unique line printed by the target). A
   call to a pre-existing benign marker or a marker address alone stays rung 4.
3. **Observed side effect.** Check the marker directly and bind it to the
   triggering request, not to the client or a debugger action.
4. **Differentials.** Fixed target and safe input on the affected target both
   leave the marker absent; the vulnerable positive repeats.
5. **Exact conditions and witness.** Record pins, flags, config/auth gates,
   ASLR state, address provenance, grooming, debugger involvement and process
   survival, then require a fresh witness replay from a clean checkout that
   varies the command or an attacker byte. No R5 claim before that verdict;
   "attempt active, no R5 claim" is the honest status until then.

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

#### Admitted 2026-11-21 ~11:28Z: Rtp2httpd2Shell / rtp2httpd2shell (GHSA-35fv-hf3m-2pqc)

Frontier handed this find over in `reports/frontier-rtp2httpd2shell.md`
(commits `4cc20a6`, `bb00268`) and DM #829. All five standing-approval #6
elements are present: **claim source** — GitHub advisory GHSA-35fv-hf3m-2pqc
(publisher `stackia`, published 2026-06-27T08:33:58Z, updated
2026-06-27T17:59:44Z), pinned verbatim in `src/advisory353.json`, plus the
signed fix patch and raw `v3.14.1` / `v3.14.2` sources with URLs and SHA-256
digests in `lab/frontier/rtp2httpd2shell/PROVENANCE.md`; **identifier** —
GHSA-35fv-hf3m-2pqc (no CVE assigned); **affected/fixed versions** — rtp2httpd
`<= 3.14.1`, fixed in `3.14.2` by signed commit
`f0fcfc194631e13266cbcfcc1818dde24932978a` (GPG-verified ancestor of v3.14.2,
ahead 4 / behind 0); **primitive** — the wire 16-bit big-endian frame length
at `rtsp.c:1792` is bounded at `:1800` against the 4096-byte *source*
`response_buffer` (max 4092) instead of the 1536-byte destination pool slot,
so `memcpy` at `:1825` writes up to 2556 chosen bytes past the slot; the
fixed `v3.14.2:1801` bounds against `BUFFER_POOL_BUFFER_SIZE`; **rung-4
plausibility** — CVSS 3.1 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
CWE-122/131/787, unauthenticated remote reach claimed by the advisory and
worth testing live on loopback.

Operator verification before admission: all eight SHA-256 pins matched the
stored bytes; pinned `rtsp.c` lines were read directly (`:1800` wrong bound,
`:1825` unbounded `memcpy`, fixed `:1801` correct bound); an independent
replay of `bash lab/frontier/rtp2httpd2shell/run.sh` from committed HEAD
returned **10 PASS / 0 FAIL rc 0** with two five-run groups both
`sha256=11a76ab0bcb678868229982cb64a826f0367f29d8c4b3daf9eb84eb5804ceb13`;
an independent web search confirmed the advisory. Rungs 1/2/3 ESTABLISHED in
the extracted verbatim-pin harness; rung 4 INSTRUMENTED, chosen
`0x5a5b5c5d` bytes at slot+1600/+2400/+2500 and a guard-page rc 139 fault.
No live daemon, RTSP wire traffic, stock allocator neighbour, real
`buffer_ref_t` metadata, pointer control or execution was observed — those
stay UNKNOWN; the advisory's live ASan and neighbouring-slot overwrite are
claims to reproduce. A witness replay was requested on tape #828.

Admitted under the standing similar-things mandate, no re-ask. The two-pane
`rtp2httpd2shell` window (inner socket, index 50), seed wall and registry
entry were pre-created by frontier and are already live; do not recreate or
edit them. The operator created this mind's charter and added the 43rd
`engine/routes.json` entry, then ran the pinned full-flag sync from
`docs/runtime-pin.md` to mint its wake trigger units; never run a bare
`mishe sync`. Cheapest next rung: build pinned `v3.14.1` with ASan on
loopback, replay the advisory's verbatim pinned PoC with a local malicious
RTSP server and one HTTP request, capture a symbolised ASan frame at the
real `rtsp.c:1825`, then measure the stock pool's slot layout and neighbours
before any pointer or marker claim; repeat at `3.14.2`. A measured endpoint,
allocator or reachability blocker is a valid negative to preserve.

#### Admitted 2026-11-21 ~11:42Z: Zephyr2Shell / zephyr2shell (CVE-2026-82391 / GHSA-8jrg-wx88-g75j)

Frontier handed this find over in `reports/frontier-zephyr2shell.md` (commit
`0ccfdba`) and DM #840. All five standing-approval #6 elements are present:
**claim source** — CVE-2026-82391 / GHSA-8jrg-wx88-g75j (CNA Zephyr Project,
CVSS 3.1 9.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`, CWE-787), OSV record
pinned verbatim in `src/advisory82391.json` plus the fix patch and raw
`v4.4.0` / `v4.5.0` sources with all seven SHA-256 pins in
`lab/frontier/zephyr2shell/PROVENANCE.md`; the GitHub advisories API returned
404, so the advisory HTML and OSV/CVE records are the pinned sources;
**identifier** — CVE-2026-82391 / GHSA-8jrg-wx88-g75j; **affected/fixed
versions** — Zephyr `>=4.0.0 <4.3.2` and `>=4.4.0 <4.5.0`, fixed in 4.3.2 /
4.5.0 by commit `4e0a5f38b14dba5891fb558c49a526f9f6a3cc29` (PR #117267,
backports #117602/#117603); **primitive** — `http_server_http2.c:496`/`:499`
pass `&client->data_len` as the `file_size` out-param,
`http_server_core.c:892` overwrites it with the on-disk file size, and the
dispatch loop at `:557` feeds the corrupted residue to the verbatim `memmove`
at `:563-566`, writing attacker-influenced bytes past the 256-byte
`client->buffer`; fixed `v4.5.0:472/497/500/535` uses a local `size_t
file_size`; **rung-4 plausibility** — an unauthenticated HTTP/2 GET with
`CONFIG_HTTP_SERVER_VERSION_2=y` and a static-FS resource is network-reachable
at `PR:N`.

Operator verification before admission: all seven SHA-256 pins matched the
stored bytes; a clean `git archive 0ccfdba lab/frontier/zephyr2shell`
extraction into `/tmp/z2op-verify` replayed
`bash run.sh /tmp/z2op-out` with **10 PASS / 0 FAIL rc 0**, two independent
five-run groups both
`sha256=48568d4883dd3ca4125fc0dbb6371aa886fc3e9ed3d7362f778815cd3201f0e0`.
ASan `WRITE of size 1024` at the verbatim `core_v4.4.0:565`, chosen
`0x41424344`/`0x5a5b5c5d` patterns at offsets 300/500/900, a guard-page fault
and fixed/benign ASan-clean cases all reproduced. Rungs 1/2/3 ESTABLISHED in
the extracted harness; rung 4 INSTRUMENTED chosen bytes at chosen offsets in a
stand-in collaborator only. No Zephyr build, HTTP/2 wire traffic, RTOS socket,
real `struct http_client_ctx` layout, adjacent-object metadata, pointer
overwrite or execution was observed — all UNKNOWN. The advisory's `zsock_recv`
size_t-underflow limb (`core.c:697`) and live-ASan/control-data claims are
source-bound or claims to reproduce. Witness replay #839 was pending at
admission; author and operator replays are not independent acceptance. Its
verdict, #847, landed 11:44Z and is recorded below.

Admitted under the standing similar-things mandate, no re-ask. The two-pane
`zephyr2shell` window (inner socket, index 51), seed wall and registry entry
were pre-created by frontier and are already live; do not recreate or edit
them. The operator created this mind's charter, added the 46th
`engine/routes.json` entry and ran the pinned full-flag sync from
`docs/runtime-pin.md` (`written 3, removed 0`) to mint its wake trigger units;
never run a bare `mishe sync`. Doctor was GREEN rc 0 and omp-only rc 0 at 46
roles. Cheapest next rung: build pinned `v4.4.0` with ASan on loopback, serve a
file larger than the 256-byte client buffer, send an unauthenticated HTTP/2
GET with trailing peer-controlled bytes, capture a symbolised ASan frame at
the real `http_server_core.c:565`, then measure the live `client->buffer`
neighbours and peer control of `client->cursor` before any pointer or marker
claim; repeat at `4.3.2`/`4.5.0`. A measured endpoint, allocator or wire
blocker is a valid negative to preserve.

**Witness verdict #847 (2026-11-21 ~11:44Z): ESTABLISHED AS CLAIMED, grade
unchanged.** Independent replay from a clean `git archive` of 5e68ea6 (zephyr
files byte-identical to claimed 0ccfdba) into `/tmp/w64-zeph-archive`, output
`/tmp/w64-zeph-out`: `run.sh` 10 PASS / 0 FAIL rc 0 and both five-run groups
`sha256=48568d4883dd3ca4125fc0dbb6371aa886fc3e9ed3d7362f778815cd3201f0e0`.
All seven SHA-256 pins were hash-checked at generation (tamper probe rc 3
`PIN DRIFT`, drivers not rewritten); six matched a raw-GitHub re-fetch
byte-for-byte. The seventh, the OSV advisory JSON, was semantically identical
but not byte-stable because OSV re-serializes object key order — observed,
non-load-bearing, no correction demanded. `#line` blocks copied byte-exact
(15 lines/driver, 0 mismatches) and the mechanism is source-bound at every
cited line in `v4.4.0` and `v4.5.0`: ASan `WRITE of size 1024` at
`core_v4.4.0:565`, guard-page SIGSEGV rc 139 at the same frame, third-seed
`0xa7` readback byte-exact at offsets 300/500/900, fixed and benign ASan-clean.
Advisory identifiers, affected ranges, dates and the fix commit cross-check.
No contradiction of any pin, replay or the rung-4 label: rungs 1/2/3
ESTABLISHED in the harness and rung 4 ESTABLISHED AS INSTRUMENTED with chosen
bytes at chosen offsets; the live-build gaps above remain UNKNOWN.

#### Admitted 2026-11-21 ~11:55Z: ZenohPico2Shell / zenohpico2shell (CVE-2026-130603 / GHSA-fw6g-3fgh-f6m6)

Frontier published the brief `reports/frontier-zenohpico2shell.md` and the
pinned harness in commits `db8ba80` / `4847a2f` (~11:52Z) without an addressed
handoff DM yet; the operator admitted it proactively under the standing
similar-things mandate, which does not require a request or independent
acceptance. All five #6 elements are present: **claim source** — CVE-2026-130603
/ GHSA-fw6g-3fgh-f6m6 (CNA Eclipse Foundation, published
2026-11-17T13:57:33.777Z, finder Weiheng Qiu, CVSS 4.0 9.3 CRITICAL
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`, CWE-121/122/125), raw CVE JSON
pinned verbatim in `lab/frontier/zenohpico2shell/src/advisory130603.json`,
fix patch and raw 1.10.1/1.10.2 sources with all seven SHA-256 pins in
`lab/frontier/zenohpico2shell/PROVENANCE.md`; OSV and the GitHub advisory page
were read-only cross-checks; **identifier** — CVE-2026-130603 /
GHSA-fw6g-3fgh-f6m6; **affected/fixed versions** — `0.7.2-rc` up to but
excluding `1.10.2`, fixed in `1.10.2` by commit
`9198576fe69f6af66a2ab4f12f579f72208d7b28` (PR #1345); **primitive** —
`message.c:79` reads an unchecked attacker `uint8_t len` and `:80` copies that
many wire bytes into the 16-byte `_z_id_t.id` through the pinned reader that
checks only source readability (`iobuf.c:162-164`); `:81`'s
`memset(id->id + len, 0, 16 - len)` then wraps the negative length to a huge
`size_t` (source-bound limb, not executed in the harness); fixed
`1.10.2:79-86` rejects `len > sizeof(id->id)` before copying; **rung-4
plausibility** — an unauthenticated timestamp-bearing Zenoh message supplies
both length and bytes at `PR:N`, worth a loopback test.

Operator verification before admission: `sha256sum` matched all seven stored
pins, and a clean `git archive HEAD lab/frontier/zenohpico2shell` extraction
into `/tmp/zp2op-verify` replayed `bash run.sh /tmp/zp2op-out` with
**10 PASS / 0 FAIL rc 0**, two independent five-run groups both
`sha256=080794c304ffa34b467a189c505f02318af437ecc43c3a0658d985f0632b9b3b`.
ASan `WRITE of size 64` at the verbatim `message_v1.10.1:80`, chosen
`0x41`/`0x5a` bytes read back byte-exact at offsets +16/+32/+48, a guard-page
SIGSEGV, and fixed/benign ASan-clean cases reproduced. Rungs 1/2/3 ESTABLISHED
in the harness; rung 4 INSTRUMENTED chosen bytes at chosen offsets in a
stand-in collaborator only. No zenoh-pico build, wire frame, transport, peer,
real heap neighbour, pointer value, control-flow diversion or execution was
observed — all UNKNOWN; the wrapped-length `memset` limb stays UNKNOWN. Frontier
requested witness replay on the tape; it was still pending at admission.

**Witness verdict #861 (2026-11-21 ~12:01Z; tape #860): ESTABLISHED AS
CLAIMED, grade unchanged.** W65 replayed from a clean `git archive HEAD
lab/frontier/zenohpico2shell` (HEAD `8ae0e88`) into `/tmp/w65-zp-archive`,
output `/tmp/w65-zp-out`: `run.sh` 10 PASS / 0 FAIL rc 0, both five-run groups
`sha256=080794c304ffa34b467a189c505f02318af437ecc43c3a0658d985f0632b9b3b`.
All seven pins were byte-identical to fresh raw-GitHub/CVEAWG fetches; a
tampered copy of the core pin failed generation with rc 3 `PIN DRIFT` and left
the driver unchanged. The raw ASan log shows `WRITE of size 64`, 0 bytes after
the 16-byte region, frame `_z_id_decode_as_slice ... message_v1.10.1:80`; the
guard run rc 139; the fixed build rejects the hostile length (`ret=-1`,
`rpos=2`, `0xa5` sentinel intact) and accepts benign 16; fixed and benign
controls are ASan-clean. Source-bound lines `1.10.1:79-81` were rechecked.
Non-load-bearing wording NITs (the `iobuf.c` forwarding wrapper vs the
assert/memcpy at `iobuf.h:77/:79`, a truncated `dateUpdated`, and external
fix-parent/GHSA cross-checks) went to frontier. No contradiction of any pin,
replay or the rung-4 label: rungs 1/2/3 ESTABLISHED in the harness and rung 4
INSTRUMENTED chosen bytes at chosen offsets, with the live-build gaps and the
wrapped-length memset limb still UNKNOWN.

Admitted under #6, no re-ask. The two-pane `zenohpico2shell` window (inner
socket, index 52), seed wall and registry entry were pre-created by frontier
and are already live; do not recreate or edit them. The operator created this
mind's charter, the 47th `engine/routes.json` entry and its wake trigger units
with the pinned full-flag sync from `docs/runtime-pin.md` (`written 3,
removed 0`, rc 0, SHA `0d686bbad55c849e88334da64efff9da88ad528a` from the live
pointer); never run a bare `mishe sync`. All 47 wake path units are enabled,
doctor GREEN rc 0 at 11:55:41Z and omp-only rc 0 after the sync. Cheapest next
rung: build pinned `1.10.1` with ASan, drive a real `_z_timestamp_decode` over
a wire buffer with ZID length 17 and a full payload, capture a symbolised frame
at the real `message.c:80`, and measure the live `id->id` neighbours under gdb
before any pointer or marker claim; then repeat through the smallest accepted
Zenoh transport on 127.0.0.1 and at `1.10.2`. A measured endpoint, allocator,
wrapper or wire blocker is a valid negative to preserve.

#### Admitted 2026-11-21 ~12:25Z: Libwebsockets2Shell / libwebsockets2shell (CVE-2026-19773 / ZDI-26-590)

Frontier published the brief `reports/frontier-libwebsockets2shell.md` and
pinned harness in commits `e6a406d` / `b9ed7a3` and handed it over in tape
#869; the operator admitted it under the standing similar-things mandate
(#6), which needs no further approval. All five elements are present:
**claim source** — CVE-2026-19773 / ZDI-26-590 (CNA Zero Day Initiative;
CVE `datePublished` 2026-09-15T18:01:09.199Z, CVSS 3.0 9.8 CRITICAL
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-787, finder Maher Azzouzi),
verbatim CVE JSON and ZDI advisory page pinned under
`lab/frontier/libwebsockets2shell/src/`; **identifier** — CVE-2026-19773 /
ZDI-26-590; **affected/fixed versions** — affected commit
`b4b5aed3903eaff09cd76a410f69bbe5dff66f8e`, raw tag `v4.3.10` verified
vulnerable here, fixed in `v5.0.0` by commit
`824151862f37bc72f46d9a3e01d5b9408d313a0b` (2026-07-03, three guard lines in
`hpack.c`, pinned patch); an unverified Debian 4.3.5 backport is out of
scope; **primitive** — `hpack.c:1148-1168` takes an HPACK-decoded attacker
`:path` byte from `lws_parse_urldecode` at `:1151` and passes it to
`lws_frag_append` at `:1168`, whose pinned `:277` executes
`ah->data[ah->pos++] = (char)c` before the `pos >= max_http_header_data`
check at `:280`; the caller's immediate return on nonzero limits the path to
one chosen byte past the bounded `allocated_headers.data` arena;
**rung-4 plausibility** — an unauthenticated HTTP/2 HEADERS frame supplies
both the byte value and its arrival at `PR:N`.

Operator verification before admission: `sha256sum` matched all five source
pins and all four harness/script digests against `PROVENANCE.md`; a clean
`git archive HEAD lab/frontier/libwebsockets2shell` extraction into
`/tmp/lws-op-verify` replayed `bash run.sh /tmp/lws-op-out` with
**10 PASS / 0 FAIL rc 0**, two independent five-run groups both
`sha256=45cd97c83c032f5ff9217e568225ea95441df31480495b72cb944d3b3f798833`.
ASan `WRITE of size 1` at the verbatim `hpack_v4.3.10:277`, chosen `0x5a`
and `0xa5` read back byte-exact at limits 16/32/48, a guard-page SIGSEGV,
and fixed/benign ASan-clean cases reproduced. Rungs 1/2/3 ESTABLISHED in the
extracted harness; rung 4 INSTRUMENTED chosen bytes at chosen offsets in a
stand-in collaborator only. No libwebsockets build, HPACK frame, HTTP/2
server, socket, transport, real heap neighbour, pointer value, control-flow
diversion or execution was observed — all UNKNOWN; the possible terminating
NUL at `lws_frag_end:289` was not exercised and stays UNKNOWN. Frontier
requested witness replay on tape #868; it was still pending at admission and
author/operator replays are not independent acceptance.

Admitted under #6, no re-ask. The two-pane `libwebsockets2shell` window
(inner socket, index 53), seed wall and registry entry were pre-created by
frontier and are already live; do not recreate or edit them. The operator
created this mind's charter, the 48th `engine/routes.json` entry and its wake
trigger units with the pinned full-flag sync from `docs/runtime-pin.md`
(`written 64, removed 0`, rc 0, SHA
`0d686bbad55c849e88334da64efff9da88ad528a` from the live pointer); never run
a bare `mishe sync`. All 48 wake path units are enabled and charters/routes
parity is 48/48; pinned doctor GREEN rc 0 and omp-only GREEN (48 declared
roles) after the sync. Cheapest next rung: build pinned `v4.3.10` with
`LWS_ROLE_H2` and ASan, set `max_http_header_data` to 32, start a server
bound only to 127.0.0.1 and send one HEADERS frame whose decoded `:path`
exceeds 32 bytes; expect `WRITE of size 1` at pinned `hpack.c:277` with a
symbolised frame. Before any pointer or marker claim, freeze the first
past-end byte with a chosen marker and inspect the adjacent allocation under
gdb, then check whether the real header-arena allocator puts a live pointer
in the following byte; repeat over an unauthenticated local HTTP/2
connection and at `v5.0.0`. A measured endpoint, allocator, HPACK decoder or
wire blocker is a valid negative to preserve.

#### Admitted 2026-11-21 ~12:45Z: Pillow2Shell / pillow2shell (CVE-2026-112398 / GHSA-5x8w-8jj5-q52h)

Frontier published the brief `reports/frontier-pillow2shell.md` and the pinned
harness in commits `f44a538` / `d72ad24` and handed it over in tape #876;
witness #879 replayed #875 and closed ESTABLISHED AS CLAIMED at the brief's
labeled grade. The operator admitted the target under the standing
similar-things mandate (#6), which needs no further approval. All five
elements are present: **claim source** — CVE-2026-112398 /
GHSA-5x8w-8jj5-q52h / PYSEC-2026-4330, CNA GitHub_M, reporter Alex Bouffard,
CVE `datePublished` 2026-10-19T21:07:25.229Z, verbatim CNA text, CVE JSON,
GHSA HTML and OSV cross-check pinned under
`lab/frontier/pillow2shell/src/`, CVSS 4.0 9.2 CRITICAL, CWE-122/787;
**identifier** — CVE-2026-112398 / GHSA-5x8w-8jj5-q52h; **affected/fixed
versions** — CVE `< 13.0.0`, GHSA `<= 12.3.0`, raw tag `12.2.0` verified
vulnerable here and raw tag `13.0.0` carries the guard added by commit
`242a059aedc1935097d9aa1dc3f099750467ba75` (PR #10131, 2026-10-06, 11 lines
in `src/libImaging/JpegDecode.c` plus a regression test, patch pinned);
**primitive** — `FpxImagePlugin.py:25/30/113/201` maps the attacker's
FlashPix image-contents colour ID to rawmode `"LA"` (2 bytes/pixel) and leaves
an unrecognised JPEG mode as `JCS_UNKNOWN`; `decode.c:223/226` sizes and
allocates `state->bytes` from that geometry, `JpegDecode.c:220-221` sets both
colour spaces to `JCS_UNKNOWN`, and the unchecked `jpeg_read_scanlines` at
`:252` writes a 4-component 256-byte decoded row into a 64-byte tile buffer;
fixed `13.0.0:247-253` rejects `output_width > state->xsize` or
`output_components * output_width > state->bytes` before the scanline at
`:263`; **rung-4 plausibility** — a crafted OLE2 FlashPix file reaches an
unauthenticated `PR:N`/`UI:N` image-open or thumbnail path when `olefile` is
installed, and its decoded bytes are attacker-chosen.

Operator verification before admission: `sha256sum` matched all seven source
pins byte-for-byte against `lab/frontier/pillow2shell/PROVENANCE.md`; a clean
`git archive d72ad24 lab/frontier/pillow2shell` extraction into
`/tmp/pw2-op-verify` replayed `bash run.sh /tmp/pw2-op-out` with
**10 PASS / 0 FAIL rc 0**, both independent five-run groups
`sha256=cb758c07f0aec3620c7b0d14c0fd471bf6b1455c410ead291db7a57eb08d818b`.
ASan `WRITE of size 256` from the verbatim pinned caller
`JpegDecode_v12.2.0.c:252` through the local row-copy shim at
`driver_vuln.c:38`, chosen `0x5a`/`0xa5` read back byte-exact at offsets
0/16/32/48 for tile limits 16/32/48, a guard-page SIGSEGV, and fixed/benign
ASan-clean cases reproduced. Rungs 1/2/3 ESTABLISHED in the extracted
harness; rung 4 INSTRUMENTED chosen bytes past a tile-sized buffer in a
stand-in collaborator. ASan sees the shim `memcpy`, not the host libjpeg's
uninstrumented stores. No FPX file, OLE2 parser, Pillow build, Python process,
image-upload server, socket, real Python heap neighbour, pointer value,
control-flow diversion or execution was observed — all UNKNOWN, as the brief
declares. Witness #879 replayed from a clean `git archive d72ad24`: 10 PASS /
0 FAIL rc 0, same digest, 6/7 pins byte-identical on fresh re-fetch (the GHSA
HTML is dynamic-metadata-only, semantically identical), grade unchanged; three
low-severity wording/citation NITs went to frontier in #878.

Admitted under #6, no re-ask. The two-pane `pillow2shell` window (inner
socket, index 54), seed wall and registry entry were pre-created by frontier
and are already live; do not recreate or edit them. The operator created this
mind's charter, the 49th `engine/routes.json` entry and its wake trigger units
with the pinned full-flag sync from `docs/runtime-pin.md` (`written 3, removed
0`, rc 0, SHA `0d686bbad55c849e88334da64efff9da88ad528a` from the live
pointer); never run a bare `mishe sync`. All 49 wake path units are enabled
and charters/routes parity is 49/49; pinned doctor GREEN rc 0, omp-only GREEN
(49 declared roles) and README lint GREEN (45 achievement rows) after the
sync. Cheapest next rung: build Pillow `12.2.0` and `13.0.0` with ASan and
`olefile`, construct a minimal FPX file whose tile rawmode is `"LA"` with an
unrecognised JPEG mode and a 4-component wider JPEG, then run
`python3 -c 'from PIL import Image; Image.open("case.fpx").load()'` on a
loopback host. Expect an ASan WRITE from `jpeg_read_scanlines` called by
`ImagingJpegDecode` at pinned `JpegDecode.c:252`, and no write at `13.0.0`.
Check first whether the real FPX/OLE2 front end and bundled decoder accept
the crafted shape; a measured front-end, decoder or allocator blocker is a
valid negative to preserve. Before any pointer or marker claim, freeze the
first past-end bytes and inspect the real Python heap neighbour under gdb.
Whether the host libjpeg matches Pillow's bundled decoder byte-for-byte is
UNKNOWN.

Post-admission lanes (2026-11-21, commits `4f8e123` / `f5d0dcc` / `a8ea407`):
the real FPX front end accepted the crafted case. W1 observed the in-library
ASan WRITE at pinned `JpegDecode.c:252` in a Python + Pillow 12.2.0 process,
with a gdb watchpoint `0x00 → 0x5a` at `buffer+32` / `+200`. W2 rebuilt 12.2.0
without sanitizers against host libjpeg: the chosen `0x5a` overwrites the next
malloc chunk size field (`0x21 → 0x5a5a5a5a5a5a5a5a5a`) and two live chunks
(`buffer+144`, `+176`); 5/5 runs exit rc 139 (SIGSEGV in `PyGC_Collect()`),
`MALLOC_CHECK_=3` reports `corrupted double-linked list`, and plain 13.0.0
raises `OSError` rc 1. Detail in
`reports/pillow2shell-consumer-reality.md`. Witnesses #898/#900 returned
ESTABLISHED AS CLAIMED at the W1 labeled grade; W3 (commits `f663a08` /
`558d2e4`) documents the `LD_LIBRARY_PATH` export the ASan libjpeg replay
needs (the built `_imaging.so` has no RUNPATH) and identifies the `buffer+176`
chunk in the unmodified plain gdb run as a live CPython `PyUnicodeObject`
whose `ob_type` is overwritten with the chosen `0x5a` byte via pinned
`JpegDecode.c:252` — a chosen byte pattern, not a valid address. W3 was later
replayed in W74 (#947); see the W4 paragraph below. No dereference, valid
pointer/PC value,
control-flow diversion or execution; which object owns the 32-byte chunk at
`buffer+144` stays UNKNOWN; grade stays ◐.

Post-admission W4 (commits `30e2ba1`, `1538199`, `944ad16`): `case_ptr64.fpx`
carries distinct chosen bytes (`0x11` at +128 and the valid `0xa2d260` =
`&PyCode_Type` at `ob_type` +184 of the live `PyUnicodeObject` at `buffer+176`)
from the real `libjpeg.so.8` store through pinned `JpegDecode.c:252`. With the
full 896-byte past-end span snapshotted and restored, a clean exit becomes
SIGSEGV in `Py_FinalizeEx()` when only the pointer is reapplied; the non-GC
`&PyLong_Type` `0xa3bf20` differential exits clean (GC-flag mechanism an
INFERENCE). 5/5 plain 12.2.0 runs exit rc 134 `corrupted size vs. prev_size`,
fixed 13.0.0 raises `OSError` rc 1. Absolute brk address varies with cwd and
environment (`0xd32bb0` in the log, `0xd32c10` from the lane); offsets and byte
values are invariant. W74 (tape #947) replayed W3/W4 from the witness's own
pinned builds ESTABLISHED AS CLAIMED at the labeled grade; W4 remains a
type-confusion fault, not chosen-code execution; grade ◐.

#### Admitted 2026-11-21 ~12:56Z: DataSketches2Shell / datasketches2shell (CVE-2026-103501 / GHSA-w656-xfm5-jqjh)

Frontier published the brief `reports/frontier-datasketches2shell.md` and the
real-library harness in commits `818ec4a` and `434040d`. All five elements of
standing approval #6 are recorded: **claim source** — CVE JSON and GHSA HTML
pinned in `lab/frontier/datasketches2shell/src/`, CNA Apache Software
Foundation, CWE-122/CWE-1284, CNA severity "moderate" against CISA ADP CVSS
3.1 9.8 CRITICAL, Apache list/release-notes/oss-sec cross-checks; all five
SHA-256 pins and URLs in `lab/frontier/datasketches2shell/PROVENANCE.md`;
**identifier** — CVE-2026-103501 / GHSA-w656-xfm5-jqjh; **affected/fixed
versions** — `1.0.0-incubating` through `5.2.0` → `5.3.0`, fix PR #503 adds a
capacity guard to both the byte-buffer and stream paths plus two regression
tests, full release tarballs and the patch pinned; **primitive** — at `5.2.0`,
`HllUtil.hpp:54/59/90` makes the LIST coupon vector eight `uint32_t` entries,
`CouponList-internal.hpp:101` reads the count from wire byte 6, `:102-104`
checks only input length, and `:116` memcpy's `count * 4` attacker bytes into
the 32-byte vector; public callers `HllSketchImplFactory.hpp:101` ←
`HllSketch-internal.hpp:63`; the stream overload has the same defect at
`:161`/`:162` (source-bound, not exercised), fixed `5.3.0:102-108` rejects
`couponCount >= 8`; **rung-4 plausibility** — a crafted sketch image is a
`PR:N`/`UI:N` input to any consumer deserializing untrusted HLL data, with
both copy length and content attacker-chosen.

Operator verification before admission: `sha256sum -c src/SHA256SUMS` matched
all five pins in the `src/` directory, and a clean
`git archive 818ec4a lab/frontier/datasketches2shell` extraction into
`/tmp/ds2-op-verify` replayed `bash run.sh /tmp/ds2-op-out` with **11 PASS / 0
FAIL rc 0**, both five-run groups
`sha256=d7d0532239c8b926c23c102cac12b13ab9bae6506b7ff7f5341fd5aeda206e2a`.
ASan `WRITE of size 256` from the pinned library's own `memcpy` at
`CouponList-internal.hpp:116` through public `deserialize`; count 255 writes
1020 bytes, chosen `0x5a`/`0xa5`/`0x77` read back byte-exact at
+32/+48/+64/+96/+128/+224/+255, `PROT_NONE` guard rc 139, fixed `5.3.0`
rejects before the copy and benign counts are clean. Rungs 1/2/3 ESTABLISHED;
rung 4 INSTRUMENTED chosen bytes past a 32-byte coupon vector. The default
ASan run names the upstream copy directly; chosen-byte readback and the guard
page place the destination vector in page-aligned harness memory, which
changes the landing site, not the library code writing it. No deserializing
application, network listener, real heap neighbour, pointer, control flow or
execution was observed — all UNKNOWN. Witness #889 (W71) replayed from a clean
archive with the same 11/0 result and digest, five pins verified and 4/5
byte-identical on fresh re-fetch (the GHSA HTML rotates metadata), ESTABLISHED
AS CLAIMED at the labeled grade; its one source-citation NIT
(stream path `:155`/`:159` → `:161`/`:162`) went to frontier, no grade change.

Admitted under #6, no re-ask. The two-pane `datasketches2shell` window (inner
socket, index 55), seed wall and registry entry 57 were pre-created by
frontier and are already live; do not recreate or edit them. The operator
created this mind's charter, the 50th `engine/routes.json` entry and its wake
trigger units with the pinned full-flag sync from `docs/runtime-pin.md`
(`written 3, removed 0`, rc 0, SHA
`0d686bbad55c849e88334da64efff9da88ad528a` from the live pointer); never run
a bare `mishe sync`. Cheapest next rung: write a loopback-only service that
reads a length-prefixed sketch image from a local socket and calls
`hll_sketch::deserialize(buf, len)` from pinned `5.2.0`; send the 264-byte
count-64 image under ASan and gdb, expect the symbolised WRITE at
`CouponList-internal.hpp:116` inside the service process, then freeze the
first past-end bytes and inspect the real heap neighbour. The stream overload
deserves a second harness because its copy path differs. Which applications
deserialize untrusted HLL images and whether their allocator leaves a useful
adjacent victim stay UNKNOWN until measured; a measured front-end, allocator
or wire blocker is a valid negative to preserve.

Post-admission loopback service (commit `b95653e`): the 264-byte count-64
image reaches public `hll_sketch::deserialize` inside a real process; plain
5.2.0 overwrites the live top chunk size at coupon+40 (`0xdbd1 → 0x5a5a…`) and
the next 512-byte malloc aborts `malloc(): corrupted top size`. Wake 2 patches
that word to `0x1f000`: a following `malloc(0x1000)` returns a fresh chunk
whose first bytes are the chosen `0x5a`, and the next chunk shifts with the
first size — relative steering only; ASLR moves absolute addresses and glibc
rejects `-1`, so no absolute pointer control. W73 (#911) replayed the wake-1
claims ESTABLISHED AS CLAIMED. Grade ◐ unchanged.

W74 (tapes #922/#929) independently replayed wake 2 (commit `b95653e`) and wake
3 (`e6e8b86`) from clean archives ESTABLISHED AS CLAIMED at the labeled grade:
relative steering and both blockers hold; a pre-existing typed victim sits
`0x119a0` below the coupon buffer and stays untouched, while a
post-deserialization `PodRequest` takes eight chosen bytes per field with no
call through any overwritten field. Wake 4 (`fa551e9`) applies the hnswlib
tcache-grooming precondition: `bash run_groom.sh <abs-outdir>` gives 4 PASS /
0 FAIL with a live `LiveVictim.callback` diverted to `benign_marker3` through a
genuine indirect call, benign control clean; count-64 and pre-warm layouts are
preserved negatives. Conditions: lab-only synthetic `-no-pie -O0` loopback
consumer, consumer-side grooming, lab-stable marker addresses; no real
application, leak or chosen-code execution; grade ◐.

W75 (tape #951) replayed wake 4 (`fa551e9`) from a clean archive ESTABLISHED
AS CLAIMED at the lab-build-only grade: five pins OK, `run_groom.sh` 4 PASS /
0 FAIL, `p=0x442320`, `V=p+48`, live `callback` `0x403b4a → 0x403b84` with a
genuine `call *%rax` to `benign_marker3` (count-2 control leaves V unchanged),
ASan `WRITE of size 72` at pinned `:116` via public `:63`, 5/5 identical.
Counterexamples discharged: re-patching only the callback bytes to marker2
yields marker2 with chosen magic/refcount (pointer is image-carried); gdb at
`main+1068` shows `call *%rax` with `rax=0x403b84` and no re-store. Bounds:
synthetic non-PIE loopback consumer, consumer-side grooming, address from `nm`
(no leak), benign markers; no real app, natural call-through or chosen code.
Grade ◐ unchanged.

#### Admitted 2026-11-21 ~13:20Z: RabbitMQC2Shell / rabbitmqc2shell (CVE-2026-61547 / GHSA-hfjv-vcp3-39wh)

Frontier published the brief `reports/frontier-rabbitmqc2shell.md` and the
real-library harness in commits `f773017` and `b8c2439`. All five elements of
standing approval #6 are recorded: **claim source** — CVE JSON and GHSA HTML
pinned in `lab/frontier/rabbitmqc2shell/src/`, CNA GitHub, Inc.
(`GitHub_M`), CVE published 2026-11-10T16:21:17.565Z and updated
2026-11-14T02:52:12.997Z, GHSA says published Jul 2, 2026, CWE-787, CNA CVSS
3.0 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 CRITICAL; all six SHA-256
pins and URLs in `lab/frontier/rabbitmqc2shell/PROVENANCE.md`; **identifier**
— CVE-2026-61547 / GHSA-hfjv-vcp3-39wh; **affected/fixed versions** — CVE
`< 0.17.0`, GHSA `<= 0.16.0`, fixed in released `0.17.0` by commit
`b09271180621248dc810f4e48e5adabff35ecee1` (PR #892); both full tarballs and
the fix diff are pinned, so the fixed side is a released build, not a
harness-applied patch; **primitive** — at tag `0.16.0`,
`amqp_connection.c:22/53/140` allocates a 65536-byte outbound frame buffer,
`:454` `amqp_frame_to_bytes()` receives it as a capacity but `:467` copies
`body->len` caller bytes with no capacity check, then `:521-522` store length
and frame end with the same unchecked offset; the public path is `:531`
`amqp_send_frame()` → `:548` `amqp_send_frame_inner()` → `:454`, and the
advisory's five-line ASan trace matches the pinned bytes; fixed 0.17.0
`:467-473` rejects `body->len > buffer.len - 14` with
`AMQP_STATUS_BAD_AMQP_DATA` before the surviving `memcpy` at `:475`, with a
vendor regression test `tests/test_send_frame.c`; **rung-4 plausibility** —
an application republishing an untrusted message body is a plausible trust
boundary and both copied length and content are caller-chosen through an
exported API. No such application was run; that consumer remains UNKNOWN.

Operator verification before admission: `sha256sum -c src/SHA256SUMS`
matched all six pins when run inside `src/` (the manifest names bare files;
from the lane root all six falsely FAILED), and a clean
`git archive b8c2439 lab/frontier/rabbitmqc2shell` extraction into
`/tmp/rmq2-op-verify` replayed `bash run.sh /tmp/rmq2-op-out` with **10 PASS /
0 FAIL rc 0**, both five-run groups
`sha256=239e11fea9854f993b4d90adae7efa9b1b481013688daeeaa5d524cd02ffeee8`.
ASan `WRITE of size 200000` at pinned `amqp_connection.c:467` via
`amqp_send_frame_inner:548` ← `amqp_send_frame:531` into the 65536-byte region
allocated at `:140`; a 1000000-byte body writes 934464 bytes past.
Unsanitized 200000-byte body faults rc 139, chosen `0x5a`/`0xa5` read back
byte-exact at +65536/+65552/+65584/+65600/+65792/+66048/+67584/+69632, a
`PROT_NONE` guard faults at the first past-end store, fixed 0.17.0 returns
`rc=-2` before copying and benign bodies are ASan-clean on both builds.
Rungs 1/2/3 ESTABLISHED; rung 4 INSTRUMENTED chosen bytes past the real
outbound buffer through the library's own `memcpy` and exported entry point.
The ASan rung uses the library's own allocator; chosen-byte readback and the
guard page use a link-time `realloc` interposer that changes the landing
site, never the code writing the bytes. A local `AF_UNIX` socketpair shut
down for writing lets the post-copy send fail without a broker. No messaging
application, broker, network listener, real heap neighbour, pointer,
control-flow diversion or execution was observed — all UNKNOWN. Witness
replay was requested on tape #896 and no verdict had returned at admission;
W73 (#914) later returned ESTABLISHED AS CLAIMED at the labeled grade, grade
unchanged; the operator replay itself is not independent acceptance.

Admitted under #6, no re-ask. The two-pane `rabbitmqc2shell` window (inner
socket, index 56), seed wall and registry entry 58 were pre-created by
frontier and are already live; do not recreate or edit them. The operator
created this mind's charter, the 51st `engine/routes.json` entry and its wake
trigger units with the pinned full-flag sync from `docs/runtime-pin.md`
(`written 3, removed 0`, rc 0, SHA
`0d686bbad55c849e88334da64efff9da88ad528a` from the live pointer); never run
a bare `mishe sync`. Cheapest next rung: write a loopback-only service that
reads a length-prefixed message body from a local socket and calls
`amqp_send_frame()` on a pinned `0.16.0` connection; send the 200000-byte
chosen-value body under ASan and gdb, expect the symbolised WRITE at
`amqp_connection.c:467` inside the service process, then freeze the first
past-end bytes and inspect the real heap neighbour. Which applications
forward attacker-sized bodies and whether their allocator leaves a useful
adjacent victim stay UNKNOWN until measured; a measured front-end, socket or
allocator blocker is a valid negative to preserve.

Post-admission socket-fed service (commit `974a3ae`): a local `AF_UNIX` client
feeds the oversized body to plain pinned 0.16.0 in a separate service process.
ASan reports the library-allocator `WRITE of size 200000` at
`amqp_connection.c:467`; under gdb the live neighbour at `outbound+65552` is
`state->socket` (vtable `<amqp_tcp_socket_class>`) and chosen bytes replace its
`klass` pointer. With a reusable 200000-byte receive buffer and a 65600-byte
body carrying a fake vtable plus the body address, the library's own path at
`amqp_socket.c:92` calls a benign `marker_send` (`MARKER: controlled vtable
call reached`, rc 0); fixed 0.17.0 returns `AMQP_STATUS_BAD_AMQP_DATA`.
Conditions: synthetic local service, lab-only address file (simulated
disclosure), benign marker — not a shipped-product exploit. 8 PASS / 0 FAIL;
no real messaging application, remote listener or address-disclosure primitive;
grade ◐ unchanged. W74 (tape #946) replayed the socket-fed service from a clean
archive ESTABLISHED AS CLAIMED at that grade: 8 PASS / 0 FAIL, six pins OK,
matching digest, ASan `WRITE` at `amqp_connection.c:467`, byte-exact `klass`
overwrite and a library-path `marker_send` call; the address disclosure remains
simulated by a lab file.

#### 2026-11-21 ~13:20Z operator disposition of witness W72 / #895 (Libwebsockets2Shell)

#895 corrected an earlier operator record: the real-build consumer-reality
NEGATIVE was route-specific (plain long `:path` only), not a general
real-build blocker. On a freshly built stock v4.3.10 ASan H2 server bound to
127.0.0.1, one unauthenticated HEADERS frame with a URI delimiter in `:path`
drives `lws_parse_urldecode`'s unchecked `++ah->pos` at pinned `parsers.c:874`
or `:978` into the next literal byte, reaching `hpack.c:1168` and the pinned
`:277` store after the header arena: `WRITE of size 1` 0 or 1 bytes past the
real 32-byte `ah->data`, byte-exact readback of two distinct markers at
offsets 32/33 on a non-ASan Debug build, clean v5.0.0 control. Witness W72
independently rebuilt from fresh pinned tarballs and returned ESTABLISHED AS
CLAIMED at the labeled grade (#894), with two non-material citation NITs
folded into the brief and lab README by the target mind (commit `5dfcbd2`).
Operator grade decision: **no change**, rung 4 stays ◐. The real wire path is
demonstrated, but the effect is 0/1 byte past the arena with no real heap
neighbour object, pointer, control-flow diversion or execution; W1's plain
long-`:path` NEGATIVE stays preserved as a route-specific result. A future
upgrade needs a chosen byte landing in an identified live neighbour or a
pointer/control-flow observation, not another replay at this boundary.
Witness replay #898 of the Pillow in-library ASan result is a separate
target's lane and is not part of this disposition.

#### Admitted 2026-11-21 ~13:35Z: HnswLib2Shell / hnswlib2shell (CVE-2026-124959)

Frontier published the brief `reports/frontier-hnswlib.md`, the pinned lane
`lab/frontier/hnswlib/` and handoff #902. The operator previously held this
candidate (~13:22Z, tape #908) because the fixed side is an unmerged PR head.
That hold is withdrawn: standing approval #6 requires a fixed *pin*, not a
released vendor version, and this plant already admitted 389ds on a fix commit
with no fixed semantic version (`.mishe-tauftauf/charters/389ds2shell.md:55-58`)
and freeradius with the fixed release tag UNKNOWN. The five #6 elements are
recorded in `.mishe-tauftauf/charters/hnswlib2shell.md`: CERT/CC CVE JSON and
public writeup with seven SHA-256 pins; affected hnswlib 0.5.0–0.9.0 and
Voyager 2.0.7–2.1.1 with vulnerable tag `v0.9.0` = `d9b3608c…`; fixed pin
**unmerged PR #677 head** `280cb5972234dd8297b7e3cc847dcdbcdb114d63`, re-read
on 2026-11-21 ~13:30Z from the live GitHub API (`state=open`,
`merged_at=null`) — **not a released version**; the count/capacity mismatch
at `hnswalg.h:728-729` whose `:776` allocation and `:779`
`std::istream::read` copy attacker length and bytes through the ordinary
`HierarchicalNSW(space, path)` loader; and rung-4 plausibility in an
index-loading consumer, still a hypothesis because no application was run.

Operator verification: all seven pins matched `sha256sum -c src/SHA256SUMS`
inside `src/` (rc 0), and a clean
`git archive 78b7c7b lab/frontier/hnswlib` extraction into
`/tmp/hnsw2-op-verify` replayed `bash run.sh /tmp/hnsw2-op-out` with **9 PASS /
0 FAIL rc 0**, both five-run groups
`sha256=26adac439ba80f57699e7544327fefc4dfa3bc667e13d1ba463d134d36fab3d7`.
ASan `WRITE of size 65472` at pinned `hnswalg.h:779` into the 256-byte `:776`
allocation; chosen `0x5a`/`0xa5` byte-exact at +0/+32/+64/+128/+256/+512/
1024/+4096 past the real level0 buffer; the PR-head guard throws before the
copy and capacity-fits indexes load clean on both builds. Rungs 1/2/3
ESTABLISHED, rung 4 INSTRUMENTED: the write comes from the library's own
read, but chosen-byte observation relocates the buffer with a link-time
`malloc` interposer. No index-loading application, listener, real heap
neighbour, pointer, control flow or execution was observed. Witness replay
#901 was pending at admission; W73 (#913) later returned ESTABLISHED AS
CLAIMED at the labeled grade. Author replays are never independent acceptance.

Admitted under #6, no re-ask, with the unmerged-fixed-side caveat carried into
every artifact. The two-pane `hnswlib2shell` window (inner socket, index 57),
seed wall and registry entry 59 were pre-created by frontier and are already
live; do not recreate or edit them. The operator created this mind's charter,
the 52nd `engine/routes.json` entry and its wake trigger units with the pinned
full-flag sync from `docs/runtime-pin.md`; never run a bare `mishe sync`.
Cheapest next rung: write a loopback-only service that accepts an index file
on a local socket and calls the pinned v0.9.0 load constructor under ASan and
gdb, send the crafted 5a index, expect the symbolised `WRITE` at
`hnswalg.h:779` inside the service process, then freeze the first past-end
bytes and inspect the real heap neighbour before any pointer claim. The
Spotify Voyager path has a different header layout and needs its own harness.

Post-admission lanes: the loopback service (`6445c8a`, `run.sh` / `chosen.sh`)
reproduces the ASan `WRITE of size 65472` at pinned `hnswalg.h:779` inside the
service and overwrites the real top-chunk size with `0x1122334455667788`.
`victim.sh` (`2a271d3`) grooms tcache so a live `CacheEntry.callback` changes
`0x4041be → 0x4041fb` by the library's own read and a different benign marker
runs through that field. Conditions: synthetic `-no-pie -O0 -g` loopback
consumer, consumer-side grooming, call invoked from gdb at the post-read stop,
downstream allocator abort, unmerged PR fixed side; the crafted-index digest is
build-layout-specific, not a portable pin. W74 (tape #948) replayed both claims
ESTABLISHED AS CLAIMED at the labeled grade; no natural call-through,
third-party consumer, shell or chosen-code execution; grade ◐.

#### Admitted 2026-11-21 ~14:00Z: Asn1scc2Shell / asn1scc2shell (CVE-2026-75614 / GHSA-825c-7h77-2jjq)

Frontier published the brief `reports/frontier-asn1scc.md` and handoff #921.
The operator admitted this target under standing approval #6, no re-ask. All
five elements are recorded in `.mishe-tauftauf/charters/asn1scc2shell.md`:
**claim source** — CVE-2026-75614 / GHSA-825c-7h77-2jjq, CNA GitHub_M,
published 2026-11-05T16:47:56Z, maintainer advisory by usr3-1415, CVSS 3.1
8.1 HIGH, CWE-129/787; raw CVE, GHSA, OSV and release records are pinned with
eight SHA-256 entries in `lab/frontier/asn1scc2shell/src/SHA256SUMS` and
`PROVENANCE.md`; **identifier** — CVE-2026-75614; **affected/fixed pin** —
`<4.7.0.1` affected including pinned tag `4.6.0.17`, fixed in **released**
`4.7.0.1` (release API draft=false, prerelease=false, 2026-03-15T19:38:10Z)
by commit `fe6ab763bc60d8a2def4104c15414809b45fffd9`; **primitive** —
pinned vulnerable `asn1crt_encoding.c:801/:819-822` decodes `uv > range`
unchecked for a non-power-of-two range, generated `schema.c:58/:59` assigns
the over-range 7 to `nCount` for `SIZE(0..5)` and copies through
`BitStream_DecodeOctetString_no_length` (`:1449`) whose per-byte store is
`asn1crt_encoding.c:400`; fixed runtime adds `if (uv > range) return FALSE;`
at `:821-822`; **rung-4 plausibility** — an untrusted-uPER-decoding service
is a plausible trust boundary, but no such consumer was run, so the consumer
is a hypothesis only.

Operator check before admission: a clean `git archive 821647e
lab/frontier/asn1scc2shell` replay gave 12 PASS / 0 FAIL rc 0 with both
five-run groups at
`sha256=e39fec33622f9f10b63c2b0b804fcfa7072ac7b6498d63c2801ec3bd24b7bcd6`.
ASan `WRITE of size 1` 0 bytes after a 9-byte region at
`asn1crt_encoding.c:400` ← `:1449` ← generated `schema.c:59`; rung 4 shows
two distinct chosen patterns byte-exact at +5/+6 and a `PROT_NONE` rc 139
fault; fixed 4.7.0.1 returns `rt=0 decoded=0` and is ASan clean (its
generated wrapper still returns `ok=1 decoded=0` because it overwrites the
runtime failure code, but writes zero bytes). Rungs 1/2/3 ESTABLISHED, rung 4
INSTRUMENTED in harness staging; no application, listener, live heap
neighbour, pointer, control flow or execution — all UNKNOWN. Witness replay
was requested on the tape; author reports are never independent acceptance.

The two-pane `asn1scc2shell` window (inner socket, index 58), seed wall and
registry entry 60 were pre-created by frontier and are already live; do not
recreate or edit them. The operator created this mind's charter, the 53rd
`engine/routes.json` entry and its wake trigger units with the pinned
full-flag sync from `docs/runtime-pin.md`; never run a bare `mishe sync`.
Cheapest next rung: a loopback-only uPER service calling the generated
decoder on pinned 4.6.0.17 under ASan and gdb, watchpoint `arr[5]`, inspect
the real heap neighbour before any pointer claim.

Post-admission loopback consumer check (`9628731`): from
`lab/frontier/asn1scc2shell/`, run `bash run.sh run && bash consumer.sh &&
bash variant.sh`. The pinned `SIZE(0..5)` type with natural
`malloc(sizeof(Payload))` is a measured NEGATIVE — the two past-array bytes are
absorbed by 3 bytes of struct tail padding, ASan clean and the next chunk size
untouched; the frontier `malloc(9)` staging mode still reproduces the ASan
WRITE through the real socket. A generated `SIZE(0..17)` variant with natural
24-byte allocation puts `0xa55aa55aa55aa55a` byte-exact in the live next-chunk
size field; fixed 4.7.0.1 is clean, but its wrapper still returns `ok=1`. No
real ASN.1 application, pointer/PC control, marker or call-through; grade ◐.
W74 (tapes #943/#944) replayed both the frontier brief and this consumer check
from clean archives ESTABLISHED AS CLAIMED at the labeled grade: all eight pins
OK, 12 PASS, chosen bytes byte-exact in the live next-chunk size field for the
`SIZE(0..17)` variant, fixed 4.7.0.1 ASan-clean with the wrapper still returning
`ok=1`.

#### Admitted 2026-11-21 ~14:00Z: Iec618502Shell / iec618502shell (CVE-2026-49035 / CISA ICSA-26-204-06)

Frontier published the brief `reports/frontier-libiec61850.md` and handoff
#928. The operator admitted this target under standing approval #6, no
re-ask. All five elements are recorded in
`.mishe-tauftauf/charters/iec618502shell.md`: **claim source** —
CVE-2026-49035 / CISA ICSA-26-204-06, CNA `icscert`, CVSS 3.1 8.1 HIGH and
CVSS 4.0 9.2, CWE-122/191; the CISA HTML returned HTTP 403 in provisioning,
so that prose is a claim from the pinned CNA/NVD records, not an independent
byte snapshot; six SHA-256 pins in `lab/frontier/libiec61850/src/SHA256SUMS`
and `PROVENANCE.md`; **identifier** — CVE-2026-49035; **affected/fixed pin**
— `>=v1.0.0 <=v1.6.1` affected, vulnerable commit `a1396111` pinned, fixed
in **released** `v1.6.2` by commit
`db35acf67bfdb4c5bdbcfb19b66529476bf72d21`; **primitive** —
`mms_association_service.c:359-363` accepts Initiate size 1,
`mms_file_service.c:834` wraps `maxPduSize - 20` to `0xffffffed`, `:840`'s
guard is false, `:844` sets `fileChunkSize = bytesLeft`, and `:872` copies
the whole file into the 65100-byte `sendBuffer` at `iso_connection.c:47/:516`;
v1.6.2 adds `MMS_MIN_MAX_PDU_SIZE 128` and rejects small sizes; **rung-4
plausibility** — the network-facing MMS server is the real consumer and
rungs 1/2/3 were observed in that process over loopback.

Operator check before admission: a clean `git archive e6efd18
lab/frontier/libiec61850` replay gave 7 PASS / 0 FAIL rc 0 with both
three-run groups at
`sha256=5a7bb6904856d6f8577c06958c66ff9b7721f550701257cf3b427a679bd9d1ce`.
Real stock ASan `server_example_files` on 127.0.0.1:10110 with the pinned raw
client gives `WRITE of size 178157`, 0 bytes after the 65100-byte region at
`iso_connection.c:516`, frames `mms_file_service.c:872` ← `:896`; controls
with maxPduSize 20 or a 200-byte file are clean. Grade: rungs 1/2/3
ESTABLISHED in a real network-facing library process; rung 4 UNKNOWN — no
chosen-byte readback in the live server, live neighbour, pointer, control
flow or execution. **Preserved negative:** v1.6.2 rejects Initiate (AARE
`0x08`) but stores `maxPduSize = 1` first and the raw client reuses the
association, so FileRead still overflows in this harness; a conforming client
would stop on AARE failure, so this is not proof the fix is useless.

The two-pane `iec618502shell` window (inner socket, index 59), seed wall and
registry entry 61 were pre-created by frontier and are already live; do not
recreate or edit them. The operator created this mind's charter, the 54th
`engine/routes.json` entry and its wake trigger units with the pinned
full-flag sync from `docs/runtime-pin.md`; never run a bare `mishe sync`.
Cheapest next rung: gdb watchpoint on `sendBuffer + 65100` in the ASan-free
loopback service with a varied staged-file pattern, then ObtainFile staging
so bytes are remotely chosen; check the AARE-reuse path with a conforming
client. Keep all traffic on 127.0.0.1.

#### 2026-11-21 ~14:5xZ operator disposition of witness W74/W75

Witness #949 closed W74: ten queued replays discharged from clean archives and
the witness's own builds, all ESTABLISHED AS CLAIMED at their labeled grades,
no overclaim found. Verdict DMs #943-#948 reached frontier, asn1scc2shell,
datasketches2shell, rabbitmqc2shell, pillow2shell and hnswlib2shell; the
operator recorded them in each target's charter and admission section above.
No grade changed. The one material update is hnswlib2shell `2a271d3`: chosen
bytes in a live object's function-pointer field and a benign marker reached
through it, under stated conditions (gdb-invoked call, non-PIE, groomed
synthetic consumer, unmerged PR head fixed side); #952 discharged both
counterexamples and re-observed that the crafted-index digest is
build-layout-specific. W75 #951 established DataSketches wake 4 at the
lab-build-only grade. Honest bounds preserved by the witness: the asn1scc
variant is a different schema, its fixed wrapper overwrites the error and
exact-9 staging is artificial for the natural 12-byte type; the IEC v1.6.2
bypass is harness-specific with rung 4 UNKNOWN; DataSketches has relative
steering only; RabbitMQC address disclosure is simulated by a lab file; Pillow
W4 is a type-confusion fault, not chosen-code execution. No admission opens or
withdraws on these verdicts; rung 4 stays ◐ (— for IEC) at every target.

#### 2026-11-21 ~15:2xZ post-verdict evidence (author-only, replay requested)

The W74/W75 verdicts above remain accurate for the builds they replayed, but
three later lanes move the current boundary recorded in README and the
reproducibility index. Iec61850 (`cff0e31`, `fcc32d8`, `b481737`) staged chosen
bytes into `CotpConnection->socket` and `socketExtensionBuffer` of the real
unsanitized server: `r4_pointer.sh` reports 11 PASS / 0 FAIL, the loopback
client receives ASCII `IEC61850-R4!` and live code bytes under gdb with ASLR
disabled, and both cases SIGABRT after the send. A conforming
`poc/exploit_client.c` fails to connect on fixed v1.6.2, so the earlier
raw-client AARE-reuse bypass stays harness-specific rather than fix failure.
Asn1scc (`ab30ea2`, `240da9e`, `2de7032`) consumed chosen next-chunk size bytes
into an overlapping allocation that changes a live generated object's fields
(W78 #967 replayed the semantic claim, flagging the ad-hoc digest recipe as a
NIT), then a wire-chosen callback pointer in a `-no-pie` lab `Session` layout
reached `marker()`; no real ASN.1 application, arbitrary-address write or ASLR
defeat, and Result 4 awaits replay. DataSketches (`cc9ba4d`, `aa9ebe8`) measured
the pinned write in the shipped PostgreSQL extension's client-`bytea`
deserialization on a loopback PG 16.4, with fixed 5.3.0 rejecting the same
image; palloc means the glibc steering lanes do not transfer, no crash or call
occurred and the shipped-app grade was not advanced. All three post-verdict
lanes are author evidence pending independent replay; no grade promotion
follows from these commits alone.

#### 2026-11-21 ~19:5xZ rung-5 attempts (FreeSWITCH ESTABLISHED, Iec61850 pending)

Two additive R5 limbs were measured under owner standing #8. FreeSWITCH
(`462e887`, recipe in `reports/frontier-freeswitch2shell.md`) carries a forged
`SSL`/`SSL_METHOD` in the same extended-length WebSocket frame, redirects
`SSL_shutdown`'s indirect call to `system()` and gets a target-written marker
(`r5`, wire variation `r5v`) with safe and pinned-fixed marker-absent controls
and a `system(rdi=forged SSL)` trace. Witness #1118 replayed it from clean
blobs, varied the wire command (`pwd>p1`) for a distinct side effect and
ESTABLISHED rung 5 under the recorded conditions: ASLR-off calibration and
trigger, opt-in module gates, lab shims, sudo-root loopback netns;
ASLR-on reachability stays UNKNOWN. The README R5 cell is filled for this
build only. Iec61850 (`3777729`, `reports/iec618502shell-r4.md`) stages an
ObtainFile command string and sends a wire-supplied chain that calls real libc
`system` in the live unsanitized server (`R5_IEC_MARKER_49035`, 18 bytes), with
benign-staged-file and released-v1.6.2 marker-absent controls and a
clean-archive 15 PASS / 0 FAIL replay. Its witness replay is still owed, so
that R5 cell stays `—`. Commands, expected bytes and gitignored-log policy are
in the 2026-11-21 addenda of `docs/reproducibility.md`; the contract and lane
status are in `docs/rce.md`.

#### Admitted 2026-11-21 ~15:4xZ: OpenJpeg2Shell / openjpeg2shell (OSV-2025-219, no CVE/GHSA)

Frontier published the brief `reports/frontier-openjpeg2shell.md` and handoff
#956. The operator admitted this target under standing approval #6, no
re-ask. All five elements are recorded in
`.mishe-tauftauf/charters/openjpeg2shell.md`: **claim source** —
OSV-2025-219 / OSS-Fuzz 403673832, "Heap-buffer-overflow in
`opj_j2k_read_tile_header`", published 2025-03-18, modified 2026-10-20,
WRITE 8, ecosystem severity HIGH; upstream issue #1620 and fix PR #1621;
eight SHA-256 pins in `lab/frontier/openjpeg2shell/src/SHA256SUMS` and
`PROVENANCE.md`. There is no CVE or GHSA id in the OSV record, so the
admission is recorded under the OSV id. **Identifier** — OSV-2025-219.
**Affected/fixed pin** — OSV names v2.5.3 and v2.5.4 affected; vulnerable
v2.5.4 pinned; fixed by master commit `91d08b11a72764f6d199f32fa0c1b1abd4edc2ad`
(merge `d33cbecc`, 2026-02-10) with **no tagged release containing it**, so
every fixed-side claim is scoped to that pin per the operator #916 precedent;
**primitive** — `j2k.c:8939` sizes the 24-byte-per-entry `tp_index` from the
TLM tile-part count (one in the PoC) while `j2k.c:4659` takes the unbounded
SOT `TPsot` into `current_tpsno`; `opj_j2k_read_sod` stores two unguarded
8-byte `OPJ_OFF_T` offsets at `:5086`/`:5088`, so `TPsot=1` writes 8 bytes
at base +32, 8 bytes past the 24-byte region; fixed `91d08b11` guards both
stores with `if (tp_index && l_current_tile_part < nb_tps)`; **rung-4
plausibility** — write value is a codestream-derived 64-bit offset chosen
through layout and the destination through `TPsot`; Pillow GHSA-78g4-xqwv-q3g8
bundles libopenjp2 2.5.4 reachable from `Image.open().load()` but that route
was NOT built or tested.

Operator check before admission: witness #955 replayed the frontier brief
(scoped commit `958b319`) from a clean archive ESTABLISHED AS CLAIMED —
10 PASS / 0 FAIL rc 0, trace
`sha256=6983a6a11c8236c6e991e15faa326b4c64f6269cf7f5f4fabca081bf7aa111ea`,
all eight pins OK, ASan `WRITE of size 8` at pinned `j2k.c:5086` through the
real `opj_decompress` chain, fixed pin `91d08b11` clean, and two one-byte
counterexamples making the TLM/SOT mismatch causal (full evidence #957,
verdict #958). Rungs 1/2/3 ESTABLISHED on the real pinned `opj_decompress`;
rung 4 INSTRUMENTED: two chosen 64-bit stream offsets byte-exact at the
TPsot-derived +32/+40 offsets in staged adjacent heap (PoC 157/159;
At admission no JPEG 2000 application, listener, real heap neighbour, pointer,
control-flow diversion or execution was shown — all UNKNOWN. Later commits
`cad1baf`/`4df17d7` found a live Python object exactly on the TPsot=1
destination and wrote an exact chosen static pointer (`&PyLong_Type`) into its
`ob_type` with ASLR on (4 PASS / 0 FAIL, trace `769e135e…`); no indirect call
followed, so rung 4 stays PARTIAL.

The two-pane `openjpeg2shell` window (inner socket, index 60), seed wall and
registry entry 62 were pre-created by frontier and are already live; do not
recreate or edit them. The operator created this mind's charter, the 55th
`engine/routes.json` entry and its wake trigger units with the pinned
full-flag sync from `docs/runtime-pin.md`; never run a bare `mishe sync`.
Cheapest next rung: build the real `opj_decompress` or Pillow/libopenjp2 2.5.4
consumer on loopback, feed the padded codestream, watchpoint
`tp_index[1].end_header`, inspect the real heap neighbour before any pointer
claim; keep every fixed-side label as a pin, not a release.

#### 2026-11-21 ~15:4xZ operator disposition of the openjpeg admission

Admitted under standing #6 on the completed frontier brief and witness #958
verdict; no grade promoted past the labeled INSTRUMENTED rung 4. WolfSsl2Shell
(CVE-2026-6679, brief `reports/frontier-wolfssl2shell.md`, handoff #973) is
**deferred**, not declined: its witness replay request #972 had no verdict at
this wake's tape tail (#981). Trigger to admit: a witness ESTABLISHED verdict
on #972; the window, seed wall, brief, harness and registry entry already
exist and must not be recreated. This disposition is only a bounded wait on
missing evidence; adjacent admission work continues on any new verdict.

#### Admitted 2026-11-21 ~15:5xZ: WolfSsl2Shell / wolfssl2shell (CVE-2026-6679 / GHSA-c9q2-5c67-xg9p)

The prior wake's WolfSsl2Shell deferral was a bounded wait on one missing
verdict, not a decline. Frontier's brief `reports/frontier-wolfssl2shell.md`
and handoff #973 carried all five elements; witness #985 at 15:48:06Z
answered replay request #972 ESTABLISHED AS CLAIMED at the labeled grades
(restated to the operator in #992 and by frontier in #993). The operator
admitted this target under standing approval #6, no re-ask. All five elements
are recorded in `.mishe-tauftauf/charters/wolfssl2shell.md`: **claim source**
— CVE-2026-6679, CNA wolfSSL Inc., published/updated 2026-06-25, "DTLS 1.3
ACK serialization heap buffer overflow via integer truncation", CWE-190/
197/787, CVSS 4.0 8.8 HIGH, vector
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`, credit Nicholas
Carlini; CVE record, cveawg API, GHSA-c9q2-5c67-xg9p and the vendor table;
fix PR `wolfSSL/wolfssl#10116`; four SHA-256 pins for both tagged tarballs,
the PR diff and the CVE JSON in `lab/frontier/wolfssl2shell/src/SHA256SUMS`
and `PROVENANCE.md`. CVE-2026-5264 is a different ACK-processing bug — keep
them separate. **Identifier** — CVE-2026-6679 / GHSA-c9q2-5c67-xg9p.
**Affected/fixed pin** — wolfSSL 5.4.0–5.9.0 affected; vulnerable
`v5.9.0-stable` pinned; fixed in the **tagged release `v5.9.1-stable`**, with
`DTLS13_ACK_MAX_RECORDS 128` in `internal.h:5852-5859`, the insert cap at
`dtls13.c:742` and the `recordsCount > 128` / `written + 16 > msgSz` checks at
`:2618`/`:2653` — stronger than PR 10116's 512 cap, no unmerged-pin caveat.
**Primitive** — pinned `dtls13.c:2537` `Dtls13GetAckListLength` truncates
`16 * numberElements` to a `word16` at `:2550`; 4097 records declare 16 bytes,
so `Dtls13WriteAckMessage` (`:2554`) sizes a 31-byte region via
`CheckAvailableSize` (`:2588`) then writes 16 bytes per record with `c64toa`
of sender-chosen epoch/seq at `:2604`/`:2606` (sink `misc.c:1010`).
`Dtls13RtxAddAck` (`:723`) is called from `Dtls13RecordRecvd` (`:1547`) for
every received handshake record before peer authentication — the pinned
remote-reach claim, NOT driven by the harness. **Rung-4 plausibility** —
pre-auth network-facing DTLS 1.3 with a structured 16-byte-per-record
sender-chosen write; the live path and a live victim object remain to be
shown, so this is a plausibility claim, not a built consumer.

Operator check: witness #985 replayed scoped commit `fdc7e80` from a clean
git archive — 4/4 pins OK, `run.sh` 13 PASS / 0 FAIL rc 0, trace
`sha256=fb6831dc85fe7afeaaf688ac519a49bccde954a03159211fb256247c1c7ac05d`,
`chosen_readback.sh` 6 PASS / 0 FAIL. ASan `WRITE of size 8` 0 bytes after a
31-byte region in `c64toa misc.c:1010` ← `Dtls13WriteAckMessage dtls13.c:2604`,
allocation via `CheckAvailableSize :2588` ← `GrowOutputBuffer internal.c:11415`;
`word16_length=16` against exact 65552. Fixed tagged v5.9.1: 128 cap,
`msgSz=2048`, write return 0, ASan-clean. Rungs 1/2/3 ESTABLISHED on the
verbatim pinned source; rung 4 INSTRUMENTED — chosen epoch
`0xc0ffee1122334455` and seq patterns at offsets 31/47/63/159 in staged
heap. At admission no DTLS socket, listener, handshake record path, live
neighbour, pointer, control-flow diversion or execution — all UNKNOWN at
admission. Later `8636e5d` drove 4097 paced loopback fragments through the
real `Dtls13RecordRecvd` to `ack_count=4097` with ASan `WRITE of size 8` at
`c64toa`; `fde4360` preserved the failed peer-set variant (peak 3991/3983).
No live neighbour, pointer control or execution.

The two-pane `wolfssl2shell` window (inner socket, index 61), seed wall and
registry entry 63 were pre-created by frontier and are already live; do not
recreate or edit them. The operator created this mind's charter, the 56th
`engine/routes.json` entry and its wake trigger units with the pinned
full-flag sync from `docs/runtime-pin.md`; never run a bare `mishe sync`.
Cheapest next rung: real loopback DTLS 1.3 server, >4096 distinct handshake
record numbers from a loopback UDP sender, gdb watch on `Dtls13RecordRecvd`
filling `seenRecords` to the wrap point, then inspect the overwritten region
for a live object or pointer before any pointer claim.

#### 2026-11-21 ~15:5xZ operator disposition of the wolfssl admission

Admitted under standing #6 at the labeled rung-4 INSTRUMENTED grade on
witness #985/#992; no grade promoted past it. The stale deferral note above
is historical and resolved by this verdict. Other peer verdicts in #992
(IEC R4, asn1scc Results 4/5) and the Pillow W5 recipe repair/negative
control are already-admitted targets at labeled grades; docs owns their index
rows. No new advisory claim in the current dossier or tape.

#### Admitted 2026-11-21 ~16:2xZ: Htslib2Shell / htslib2shell (CVE-2026-62257 / GHSA-6q7c-m967-9v37)

Frontier's admission request #997 carried brief
`reports/frontier-htslib2shell.md`, scoped harness commit `bced853`, a seed
wall and an already-live two-pane window (index 62). Witness verdict #1008
(restating #1007 to frontier) replayed `bced853` from a clean archive with its
own offline rebuild: 10/10 pins, 9 PASS / 0 FAIL rc 0, trace
`sha256=40f5992496d13bfc3b575625a5b6bb6e8dfbd1eb397b8b5b25ced7458c04f464`,
source lines 1378/1388/2075/2079/3882 and `cram_io.c:4620` matching, fixed
tagged 1.24 rejecting codec 51, and the index-1025 negative reproduced
independently. The operator admitted this target under standing approval #6,
no re-ask. All five elements are recorded in
`.mishe-tauftauf/charters/htslib2shell.md`: **claim source** — CVE-2026-62257
/ GHSA-6q7c-m967-9v37, CNA GitHub, Inc., "Heap read and write overflow in
HTSlib CRAM 4.0 decoder", CWE-122/125/787, CVSS 4.0 8.8 HIGH, vector
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N`, credit Trail of
Bits and Anthropic; CVE record, cveawg API, OSV, GHSA and ten SHA-256 pins in
`lab/frontier/htslib2shell/src/SHA256SUMS` and `PROVENANCE.md`. **Identifier**
— CVE-2026-62257 / GHSA-6q7c-m967-9v37. **Affected/fixed pin** — affected
`<1.21.2`, `1.22.0–1.22.2`, `1.23.0–1.23.1`; vulnerable tagged 1.23.1, fixed
tagged 1.24 plus 1.21.2/1.22.3/1.23.2 backports; fix commits d66a77d
(codec-local `expanded` members, no `hdr->ncodecs++`), c0b5037 (int32/nbits
guards) and a3e8dca (CRAM v4 removed). **Primitive** — `cram_io.c:4620`
allocates 512 pointer slots; `cram_codecs.c:3882` increments `hdr->ncodecs`
per sub-codec; `cram_xpack_decode_expand_char` at `:1378` reads and at `:1388`
writes `slice->block_by_id[512 + codec_id]`, reached with `codec_id=1` (index
513) through real `cram_decoder_init`/`cram_xpack_get_block`; XRLE has the same
pattern at `:2075`/`:2079` (not exercised). **Rung-4 plausibility** — an
8-byte pointer store with a partially file-derived index and a tagged fixed
release; `AV:N`/ACE are advisory claims about downstream deployments, with
no web-facing consumer built here.

Rungs 1/2/3 ESTABLISHED at the labeled sink/accounting/ASan grades; rung 4
stays INSTRUMENTED. Later wakes built a real CRAM v4 file with htslib's own
writer and a parser path from file bytes to the OOB sink, and a file-derived
`codec_id=2` plain-build pointer store whose live neighbour is the slice's
`s->cigar` array; consumer order rewrites those entries before they are read,
so there is still no chosen pointer, consumed neighbour, control-flow
diversion or execution.
The negative `codec_id=513` (index 1025) leg, whose read landed in live heap
(`0xbebebebebebebebe`) with no ASan report, is preserved. The two-pane window,
seed wall and registry entry were pre-created by frontier and were not
recreated or edited. The operator created the 57th `engine/routes.json`
entry and this mind's wake trigger units with the pinned full-flag sync from
`docs/runtime-pin.md`; never run a bare `mishe sync`. The original cheapest-next-rung CRAM-file experiment has been run (see the
reproducibility index, Htslib2Shell row): a genuine file reaches the sink
under ASan with three reports, and `crafted2.cram` fires an unsanitized store
in a plain build. The current ceiling is a record shape whose quality-phase
QS decode succeeds after CIGAR generation so the corrupted `s->cigar` is
actually consumed, plus a web-facing decoder accepting uploaded CRAM.

#### Admitted 2026-11-21 ~17:0xZ: CivetWeb2Shell / civetweb2shell (CVE-2025-55763)

Frontier's admission request #1025 carried brief
`reports/frontier-civetweb2shell.md`, harness `lab/frontier/civetweb2shell`
(commit `7164a1a`, four pins, 23 PASS / 0 FAIL, trace
`2ecaac759e4230f9549507091cff212adb68dd63e650d3abf6ced2406e5e2d50`,
reproduced twice), a seed wall and an already-live two-pane window (inner
socket index 63). Witness verdicts #1027/#1029 replayed a clean
`git archive 7164a1a` with an offline rebuild: 4/4 pins, 23 PASS / 0 FAIL
rc 0, exact trace match, ASan `WRITE of size 2` at `civetweb.c:15261` in
`handle_request` reached through the real listener, 0 bytes after an
8197-byte region, fixed merged commit `c584455` build ASan clean with 301.
The operator admitted this target under standing approval #6, no re-ask.
All five elements are in `.mishe-tauftauf/charters/civetweb2shell.md`:
**claim source** — CVE-2025-55763, MITRE record published 2025-08-29,
CISA-ADP CVSS 3.1 7.5 HIGH with an availability-only vector, public
`krispybyte` PoC, four SHA-256 pins in
`lab/frontier/civetweb2shell/src/SHA256SUMS`. **Identifier** —
CVE-2025-55763. **Affected/fixed pin** — affected 1.14–1.16, vulnerable
tagged v1.16, fixed only as merged commit `c584455`
(`civetweb/civetweb#1347`); no tagged fixed release is claimed. **Primitive**
— raw 9002-byte request path survives `remove_dot_segments` cleaning to `/d`
and fills the 8197-byte redirect buffer allocated at `civetweb.c:15253`, so
`:15261` stores `?\0` 0 bytes past the region. **Rung-4 plausibility** — a
real network-facing C listener and deterministic trigger, but a bounded
string append, not a pointer write; the RCE claim is unverified.

Rungs 1/2/3 ESTABLISHED at the labeled sink/accounting/ASan grades; rung 4
stays INSTRUMENTED — no chosen pointer, control-flow diversion or execution.
Wake 1 measured chosen query bytes in a live adjacent canary in an
instrumented copy. Later unmodified-build measurements (`f6c542a` natural
adjacency, `cb75a02` chosen-byte overwrite of a live heap header) supersede
the earlier instrumented-only and availability-only ceilings. Witness #1050
first recorded it UNKNOWN-WITH-MISSING-EVIDENCE because the scripts were
untracked; commit `b9bd4ee` supplies `run-rung4.sh` and raw logs (19 PASS /
0 FAIL, trace `6678d7a9…e0be3d2`), so the replay input is durable but no
independent verdict has landed yet. Preserved negatives: public PoC returns 404 in the
test document root, long query with short path returns clean 301, short
slash run is a clean control. The two-pane window, seed wall and registry
entry were pre-created by frontier and were not recreated or edited. The
operator created the 58th `engine/routes.json` entry and this mind's wake
trigger units with the pinned full-flag sync from `docs/runtime-pin.md`;
never run a bare `mishe sync`. The wake-1 chosen-byte neighbour is durably
replayable (`bash lab/frontier/civetweb2shell/run-rung4.sh <outdir>`); its
canary was instrumentation. Natural adjacency and a chosen-byte overwrite of
live heap metadata were later measured in the unmodified build
(`f6c542a`, `cb75a02`). No chosen pointer, control-flow diversion or code
execution was observed.

#### Admitted 2026-11-21 ~17:5xZ: Open625412Shell / open625412shell (CVE-2026-126962 / GHSA-x8hf-mwqg-74x6 / ZDI-26-990)

Frontier's find-nineteen admission DM #1049 carried brief
`reports/frontier-open625412shell.md` (commit `86d4da6`), harness
`lab/frontier/open625412shell` (two hash-pinned full tagged tarballs and four
committed source/patch pins, 8 PASS / 0 FAIL, trace
`31e535b91ae2375978344c27b33b25b38fd9dda9f096ccf96e001672dff71284`), a seed
wall and an already-live two-pane window (inner socket index 64, registry
updated by frontier). The operator admitted this target under standing approval
#6, no re-ask. Operator admission replay ~17:49Z: 4/4 committed pins verify
with `sha256sum -c`, the tarball manifest verifies inside `run.sh`, 8 PASS /
0 FAIL rc 0 with the same trace, ASan `WRITE of size 8` at
`ua_subscription.c:1645`, fixed 1.5.6 clean. All five elements are in
`.mishe-tauftauf/charters/open625412shell.md`: **claim source** —
CVE-2026-126962 / GHSA-x8hf-mwqg-74x6 / ZDI-26-990, MITRE published
2026-11-17T23:12:58.718Z, GHSA published 2026-11-18T00:33:24Z, ZDI-26-990
2026-11-13 CVSS 8.8 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` with PR:L a real
precondition and RCE a claim; records, fix commits, tag containment and hashes
in `lab/frontier/open625412shell/PROVENANCE.md`. **Identifier** —
CVE-2026-126962 / GHSA-x8hf-mwqg-74x6. **Affected/fixed pin** — MITRE affected
1.5.4; vulnerable tagged 1.5.4, fixed **tagged v1.5.6** containing fix commits
`2da371bcdaadeb23051635a60e38f31039af9fd8` and
`bc30df3adab5cc61383cb7e7f551bfd6f7ac160c`; the fix loop is present at 1.5.6
`:629` and absent from 1.5.4. **Primitive** —
`Operation_TransferSubscription` memcpys the whole `UA_Subscription` at
`:599`, migrates `monitoredItems` at `:619-627` but not
`samplingMonitoredItems`, leaving PUBLISH-sampling items' `le_prev` in the old
subscription; its deferred free is followed by an 8-byte `LIST_REMOVE` write
into freed memory at `ua_subscription.c:1645`. **Rung-4 plausibility** — a
network-reachable OPC UA server service with an exact tagged fix; grooming the
freed chunk and observing a downstream dereference is a claim, not an
observation.

Rungs 1/2/3 ESTABLISHED at the labeled service/accounting/ASan grades; rung 4
INSTRUMENTED. Live-neighbour and non-NULL pointer overwrites were later
observed (`17de7c0`, `f167900`): the stale write lands on byte 200 of a live
replacement subscription whose head changes `0x514000000840` →
`0x514000000440`, an item owned by the still-live transferred subscription.
The values come from created objects, not attacker-chosen bytes; no diversion
or execution. Two documented stand-ins: the
`allowTransferSubscription` consent hook returns true (authorization is a
precondition, not the bug) and the harness calls the same internal
`UA_Subscription_delete` the status-change path uses before driving the event
loop to the deferred free, because no client PublishRequest was queued. No
listener and no off-process traffic. The window, seed wall and registry entry
were pre-created by frontier and were not recreated or edited. The operator
created the 59th `engine/routes.json` entry and this mind's wake trigger units
with the pinned full-flag sync from `docs/runtime-pin.md`; never run a bare
`mishe sync`. This makes 55 admitted target minds in the README table; an
independent witness replay is still owed.

#### Admitted 2026-11-21 ~18:0xZ: KnotResolver2Shell / knotresolver2shell (CVE-2026-66374)

Frontier's DM #1070 carried brief `reports/frontier-knotresolver2shell.md`
(commits `186fa11`, `814526b`), two hash-pinned tagged tarballs and a fix patch
with SHA-256 pins in `lab/frontier/knotresolver2shell/src/SHA256SUMS` and a
URL/digest table in `PROVENANCE.md`. The operator admitted this target under
standing approval #6, no re-ask. Operator pin check ~18:03Z: `sha256sum -c`
3/3 OK. Unlike the recent admissions, this one is **RUNG 0** — frontier built
nothing, ran no PoC and opened no window or seed wall; the operator created
both. All five elements are in
`.mishe-tauftauf/charters/knotresolver2shell.md`: **claim source** —
CVE-2026-66374 (MITRE published 2026-07-25T00:28:34.320Z, CVSS 3.1 8.1
`AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:L`), researcher report at
`seclists.org/oss-sec/2026/q3/226` by Przemyslaw Frasunek with follow-up `/234`,
and vendor 6.4.1 NEWS 2026-07-22 ("allowing even RCE"); the RCE language is a
claim. **Identifier** — CVE-2026-66374 (no GHSA cited). **Affected/fixed pin**
— advisory range "before 6.4.1"; vulnerable tagged v6.4.0 tarball
`e8e771deb65e57827e709deb286ca884702e44a6e7ae062d7e01a12c45558fc3`, fixed
tagged v6.4.1 `20eb8b31a68e28b7e27e1787e8ba97dafee00efd04894dd777dfbde9ad902950`,
fix commit `7eb2e11810966323ed7c2385b8922eb8d57c46d2` an ancestor of v6.4.1
(compare ahead 11, behind 0), patch pin
`d40555c4072a351ab000f7c388b8eed00596cd7c8908ec00d84414fa8abd73ce`.
**Primitive** — pinned 6.4.0 `kr_recv_stream_data_cb()` reallocs to
`wire_buf_data_length(...) + datalen` but separately does
`stream->pers_inbuf.size += datalen` at `daemon/quic_conn.c:107`, so tracked
capacity drifts above the allocation; unbounded `memcpy`s at `:120`/`:124`
write attacker STREAM-frame bytes with no offset or FIN consistency check
(`:133–136`). Pinned 6.4.1 bounds the copy with an offset assert `:158–161`,
split prefix parsing and `wire_buf_reserve()` `:166–203`, a free-space /
`malformed` check `:216–224` and a FIN size check `:229–238`; no `size +=`
line remains. **Rung-4 plausibility** — an unauthenticated DoQ listener with
a tagged fix and a source-bound accounting bug; the researcher claims six
STREAM frames, an ~814-byte OOB write over a gnutls cleanup handler's
`flag`/`fn`/`arg`, RIP/RDI control and a `system()` PoC with ASLR off.
Caveats kept honest: DoQ is beta and non-default, the write and RIP control
depend on jemalloc size classes and gnutls version, ASLR-on exploitability
needs an unknown information leak, and the PoC was not fetched or run.

At admission no rung was established; commit `bebef9b` later reached rung 3 on
pinned 6.4.0 (ASan `WRITE of size 1198` at `quic_conn.c:124` past a 5762-byte
realloc, fixed 6.4.1 rejecting frame 2 cleanly), with rung 4 UNKNOWN. The
operator created the 60th `engine/routes.json` entry and this mind's wake
trigger units with the pinned full-flag sync from
`docs/runtime-pin.md`, a seed wall and the two-pane window (inner socket index
65). Never run a bare `mishe sync`. This makes 56 admitted target minds in the
README table; an independent witness replay is owed once a harness exists.

#### Admitted 2026-11-21 ~19:00Z: ATS2Shell / ats2shell (CVE-2026-58154)

Frontier's DM #1076 carried brief `reports/frontier-ats2shell.md` (commit
`595abba`), two hash-pinned tagged tarballs, their published SHA-512 sidecars
and a fix patch with SHA-256 pins in `lab/frontier/ats2shell/src/SHA256SUMS`
and a URL/digest table in `PROVENANCE.md`. The operator admitted this target
under standing approval #6, no re-ask. Operator pin check ~18:59Z:
`sha256sum -c SHA256SUMS` 5/5 OK and `sha512sum -c` on both sidecars 2/2 OK.
All five elements are in `.mishe-tauftauf/charters/ats2shell.md`: **claim
source** — CVE-2026-58154 (CNA Apache, MITRE published 2026-07-29T08:24:02Z,
CWE-787, CVSS 3.1 8.9 `AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:H`), vendor
security-2026-07.html, Apache announcement and oss-sec /2026/q3/338; the
advisory bundles 34 issues, so its severity is not evidence for this hunk.
**Identifier** — CVE-2026-58154 (no GHSA cited). **Affected/fixed pin** —
affected 8.0.0–8.1.11 / 9.0.0–9.2.14 / 10.0.0–10.1.3, fixed 9.2.15 / 10.1.4;
vulnerable tagged 10.1.3 tarball
`b92302005fbd79c3918b97c8546471b988ce0a11dc99a2d39ba092bec45d843a`, fixed
tagged 10.1.4 `47f09c65a3de70db38990124834f292081520e3290a7e781898291019b6f9d9f`,
fix `f4561a945ac52010a598e0cd19b12d058044c3d2` with 10.1.x backport
`5642692b888fcc9cf26a43ec2f39a05f938c4963` an ancestor of tag 10.1.4 (compare
ahead 128 / behind 0), patch pin
`6a6626f89f4255beee82b900a1ad35aa8150862ded9dedcd92cedd396e178092`.
**Primitive** — pinned 10.1.3 `src/proxy/hdrs/MIME.cc:2427-2432` stores fixed
`0x20` at `text.data()-1` and, on a preceding CR, at `input.data()-1`; fixed
10.1.4 `:2477-2484` guards with `unfold > input.data()` and `m_line.back()`.
The fix's two-fragment regression input is `"Foo: bar\r"` then `"\n baz\r\n"`;
its NOTE limits the trigger to a CR|LF split across parser views.
**Rung-4 plausibility** — pre-auth HTTP header parsing in a web-facing reverse
proxy with a source-bound one-byte store; attacker influence is the split
position, not the byte value. Ranked below KnotResolver2Shell: no chosen bytes,
no pointer control, no public RCE claim for this hunk, and allocation-boundary
reachability UNKNOWN without a build.

At admission no rung was established: no build, no bytes, no trigger. The
operator created the 61st `engine/routes.json` entry, this mind's wake trigger
units with the pinned full-flag sync from `docs/runtime-pin.md`, a seed wall,
the charter and the two-pane window (inner socket index 66). This makes 57
admitted target minds in the README table. Never run a bare `mishe sync`. The
bounded first experiment is an ASan build of the pinned 10.1.3 / 10.1.4
MIMEScanner unit tests replaying the fix's two-fragment input; a witness replay
is owed once a harness exists.

#### Admitted 2026-11-21 ~19:5xZ: Exim2Shell / exim2shell (CVE-2026-45185)

Frontier's DM #1092 carried brief `reports/frontier-exim2shell.md` (commit
`1bbfaef`), two hash-pinned release tarballs and the raw fix hunk in
`lab/frontier/exim2shell/src/SHA256SUMS`. The operator admitted this target
under standing approval #6, no re-ask. Operator pin check 19:44Z:
`sha256sum -c SHA256SUMS` 2/2 OK (self-computed digests, no published sidecar).
All five elements are in `.mishe-tauftauf/charters/exim2shell.md`: **claim
source** — vendor advisory `EXIM-Security-2026-05-01.1.txt` (announced
2026-05-12, reporter federic.kirschbaum@xbow.com), MITRE CVE record (CNA MITRE,
2026-05-12, CWE-416, CVSS 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), XBOW
blog as a claim (oss-security /2026/05/12/4 body not retrieved). **Identifier**
— CVE-2026-45185 (no GHSA cited). **Affected/fixed pin** — affected 4.97 through
4.99.2, fixed 4.99.3; vulnerable tarball
`e9e33c8cde9dddc117eaab40ae529ed703537b14e1257a06b98460738f75da84`, fixed
`714efe07930ec902224c62c86d446a85b1ee341abdd6c76699949d4de2b52524`; fix is
`tls_close(NULL, TLS_NO_SHUTDOWN)` → `tls_close_notify()` at `tls-gnu.c:639`
plus `smtp_rcv_cleartext()` and bdat pop/re-push in `smtp_in.c:984+`. Exact
fix commit ID UNKNOWN — tarballs only. **Primitive** — a GnuTLS `close_notify`
mid-BDAT frees the 4096-byte `xfer_buffer` while the bdat receive layer is
still installed; the next cleartext byte reaches stale `tls_ungetc()` and
stores one fixed `0x0A` at `xfer_buffer[--lwm]`. XBOW's ASLR-off/non-PIE RCE
escalation is a labeled claim; the real build yielded a stack leak.
**Rung-4 plausibility** — pre-auth SMTP path, one-byte write into freed heap
metadata, byte-pinned fixed side; attacker controls the position, not the byte.
Ranked above ATS: a public escalation narrative exists. Honest ceiling: ASan
write confirmation first, then a benign marker at a chosen allocator offset;
measure the host's actual allocator state before grooming (nginx2root lesson).

At admission no rung was established: no build, no bytes, no traffic. The
operator created the 62nd `engine/routes.json` entry, this mind's wake trigger
units with the pinned full-flag sync from `docs/runtime-pin.md`, a seed wall,
the charter and the two-pane window (inner socket index 67). This makes 58
admitted target minds in the README table. Never run a bare `mishe sync`. The
bounded first experiment is a `USE_GNUTLS=yes` ASan build of 4.99.2 driving
STARTTLS → short BDAT → close_notify → one cleartext byte on loopback, with a
4.99.3 control; a witness replay is owed once a harness exists.

#### Admitted 2026-11-21 ~20:32Z: NettyTcnative2Shell / netty2shell (CVE-2026-116539)

Frontier's DM #1119 carried brief `reports/frontier-netty2shell.md` (commit
`47a8038`) with three hash-pinned files in
`lab/frontier/netty2shell/src/SHA256SUMS`. The operator admitted this target
under standing approval #6, no re-ask. Operator pin check 20:30:34Z:
`sha256sum -c SHA256SUMS` 3/3 OK (self-computed digests; the auto-generated
GitHub tag archives have no published sidecar). All five admission elements
are in `.mishe-tauftauf/charters/netty2shell.md`: **claim source** — maintainer
advisory GHSA-gf9q-9mg7-g5qh (published 2026-10-26 by `normanmaurer`, reporter
`@August829`), Debian tracker CVE-2026-116539 and the NVD-derived
GHSA-22qq-f4wc-4vfx; the CVE and NVD full bodies were not retrieved.
**Identifier** — CVE-2026-116539 / GHSA-gf9q-9mg7-g5qh. **Affected/fixed pin**
— affected `<= 2.0.83.Final`, fixed 2.0.84.Final; vulnerable tarball
`f6ae09cf544397edd33ffd23affd7cad09059d757b1510d4d909539cadbcb335`, fixed
`cb419d0132a970338087a677a82dc4e5e3a4837c1da6ff1f15bd1a0ba94ccef0`, fix patch
`b51333461dfbbc261f9e8463a1f602482de9c59efcafade677caf0431a88a7ec`, fix
commit `92dd66fd1243d85c05a61288f96367a70260b6b8` (parent `e28f849e`). The raw
hunk in `openssl-dynamic/src/main/c/ssl.c` `@@ -196,7 +196,9 @@` adds a modulo
to `startIndex` in `tcn_write_to_bytebuffer`. **Primitive** — after a partial
drain of the non-application ring, offset + length exceeds the buffer size;
with size 10 the maintainer's four JNI calls reach `startIndex=11`,
`writeChunk=-1` and `memcpy(&buffer[startIndex], in, (size_t)writeChunk)` at
raw `:207-209`, a near-`SIZE_MAX` length write past an `OPENSSL_malloc` buffer,
plus an OOB `&in[writeChunk]` read. The observed consequence is a SIGBUS crash
(3/3), not RCE. **Rung-4 plausibility** — attacker-chosen source bytes at a
cross-object destination with a byte-exact fixed side; first bytes past the
ring are chosen input. Honest gate: wire-only reachability UNKNOWN — the
maintainer states the PoC does not derive the trigger from unmodified TLS wire
bytes against a specific integrator; buffer size and partial-drain timing
matter. First work stays harness-grade rungs 1–3.

At admission no rung was established: no build, no bytes, no traffic. The
operator created the 63rd `engine/routes.json` entry, this mind's wake trigger
units with the pinned full-flag sync from `docs/runtime-pin.md`, a seed wall,
the charter and the two-pane window (inner socket index 68). This makes 59
admitted target minds in the README table. Never run a bare `mishe sync`. The
bounded first experiment is a Linux ASan build of the pinned 2.0.83.Final
`openssl-dynamic` library plus the advisory's four-step JNI harness, with a
2.0.84.Final fixed control; a witness replay is owed once a harness exists.

#### Admitted 2026-11-21 ~21:03Z: WAMR2Shell / wamr2shell (CVE-2026-54912)

Frontier's newest ranking (commit `7dff88c`, 20:58:18Z,
`reports/frontier-wamr2shell.md`) put this candidate at #1, ahead of Perl
CVE-2026-15534 at #2. The operator admitted it under standing approval #6,
no re-ask, with no separate DM required. Operator pin check ~21:02Z:
`sha256sum -c SHA256SUMS` 5/5 OK in `lab/frontier/wamr2shell/src`
(self-computed digests; raw upstream files and auto-generated commit patches
carry no published sidecar). All five admission elements are in
`.mishe-tauftauf/charters/wamr2shell.md`: **claim source** — maintainer
advisory GHSA-jjv3-x3jf-cg49, CVE record CVE-2026-54912 and OSV, all read by
frontier; secondary aggregators are not relied on for bytes. **Identifier** —
CVE-2026-54912 / GHSA-jjv3-x3jf-cg49, CWE-787. **Affected/fixed pin** —
affected `<=2.4.4`, fixed `2.4.5`, `WAMR_BUILD_FAST_INTERP=1` affected
configuration; fix commit `b1353b5e8983047ff68829c99abf1355d5f389cf`;
pinned vulnerable/fixed `wasm_loader.c`, patch and upstream regression
`.wasm`/`.wat` with digests in the charter. **Primitive** — Pass 1 sizes
`p_code_compiled` once (`WAMR-2.4.4-wasm_loader.c:9329-9332`); between passes
the const arrays are sorted and deduped, so Pass 2 emits table references and
`reserve_block_ret()` copy operands Pass 1 never counted, writing past the
buffer. Fix `b1353b5e` aligns the decision across passes and raises the dedup
threshold to `FAST_INTERP_CONST_DEDUP_SCAN_MAX 32`. Published consequence is
an ASan `WRITE of size 2` during `wasm_runtime_load`, before guest execution.
**Rung-4 plausibility** — the overflow stream carries attacker-selected
constant immediates, so chosen-byte placement is plausible but unmeasured;
wire reachability is UNKNOWN because WAMR has no in-tree listener and no
consumer is named. No RCE wording.

At admission no plant rung was established: no plant build, bytes or traffic.
The operator created the 64th `engine/routes.json` entry, this mind's wake
trigger units with the pinned full-flag sync from `docs/runtime-pin.md` (3
units written, 0 removed, wake path enabled+active), a seed wall, the charter
and the two-pane window (inner socket index 69). This makes 60 admitted
target minds in the README table. Never run a bare `mishe sync`. The bounded
first experiment is an ASan build of pinned 2.4.4 and 2.4.5 with
`-DWAMR_BUILD_FAST_INTERP=1`, replaying the exact upstream `.wasm` with a
clean fixed control, then measuring chosen-immediate byte placement;
a witness replay is owed once the harness exists.

#### Measured follow-through (21:02Z): WAMR W90 and Exim wake 2

Both bounded first experiments have now run, so the two admission-time
plausibility notes above are historical, not pending work. WAMR (`8686e9d`,
`reports/frontier-wamr2shell.md`): both tags built with fast-interp and ASan;
the pinned upstream `.wasm` gives an ASan `WRITE of size 2` on 2.4.4 and no
load-time fault on 2.4.5 — rungs 1–3 and the rung-4 negative are independently witness-ESTABLISHED (W91, #1147).
The admission guess that the OOB stream carries chosen immediates is REJECTED
by the instrumented Pass-2 log: its 61 would-be writes are const-table indices
and host branch pointers, so rung 4 is a measured negative and any future
rung-4 attempt needs a different overflow shape. Exim (`cd925eb`, `671a3b2`,
`reports/exim2shell-wake2.md`): with ASan's report redirected from the forked
child's closed stderr, the `three` shape gives a heap-use-after-free
`WRITE of size 1` at `tls.c:510` on 4.99.2 and no report on 4.99.3 — rung 3
confirmed. A later lab-only trace on the plain 4.99.2 build reached the
`receive.c:2141` call site, but `tls_close()` installs safe `smtp_ungetc`
before it and `bdat_pop_receive_functions()` restores `tls_ungetc` only
afterwards; no stale-buffer write or chosen byte followed, so rung 4 stays
unclaimed. Witness #1140 (DM 4727) ESTABLISHED rung 3 as claimed on independent
ASan-linked pinned builds, and its citation fixes landed in `a6fbe8e`. No
wire-to-RCE claim exists for either target.

#### Measured follow-through (21:27Z): WAMR chosen-immediate rung 4

The W91 rung-4 negative above applies to the upstream PoC only. A different
module shape — the pinned `.wasm` binary-patched to append eight
`i64.const <chosen>; drop` pairs after the 21-result block — reaches inline
immediate emit sites after the two-pass byte-count desync. Instrumented 2.4.4
logs chosen 8-byte values at 11/29/47/65 bytes past `p_code_compiled_end`,
with two value sets giving two different byte sequences at the same offsets;
unmodified ASan 2.4.4 reports a load-time `WRITE of size 8` in
`wasm_loader_emit_const :9382`, and 2.4.5 is clean. Rung 4 is now an author
claim pending witness replay; no wire consumer was driven and no guest code
executed, so rung 5 stays UNKNOWN. Envoy v1.39.3 is named as a genuine
network-to-`wasm_runtime_load` consumer pinning WAMR 2.4.4 fast interp, but
is NOT built or driven here. Evidence and generator:
`reports/wamr2shell-rung4.md`, `lab/frontier/wamr2shell/make_chosen_variant.py`.

#### Witness verdicts (21:1xZ): OpenJpeg rung-4 limbs

DM #1151 returned ESTABLISHED for both OpenJpeg natural-call limbs at their
labeled scope: #1144's codestream-chosen `&PyDict_Type` call through natural
`_Py_Dealloc` (six core invariants replayed; one non-grade-changing `LOAD_OK`
harness nit on the witness layout) and #1149's GOT-chosen unresolved `system`
PLT stub with a NUL argument (9 PASS / 0 FAIL). No chosen argument,
continuation into `system`, shell or listener was observed, so rung 4 stays
PARTIAL at the INSTRUMENTED grade and rung 5 UNKNOWN. The Exim #1140 citation
corrections landed in `a6fbe8e`; the plain-build `smtp_ungetc` ordering
NEGATIVE is recorded in `docs/reproducibility.md`.

#### Admitted 2026-11-21 ~21:34Z: Perl2Shell / perl2shell (CVE-2026-15534)

Frontier's brief `reports/frontier-perl2shell.md` (commit `ab458c4`, 20:46Z)
was the head of the unadmitted queue: Apache2Shell, briefly ranked #1 at
21:26Z (tape #1155, commit `4ba253f`), has been admitted since 2026-11-20
(`docs/task.md:2586`, charter, window, 41 wakes), so no duplicate target or
window was created for it. The operator rechecked Perl's pins at 21:33Z:
`sha256sum -c SHA256SUMS` 7/7 OK in `lab/frontier/perl2shell/src`
(self-computed digests; raw upstream files and auto-generated commit patches
carry no published sidecar). All five admission elements are in
`.mishe-tauftauf/charters/perl2shell.md`: **claim source** — CPAN Security
Group CVE record for CVE-2026-15534 (2026-08-09) and Stig Palmquist's
oss-security disclosure; secondary GHSA-2cxw-qmfc-3vx3, USN-8736-1.
**Identifier** — CVE-2026-15534, `regexec.c`/`S_regmatch`, CWE-190/125/787.
**Affected/fixed pin** — CNA range `0`–`5.45.1`; fixed in 5.45.2 or by the
two pinned patches `568e6fd` (unsigned countdown) and `54cf3d4` (64-bit
clean cache); pinned 5.44.0/5.45.1/5.45.2 `regexec.c` and 5.45.1/5.45.2
`regexp.h`. **Primitive** — the `I32` multiply at
`v5.45.1/regexec.c:9200-9206` clamps only negatives, so a 286331153-byte
subject with 15 WHILEMs wraps to 14 and allocates a 2-byte `poscache`;
`:9235-9240` reads out of bounds by match position × node count and
`CACHEsayNO :6504-6507` writes a single bit. **Rung-4 plausibility** — a
position-derived bit flip in heap metadata is a plausible corruption
primitive, but no chosen byte or pointer control is given, the WHILEM
pattern is unpublished, and wire reachability is UNKNOWN (CISA scores AV:L).
No RCE wording.

At admission no plant rung was established: no build, bytes or traffic. The
operator created the 65th `engine/routes.json` entry, this mind's wake
trigger units with the pinned full-flag sync from `docs/runtime-pin.md` (3
units written, 0 removed, wake path enabled+active), a seed wall, the charter
and the two-pane window (inner socket index 70). This makes 61 admitted
target minds. Never run a bare `mishe sync`. The bounded first experiment is
an ASan 5.45.1 build, deriving a 15-WHILEM pattern for the 286331153-byte
subject and replaying on a 5.45.2 control before any chosen-byte claim; a
witness replay is owed once the harness exists.

#### 2026-11-21 ~21:5xZ boundary reconciliation (commits `091488e`…`e8b106c`)
Four lanes changed evidence without changing their README grade cells:
- OpenJpeg (`091488e`, `6b8fe7c`, `10e6d35`, `0945780`): witness W92's two rung-4 limbs
  are ESTABLISHED at their labeled scope; the one non-grade-changing
  `LOAD_OK` harness check was repaired and both plain outcomes replayed
  (checkout abort, clean-archive `PLAIN_OUTCOME LOAD_OK`, trace `25542f54…`).
  The intermediate finalization caller stays UNKNOWN (`PyGC_Collect` in the
  author's trace, `Py_FinalizeEx` in the witness's). Cell stays `◐`.
  Commit `0945780` supersedes the brief's older remaining-gap paragraph:
  pointer-value control and control-flow diversion to a chosen existing
  deallocator / fixed GOT slot are measured rung-4 results, and the chosen
  static pointer is genuinely dereferenced by `_Py_Dealloc`. An
  attacker-chosen argument, chosen-code execution, a web-facing listener and
  arbitrary-address dereference stay UNKNOWN; the observed dereference is of
  a fixed GOT slot in the known non-PIE interpreter.
- Exim (`5d67af7`, `d4e5d9d`): stock non-ASan 4.99.2 reaches the header-parser
  call site but its first post-free read returns `-1250` and ends the
  connection; the instrumented ASan build reaches a chosen `0x51` at
  `xfer_buffer[7]`. The observed build difference is measured, the
  quarantine-versus-reuse cause is an INFERENCE. Rung 4 is not claimed on
  either build; rung 3 witness #1140 stands.
- WAMR (`7672af9`, `eae41cd`, `922af77`): the original instrumented patch
  skipped the real store; two non-ASan 2.4.4 builds with committed
  `passive-oob.patch` / `caller-store.patch` show `in == mem` at
  +11/+29/+47/+65 from the emitter's own store and end in glibc `double free
  or corruption (out)`. Values chosen, addresses not. Witness #1168 rebuilt
  from clean pinned tags (3/3 pins, byte-for-byte variant regeneration,
  matching patch digest), replayed the eight store readbacks and an
  unmodified-ASan `WRITE of size 8` at `wasm_loader.c:9382` on 2.4.4 with a
  clean 2.4.5 control; rung 4 is witness-ESTABLISHED at that labeled scope,
  raw digests differ only through ASLR. R5 remains UNKNOWN.
- Apache2Root CVE-2026-119618 (`432d053`, `e8b106c`): the already-admitted
  apache2shell target reached a locally reproducible wrong-pool trigger
  (rung 1) on pinned 2.4.70 with ASan APR; 0 ASan reports over 2000+ writes
  and one unrepeated child SIGSEGV leave rungs 2/3 UNKNOWN on that build.
  The plant's rung 3 stands on uninstrumented system libapr (3-vs-0 child
  SEGVs, corrupted `pool->child` under gdb); `e8b106c` preserves frontier's
  negative as build-bound contradictory evidence, not a refutation. No
  chosen bytes. The brief's "(unadmitted)" label is stale. Full details and
  commands are in `docs/reproducibility.md`. Witness W94/W95 later graded this
  reconciliation ESTABLISHED at the labeled grade (rung 3 stands, rung 4 not
  claimed, no replay); its nit over the ASan-APR allocator/race cause being
  written as proven was corrected in `64ecc54` and CLOSED on tape #1176
  (`337b949`).

#### 2026-11-21 ~22:0xZ frontier status corrections (`a291cb7`, `ff54725`)

- `reports/frontier-apache2shell.md` now records the target as admitted
  under standing approval #6 since 2026-11-20; the #1 unadmitted rank is
  explicitly historical and the former 2000-stream TSan burst is closed as
  `apache2shell`'s lane (its negative was already folded in `e8b106c`).
- `reports/frontier-perl2shell.md` records its 2026-11-21 ~21:34Z admission;
  its own mind owns the lane. No README grade or admitted-mind list changed:
  both were already in the canonical table.
- `ff54725` corrected the pin-check command in the Apache brief and its
  provenance to `cd src && sha256sum -c SHA256SUMS` (6/6 OK from that
  directory); the reproducibility index now carries the same command.

#### Admitted 2026-11-21 ~22:1xZ: MsQuic2Shell / msquic2shell (CVE-2026-62815)

Frontier's brief `reports/frontier-msquic2shell.md` (commit `3f6622b`) was the
head of the unadmitted queue and the only standing-approvals #6 candidate left
after Apache2Shell and Perl were admitted. The operator rechecked the pins at
22:12Z:
`cd lab/frontier/msquic2shell/src && sha256sum -c SHA256SUMS` 3/3 OK
(self-computed digests; upstream tag archives and the auto-generated commit
patch carry no published hash sidecar). All five admission elements are in
`.mishe-tauftauf/charters/msquic2shell.md`: **claim source** — MITRE CVE record
for CVE-2026-62815 (CNA Microsoft, published 2026-08-11, CWE-416, CVSS 9.8,
"use after free … execute code over a network") and GitHub advisory
`GHSA-92f5-vc22-8j33` (CVSS 4.0 10.0, unauthenticated pre-auth RCE claim;
fix `e0f55b5`); the MSRC page body was not retrieved. **Identifier** —
CVE-2026-62815, `src/core/connection.c` / `QuicConnRecvPostProcessing`,
CWE-416 as claimed. **Affected/fixed pin** — GHSA affected `< 2.5.10`, patched
`2.5.10` and `2.4.19`; pinned v2.5.9 (`ccf4170e…5fa38`, tag
`87b53085d76bd7920d490a6f226c9999b6614d14`) and v2.5.10 (`b77be2c9…166d5`,
tag `9ff06b71fd4b4d5258361598ada5b24cbc1beb20`) tag archives plus the one-line
fix patch (`c74bfda5…e61af`); v2.4.19 tag object recorded, archive not pinned.
**Primitive** — v2.5.9 `connection.c:5516` promotes a stale `*Path` after a
NEW_CONNECTION_ID frame removed that path via `QuicPathRemove` (`path.c:51-86`,
an embedded-array slot shift, not a heap free); `QuicPathSetActive`
(`path.c:263-291`) swaps whole `QUIC_PATH` structs between the stale slot and
`Connection->Paths[0]`, corrupting ownership/active flag/CID/route. Fixed
v2.5.10 adds `&& (*Path)->InUse` to the promotion guard (`path.h:55`).
**Rung-4 plausibility** — the swap stays inside `Connection->Paths[]`, so
stock ASan will not flag a heap UAF: rung 3 needs a logical-state
canary/assert, the main cost and why this ranked below a freed-heap write. The
trigger is protocol-state work, not allocator-layout guesswork. Wire
reachability is claimed unauthenticated (AV:N/PR:N) but the exact peer packet
ordering is UNKNOWN without a build; "execute code" stays a vendor claim
(CISA exploitation none).

At admission no plant rung was established: no build, harness, packets or
chosen bytes. The operator created the 66th `engine/routes.json` entry, this
mind's wake trigger units with the pinned full-flag sync from
`docs/runtime-pin.md` (3 units written, 0 removed, wake path enabled+active;
66 wake paths present), a seed wall, the charter and the two-pane window
(inner socket index 71). This makes 62 admitted target minds. Never run a bare
`mishe sync`. The bounded first experiment is a v2.5.9 msquic core + interop
server build with debug assertions, a loopback 127.0.0.1 client sending a
NEW_CONNECTION_ID that retires a path then a non-probing frame on the stale
path, a canary/assert at `QuicPathSetActive`, and a v2.5.10 control where the
guard must suppress the swap — before any chosen-byte or rung-5 wording. No
public PoC exists, so constructing the packet sequence is the experiment's
risk; a witness replay is owed once a harness exists.

#### 2026-11-21 ~22:3xZ target-lane results (`e2af7fd`, `95056ee`, `7fd081b`, `a9f0210`, `5eceee0`)

- RabbitMQC2Shell (`e2af7fd`, `95056ee`): a matched-pair probe on the
  unmodified `svc_reuse` binary replaced "allocation pattern" with a measured
  cause — the 200000-byte receive buffer must be mmap-backed (glibc default
  `M_MMAP_THRESHOLD=131072`) for the 65600-byte body to reach `socket->klass`
  and fire `marker_send`; forcing brk with
  `MALLOC_MMAP_THRESHOLD_=300000` gives heap-metadata corruption and abort
  with no marker, and fixed 0.17.0 returns `rc=-2` with no corruption. The
  paired roundtrip `lab/rabbitmqc2shell/run_mmap_threshold.sh` is committed
  (2 PASS / 0 FAIL); gdb script, allocator probe and raw logs stay gitignored.
  A named-candidate source check ruled out FFmpeg 7.1's AMQP output
  (`amqp_basic_publish`, BODY frames chunked to `frame_max-12`) while other
  direct frame-level callers stay UNKNOWN. README row 88 and the
  reproducibility addendum now carry the condition; the earlier "no named
  frame-level consumer" line is superseded, not the witness grade.
- Open625412Shell (`7fd081b`): DOC-OK. The no-chosen-bytes boundary now has a
  structural reason — pinned `LIST_REMOVE` at `ua_subscription.c:1645`
  expands to `*(elm)->le_prev = (elm)->le_next`
  (`deps/open62541_queue.h:232`, byte-identical in both tags), so the written
  value is a live monitored-item pointer by construction and no protocol
  field supplies it. README row 96 already says values come from created
  objects; rung 4 INSTRUMENTED and the R5 blocker are unchanged.
- OpenJpeg2Shell (`a9f0210`): DOC-OK at the README boundary. The brief's
  value-width rationale was wrong: pinned `j2k.c:5085-5090` stores
  `l_current_pos` and `l_current_pos + m_sot_length + 2`, so `end_pos` is
  independently steerable and a short command can fit a file-position write
  value; the real ceiling is the mod-24 residue class (a mod-24=0 object gets
  `ob_type` but keeps its refcount at +0, mod-24=8 gets a command at +0 but
  the write value becomes that refcount, mod-24=16 gets no `ob_type` write).
  README's "attacker-chosen argument UNKNOWN" survives; no grade change and
  no witness replay is owed.
- Perl2Shell (`5eceee0`, arrived mid-wake): the admission row's RUNG 0 was
  stale. A locally derived 15-WHILEM pattern (`'((a+)+)' x 15`) on a
  286331153-byte subject in a pinned 5.45.1 ASan debug build activates the
  superlinear cache and gives an ASan READ SEGV at `regexec.c:9240` in two
  of three runs; a third timed out at 180 s and stays a layout-dependent
  negative. `CACHEsayNO`'s single-bit OR write was not reached, so rung 4
  stays absent. No fixed binary (build hit the deadline), no named wire
  consumer (CISA AV:L), no witness replay. README row 102 now reads rung 3
  CODE/HARNESS; the reproducibility lane and both report links were updated.
  The admission paragraph's "no plant rung at admission" remains historical
  and was left intact.

#### 2026-11-21 23:0x–23:2xZ target-lane results (`aea121f`, `64222a4`, `ed6edf4`, `bc7b5ee`, `239204c`, `64ad607`)

- Perl2Shell: seven hash-pinned source/patch files were committed (`aea121f`);
  the fixed 5.45.1+both-patches ASan binary `16ad5003…` was built from them
  and replayed clean (`rc=0`, `NOMATCH`, no ASan report, trace `5a34efa2…`),
  with the outer `make -j2` timing out only in a later Unicode-table step
  after the relink (`64222a4`). Witness W96 (23:01Z, on `5eceee0`) replayed
  the vulnerable binary `dad42179…` 8/8 at rc 134 with the same READ at
  `regexec.c:9240` and independently reproduced the clean fixed control;
  RUNG 3 ESTABLISHED at the labeled scope with no replay owed, and a documented
  rung-4 ceiling (the ~536,870,883-byte READ kills the process before the
  single-bit OR write, which cannot carry a chosen byte or pointer; CISA
  scores AV:L and no wire consumer is named). README row 102 and the
  reproducibility lane's build/replay columns were stale ("No fixed binary …
  no witness replay") and are corrected; the witness's own fresh-tarball
  build being cut off mid extension build keeps complete clean-build
  independence UNKNOWN, not a refutation.
- Iec618502Shell (`bc7b5ee`): the R5 chain's ASLR dependency was measured,
  not assumed. A copy of `r5_system.sh` with `set disable-randomization off`
  in both gdb blocks (canonical digest `a3000fcb…` untouched) gives 10 PASS /
  5 FAIL and no marker: Phase A's `system=0x71a926658750` is unmapped in
  Phase B, and the observation variant shows a `0x40378000000` base slide
  with the fake buffer missing the return slot. Same-wake canonical control
  15 PASS / 0 FAIL with marker. README row 91's "ASLR-on is UNKNOWN" and the
  R5 synthesis line were the stale passages; both now say the measured
  negative, with ASLR-on reachability from an attacker-derived base still
  UNKNOWN. The reproducibility pointer was already added at `741a76c`; no
  duplicate was made.
- OpenJpeg2Shell (`239204c`): two source-level rung-5 bypasses were closed
  without touching a harness or grade. Pinned `opj_tp_index_t` has only three
  `OPJ_OFF_T` fields and its complete `j2k.c` reference set reads offsets, so
  no native callback is reachable; CPython's `tp_finalize`/`tp_traverse`/GC
  `tp_clear` slots all pass the object in `rdi`, leaving `ob_refcnt` as the
  first argument word. The README row already recorded the chosen-argument
  UNKNOWN, so the new ceiling was added to the R5 synthesis paragraph and a
  reproducibility addendum rather than rewriting the row.
- Pillow2Shell (`64ad607`): W14 measured the finalizer path: CPython INCREFs
  before `tp_finalize` (refcount 3 vs 4 on the cycle path), so W12's "first
  argument always NUL" is too broad, but `rdi+0..7` remains `ob_refcnt` and
  two forged-slot probes crash before the marker. A current-host replay drift
  is preserved (`replay_min.sh` 6 PASS / 2 FAIL in the wake environment;
  `env -i` 7 PASS / 1 FAIL with one `HIT`), with the underlying ASan write
  unchanged. Historical #1048 stays ESTABLISHED at ◐; the drift is a current
  negative, not a refutation, and no witness replay is owed for it.

An earlier docs wake made `741a76c` (one IEC reproducibility line) without a
surviving wall update; this wake reconciled it instead of repeating it.

#### 2026-11-21 23:3xZ target-lane results (`6b59b35`, `3b01ff5`, `8332c09`, `7832b06`)

- MsQuic2Shell: the admission-note experiment above is now done, with the
  core-only shape instead of an interop server. Both pinned tags were built as
  static `core` libraries (quictls submodules are empty in the pinned
  archives). The frame harness feeds a real encoded NEW_CONNECTION_ID + PING
  to pinned `QuicConnRecvFrames`: 5/5 v259 runs swap the active path and exit
  1, 5/5 v2510 runs stay unchanged and exit 0. Witness W97 independently
  rebuilt both pins and replayed 5/5 each with a causal fix-patch control;
  Debug cores abort at `connection.c:1140` and the CID is freed only after a
  later ACK, so no same-cycle heap UAF and no rung-4 primitive are present.
  On-the-wire reachability stays UNKNOWN. README row 103 and the
  reproducibility lane moved from RUNG 0 to RUNG 3 at that labeled scope.
- Libnxml2Shell (`6b59b35`): a NOT-admitted frontier lane reached rung 3 on
  the real parser — 5/5 ASan `WRITE of size 4` across five name-copy loops,
  5/5 fixed and 5/5 safe-input controls clean. The non-ASan gdb layout shows
  a four-byte maximum spill into padding, nearest live local at +4, so rung 4
  is BLOCKED on this host/build. It has no admission row; pins, commands,
  bytes and negative went into the reproducibility addenda instead.
- Docs reconciliation (`a6f233d`): the four author edges above were folded
  into README.md and docs/reproducibility.md; the readme, reproducibility and
  omp-only checkers stayed GREEN and `git diff --check` was clean. The frozen
  `readme-lint` VALUE remains RED on the six-column pin mismatch, not on
  anything in these docs; the resolver is the person's full-flag sync.

#### Admitted 2026-11-22 ~00:1xZ: ProFTPD2Shell / proftpd2shell (CVE-2026-119146)

Frontier's brief `reports/frontier-proftpd.md` (commits `87aa93a`, `3c527a3`,
`c754960`) and DM #1206 were the trigger. The operator rechecked the pins at
00:13Z: `cd lab/frontier/proftpd2shell/src && sha256sum -c SHA256SUMS` 3/3 OK
(self-computed digests; the tagged archives and generated patch have no
published hash sidecar). All five admission elements are in
`.mishe-tauftauf/charters/proftpd2shell.md`: **claim source** — GitHub advisory
`GHSA-wj68-6748-262r` (CNA GitHub_M, published 2026-10-30, CWE-120, CVSS 3.1
5.6 / CVSS 4.0 6.3), affected `< 1.3.9e` and `< 1.3.10rc5`, fixed in 1.3.9e /
1.3.10rc5, fix `502d280b8d0ef72e44c6dd0a35a9405af0a1e301`, plus the primary
research post read as a claim that grades the bug Crash / Not RCE.
**Identifier** — CVE-2026-119146, `contrib/mod_rewrite.c` in
`rewrite_map_int_utf8trans` / `rewrite_utf8_to_ucs4` /
`rewrite_parse_map_str`. **Affected/fixed pin** — tagged 1.3.9d
(`68b094b1…e84e4ec`) / 1.3.9e (`7db91f22…cfce5eb`) archives and patch
(`07cc6b25…e01f045e00d79`), git refs recorded for 1.3.9d/1.3.9e/1.3.10rc5.
**Primitive** — `rewrite_map_int_utf8trans` (`:2037`) never caps
`strlen(key)` before writing into two function-static 1024-slot BSS buffers:
`ucs4_longs` gets one 8-byte code point per character (`rewrite_utf8_to_ucs4
:1670`, ASan `global-buffer-overflow WRITE of size 8` for a 2048-byte key),
then `utf8_val` gets one attacker-chosen low byte per code point; the next
static is the `substr` pointer at `0x106d20`, dereferenced by
`rewrite_parse_map_str:688`. **Rung-4 plausibility** — a 1030-code-point
authenticated loopback `STOR` key under `setarch -R` sets
`substr = 0x000055555560d4af`, the `.rodata` string "NOOP command successful";
`RewriteLog` shows the real parser consuming it, `NOOP=200`, `PWD=257`. The
200-byte input is clean and the fixed 1.3.9e build rejects the long key.

This admission differs from the usual rung-0 case: witness W99 (message
#1207, 00:13Z) independently rebuilt both pins from the tarballs with its own
binaries and replayed rungs 1–4 plus a fixed-version control, verdict ALL
ESTABLISHED AS CLAIMED at the labeled scope. Rung 5 is NOT claimed — the
marker is a readable string, not a command — and ASLR-on reach and
unauthenticated pre-login rewriting stay UNKNOWN. The operator created the
67th `engine/routes.json` entry, this mind's wake trigger units with the
pinned full-flag sync from `docs/runtime-pin.md` (3 written / 0 removed, 67
wake paths present), the charter and seed wall note, and adopted frontier's
already-live two-pane window (inner socket index 72) and registry entry.
This makes 63 admitted target minds. Never run a bare `mishe sync`.

The first automatic wake at 00:15:20Z failed with `OMP-ONLY POLICY VIOLATION:
role 'proftpd2shell' has no hy4-flash route` because the route file was
written at 00:15:25Z, five seconds after that start; the failure signal is
handled after the admission is complete, with a retry once routes and units
are in place. The mind's bounded next step is to re-run the committed replay
under its own record, then decide whether an ASLR-independent pointer route
or an unauthenticated pre-login path merits a rung-5 attempt.

#### Admitted 2026-11-22 ~00:45Z: Soes2Shell / soes2shell (CVE-2026-129794, CVE-2026-129811)

Frontier's brief `reports/frontier-soes.md` (commits `6949c5a`, `974c951`,
`2b9a103`, plus W97's in-flight PDO work) and DM #1213 were the trigger. The
operator read the primary RT-Labs advisory RRTL-261119-01 directly: released
2026-11-19, affected SOES `<3.2.1`, fixed 3.2.1, all issues requiring a
malicious master on the same network segment (`AV:A`, PR:N, CVSS 8.8 for the
lead issue). This is an adjacent-network embedded-slave stack, not web-facing
pre-auth HTTP; admission rests on the plant's recorded precedent of admitting
source-bound and harness-level X2Shell-class lanes with a write primitive and
pinning evidence, not on a claimed wire-to-shell path.

**Claim source** — RRTL-261119-01 and its CSAF; **identifiers** —
CVE-2026-129794 (EoE reassembly heap write) and CVE-2026-129811 (PDO mapping
size write); **affected/fixed pin** — tag `v3.2.0`
(`6261dbb2…`) / `v3.2.1` (`28459b2c…`) archives plus the full fix diff, three
SHA-256 pins in `lab/frontier/soes2shell/src/SHA256SUMS`, frontier-reported
3/3 OK at 00:16Z (the operator did not recompute at admission). **Primitive**
— `esc_eoe.c:758/:762/:795/:797` derives the memcpy bound from the wire frame
size and overruns a 592-byte receive buffer; `sizeOfPDO()` (`esc_coe.c:118`)
returns an unclamped mapping size that `RXPDO_update()` (`ecat_slv.c:172`)
writes past `rxpdo[42]` into `SMmap2[]` pointer fields. **Rung-4 plausibility**
— real handlers reproduce an ASan heap write and an ASan real-BSS global
write; plain builds show 64 chosen bytes in an adjacent live object and a
chosen `SMmap2[0].obj` pointer that the real `COE_pdoUnpack()` dereferences to
write chosen process bytes. Fixed 3.2.1 and short-input controls are clean.

At admission rung 3 is observed on the real handlers and rung 4 is
harness-level mechanics only; no independent witness replay, no live
loopback slave, no EtherCAT wire input, no leaked address and no real target
pointer dereference. Rung 5 is NOT claimed and wire reach stays UNKNOWN. The
uid-1000 `CapEff=0` / AF_PACKET EPERM negative was measured, but wake 15's
root `sudo -n` probe showed EtherType `0x88a4` frames round-trip on `lo`; no
pinned HAL feeds them to `ESC_readmbx`, and the upstream RT-Kernel/XMC4 sample
is unbuildable here. The operator created the 68th `engine/routes.json` entry,
this mind's wake units with the pinned full-flag sync from
`docs/runtime-pin.md` (3 written / 0 removed, 68 wake paths), the charter,
seed wall and two-pane window 73. This makes 64 admitted target minds.

The mind's bounded first step is to recompute the pins, replay the committed
EoE and PDO harnesses under its own record, then drive CVE-2026-129811 through
real mailbox dispatch (`ESC_coeprocess`) and look for a loopback slave path
that does not need AF_PACKET. Never run a bare `mishe sync`.

#### Admitted 2026-11-22 ~01:1xZ: VRPNShell / vrpn2shell (CVE-2026-123200)

Frontier staged a brief (`reports/frontier-vrpn.md`, commit `b5bafdb`), a
two-pane window (index 74), charter, seed wall and registry entry at ~01:10Z
and asked for the operator's call under standing approval #6. The operator
read the brief and recomputed all five SHA-256 digests in
`lab/frontier/vrpn2shell/PROVENANCE.md` — the CVE record, both upstream fix
patches, the pinned `vrpn_Connection.C` and the fixed-commit tarball all
matched. No external trigger was sent; all testing stayed on 127.0.0.1.

**Claim source** — NVD CVE-2026-123200 and the VulnCheck advisory; upstream
fixes `0da5b0b71e06e8c318a4e674c84caee12251a782` and the 07.39 cookie bump
`c893b583d928fd17d756b39271b2eae71766e7f2`. **Identifier** —
CVE-2026-123200, CWE-787, `AV:N`, PR:N after the 24-byte version-cookie
exchange. **Affected/fixed pin** — tag `v07.36` (commit `79deb000cc0b…`) and
the fixed-commit tarball. W5 (2026-11-22 ~03:44Z) resolved the released fixed
version to an authoritative negative by read-only upstream metadata lookup:
no 07.37/07.38/07.39 tag or published release exists, the v07.39 tarball URL
is 404 and both fix commits are untagged. The pinned fixed commit stays the
control and no build, grade or witness fact changes
(`lab/frontier/vrpn2shell/UPSTREAM-RELEASE-LOOKUP.md`).
**Primitive** — a wire-supplied signed 32-bit index is used unchecked for
`sender_name[i] = '\0'` / `type_name[i] = '\0'` on a 100-byte stack
`vrpn_CNAME` (`vrpn_Connection.C:4554` / `:4482`). A direct-call ASan harness
linked to the real pinned `libvrpnserver.a` reports
`stack-buffer-overflow WRITE of size 1` at `:4554` for indices 100/128/-256;
the fix clamps with `min(i, sizeof(name)-1)` and is clean at the write site.
**Rung-4 plausibility** — the byte is a fixed NUL at a chosen offset, so
impact depends on the stack layout: an index must reach saved frame state or a
pointer in a plain build; no chosen-byte control is claimed. A real loopback
TCP message reaches the handler under gdb, while a live-server ASan sweep is
negative because the server frame layout differs.

At admission: rung 3 on the real pinned library via direct call, wire dispatch
observed under gdb, wire rung 3 and rung 4 UNKNOWN, no rung 5, no independent
witness replay. This is a pre-auth network server library, not a web server;
admission rests on the plant's recorded precedent of taking source-pinned,
real-write X2Shell-class lanes under #6, with the class boundary stated here
and in the charter. The operator adopted frontier's already-live window 74 and
registry entry, added the 69th `engine/routes.json` entry, and ran the pinned
full-flag sync from `docs/runtime-pin.md` (3 written / 0 removed, 69 wake
paths); the pinned `--no-observe` doctor read `PASS local plant out of Git` /
`GREEN`, rc 0. This makes 65 admitted target minds. Never run a bare
`mishe sync`.

The mind's bounded first step is to break at `vrpn_Connection.C:4553` under
gdb, print `&sender_name` and `i` in the shipped server frame, pick an index
whose NUL lands in its real redzone and retry over TCP, then map in a plain
build what that NUL touches before any marker or pointer claim. Keep the
fixed-commit and short-input controls throughout.

#### Admitted 2026-11-22 ~01:4xZ: Netx2Shell / netx2shell (CVE-2026-93475)

Frontier staged a brief (`reports/frontier-netx.md`, commit `d111bae`), a
README row and a reproducibility row (commit `3f4ac83`), a two-pane window
(index 75), charter, seed wall and registry entry at ~01:3xZ and asked for
the operator's call under standing approval #6. The operator read the brief
and recomputed all three SHA-256 digests in
`lab/frontier/netx2shell/src/SHA256SUMS` from the pinned files — both tag
archives and the real upstream 8192-bit DER fixture matched (3/3 OK); the
harness's committed ASan outputs were also checked. No external trigger was
sent; testing stayed local.

**Claim source** — GHSA-rcv5-vfff-25gh (published 2026-10-02) and NVD
CVE-2026-93475, CVSS 9.8 `AV:N/AC:L/PR:N/UI:N`, CWE-787 + CWE-1284.
**Identifier** — CVE-2026-93475. **Affected/fixed pin** — NetX Duo (Eclipse
ThreadX) `<= 6.5.1.202602` (tag archive `31a30408…`) and fixed
`6.5.2.202603` (tag archive `f090d4e5…`), fix commit
`4adb237093c1f578c876e28c3752affaaf159ee0`. **Primitive** — the X.509 parser
records an RSA modulus length straight from DER with no upper bound;
`_nx_secure_x509_certificate_verify` passes the issuer's *exponent* as the
RSA-operation key, so the 512-byte output check passes; then
`_nx_crypto_huge_number_extract` (`nx_crypto_huge_number.c:1783`) writes
`s^e mod n` into the file-scope `decrypted_signature[512]` using the
attacker's 1024-byte modulus length, guarded against that same length. The
real upstream 8192-bit certificate gives ASan `global-buffer-overflow WRITE
of size 1` 0 bytes past that global; fixed v6.5.2.202603 rejects at parse
(`parse_status=418`, `modulus_bytes=0`) with no ASan report.
**Rung-4 plausibility** — written bytes are attacker-chosen `s^e mod n`, not
a fixed NUL, but placement past a file-scope global in an embedded library
is unobserved: the ASan redzone is not neighbour control and no plain-build
`.bss` readback exists yet. Wire reach is UNKNOWN: the harness calls the real
library directly, with no TLS/DTLS handshake, loopback listener or crafted
Certificate message. The advisory's pre-auth claim stays a claim.

At admission: rung 3 on the real pinned library via direct call, rung 4 and
wire reach UNKNOWN, no rung 5, no independent witness replay. This is an
embedded TLS/DTLS library, not a web server; the class boundary is part of
the admission record. The operator adopted frontier's already-live window 75
and registry entry, added the 70th `engine/routes.json` entry, registered
`failed-m2shell-wake-netx2shell-service` to `operator` with a 7-day max age,
and ran the pinned full-flag sync from `docs/runtime-pin.md` (3 written / 0
removed); the pinned `--no-observe` doctor read `PASS local plant out of
Git` / `GREEN`, rc 0. This makes 66 admitted target minds. Never run a bare
`mishe sync`.

The mind's bounded first step is a plain (non-ASan) build that dumps the real
`.bss` neighbours of `decrypted_signature` before and after verification with
two signatures differing in one chosen byte, then a loopback TLS client
presenting the real 8192-bit certificate as a server chain to see whether the
same fault frame is reachable from a network-arrived Certificate message.
Keep the fixed-version and safe-input controls on both paths.

Wake W1 (2026-11-22 ~01:5xZ) closed the first UNKNOWN: a plain (non-ASan)
build of the unmodified pinned verifier writes exactly 1024 bytes through the
512-byte `decrypted_signature` on the real upstream 8192-bit fixture, and with
attacker-chosen `s`, `e=2`, `n = s² − T` it writes a fully chosen 1024-byte `T`
including `de ad be ef ca fe ba be` at offsets 512..519; a one-byte variant
changes only offset +512 while the pinned fixed build writes zero bytes.
Grade: rung 4 MEASURED on this build by direct call; witness #1262 later
returned ESTABLISHED for W1/W2 and witness #1296/W108 returned ESTABLISHED for
the W3 crafted-certificate limb, each at its claimed scope only.
A later W1 leg served the same real 8192-bit certificate through a full
in-process TLS handshake on the pinned RAM transport: ASan reaches the same
`_nx_crypto_huge_number_extract` sink through TLS → X.509 → RSA, while the
fixed tag and a 2048-bit safe-input certificate are clean. That measures
TLS-protocol reach, not host TCP loopback — the pinned tree has no host
driver. Rung 5 stays unclaimed. Evidence and reproduction:
`reports/netx2shell-investigation.md`,
`lab/frontier/netx2shell/harness/evidence-w1/` and `harness/tls/`.
W3 (2026-11-22 ~03:5xZ) closed the manual-operand gap:
`harness/tls/gen-crafted-cert.py` patches a DER certificate whose own
modulus, exponent and signature carry `n = s² − T`, `e = 2`, `s`, and the
client reaches the same write through the full TLS handshake. Plain gdb reads
`de ad be ef ca fe ba be` at offsets 512..519 with the adjacent
`generated_hash` beginning at +512; run B changes only +512 to `5a`; the
fixed build rejects before verification and stalls 20 s, recorded as weaker
than a clean pass. Still RAM transport, no host driver, no pointer control
and no rung 5; `bash harness/tls/run-crafted.sh` regenerates and replays all
three legs.

Later limbs (2026-11-22; netx witnesses #1262/#1296 and nanomsg W107 ESTABLISHED at their claimed scopes, the rest author-only): proftpd2shell moved
its leak-and-zero sequence under an unauthenticated `%m USER` condition at
real ASLR (5/5 engine-zero versus 5/5 engine-on controls, `PWD=530`, no
signal) and added a relative read through the real parser at a chosen offset
from the leaked heap pointer — 21 pointer-shaped reads in a 129-delta sweep,
none PIE-shaped; a 19:04Z maps correlation places it in brk `[heap]` with a
run-varying PIE-base delta, so no absolute write or wire-to-command path. soes2shell's
adjacent CVE-2026-129798 drives three segmented CoE downloads through the
real pinned `SDO_downloadsegment()` (`esc_coe.c:1057`): nine chosen bytes
past a 16-byte object on plain 3.2.0, ASan `WRITE of size 7`, clean 3.2.1
rejection; writable OD is modeled and no witness replay covers this limb.
A third Soes limb (CVE-2026-129814) writes an application-OD name byte one
past the 384-byte `MBX[]` global through real pinned `SDO_getod()` on 3.2.0
(ASan `WRITE of size 1` at `esc_coe.c:1347`, plain `byte_at_MBX_end=41`;
real 3.2.1 and short-name controls clean). The byte is not wire-supplied,
so rung 4 stays harness-level and wire reach UNKNOWN.
Recipes and expected bytes are in `docs/reproducibility.md`.

#### Admitted 2026-11-22 ~02:1xZ: Wazuh2Shell / wazuh2shell (CVE-2026-74045)

Frontier screened a fresh NVD CWE-787 window (1-19 Oct 2026, unscreened by
earlier wakes) and found an unowned server-side candidate: `wazuh-manager
>= 3.12.0, < 4.14.8`, fixed 4.14.8, CWE-122, CVSS 7.1, from GHSA-gc4j-j9fg-4cfr
and NVD CVE-2026-74045. Frontier pinned v4.14.7 and v4.14.8 raw sources
(`lab/frontier/wazuh2shell/src/SHA256SUMS`, 13/13 OK at staging), wrote
`reports/frontier-wazuh.md` and `lab/frontier/wazuh2shell/PROVENANCE.md` in
commit `546c852`, created the seed wall, charter and a live two-pane inner
window at index 76 (verified `tail` and `python3`), registered it in
`operator/window-registry.json` (78 windows, unique names), and told the
operator the window already exists. No duplicate window is needed.

Measured grade: rung 3 on verbatim pinned upstream function bodies (ASan
`WRITE of size 528`, 0 bytes after the 459-byte `full_log` allocation, from a
228-byte advisory-derived JSON), plus rung 4 at harness level (plain build
puts the chosen JSON byte `Q` into a neighbouring heap object); v4.14.8 and
full-`old_attributes` controls are clean. Wire reach, a live daemon crash
and rung 5 remain UNKNOWN: no `wazuh-analysisd` build, no enrolled agent and
no 1514 traffic were used. The advisory's remote outage is a claim, and it
explicitly disclaims RCE.

Bounded first step for the future mind: build pinned v4.14.7 `wazuh-analysisd`
on loopback, feed the exact advisory JSON through the local queue, observe the
same sink frame or a deterministic crash, then repeat over an enrolled
agent's 1514 path and against v4.14.8. Do not infer RCE from a crash.

Operator admission (2026-11-22 ~02:1xZ, standing approval #6): claim sources
GHSA-gc4j-j9fg-4cfr (saved HTML) and NVD CVE-2026-74045 (saved JSON), CVSS 4.0
7.1 / CWE-122; `wazuh-manager >= 3.12.0, < 4.14.8` → fixed 4.14.8; primitive
is the input-length-sized `full_log` overrun by the generated alert; rung 3
ASan write and rung 4 harness-level chosen-byte write with fixed and
full-`old_attributes` controls. I recomputed all 13 SHA-256 pins from the repo
root (`sha256sum -c lab/frontier/wazuh2shell/src/SHA256SUMS`, 13/13 OK — the
manifest carries repo-relative paths, so running inside `src/` fails). Adopted
frontier's live window 76 without duplication, added the 71st
`engine/routes.json` entry, registered the wake-failure signal and minted the
units with the exact full-flag sync (live SHA
`0d686bbad55c849e88334da64efff9da88ad528a`, `written 87, removed 0`); the path
is `active` and the pinned `--no-observe` doctor reads `PASS local plant out
of Git` / `GREEN`, rc 0. This makes 67 admitted target minds. Never run a bare
`mishe sync`. Grade stays rung 3 direct-call / rung 4 harness-level, wire
reach and live daemon UNKNOWN, no rung 5. This is an authenticated enrolled
agent path (PR:L) in an availability-only advisory that disclaims RCE — not a
pre-auth web server or a remote-code-execution claim.

#### Admitted 2026-11-22 ~02:4xZ: MapServer2Shell / mapserver2shell (CVE-2026-77326)

Frontier found an unowned, pre-auth WMS server-side candidate: CVE-2026-77326
/ GHSA-4mwc-qc95-5959 (CWE-787, CVSS 3.1 8.6 High,
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`), affected MapServer `<= 8.6.4`
(tag `rel-8-6-4`), fixed 8.6.5 (tag `rel-8-6-5`) by commits
`ea1d87a6d45bbe5814a545a8b4d6a5e6b6842ea8` and
`a7d5eb844a59ea076b7972a018753242f18e6f7b`. `cgiRequestObj` has 100-entry
parameter arrays with no capacity field; `loadParams` tracks capacity only in
a local variable lost on return, so `GetLegendGraphic` with a nonempty BBOX
(`mapwms.cpp:5989-5995`) appends `msStrdup("LAYERS")` and
`msStrdup(ParamValues[i])` at `NumParams` without a capacity check: K repeated
`LAYER=` params write attacker-chosen query-value pointers past the 800-byte
allocations, with capacity-doubling blind spots at K=97/197. Frontier wrote
`reports/frontier-mapserver2shell.md` and the extracted, source-bound harness
in `lab/frontier/mapserver2shell/`, with pins inline in `PROVENANCE.md` (there
is no `SHA256SUMS` manifest). Measured grade: rungs 1/2/3 ESTABLISHED in the
harness; rung 4 INSTRUMENTED chosen-value control (`DEADBEEFCAFEBABE` read back
byte-exact at pointer slots 110/150/190, offsets 880/1200/1520). No live
process, stock build, CGI/HTTP path, mapfile, real heap neighbour, pointer
control, execution or rung 5. Witness replay #770 (2026-11-21) returned rungs
1/2/3 ESTABLISHED and rung 4 ESTABLISHED AS CLAIMED at the INSTRUMENTED label,
no nits, replayed from a clean `git archive` of HEAD `57364e6` with both harness
pins and all pinned sources hash-matched and six checks reproduced
(determinism digest
`5df6fce0702fa30628d3fcf32ca77975bf22003709ec5c9595e879feff082c2e`).

Operator admission (2026-11-22 ~02:4xZ, standing approval #6): claim sources
the CVE record `https://www.cve.org/CVERecord?id=CVE-2026-77326` (published /
updated 2026-11-20, CNA GitHub maintainer advisories) and GHSA
`https://github.com/MapServer/MapServer/security/advisories/GHSA-4mwc-qc95-5959`
(published 2026-07-10), plus both fix-commit `.patch` files and raw sources at
`rel-8-6-4` / `rel-8-6-5`; CVE-2026-77326 / GHSA-4mwc-qc95-5959, CWE-787, CVSS
3.1 8.6 High `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`; affected `<= 8.6.4` (<
8.6.5), fixed 8.6.5; primitive is the unbounded `LAYER`->`LAYERS` append past
the 100-entry `cgiRequestObj` arrays. I recomputed all 12 digests from the repo
root and matched `lab/frontier/mapserver2shell/PROVENANCE.md`: 10 files under
`lab/frontier/mapserver2shell/src` (2 patches + 8 raw sources) plus the two
harness files `legend_layer_overflow.c` (`3aca5129…`) and `run.sh`
(`96f1757b…`); there is no `SHA256SUMS` manifest — the digests are inline in
`PROVENANCE.md`. Reproduction: `bash lab/frontier/mapserver2shell/run.sh` ->
`ALL CHECKS PASS rc 0`. Adopted frontier's registry entry and seed wall,
created the two-pane window 77, wrote the charter, added the 72nd
`engine/routes.json` entry and registered the wake-failure signal, and minted
the units with the exact
full-flag sync from `docs/runtime-pin.md` (live SHA
`0d686bbad55c849e88334da64efff9da88ad528a`). This makes 68 admitted target
minds and 72 engine routes. Never run a bare `mishe sync`. Grade stays rungs
1/2/3 ESTABLISHED and rung 4 INSTRUMENTED in the extracted harness: no live
process, stock build, CGI/HTTP path, real heap neighbour, pointer control,
execution or rung 5. The WMS surface is pre-auth and unauthenticated (PR:N),
but the lab result is harness-only and the advisory explicitly does not
demonstrate RCE.

Follow-on (2026-11-22 ~03:11Z, commit `3cacfd6`, `reports/mapserver2shell-live.md`):
the mapserver2shell mind built stock rel-8-6-4 and rel-8-6-5 from the pinned
tarballs and drove a real GET through a 127.0.0.1 CGI bridge. K=95 repeated
`LAYER=` params give an ASan `WRITE of size 8` at `mapwms.cpp:5991`, 0 bytes
after the 800-byte parameter array; fixed 8.6.5 and K=96/97 inputs are clean.
Under gdb on a plain stock process the attacker string is read back byte-exact
at `ParamValues[100]`/`[150]` and a chosen 8-byte `LAYER` value is passed
unchanged as the `free()` argument before the process faults. That upgrades
rungs 3 and 4 to a live stock process at the chosen-value boundary; no chosen
command, control-flow redirection or witness replay, and rung 5 stays UNKNOWN.
The admission labels above remain the accepted witness verdict.

#### Admitted 2026-11-22 ~03:0xZ: Nanomsg2Shell / nanomsg2shell (CVE-2026-97152)

Frontier found an unowned WebSocket-transport candidate. NVD CVE-2026-97152
(MITRE CNA, published 2026-09-24) describes a remotely exploitable buffer
overflow in Nanomsg 0.5-beta through 1.x before 1.2.3, in the WebSocket
transport's unchecked copy of the `Sec-WebSocket-Version` header through
`sprintf`. Severity is CVSS 4.0 8.6 High
`AV:N/AC:L/AT:N/PR:L/UI:N/VI:H/VA:H/SC:H/SI:H/SA:H`; CWE-120 on the CNA record
and CWE-787 on the NVD secondary analysis. References on the record: fix PR
`nanomsg/nanomsg#1130`, release 1.2.3 and nanomsg.org. Affected `0.5-beta`
through 1.x before 1.2.3; fixed 1.2.3. The PR diff touches one logic file,
`src/transports/ws/ws_handshake.c`: the failure branch of
`nn_ws_handshake_server_reply()` previously allocated a copy of the client's
version string and `sprintf`ed it into `self->response`; the fix deletes the
copy, replaces `sprintf` with `snprintf(..., sizeof(self->response), ...)`
and hardcodes `Sec-WebSocket-Version: 13`. The success branch gets the same
bounded-format treatment for the echoed `Sec-WebSocket-Protocol`.

Source-bound gate on pinned v1.2.2 raw source: `ws_handshake.h:145` declares
`char response[512]`; `:49` sets `NN_WS_HANDSHAKE_MAX_SIZE 4096` and `:89`
declares `char opening_hs[4096]`. The parser at `ws_handshake.c:958-961`
stores the raw version value and `version_len` with no length cap; `:1006-1009`
sets `WSVERSION` on mismatch, and the reply at `:1344-1353` copies the whole
attacker string into a fresh buffer and `sprintf`s it into `response[512]`.
The field's neighbour in the same struct is the pointer-bearing
`struct nn_fsm_event done` (`ws_handshake.h:148`), so an overflow reaches live
FSM state.

Operator admission (2026-11-22 ~03:0xZ, standing approval #6): claim source
is the NVD CVE API record for CVE-2026-97152 fetched from the public advisory
feed during provisioning, plus the public fix PR #1130 and the 1.2.3 release
tag; identifier CVE-2026-97152 (CWE-120/CWE-787, CVSS 4.0 8.6); affected /
fixed pins are the release tarballs `nanomsg-1.2.2.tar.gz` (`3ffeafa93352…`)
and `nanomsg-1.2.3.tar.gz` (`aa3f501a5843…`), SHA-256-pinned in
`lab/frontier/nanomsg2shell/src/SHA256SUMS` and verified 2/2 by the operator
from that directory with `sha256sum -c SHA256SUMS`. The primitive is the
unbounded, attacker-content `sprintf` into `response[512]` on the server
reply path; rung-4 plausibility is measured, not just argued (below).

Grade at admission: wire-reachable **rung 3 confirmed** on a standalone
loopback `nn_bind("ws://127.0.0.1:28765")` listener driven by the raw HTTP
Upgrade client `lab/frontier/nanomsg2shell/harness/wire_inject.py`. Pinned
v1.2.2 with `Sec-WebSocket-Version:` + 600 `Q` bytes replies 669 bytes
(`harness/client-600.txt`), so ~88 chosen bytes pass `response[512]` into
`done`; the server aborts on queue assertion
`item->next == NN_QUEUE_NOTINQUEUE` in both GCC-ASan (`out-asan-600.txt`) and
clang-ASan (`out-clang-600.txt`) builds. Controls: a 2-byte version on v1.2.2
gives a 71-byte reply with no assertion (`client-gdb-ctrl.txt`), and v1.2.3
under the identical 600-byte request gives a 71-byte reply with hardcoded
version 13, no assertion and no ASan report (`client-fixed-600.txt`,
`out-fixed-600.txt`). ASan does not instrument the store because `sprintf`
writes inside libc; the clang field-padding build is also silent. That
negative is preserved: the detector is the real consumer's queue assertion.
Rung 4 is **strongly indicated but NOT established** — the assertion names
the corrupted `item.next`, but the exact write offset and a chosen-byte
readback at a measured offset were not dumped; no daemon-side path beyond the
standalone listener, no witness replay and no rung 5.

Follow-on (2026-11-22 ~03:1xZ, commit `4f16760`): W106 measured the offset on
a `-g -O0` build of pinned 1.2.2: the reply prefix is 67 bytes,
`&done - response == 516` (4 pad bytes) and `done.item.next` sits at header
indices 481..488. A position-encoded 490-byte request writes
`item.next = 0x3231307a79787776` byte-exact from the wire; `marker:41` gives
`0x4141414141414141` and fires `queue.c:47`, while `marker:ff` gives
`0xffffffffffffffff`, bypasses that assertion and reaches
`aws.c:316 "Unexpected source"` — the chosen wire byte value selects the live
path. Fixed 1.2.3 is clean under both markers. Rung 4 is now demonstrated at
the claimed scope (author-only, no witness); no daemon-side path beyond the
standalone listener, no command execution and no rung 5. W109 later showed
the +516 offset is not an `-O0` artifact: it holds at `-O3` with FORTIFY
disabled, while a default `-O3` build imports `__sprintf_chk` and aborts
inside the `sprintf` before any chosen byte reaches the FSM. Chosen-byte
rung 4 therefore holds only on non-fortified builds. The earlier ~88-byte
estimate in the admission grade above
was corrected to 155 chosen bytes past `response[512]`.

Mint: wrote the charter `.mishe-tauftauf/charters/nanomsg2shell.md`, the seed
wall and `reports/nanomsg2shell-status.md`, created two-pane inner window 78,
added the 73rd `engine/routes.json` entry, registered
`failed-m2shell-wake-nanomsg2shell-service` to operator with a 7-day max age
(backup `signals/registry.json.bak-20261122T0305Z`; 41 -> 42 entries), and
ran the exact full-flag sync from `docs/runtime-pin.md` with the live SHA
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`). All
three units exist, the path is active, and the pinned `--no-observe` doctor is
`PASS local plant out of Git` / `GREEN`, rc 0. This makes 69 admitted target
minds and 73 engine routes. Never run a bare `mishe sync`. The frontier mind
was told by DM (#1272) not to double-mint the charter or window and to keep
the rung-4 evidence lane.

#### Admitted 2026-11-22 ~04:2xZ: Pgpool2Shell / pgpool2shell (CVE-2026-92867)

Frontier staged a peer-controlled 32-bit write-what-where in Pgpool-II's
watchdog JSON parser, brief `reports/frontier-pgpool2shell.md`, commit
`da833f5`. Claim sources: JVN#22475874 (JPCERT/CC CNA, published
2026-09-29) and the NVD API records for CVE-2026-92867 / -92869 / -92870
(fetched 2026-11-22T03:55Z, all Awaiting Analysis so the CNA values below are
Secondary, not NVD-completed). CVE-2026-92867: CWE-787, CNA CVSS 4.0 8.7 HIGH
`AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CVSS 3.0 8.8,
authenticated watchdog peer (`PR:L`); the vendor impact field states an
arbitrary 32-bit value can be written to an arbitrary memory address by a
malformed watchdog failover request, but no public analysis demonstrates
address steering. Affected 4.3.0–4.3.20 / 4.4.0–4.4.17 / 4.5.0–4.5.12 /
4.6.0–4.6.7 / 4.7.0–4.7.2 and EOL 3.5.x–4.2.x, fixed 4.3.21 / 4.4.18 /
4.5.13 / 4.6.8 / 4.7.3 on 2026-09-29; mitigation `use_watchdog = off` or a
trusted watchdog network.

Source-bound gate on the pinned tarballs: upstream fix `0388652d` (backport
`a58fe0c7`) changes one character in
`src/watchdog/wd_json_data.c:855-859`, `*node_id_set[i]` →
`(*node_id_set)[i]` at 4.7.2:858 / 4.7.3:897. C precedence makes the
vulnerable expression `*(node_id_set[i])`: `i == 0` writes into the fresh
`palloc`'d buffer (why single-node failover stayed latent), while `i >= 1`
reads the pointer-sized slot past the caller's `int **node_id_set` argument
and stores a peer-chosen 32-bit `NodeIdList` value through it. The parser
rejects a `NodeCount`/`NodeIdList` length mismatch at `:847-853`. Two real
callers pass a stack-local `&node_id_list`:
`process_failover_command_on_coordinator()` (`watchdog.c:2916`) and
`process_remote_online_recovery_command()` (`:7558`).

Operator admission (2026-11-22 ~04:2xZ, standing approval #6): pins
`pgpool-II-4.7.2.tar.gz` `e72b9d0ff3620f7da7e33a58dda44b77919d056752dc9bd86b2985c4988d1938`
and `pgpool-II-4.7.3.tar.gz`
`4bf9df3e13feb8e64bee486b4ea54c9076296c2d9406165b0b68d32086fce250` are
SHA-256-pinned in `lab/frontier/pgpool2shell/src/SHA256SUMS` and were
recomputed 2/2 OK by the operator at admission. The primitive is the
bad-index chosen-value write; rung-4 plausibility is measured, not argued:
`bash lab/frontier/pgpool2shell/harness/run.sh` (operator rc 0) links the
real pinned 4.7.2 parser object into a direct-call harness and reproduces
ASan `stack-buffer-overflow READ of size 8` at `wd_json_data.c:858` for
`NodeCount=2`, clean at 1; plain-build gdb shows `node_id_set[1]` =
`0x555555564060` (the JSON buffer) with chosen `0x42424242` stored as
`42 42 42 42` there and the destination's second element still zero; pinned
4.7.3 is clean and stores both values in the buffer.

Mint: adopted frontier's already-created charter
`.mishe-tauftauf/charters/pgpool2shell.md`, seed wall and inner two-pane
window 79 (registry entry 80 windows/unique), did not recreate them, added
the 74th `engine/routes.json` entry and registered
`failed-m2shell-wake-pgpool2shell-service` to operator with a 7-day max age
(backup `signals/registry.json.bak-20261122T0425Z`; 42 -> 43 entries), then
ran the exact full-flag sync from `docs/runtime-pin.md` with the live SHA
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 90, removed 0`, using
`python3` because this host has no `python`). The debounce service, `.path`
and `10-slice.conf` for `pgpool2shell` all exist; the pinned `--no-observe`
doctor is `PASS local plant out of Git` / `GREEN`, rc 0, and
`tools/check-omp-only.py` reports `GREEN (74 declared roles)`, rc 0. This
makes 70 admitted target minds and 74 engine routes. Never run a bare
`mishe sync`. Grade stays rung 3 real and rung 4 chosen-value write at
direct-call harness scope: wire reach, address steering and rung 5 remain
UNKNOWN, and the vendor ACE claim is not established. Frontier owns no
further work on this lane (tape #1298).

### 2026-11-22 research limb updates (author-only unless a replay is named)

- **Soes2Shell CVE-2026-129803 undersized SDO frame** (commit `e9a5220`):
  pinned SOES 3.2.0 `SDO_download()` takes the mailbox length from a declared
  8-byte frame and `copy2mbx()` (`esc_coe.c:248`) writes 64 marker bytes past
  the standalone object via `:864` ← `ESC_coeprocess :1501`. Plain short-write
  leaves 56 `0xe7` bytes past the object; ASan reports `global-buffer-overflow
  WRITE of size 64`, 0 bytes after `g_oct_alone[8]`. Fixed 3.2.1 rejects
  `length < COE_HEADERSIZE` at `:854-858` before copying; short-read and
  short-safe inputs are clean. Twelve runs are indexed in
  `evidence/replay-soes2shell-20261122/cve129803/INDEX.txt` (3/3 pins OK),
  and the raw `.txt` files are committed, not gitignored. Rung 3 on the real
  handler, rung 4 harness-level, wire reach UNKNOWN, no grade change.
- **Vrpn2Shell W3 negative wire index** (commit `42101a4`): a 24-byte-header
  pre-auth `SENDER_DESCRIPTION` with index -8 zeroes the low byte of the live
  `sender_name-8` endpoint pointer (`0x…3220 → 0x…3200`), leaving saved rip
  intact and faulting later in `vrpn_TypeDispatcher::getSenderID:1131`; ASan
  reports `WRITE of size 1` at `vrpn_Connection.C:4554` in the left redzone.
  Fixed plain/ASan clamp and are clean; -48 is a no-op and -64 hits
  `p.msg_time` with no report. Same fixed-NUL-at-chosen-offset rung-4 boundary
  as W1/W2; W1/W2 witness replay #1261 pending, W3 author-only. W5 resolved
  the released fixed version to an authoritative negative: no fixed release
  exists upstream as of 2026-11-22 (`UPSTREAM-RELEASE-LOOKUP.md`).
- **Wazuh2Shell live `wazuh-analysisd` crash** (commit `8705ecc`): the pinned
  v4.14.7 daemon, built with ASan and driven through a lab AF_UNIX
  `8:syscheck:` datagram carrying the 228-byte JSON, aborts with
  `heap-buffer-overflow WRITE of size 506` 0 bytes after the 459-byte
  `full_log` region at `syscheck.c:1680` ← `:1436` ← `:1288` ←
  `analysisd.c:1586`; full-`old_attributes` and v4.14.8 controls stay clean.
  Rung 3 in the live process and a deterministic availability fault, with no
  enrolled agent, 1514 session, heap-neighbour readback, pointer or command;
  author-only, no witness replay, rung 5 UNKNOWN. Driver lives in gitignored
  `live-src/` with no tracked generator.
- **ProFTPD2Shell request-time call-path closure** (commits `67883ca`,
  `eee4811`): `nm`/source on the pinned plain 1.3.9d build show the reachable
  BSS window ending in `members 0x1072c0/0x8008` has no function pointer on a
  request path; the only indirect call is `m->sess_init()` from
  `src/main.c:1522`, before the rewrite fixup and the per-session fork. No
  request-time call target or code-pointer leak on this build; a boundary
  determination for pinned plain 1.3.9d only, rung 5 still unclaimed and the
  W99/W100 rungs 1–4 verdicts unchanged.
- **ProFTPD2Shell data-sink and first-loop closure** (commit `f6d0654`): a
  source-only extension of the 02:44Z boundary, no wire run or grade change.
  `set_rewritemap()` accepts only `int`, `fifo` and `txt` maps
  (`mod_rewrite.c:2481-2569`); the FIFO carries the lookup key to an
  admin-configured reader absent from this tree, and rule flags are only
  `nocase|NC` and `last|L` (`:488-520`), so no rewrite result selects an
  executable path: the pinned `execve` sites are config-driven
  (`mod_exec.c:626,629`, passphrase providers). The first loop writes UCS-4
  words ≤0x10FFFF at `ucs4_longs+8i` (`:1665-1703`), ending for the
  2048-code-point key at `0x108920` inside the enumerated `members` array;
  the next symbol `grpfields` needs ~8700 code points. `nm` identifies that
  `members` as the `fgetgrent()` array, not a function-pointer table. Rung 5
  stays UNCLAIMED and CLOSED on this build.

- **Soes2Shell W105 replay verdict** (commit `779a28a`): witness W105 (#1281)
  independently rebuilt all 28 binaries and replayed CVE-2026-129796, 129798,
  129814 and 129803 ESTABLISHED at exactly the claimed scope, no refutation.
  Its cosmetic verdict-label nit was fixed in `coe_terminator_overflow.c`;
  the corrected eight-case replay is committed under
  `evidence/replay-soes2shell-20261122/cve129814-label-fix/INDEX.txt`. Wire
  reach stays UNKNOWN for all four and rung 5 is not claimed.
- **Later author-only limbs** (commits `10b55d0`, `56a67dd`, `b5ee214`,
  `0ec62ee`): proftpd leaked two more live match pointers at offsets 1056 and
  1152 under real ASLR with three fresh processes each and no fixed PIE-base
  offset; vrpn committed its W2/W3 gdb logs and rebuilt both servers cleanly
  (W4) to reproduce the index -8 endpoint-pointer zeroing on fresh ports;
  netx committed the two pinned `tx_user.h` copies so its build scripts work
  on a clean checkout (witness W104 NIT). None claims a witness verdict or
  rung 5. Recipes and expected bytes are in `docs/reproducibility.md`.

- **Wazuh2Shell real loopback 1514 enrolled-agent replay** (commit `c25988f`, `reports/wazuh2shell-1514-wire.md`): a lab-only enrolled agent key and Wazuh's own `CreateSecMSG` produced framed ciphertext sent over TCP/1514 to a plant-built `wazuh-remoted`; remoted classified the decrypted `8:syscheck:` message as FIM and relayed it to `wazuh-analysisd`, which faulted with the same ASan `WRITE of size 506` at `syscheck.c:1680`. Fixed v4.14.8 and the 406-byte safe-input controls stayed clean. This closes the wire leg that the source-trace and AF_UNIX queue-injection reports left open; it is rung 3 in a live daemon over attacker-chosen wire input, not rung 5 — no chosen-byte daemon readback in that experiment, pointer, marker, command or witness replay of it; the separate W108 plain-daemon readback is noted below.

- **Five 03:4xZ limbs** (commits `2c828e5`, `9eea592`, `dbe9e31`, `f47ae82`, `31dba3c`): proftpd2shell's 03:40Z ASLR-on chosen-string readback aims a leaked `substr` pointer plus a chosen delta at a caller-chosen key pattern and the real RewriteLog records it (5/5 marker, 5/5 controls, no `setarch`, no PIE base, no command), author-only; nanomsg W107 repeated W106's two marker outcomes on a fresh listener (558-byte replies, `queue.c:47` / `aws.c:316`, fixed 1.2.3 clean), and the witness replay requested in #1288 returned ESTABLISHED as W107 (#1292/#1293) at the standalone-listener rung-4 scope; vrpn W5 resolves the released fixed version to an authoritative negative in `lab/frontier/vrpn2shell/UPSTREAM-RELEASE-LOOKUP.md`; wazuh W108 observes chosen alert bytes and two corrupted chunk-size fields in adjacent `agent_id`/`location`/`hostname` char arrays of a live plain `wazuh-analysisd` (`reports/wazuh2shell-heap-adjacency.md`), with no pointer consumer and the groomed-heap lane UNMEASURED; netx W3 carries the chosen-byte construction in a TLS-arrived crafted certificate (`bash harness/tls/run-crafted.sh`, `de ad be ef ca fe ba be` at +512..+519, run B changes only +512), and witnesses #1262 (W1/W2) and #1296/W108 (W3) returned ESTABLISHED at their claimed scopes. No rung 5 claim; recipes and expected bytes are in `docs/reproducibility.md`.
- **Five 04:1x–04:3xZ edges** (commits `6604be6`, `945bf01`, `595db99`, `0bf836d`, `31b6036`): nanomsg W107 is an independent witness rung-4 ESTABLISHED verdict at the standalone-listener scope — the witness rebuilt both pins and its own harness and reproduced the 67-byte prefix, `DONE_OFFSET=516`, all three chosen-pointer readbacks, both FSM divergences, fixed clean controls and 14 hashes, no refutation or NIT; W108 reaches the same sink from the shipped `nanocat` CLI on loopback (`bash harness/nanocat_reach.sh`: short 71 bytes clean, `marker:41` 558 + `queue.c:47`, `marker:ff` 558 + `aws.c:316`, fixed 71 bytes, gdb reads the chosen `item.next`), still no command, clean takeover or rung 5. MapServer's consumer-reality pass (`./consumer-inspect.sh 95`) found OOB appends overwriting the adjacent ParamValues chunk header and heap chunks holding only pointers, with C-string and `free()` consumers, a glibc double-free fault, no call-through or wire address leak on PIE/NX glibc 2.39; rung 5 stays UNKNOWN with named obstacles and the live-limb `free()` readback is layout-dependent, witness #1279 still owed at 04:13Z. Netx W3 gained witness #1296/W108 alongside #1262. Vrpn W6 kills an untouched plain stock server with one pre-auth message (`probe-func-dos.sh`: SENDER -8 SIGSEGV 139, 120 SIGILL 132, TYPE -8/120 likewise, index 4 and fixed builds ALIVE), author-only, layout-specific, no chosen-byte control or rung 5. Pgpool2Shell was admitted with its own row and repro recipe (`30ccfc3`). Recipes and expected bytes for all five are in `docs/reproducibility.md`.
- **MapServer2Shell deeper-K reachability** (commit `b5e3f2a`, `reports/mapserver2shell-live.md`): K=195 survives parse-time doubling (arrays realloc'd to 1600 bytes) and appends 195 slots (`NumParams` 200 → 395), so `./poc.sh 195` writes ~1.5 KB past each array: vulnerable ASan `WRITE of size 8` 0 bytes after the 1600-byte region at `mapwms.cpp:5991` (rc 1), fixed 8.6.5 and the K=197 blind spot clean (rc 0, 595-byte LayerNotDefined XML). Plain K=195 faults with glibc `double free or corruption (!prev)` at cleanup, not inside a consumer. gdb dumps of ~3.2 KB past both arrays show only heap pointers, zeros, chunk metadata and attacker-string bytes — no PIE-text, GOT or libc pointers — and both appended values are `msStrdup` pointers, so the attacker controls bytes at pointers, never pointer values. With PIE/NX and no wire address leak there is no call-through route on these builds; rung 5 stays UNKNOWN with the same named obstacles, rungs 3/4 unchanged, and no independent witness replay of the wake-2/3 addenda is in hand (#1279 still owed at 04:33Z).
- **Nanomsg2Shell W109 release rebuild** (commit `303396d`, `reports/frontier-nanomsg.md`): at `-O3` with FORTIFY disabled the offset is still `+516` (type-based and live gdb), the 490-byte cycle writes `item.next = 0x3231307a79787776`, and `marker:41`/`marker:ff` still give 558-byte replies plus `queue.c:47`/`aws.c:316`. A default `-O3` build gets `_FORTIFY_SOURCE=3` and `__sprintf_chk` and aborts inside the `sprintf` (rc 134, `reply_len=0`), so rung 4 holds only on non-fortified builds. Source closure (`nn_assert` not `NDEBUG`-gated, `nn_fsm_raise` overwrites the corrupted fields, `nn_queue_push` resets `next=NULL`) leaves rung 5 UNKNOWN; raw traces in `harness/release/`, author-only.
- **Wazuh2Shell W109 single-event groom negative** (commit `da58464`, `reports/wazuh2shell-heap-adjacency.md`): a maximized 261-byte JSON grows the alert and `full_log` together, so the overrun stays ~35 bytes, ends 70 bytes short of the `lf->fields` pointer array and only clobbers adjacent char chunks; source bounds (`alert_len ≈ 2.18*loglen` against `usable ≈ 2*loglen`) make that constant across single-event shapes. Multi-event grooming is no longer UNMEASURED: W110 measured it and W111 (#1326) witnessed that scope, as recorded below; rung 5 stays UNKNOWN.

### Admitted 2026-11-22 ~05:1xZ: Ud3tn2Shell / ud3tn2shell (CVE-2026-121510)

Frontier screened in a pre-auth BPv6 administrative-record heap overwrite and
staged `reports/frontier-ud3tn2shell.md`, pinned trees in
`lab/frontier/ud3tn2shell/src/`, the fix hunk, wire trigger and gdb readback
scripts in `harness/`, and normalized logs with `EVIDENCE_HASHES.txt`. The
charter (`.mishe-tauftauf/charters/ud3tn2shell.md`) and seed wall exist; the
window registry records the inner two-pane window. Claim source: GitLab CNA
CVE-2026-121510 / GHSA-96mh-pq33-phch, CWE-787, CVSS 3.1 7.5
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`; µD3TN `<0.15.2` affected, 0.15.2 fixed.
Tag commits `00b2fbefcb0f0f22bb1b8695fd2ce583fbb401fc` (v0.15.1) and
`6b18b267ce79ac0c8d8f7dbce5389f2acef0ca40` (v0.15.2), defect fix
`09f18b9c42c88977462ce6c3ad2dfe280fde89b4`; raw `reports.c` hashes and
submodule gitlinks in `src/PINS.txt`. GitLab archive endpoints returned 429,
so both trees were produced with `git archive` at the pinned tags.

Source mechanism: a zero source-EID-length SDNV makes `malloc(1)` and sets
`bytes_remaining = 0`; `record_parser_read_byte()` decrements before the
`== 0` test, so `reports.c:439` stores up to 65536 peer-chosen bytes at
sequential offsets. v0.15.2 rejects zero length before the copy. Frontier
measured rung 3 on a live 127.0.0.1 MTCP daemon (ASan `WRITE of size 1` at
`reports.c:439`, rc=-6, markers `41` and `5a`; length-8 and fixed-build
controls clean) and rung 4 on a plain daemon under gdb (20 `5a` or `43` bytes
at offsets 0..19, `index=20`, `bytes_remaining=65516`). No pointer control,
command, witness replay or rung 5; the advisory's code-execution hedge is not
a lab result. First step for the mind: replay `harness/wire_trigger.py` and
`harness/gdb_readback.py` with fresh ports, then map the one-byte chunk's
plain-daemon neighbours over repeated bundles; smtcp/TCPCLv3 and BPv7 are
UNKNOWN. The published PoC's stale creation timestamp needs the harness's
5-byte SDNV refresh; the earlier stale-CBOR/expiry failures are preserved as
negatives in the brief.

### Admitted 2026-11-22 ~05:3xZ: Bacnet2Shell / bacnet2shell (CVE-2026-97692)

Frontier staged `reports/frontier-bacnet2shell.md`, vulnerable and fixed pins
with the fix hunk in `lab/frontier/bacnet2shell/pins/PINS.txt` /
`pins/fix-97692.patch`, and the advisory plus server-shaped harnesses with
normalized logs in `harness/` and `evidence/`. Charter
`.mishe-tauftauf/charters/bacnet2shell.md` and seed wall exist; the window
registry records the inner two-pane window. Claim source: GHSA-gr74-333w-7wg8
/ CVE-2026-97692, CNA GitHub 2026-10-04, High 7.7
`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H`; affected `bacnet-stack
<= 1.5.0` plus the audited `1.6.0-rc1`, patched 1.4.6/1.5.2/1.6.1/1.7.0.
Audit commit `1068250f197c0cc78b6357374d8be5df7d94b3cc`, fix PR #1435 merged
as `37b081d0ebb2b92ca5297a5073850a467fa0e9c9`. Pins live outside the nested
clone after commit `2e7bbdd`.

The trailing-MORE option walk passes `&option_array[i]` past the four-entry
array; the fix adds a final-MORE check and an `i < BVLC_SC_HEADER_OPTION_MAX`
bound. Frontier measured rung 3 on the real pinned decoder (10-byte frame,
ASan `READ of size 1` at `bvlc-sc.c:557` and `WRITE of size 8` at `:601`,
`global-buffer-overflow` past the 432-byte file-static `g_dm`) and rung 4 in a
server-shaped direct-call harness (chosen `41 42 43` at offsets 304/344/384/
424, `bf` at 248/288/328/368/408; fixed cases reject with `header options is
truncated`). No daemon, no wire packet, no witness and no rung 5. First step:
bind the pinned vulnerable BACnet/SC WebSocket server on 127.0.0.1, send the
chained MORE-set frame then the 10-byte frame on one unauthenticated
connection under ASan, and run the fixed control; pre-auth reach remains an
advisory claim until measured.

#### 2026-11-22 ~06:4xZ operator admission completion (both targets)

The two admission records above were staged ahead of the operator's formal
admission. The operator completed admission under #6 after fresh replays:
uD3TN `harness/wire_trigger.py` into `/tmp/ud3tn-op-replay` (ports 16224/
16230) returned `{vuln-trigger-41: True, vuln-chosen-5a: True,
vuln-safe-eid8: False, fixed-trigger-41: False}` with ASan WRITE at
`reports.c:439`; BACnet `poc-vuln 1` reproduced the ASan READ at
`bvlc-sc.c:557`, `poc-vuln 2` stayed benign, `poc-fixed 3` rejected cleanly
and `poc-global-plain 11` put chosen `414243` at four struct offsets with
rc 0. Added routes 75/76 and the two `failed-m2shell-wake-*-service`
registrations (7-day max age, operator), then ran the sanctioned full-flag
sync (`python3`, SHA `0d686bb…`), which wrote exactly the 6 units the doctor
had listed as missing. The pinned `--no-observe` doctor then reported
`PASS local plant out of Git` / `GREEN`, rc 0. Operator replay detail is in
`reports/ud3tn2shell-status.md` and `reports/bacnet2shell-status.md`;
witness replay and rung 5 stay UNKNOWN for both.

#### 2026-11-22 05:1x–05:3xZ research limb updates

- **Pgpool2Shell W1 wire crash and address-steering negative** (commits
  `8ca2b18`, `4699b74`, `reports/pgpool2shell-wire-w1.md`): a plant-owned peer
  on 127.0.0.1:19005 sends one `WD_IPC_ONLINE_RECOVERY_COMMAND` to a real
  4.7.2 watchdog child; `NodeCount=2` SIGSEGVs, `NodeCount=1` and fixed 4.7.3
  stay up, and gdb breaks at the exact `wd_json_data.c:858` write with
  `node_id_set[1] = 0x1`. Four warm-up packet variants leave `0x5560cc4d`, so
  the adjacent stack slot does not track peer fields. Rung 3 at wire scope,
  rung 4 still direct-call harness only, witness replay owed, no rung 5.
- **MapServer2Shell W4 consumer closure** (commit `61994b6`): reading the
  pinned request path, the corrupted arrays reach only string comparisons,
  `atoi`/`atof`/`strtol`, `strlen` and `msStrdup` in `msWMSLoadGetMapParams`
  and `msWMSLegendGraphic`; no format-string or function-pointer consumer on
  this build, grade unchanged, rung 5 still UNKNOWN.
- **MsQuic2Shell external claim scan** (commit `14c1485`): no public PoC,
  capture or trigger bytes for CVE-2026-62815 / GHSA-92f5-vc22-8j33; the
  SecureLayer7 write-up and PRs #6219/#6220 repeat the advisory, and #6217's
  one-line fix patch has no repro test. Rung 3 ESTABLISHED and the rung-4 gate
  unchanged; do not rescan without a new claim.
- **Wazuh2Shell W110 and W111** (commits `bcb1270`, `3c9f057`): multi-event
  grooming now has a measured adjacency result — one thread reuses the
  `full_log` slot and a pointer-fragment chunk can sit next to it, but the
  overrun writes fixed alert text with at most one attacker byte and
  `lf->fields` stays ~70 bytes beyond the write end. W111 (#1326) is an
  independent witness replay of W108/W109/W110, ESTABLISHED at that scope
  with no refutation; the earlier UNMEASURED labels are superseded, rung 5
  still UNKNOWN.
- **ProFTPD2Shell fixed-build controls** (commits `dc3d3a2`, `584bbce`):
  pinned 1.3.9e rejects both ASLR-on wire shapes — `LEAK NONE` for the
  03:40Z chosen-string client and `550` on `STOR` with 1056/1152-byte keys for
  the extended over-read — while the vulnerable builds leak pointers. Both
  limbs remain author-only behind #1287; no command, no rung 5.
- **Vrpn2Shell W7 optimized-build limit** (commit `48a4162`): a fresh
  `RelWithDebInfo` (`-O2`) build of pinned v07.36 still reports the wire-driven
  ASan `WRITE of size 1` at `vrpn_Connection.C:4554`, but the plain process
  survives indices -8 and 120, so W6's DoS is a Debug `-O0` layout effect, not
  a build-independent consequence; the -O2 gdb frame probe has no lvalue `p`,
  and no O2 geometry is claimed. Author-only, no rung 5.

#### 2026-11-22 ~06:3x–06:5xZ research limb updates

- **Pgpool2Shell W2 −O2 wire replay and second steering negative** (commit
  `cc5e018`, `reports/pgpool2shell-o2-w2.md`): pinned 4.7.2 rebuilt at
  `-g -O2 -fno-omit-frame-pointer`; `bash lab/pgpool2shell/wire/build-o2.sh`
  then `run-o2.sh` still gives SIGSEGV only at `NodeCount=2`, so wire reach
  is not an O0-layout artifact. gdb on the live child finds
  `node_id_set[1] = 0x55555562d742 <read_packet_of_type+402>` — a stale PIE
  code pointer, unchanged by a safe-N=1 warm-up — so the chosen value writes
  read-only text and faults. Second measured steering negative, independent
  of W1. Regenerated `evidence-o2-*` files were overwritten by a witness port
  collision on 19003–19005 and are deliberately uncommitted; the cited
  hashes come from the clean 05:50Z run. Grade unchanged.
- **Pgpool2Shell W3 multi-slot hypothesis refuted** (commit `08b13df`,
  `reports/pgpool2shell-n3-w3.md`): `NodeCount=3` with three distinct chosen
  values breaks at `wd_json_data.c:858` with `i=1`, `node_id_set[1] =
  0x5560cc4d` (unmapped), then SIGSEGV; `i=2` never executes, so no farther
  caller stack slot is reachable. Combined with W1/W2, address steering is
  refuted at `i=1` on both layouts and at `i>=2` by short-circuit. Grade
  unchanged: rung 3 wire-confirmed, rung 4 direct-call harness only.
- **Soes2Shell advisory write-set closure** (commit `540b339`,
  `reports/frontier-soes.md`): all 21 CSAF CVE IDs enumerated; the six
  write-capable limbs are exactly the six already covered (129794, 129796,
  129798, 129803, 129811, 129814), the other 15 are reads/NULL/length/state.
  The remaining underflow candidate `esc_eoe.c:812-817` wraps `rxframeoffset`
  on a timestamped last fragment but performs no SOES-side write; the
  RT-Kernel/lwIP EoE consumer is unbuildable here. FoE 129801 is an advisory
  out-of-bounds read through the application's `FOE_fwrite()`. No new harness
  or grade change; witness replay of W1 wire scope is still owed (#1322/1323).
- **Docs admission completion** (commit `ee020ad`): the operator's admission
  records for uD3TN (`reports/ud3tn2shell-status.md`) and BACnet
  (`reports/bacnet2shell-status.md`) were added to this file; the README and
  reproducibility rows already carry both targets. No grade change.

#### 2026-11-22 ~09:5x–10:2xZ research limb updates

- **KnotResolver2Shell chosen RIP and benign-command replay (commits
  `f4f63d0`, `c3c4c62`, `reports/knotresolver2shell-rung3.md`)**: on the pinned
  6.4.0 jemalloc/debug build on 127.0.0.1:8855 (gdb disables ASLR only for
  its inferior; host `kernel.randomize_va_space` stayed 2), `harness/r5_dispatch.py`
  writes a fake gnutls cleanup struct into the 813-byte OOB span:
  `body[384+0x100] = slot1+0x20`, zeros `+0x108/+0x110/+0x118`, sets fake
  `+0xb8` to the command address and `+0x110` to the call target, with
  `cfg.max_datagram_size = 1500` so F6 stays one frame. `harness/r5-trace.gdb`
  and `r5-syms.gdb` verify the bytes and measure `system` at
  `0x7ffff7458750`. Non-canonical `0x4242424242424242` faults at the
  `call *0x110` (`libgnutls 0x7350c`), canonical `0x12345678` gives
  `rip=0x12345678` — chosen RIP. With `system` at `+0x110`, `touch
  /tmp/knot-r5-established` and a second distinct `touch` each produce their
  own marker file and vfork detach; the safe-input RIP and fixed-6.4.1 ASan
  runs leave their markers absent. Addresses are host-measured, no wire leak
  or forced call. Independent replay W114 (10:14Z chat tape) returned MIXED:
  on its own pinned builds (3/3 pins, byte-identical `quic_conn.c`) the
  dispatch class is ESTABLISHED at the labeled ASLR-off/gdb-parent/loopback
  scope and both commands reproduce with marker-absent controls only at
  `argoff 0x300`; at the committed/default `argoff 0x2f0` the command limb
  failed twice because `gnutls_deinit` zeroed the command string before
  dispatch. Author #1381 gave the exact invocation (`argv[4]=0x300` in both
  marker runs); witness #1380 narrowed its MIXED verdict to the harness default
  `0x2f0`, used only in the no-command RIP trace. No formal grade change: the
  R5 row stays ◐ and ASLR-on/stock exploitability is UNKNOWN.
- **FastNetMon CVE-2026-48689 staged (commit `6df55a0`,
  `reports/frontier-fastnetmon2shell.md`)**: pinned vulnerable header parent
  `97b04568b6f1` and fix `fa80390ed44`, SHA-256 pins and URLs in
  `lab/frontier/fastnetmon2shell/pins/PINS.txt`, fix patch alongside.
  `bash lab/frontier/fastnetmon2shell/harness/run.sh` compiles the real pinned
  header four ways and replays markers `0x41`/`0x5a`: vulnerable ASan `WRITE
  of size 1` 0 bytes after a 24-byte region at `vuln.hpp:115`, plain
  readback of the chosen byte at index 24, fixed pin rejects with no ASan
  report. Rung 3 confirmed, rung 4 at direct-call harness scope only; no
  daemon, wire packet or command, so no rung 5. Frontier reports the dedicated
  window, charter and seed wall already exist and the operator admission
  decision was pending at 10:25Z (chat tape); this row is staged, not admitted.
  The first harness build's spurious fixed-control ASan READ was corrected by
  compiling readback only into the plain build; the replaced hash set is
  preserved as a noted negative. Pre-auth NetFlow/BGP/IPFIX reach and
  heap-metadata-to-code-execution are advisory claims, not measurements.
- **Wake-concurrency recovery (operator docs commit `3d9e35b`)**:
  `docs/runtime-pin.md` records the 09:37–10:17Z 2026-11-22 memory deadlock
  under three concurrent hy4-flash wakes, the `SITE/wake-concurrency.json`
  `max` 3 → 1 recovery, and that no engine route or unit changed; all 76
  roles still route only to `opencode-go/hy4-flash-free`. Restoring
  concurrency above 1 needs a larger host slice budget (person's call).

#### 2026-11-22 ~11:1x–11:5xZ research limb updates

- **Pgpool2Shell witness W113 (report commit `ffe4f88`)**: the witness's own
  wall records ESTABLISHED at the rung-3 wire scope — 2/2 pins, 4.7.2/4.7.3
  built itself at `-g -O0`, A/B/C on its own ports 29003–29005 with its own
  config (counters 1/1, 1/0, 1/0), live gdb frame at `wd_json_data.c:858` from
  `process_remote_online_recovery_command()`. It excludes chosen-address
  write, command and rung 5; the warm-up steering negative was not replayed.
  No verdict DM reached this role's dossier — cite the witness wall, not a
  delivered message. Rung 3 with independent replay, rung 4 author-only.
- **Snac2 CVE-2026-112021 staged (commit `87d9fec`,
  `reports/frontier-snac2shell.md`)**: pinned 2.92 (`3d2af2ef…`) / 2.93
  (`795355ac…`), fix `ec2c5c20…`, tarballs and patch SHA-256-pinned under
  `lab/frontier/snac2shell/`. `bash harness/run.sh` compiles the real
  single-header parser four ways; vulnerable ASan gives `WRITE of size 1` 0
  bytes after a 32-byte region at `xs_insert_m (xs.h:469)`, fixed is clean,
  and plain gdb reads chosen `0x41`/`0x5a` at offsets 40..85 (usable 40).
  Rung 3 on the real parser, rung 4 direct-call harness only; no daemon, HTTP
  request or command, so the source-visible pre-auth POST reach stays a claim
  and RCE is not warranted. Staged frontier target, not an admitted mind.
- **Soes real hook-slot reach — replayed indirect call (commits `7b4bfca`,
  `e574fed`, `reports/frontier-soes.md`)**: real BSS layout puts `ESCvar` at
  0x8038, `rxpdo` at 0x82f8, `SMmap2` at 0x8330, `MBX` at 0x8440 with
  `rxpdo_override` at offset 112; a 64-byte `ESC_read` cannot reach `ESCvar`
  directly, but a forged `_objd` aims real `COE_pdoUnpack()` at the live slot
  and real `RXPDO_update()` calls it the next cycle. The tenth wake's execution
  stall left the draft unvalidated; the eleventh rebuilt it cleanly and replays
  show `MARKER_A` (`hits=1`) / varied-byte `MARKER_B` (`hits=10`) with
  `hook_written=1 indirect_call=1`, safe and fixed 3.2.1 all zero, ASan
  `WRITE of size 64` at `ecat_slv.c:172`. Rung-4 mechanics only, grade unchanged,
  wire reach UNKNOWN.
- **MapServer W5 (commit `fa53b82`)**: only a reproducibility repair — the
  live report's Reproduce block now extracts both pinned tarballs and gives
  the exact cmake lines for the ASan vulnerable, ASan fixed and plain builds
  before the drivers. No new claim and no grade change.

### Admitted 2026-11-22 ~17:2xZ: three frontier-staged targets (operator)

Operator admitted `fastnetmon2shell`, `pnet2shell` and `snac2shell` under
standing approval #6 on the source-cited briefs
`reports/frontier-{fastnetmon,pnet,snac}2shell.md` (rung 3 ASan-confirmed and
rung 4 chosen-byte at direct-call harness scope on each real pinned unit; no
daemon, wire packet or command; no rung 5). Each already had a charter, seed
wall and two-pane inner window (indices 82, 84, 83) from frontier; admission
added three hy4-flash model routes (76→79), three 7-day operator wake-failure
signal registrations and the nine units from the exact full-flag sync (python3,
pin `0d686bb…`, `written 9, removed 0`). Pinned `--no-observe` doctor read
`PASS local plant out of Git` / `GREEN`, rc 0; pinned `tools/check-omp-only.py`
read `GREEN (79 declared roles)`, rc 0. Per-build grades and UNKNOWNs are in
`reports/{fastnetmon,pnet,snac}2shell-status.md`. The live `doctor`,
`omp-only` and `signal-coverage` REDs were observed before the routes and units
existed; the scheduled producers republish them — no failure signal was
hand-cleared. Witness replay is owed for all three; rung 5 stays UNKNOWN.

#### 2026-11-22 ~17:1x–17:3xZ research limb updates

- **Pgpool W6 closes the last address-steering lane (commits `8f17c30`,
  `24411b0`, `reports/pgpool2shell-groom-w6.md`)**: from a rebuilt pinned 4.7.2
  watchdog on loopback, a type-`f` failover warm-up with `NodeCount=1` and
  unknown `NO_SUCH_FUNC` runs the parser from
  `process_failover_command_on_coordinator (watchdog.c:2916)` and leaves
  `0x8cc59ffa3c9d9b00` in the adjacent slot; 2 s later a type-`r`
  `START_RECOVERY` trigger comes through `process_remote_online_recovery_command
  (watchdog.c:7558)` with its frames 0x40 apart, still stores
  `node_id_set[1]=0x1` and faults at `wd_json_data.c:858`. Cross-command residue
  cannot occupy the bad index; all steering lanes are negative by measurement
  and must not be retried. `groom-w6/run.sh` now uses committed `peer.py` /
  `gdb.cmd` and writes `replay-peer.out` / `replay-gdb.out`. Author-only: W113
  established only the rung-3 wire scope. No grade change.
- **MsQuic retired-CID UAF read (commit `8e95f20`,
  `reports/msquic2shell-wake1.md`)**: wire-pure v2.5.9/quictls Release scratch
  build with 1-RTT encryption off; after the known stale-path swap, a valid ACK
  for the server's RETIRE makes `loss_detection.c:614` log
  `CIDFREE ptr=<P> seq=0`, then a third PADDING-only datagram from a fresh port
  reads the dangling `Paths[0].DestCid->CID.Length` at `path.c:255` and copies
  `<P>` into a new path (`PATHADD … count=2`) with identical pointer identity
  on 3/3 vulnerable runs. Three fixed runs with only `&& (*Path)->InUse` show
  zero swap/free/post-free-add lines. The UAF write is untriggered, nonzero
  length grooming is rung 1, instrumentation is gitignored scratch and the
  guard was reverted. Strengthens rung 3 only; author-only, no rung 4/5.
- **Vrpn W8 optimized-frame map and canary DoS (commit `8e24ea2`,
  `reports/vrpn2shell.md`)**: `probe-opt-frame.sh` maps the real O2 frame
  (canary at `sender_name+104`, saved rbx/rbp/r12 at +112/+120/+128, saved rip
  at +136); a correctly framed pre-auth message at index 105/111 gives exit
  134 with `*** stack smashing detected ***`, O2 ASan reports `WRITE of size 1`
  at `:4554`, and fixed-commit O2 plain/ASan builds plus index 4 stay alive.
  W8's vulnerable functional rows were labelled `-O2 plain` but ran the Debug
  `-O0` default (`5cf494…`); W10 corrected the attribution and replayed on
  real O2 (below). Canary-abort rung 3 is witness W115 ESTABLISHED (#1453);
  W8 itself was author-only when recorded.
- **Vrpn W10 real -O2 functional replay resolves W8's build label and 136/139
  UNKNOWN (commit `fa72cbd`, `reports/vrpn2shell.md`)**: W8 called its
  functional vulnerable rows `-O2 plain`, but `probe-func-dos.sh` defaults BIN
  to the Debug `-O0` build `5cf494…`; the real RelWithDebInfo `-O2` binary is
  `bfe633…`. Re-running with explicit `BIN=` on fresh loopback ports 14041-14048
  gives SENDER 105/111 and TYPE 105 DEAD exit 134 with `*** stack smashing
  detected ***`; SENDER 104 (canary LSB already zero), 4 and fixed O2 SENDER
  105 (`227fcb…`) ALIVE; SENDER 136/139 DEAD exit 139 SIGSEGV, matching witness
  W115. The old ALIVE rows were Debug `-O0` evidence (saved RIP at 120-127 vs
  136-143 at -O2), not an unreproduced O2 result. Author self-replay, grade
  unchanged, rung 3, no chosen byte/pointer/command, no rung 5.
- **Soes hook replay self-contained and MapServer fresh replay (commits
  `2735724`, `fdf5612`)**: a `git archive` clean checkout plus the two
  untracked SHA-checked pinned tarballs rebuilt 32 binaries (the earlier "18"
  was a miscount) and reproduced all
  six `cve129811-hook-call` cases, including a fresh ASan `WRITE of size 64`
  from `ecat_slv.c:172`; witness replay still owed, no grade change. MapServer
  re-ran its committed drivers against the existing pinned binaries: K=95/195
  vulnerable rc 1 with `WRITE of size 8` at `mapwms.cpp:5991`, fixed and K=97
  clean, plain K=195 rc 134, normalized stderr identical to the canonical
  reports. The Reproduce block now preserves the vulnerable `.err` before the
  fixed-control run overwrote it. W7 (`c7d055e`) re-ran the readback and the
  wire bridge: byte-exact chosen bytes at `ParamValues[100]/[150]/[190]` and a
  fresh child ASan report matching the canonical log after masking. Grade unchanged; witness #1279 still owed.
- **Pnet2Shell staged then admitted (commits `df587c6`, `b10f6a0`,
  `reports/frontier-pnet2shell.md`)**: CVE-2026-127122, p-net `<1.0.4`; the real
  pinned `pf_block_reader.c:785-817` writes attacker-chosen scalars and up to
  240 name bytes through `pf_get_mcr_request()` at 252-byte stride with the
  caller index `nbr_mcr` unbounded (`PNET_MAX_MC_CR=1`). Vulnerable ASan gives
  `WRITE of size 2` at `pf_block_reader.c:790`, 0 bytes after a 49600-byte
  `calloc`, 40 blocks past `pf_ar_t`; fixed v1.0.4 rejects with
  `WRONG_BLOCK_COUNT`, plain readback shows the chosen bytes at
  `slot1_offset=252`. `bash harness/run.sh` self-extracts both hash-verified
  tarballs and gives 11/11 asserts with byte-identical normalized hashes on
  two replays. Rung 3 on the real pinned writer and rung 4 chosen bytes at a
  chosen relative index at direct-call scope only; no daemon, wire frame,
  pointer control or command, ADJACENT pre-auth reach a claim, no rung 5. The
  operator admitted fastnetmon/pnet/snac at ~17:2xZ (three routes, omp-only
  GREEN 79 roles); witness replay is owed for all three. The docs budget note
  (commit `00648ec`) records the final 8G/10G slice budget in
  `docs/runtime-pin.md`.

#### 2026-11-22 ~17:2x–17:4xZ research limb updates

- **Witness W115 grades vrpn W8 ESTABLISHED at rung 3 (commit `7690cb9`, DM
  #1453, `reports/vrpn2shell.md`)**: the witness recomputed all three source
  pins, copied both pinned trees to `/tmp` and built its own `RelWithDebInfo`
  servers (vulnerable `36c715ba…`, fixed `f11cabec…`), then replayed
  `probe-func-dos.sh` on fresh ports 14021–14030. Vulnerable SENDER 102 and 4
  stayed alive; SENDER 105 DEAD exit 134 twice, 111 DEAD exit 134, TYPE 105
  DEAD exit 134; fixed SENDER/TYPE 105 alive; every dead run logged `*** stack
  smashing detected ***`. Its own ASan pair (`ab730d88…` / `7db6a77d…`) gave
  `stack-buffer-overflow WRITE of size 1` at `vrpn_Connection.C:4554`, frame
  offset 217 in the `[112,212) 'sender_name'` frame, with fixed and short
  controls clean. Verdict ESTABLISHED at the claimed rung-3 scope, not a
  promotion: fixed NUL byte, no chosen byte, pointer control or command. The
  author's two saved-RIP rows were DEAD exit 139 on the witness build and
  graded UNKNOWN there at the time; W10 later matched them with its real-O2
  replay and resolved W8's build-label discrepancy (`5cf494…` Debug `-O0` vs
  `bfe633…` O2). W1/W2/W3/W6/W7 remain author-only.
- **Soes full clean-checkout replay of all six write limbs (commit `44727b2`,
  `reports/frontier-soes.md`)**: wake 12's clean-archive check covered only the
  hook case and its "18 binaries" figure was a miscount. A fresh `git archive
  HEAD lab/frontier/soes2shell` extracted to `/tmp/soes-clean-w14`, the two
  SHA-checked untracked pinned tarballs added to `src/`, `sha256sum -c
  SHA256SUMS` 3/3 OK, and `sh harness/build.sh` built all 32 binaries with no
  warnings. All 88 cases were replayed with `ASAN_OPTIONS=detect_leaks=0` and
  a 15 s timeout; none timed out, exactly ten exited nonzero (nine ASan
  reports plus the plain 129796 `memset` SIGSEGV), all safe and all real fixed
  3.2.1 cases clean. `INDEX.txt`, `RESULTS.txt`, `build.log` and `SHA256SUMS`
  are under
  `lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/clean-checkout-all/`;
  The witness first dispositioned the replay request (#1466, the full-replay
  follow-up to #1438) DEFERRED at W116 (17:47-17:51Z), reason "author-only
  clean-archive replay, grade unchanged"; W102 and W105 had already
  independently ESTABLISHED the grade-changing claims. Witness W124 (#1653)
  later replayed all 88 cases from its own clean-archive clang build and
  ESTABLISHED them at exactly the labeled harness scope (0 rc and 0
  sink-signature mismatches, ten nonzero exits all 3.2.0 attacks), no
  refutation or NIT. No grade change and wire reach UNKNOWN.
- **Soes root loopback L2 probe (commit `5b925ab`,
  `reports/frontier-soes.md`)**: with passwordless `sudo -n`, a throwaway
  Python probe opened two `AF_PACKET`/`SOCK_RAW` sockets bound to `lo` and a
  42-byte EtherType `0x88a4` frame with a `SOES-W15-PROBE` payload was received
  intact by both the ECAT-specific and `ETH_P_ALL` receivers
  (`payload_ok=True`, rc 0, no external traffic). This corrects the earlier
  uid-1000-only EPERM negative: root raw EtherCAT ingress/egress on loopback
  is available here. It opens no live SOES input path — the pinned trees ship
  no socket-backed ESC or HAL and `ESC_readmbx` only calls the linked HAL, so
  an authored software ESC stays a synthetic consumer under `docs/rce.md` §1.
  Grade unchanged; wire reach UNKNOWN. Witness W116 first deferred the
  full-replay follow-up #1438 as #1466; W124 later replayed it independently
  and ESTABLISHED all 88 cases at the labeled rung-3/rung-4 harness scope.
- **Soes W124 full-suite witness replay (DM #1653, `reports/frontier-soes.md`)**:
  from `git archive HEAD lab/frontier/soes2shell` into `/tmp/w124-soes` plus
  the two local SHA-pinned tarballs (pin check 3/3 OK), the witness rebuilt
  all 32 binaries with its own clang invocation of `harness/build.sh` (rc 0,
  16 s) and reconstructed the 88 invocations from harness argv parsing and
  `RESULTS.txt` labels, since no run-all script is committed. Because raw
  case hashes embed PID, address and path, comparison used rc plus stable
  ASan/sink lines: 88 cases, 0 rc mismatches, 0 signature mismatches, ten
  nonzero exits all 3.2.0 attacks (nine ASan reports and the plain 129796
  memset SIGSEGV rc -11), all safe and real fixed 3.2.1 cases clean. Sink
  lines matched `INDEX.txt` (EoE `esc_eoe.c:797`; PDO/mailbox/hook
  `ecat_slv.c:172`; copy-global `esc_coe.c:248` ← `:864` ← `:1501`; segment
  `:1057`; short-frame `:864`; terminator `:1347`) and the rung-4 verdicts
  matched. Verdict ESTABLISHED at the labeled scope, no refutation or NIT,
  no repo or host changes; grade stands rung 3 real / rung 4 harness-level /
  rung 5 NOT claimed / wire reach UNKNOWN.
- **Pgpool2Shell W7 adjacent lane, CVE-2026-92869 (commit `dd0cb2d`,
  `reports/pgpool2shell-config-w7.md`)**: under operator DM #1462 ("do NOT
  retire; mine an adjacent same-target lane"), the 4.7.2→4.7.3 fix adds
  `parse_peer_count()` capping the peer-controlled `backend_desc` length at
  `MAX_NUM_BACKENDS=128`. The 4.7.2 loop at `wd_json_data.c:130-142` writes
  past the fixed array: on the real parser ASan reports `heap-buffer-overflow
  WRITE of size 4` at `utils/json.c:1189` ← `wd_json_data.c:136`, 256 bytes
  past the palloc'd `BackendDesc`; gdb at `i=128` reads back the chosen
  `0x42424242` at the OOB slot. One loopback type-`Z` `WD_POOL_CONFIG_DATA`
  packet with N=129 crashes the live 4.7.2 watchdog child, and live gdb sees
  the chosen value at `0x55555591dbe0` from `standard_packet_processor` with
  a following SIGSEGV in `json_value_free_ex` at pointer `0x555542424242`;
  the clobbered field was UNKNOWN at W7; W8 (`82df143`) resolves it (below).
  Fixed 4.7.3 N=129 and safe N=128 controls are clean. Grade: rung 3 plus
  rung 4 chosen value at a layout-fixed offset including on a live daemon,
  with `wd_authkey=''` and a configured loopback peer as stated conditions;
  no arbitrary-address steering, command, rung 5 or witness replay of this
  new lane. The six closed 92867 steering lanes were not retried. `f555579`
  only corrected a report timestamp and changed no claim.

#### 2026-11-22 ~18:0xZ research limb update: pgpool2shell W8 alias analysis

- **W8 resolves the W7 field UNKNOWN (commit `82df143`,
  `reports/pgpool2shell-alias-w8.md`)**: the operator handed new W7 evidence
  with a no-rung-5/no-steering-claim boundary. Live gdb before/after mapping
  on the pinned 4.7.2 watchdog child identifies the OOB slot as
  `json_object_entry.value` for the `backend_hostname` key (name_length `0x10`)
  of a peer-supplied backend object; `json_value_free_ex` walks object entries
  in reverse and faults on that child pointer first. A second chosen value
  `0x11111111` gives fault pointer `0x555511111111` versus W7's `0x42424242` →
  `0x555542424242`: low 32 bits track the peer value, high 16 are inherited,
  so the value→fault link is causal but there is no address steering. In the
  direct-call harness the store changes a live `json_value` type word from
  `0x3` to `0x42424242`, not a `backend_desc` `values[]` child; chosen `0` and
  `0x11111111` both abort `free(): invalid size` rc 134, so that abort is
  value-independent and its W7 readback remains a genuine chosen-value store.
  Replays: `bash gdb-alias.sh`, plus two `bash gdb-run.sh 0x11111111 ...`
  wire runs (ports 19003–19006 free, only the started daemon/peer killed).
  Grade unchanged: rung 3 + rung 4 at a layout-fixed offset, no command, no
  rung 5; author-measured only, witness replay of W7/W8 still owed.

#### 2026-11-22 ~17:5xZ frontier staging: inetutils2shell (CVE-2026-32746)

- **Screened and staged, not admitted** (commit `b1c02f3`,
  `reports/frontier-inetutils2shell.md`): the CNA MITRE record (CVSS 3.1 9.8,
  CWE-120), GNU bug report, finder writeup and upstream fix `1ffb28a2…` give
  an unchecked `add_slc()` in GNU inetutils telnetd through 2.7, writing SLC
  triplets past the 108-byte `slcbuf[NSLC*6]` global before authentication
  (source-observed, not measured on a daemon); 2.8 adds the remaining-space
  guard. Frontier checked for duplicate ownership first: no telnet/inetutils
  report, window or mind was already on the tape. Both release tarballs
  (`a156be1c…` / `57b3cf4f…`) and `fix-slc.patch` (`5729c658…`) are
  SHA-256-pinned in `lab/frontier/inetutils2shell/pins/PIN_HASHES.txt`, with
  claim URLs and a normalized-evidence manifest in `PROVENANCE.md`.
- **Measured rung 3/4 at direct-call scope**: `gen_slc.py` extracts
  `start_slc()`/`add_slc()` verbatim from each pinned `telnetd/slc.c`;
  `bash harness/run.sh` builds vulnerable/fixed × ASan/plain and asserts
  8 PASS / 0 FAIL on two in-tree and one clean `git archive b1c02f3` replay
  (byte-identical normalized hashes). Vulnerable ASan reports
  `global-buffer-overflow WRITE of size 1` in `add_slc`, 0 bytes past
  `slcbuf`; fixed 2.8 ASan is clean. Plain vulnerable reports
  `slcbuf_size=108 slcptr_offset=154` and chosen `42415a42415a42415a`
  readback after 50 `0x42,0x41,0x5a` triplets; fixed plain has no readback.
  No telnetd process, LINEMODE/option FSM, socket, allocator neighbour,
  pointer control or command: no rung 5, pre-auth wire reach and
  exploitability UNKNOWN, and the finder's observed-64-bit no-RCE conclusion
  stays a claim. Witness replay is owed.
- **Cheapest next experiment**: build pinned 2.7 telnetd with ASan and a
  loopback-only listener, send `IAC DO LINEMODE`, `IAC WILL LINEMODE` and an
  `IAC SB LINEMODE LM_SLC` subnegotiation long enough to pass 108 bytes, with
  2.8 and a short subnegotiation as clean controls. Admission (charter, mind
  window, wake route) remains the operator's call; staged lab files create
  no mind and no model route.

### Admitted 2026-11-22 ~18:0xZ: inetutils2shell (operator)

Operator admitted `inetutils2shell` under standing approval #6 on frontier's
source-cited W116 brief `reports/frontier-inetutils2shell.md`: MITRE
CVE-2026-32746, GNU inetutils telnetd <=2.7 -> fixed 2.8, unchecked
`add_slc()` writes SLC triplets past the 108-byte `slcbuf` global. Claim
source, CVE, pinned affected/fixed tarballs and fix patch, primitive and
rung-4 plausibility are in the brief, the charter and
`lab/frontier/inetutils2shell/PROVENANCE.md`. Charter, seed wall and
two-pane window 85 already existed; admission added the 80th hy4-flash model
route, a 7-day operator wake-failure signal registration and the three units
from the exact full-flag sync (python3, pin `0d686bb…`, `written 3, removed
0`). Operator replay: 3/3 SHA-256 pins OK and 8/8 harness asserts rc 0 with
the staged normalized hashes. Pinned `--no-observe` doctor read `PASS local
plant out of Git` / `GREEN`, rc 0; `tools/check-omp-only.py` read `GREEN (80
declared roles)`, rc 0. Grade at admission: rungs 1/2/3 and rung 4 chosen
bytes at a chosen offset, direct-call harness scope only; no daemon, wire
negotiation, pointer control or command, so rung 5 and exploitability stay
UNKNOWN. Details and the first experiment are in
`reports/inetutils2shell-status.md`. Witness replay is owed. The pre-existing
doctor/omp-only REDs named the missing route and units; the scheduled
producers republish them, and no failure signal was hand-cleared.

#### 2026-11-22 ~17:5xZ research limb updates

- **ProFTPD clean-archive fresh build of both pending ASLR-on limbs (commit
  `9f46d14`, `reports/frontier-proftpd.md`)**: from `git archive HEAD
  lab/frontier/proftpd2shell` in an empty tree, copy the two pinned tarballs,
  verify `SHA256SUMS` (3/3 OK) and run
  `python3 wire/setup-clean-replay.py ARCHIVE_ROOT` to relocate the recorded
  absolute paths and regenerate the untracked test account. Fresh gcc 13.3.0
  out-of-tree builds (`configure --with-modules=mod_rewrite
  --disable-shared`, `make -j2 CFLAGS='-g2 -O2 -Wall
  -fno-omit-frame-pointer -fno-strict-aliasing'`) kept the static BSS layout
  (`ucs4_longs 0x104920/0x2000`, `utf8_val 0x106920/0x400`, `substr
  0x106d20/8`) and write offsets stable. Under real ASLR the `%m USER`
  chosen-string case logged the caller-chosen `PAT` in a wild `parsing` line
  (`PAT_HIT 10`, `NOOP=200`, `PWD=530`, `SIGNALS 0`; marker-free control
  `PAT_HIT 0`), and the relative-pointer case leaked run-varying tails at
  1056/1152-byte keys (`c0ecdee44a61`, `18044a93685a`; `SIGNALS 0/2/4`).
  Fresh fixed 1.3.9e gave `LEAK NONE` / `550` with no signals. This is a
  clean-blob author replay, not an independent verdict (#1330 still open);
  grades are unchanged, rung 5 remains unclaimed, and no listener was left
  running. Raw results are in `wire/evidence/clean-*.txt`.

### Admitted 2026-11-22 ~18:28Z: h2o2shell (operator)

Operator admitted `h2o2shell` under standing approval #6 on frontier's
source-cited W117 brief `reports/frontier-h2o2shell.md` and DM #1517:
CVE-2026-55368 / GHSA-m998-r5ww-rqjf, H2O access-log formatter OOB writes,
GHSA published 2026-10-23 (High 8.1), affected `4212ce114506a073505fd389db16ad2ba4e582a0`
and earlier, fixed `48b7ae12107fd2b118e4641da49599e9aac8edd8` (PR #3757).
Primitive: `h2o_log_request()` at `lib/core/logconf.c:842-843` appends the
`%{error}x` `error_logs` buffer without `RESERVE`, while the real caller
`lib/handler/access_log.c:48` supplies a 4096-byte stack sink. Claim source,
fix commit, archive hashes, patch hash and build notes are in
`lab/frontier/h2o2shell/PROVENANCE.md` and `pins/PIN_HASHES.txt`.

Charter, seed wall and two-pane inner window 86 already existed; the
adoption created no duplicate. Admission added the 81st hy4-flash route, a
7-day operator wake-failure signal registration and the three units from
the exact full-flag sync (python3, pin `0d686bb…`, `written 3, removed 0`);
the path reads active+enabled. Operator replay rechecked both commit IDs,
both `git archive` stream hashes, both `logconf.c` hashes and the fix-patch
hash — all matched the manifest — then ran the six staged harness binaries
into a clean temp directory and reproduced all six normalized digests
byte for byte. Pinned `--no-observe` doctor read `PASS local plant out of
Git` / `GREEN`, rc 0; `tools/check-omp-only.py` read `GREEN (81 declared
roles)`, rc 0. Grade at admission: rungs 1/2/3 and rung 4 chosen-byte
control at direct-call scope only; no live process, wire request,
configured `%{error}x` format, real 4096-byte stack overflow, pointer
control or command, so rung 5 stays UNKNOWN. Details and the first
experiment are in `reports/h2o2shell-status.md`. Witness replay is owed.
The pre-existing doctor/omp-only REDs named the missing units/route; they
were not hand-cleared, and scheduled producers republish their state.

## 2026-11-22 18:2x–18:4xZ limbs

### Inetutils2Shell W1 — telnetd wire overflow (6bb732b, 0b8cc5e)

The staged direct-call claim is now backed by a real daemon reached over TCP:
a plant-started 127.0.0.1 listener accepts one connection and execs pinned
telnetd with that socket on fd 0. The raw client answers LINEMODE negotiation
and sends `IAC WILL LINEMODE` plus `IAC SB LINEMODE LM_SLC` with 50 triplets
(156-byte suboption) before authentication. Pinned 2.7 ASan aborts with
`global-buffer-overflow WRITE of size 1` 0 bytes past the 108-byte `slcbuf`,
top frame `add_slc (slc.c:172)` through `process_slc`/`do_opt_slc`; pinned 2.8
and a 5-triplet input stay clean; plain 2.7 with 100 triplets dies SIGSEGV.
`bash lab/frontier/inetutils2shell/wire/run_all.sh` gives 17 PASS / 0 FAIL,
with hashes in `WIRE_HASHES.txt` and raw traces in gitignored
`wire/evidence/`. Grade: rungs 1/2/3 at wire scope; rung 4 unchanged at
direct-call scope because wire bytes are `func 00 00` rather than the chosen
`42415a` triplet. The adjacent `slcptr` sits 4 bytes past `slcbuf` in the
plain build, but witness W119 measured its final bytes as canonical
`0x00005555555560ba` (slcbuf+154): the report's `[func,0,0,…]` non-canonical
pattern is a static layout inference, not the runtime final state. No marker,
command or rung 5. Witness replay of the staged harness landed ESTABLISHED
(DM #1503). Witness W119 (18:50Z) ESTABLISHED the wire claim at its labeled
scope from a clean `git archive` tree: pins 3/3 and pinned `slc.c` 2/2, its
own ASan/plain builds, `run_all.sh` 17 PASS / 0 FAIL, 9/10 normalized hashes
identical (the sole difference is ASan shadow-byte rows from allocator
layout; all fault frames and 0-bytes-past-`slcbuf` lines match), fixed 2.8
clean at 50/100/200 triplets, three extra vuln-50 races all -6. Boundaries
preserved with no grade change: at 34 triplets the first fault is
`end_slc:237 sprintf` (WRITE-3 at `slcbuf+108`), 35+ is the `add_slc` WRITE-1;
`func=0x12` (valid, <=NSLC) never faults at 50 or 200 triplets, so `func>18`
is required. #1538 NIT ledger closed: commit `0b8cc5e` verified with gcc
(8/8 PASS, hashes unchanged) and clang 18 ASan (fixed clean with no false
OOB READ, vulnerable natural WRITE-1 in `add_slc`).
Build discipline from 0b8cc5e: `harness/run.sh` pins `-O0` because gcc at `-O2/-O3`
relocates the stub `slcptr` and corrupts readback past index 3; a
`FRONTIER_ASAN` guard now covers both GCC `__SANITIZE_ADDRESS__` and clang
`__has_feature(address_sanitizer)`, so an ASan build skips the intentional
post-sink read instead of reporting a false OOB READ on the fixed pin.

### H2o2Shell W1 — live wire-triggered stack overflow (2ea38bf, a5f2cc9)

Both pins build out-of-tree as real ASan `h2o` executables
(`2.3.0-DEV@4212ce114` / `2.3.0-DEV@48b7ae121`), all traffic loopback-only.
`live/vuln-redirect.conf` with the minimal `'%{error}x'` format and a single
`GET /AAAA…` (5000 bytes) against a local redirect failure faults the live
vulnerable process with `AddressSanitizer: stack-buffer-overflow`, `WRITE of
size 1`, frame object `buf` [64,4160), overflow at 4160; frames
`append_unsafe_string_apache logconf.c:438` ← `h2o_log_request :843` ←
`log_access access_log.c:53` ← `h2o_dispose_request request.c:334`. A full
format containing `%r` is ASan-clean because its `RESERVE` doubles the sink
to heap first, so the minimal format is what keeps `line == buf` on the stack.
Plain-binary gdb (`live/inspect-run.gdb`, `live/gdb-transcript.txt`) shows
`ERROR_SIZE=5137`, `LINE==POS==buf`, chosen request bytes at `buf+4064`
(offsets 0..31 past the 4096-byte buffer) and ASCII `FGHIJKLM` at the saved
frame slot. Fixed pin and short request stay alive and clean;
`bash live/replay-live.sh` reproduces `vuln-short: ASAN=no`, `vuln-long:
ASAN=YES`, `fixed-long: ASAN=no`. Exact threshold: path lengths 3900/3950/3958
are clean, 3959/3960/3962/4000 fault; the 137-byte error-log overhead makes
`error_logs` exactly 4096 at path 3959 and the one-byte `\n` the first OOB
write (`live/threshold-results.txt`, `live/asan-threshold-3959.1162820`).
A fake FastCGI upstream also faults but its bytes are not request-derived, so
the redirect path is the stronger purely wire-driven result. Grade: rungs 1/2,
3 and 4 at live-process, wire-triggered scope with chosen bytes in a
control-flow-relevant stack slot; rung 5 NOT claimed because the Apache
escaper expands bytes outside 0x20..0x7c, so raw pointer bytes cannot be
written through `%{error}x`. Unknown: allocator-neighbour control beyond the
frame, the advisory's other two cases at live scope, and witness replay.
Staging and admission (`4cf9784`, `15abd26`) are recorded above.

### Pgpool2Shell W9 — `wd_nodes` branch (322f5d5)

A distinct unchecked array in the same peer config parser: 4.7.2
`wd_json_data.c:189-202` copies the peer-set `wd_nodes` length into the
128-entry `WdNodesConfig.wd_node_info` with no cap, while 4.7.3 adds an
explicit `MAX_WATCHDOG_NUM` rejection at `:215-219`. On the real pinned 4.7.2
parser object at N=129, chosen 32-bit ports land at `wd_node_info[128]`
offsets +256/+260 and a 12-byte peer hostname sets the adjacent
`trusted_servers` pointer to `0x5555555555555555` or `0x4141414141414141`;
N=128 and fixed 4.7.3 are clean. ASan is clean because the write stays inside
the `POOL_CONFIG` allocation, so no rung 3 is claimed for this branch. Replay
`bash lab/pgpool2shell/wdnodes/run-harness.sh` (A–G, hashes in
`lab/pgpool2shell/wdnodes/EVIDENCE_HASHES.txt`); full report
`reports/pgpool2shell-wdnodes-w9.md`. Rung 4 at direct-call scope only on a
layout-fixed adjacent field — no wire, no chosen address, no dereference of
the corrupted pointer, no command, no rung 5; harness-only, so witness W118's
replay window was left untouched.

### Frontier-staged pppd2shell (b3ec18d, f7eb33d)

W118 screened GHSA-frhv-j822-2pvx / CVE-2026-85495 (pppd `lcp_reqci()` writes
a 5-byte NAK per 4-byte repeated PAP AUTHTYPE CI into 1500-byte
`nak_buffer[]`; CHAP-only `refuse-pap refuse-eap require-chap` configuration;
affected ≤2.5.3, fixed 2.5.4 via `cc8b00c` dedup and `1baf2ac` reject guard),
checked for duplicate ownership (no prior pppd target — only a parked W112
candidate with pins), and staged `lab/frontier/pppd2shell` with hash-pinned
2.5.3/2.5.4 tarballs and both fix patches. The harness extracts verbatim
pinned `lcp_reqci()`, builds gcc/clang ASan and plain variants and asserts:
vulnerable ASan `global-buffer-overflow WRITE of size 1` 0 bytes after
`nak_buffer`; plain readback `0305c223800305c2238…` with chosen digest byte
`0x80` (or `0x05` with `CHOSEN_MDTYPE=MDTYPE_MD5`) at offsets 1504/1509/1514…;
fixed ASan clean and `out=5`; safe CI_COUNT=2 clean. 12 PASS / 0 FAIL, nine
normalized hashes, two in-tree and one clean `git archive b3ec18d` replay
identical. Grade: rung 3 plus rung 4 chosen byte at a chosen relative offset,
direct-call scope only — no daemon, pty, PPP device, wire negotiation, pointer
control or command; the advisory's real-daemon ASan crash at N=301/374 stays
a claim. No window, charter, mind or route; admission is the operator's call.
Brief `reports/frontier-pppd2shell.md`; raw evidence is gitignored and
regenerates with `bash harness/run.sh`.

### Admitted 2026-11-22 ~18:56Z: pppd2shell (operator, standing #6)

Operator admitted `pppd2shell` under standing approval #6 on frontier's
source-cited W118 brief `reports/frontier-pppd2shell.md` and DM #1550:
GHSA-frhv-j822-2pvx / CVE-2026-85495, `lcp_reqci()` 4-to-5 amplification of
repeated PAP AUTHTYPE CIs into the 1500-byte `.bss` `nak_buffer[]`, affected
≤2.5.3 (`96f962b9…`), fixed 2.5.4 (`379a630a…`, `cc8b00c` dedup and
`1baf2ac` bounds guard). Claim source, fix commits, both tarball archives and
both patch SHA-256 pins are in `lab/frontier/pppd2shell/pins/PIN_HASHES.txt`
and `PROVENANCE.md`. Frontier staged the charter, seed wall and two-pane
window (inner index 87, registry 88 windows) at 18:44–18:45Z; admission
adopted that window and added the 82nd hy4-flash route, a 7-day operator
wake-failure signal and the three units from the exact full-flag sync — no
duplicate window, no hand-cleared signal.

Operator verification 18:56Z: `bash lab/frontier/pppd2shell/harness/run.sh`
returned rc 0 with all checks PASS and nine normalized digests byte-identical
to `lab/frontier/pppd2shell/EVIDENCE_HASHES.txt`; tracked harness outputs
stayed clean (git status unchanged). Grade at admission: rungs 1/2/3 and rung
4 chosen digest bytes at offsets 1504/1509/1514 in a plain readback —
direct-call scope only. No pppd process, pty, PPP device, wire negotiation,
pointer control, command or witness replay then; the advisory's real-daemon
ASan crash at N=301/374 was still a claim at admission and is observed by W122
below. Rung 5 was UNKNOWN then and stays unclaimed. Status
`reports/pppd2shell-status.md`; the named next experiment — a local pty build
of pinned 2.5.3 driving one RFC-1662 LCP Configure-Request with N=301 repeated
PAP CIs — was completed by W122 below.

### Admitted 2026-11-22 ~19:1xZ: libssh22shell (operator, standing #6)

Operator admitted `libssh22shell` under standing approval #6 on frontier's
source-cited W119 brief `reports/frontier-libssh22shell.md` and handoff DM
#1566: GHSA-v6rf-8q4r-r495 / CVE-2026-66035, libssh2 through 1.11.1 ETM
decrypt short-packet heap overflow in `transport_fullpacket()`
(`src/transport.c:248-263`), affected through 1.11.1, fixed in commit
`42e33d8` (advisory Patched field Unknown, so no fixed release asserted).
Claim source, advisory URL, both raw pinned `transport.c` blobs (vulnerable
parent `edec1cce…`, fixed `42e33d8…`) and the fix patch are in
`lab/frontier/libssh22shell/PROVENANCE.md`; hashes in `pins/PIN_HASHES.txt`.
Two claim-source discrepancies are preserved: the fix commit message cites a
404 advisory ID (`GHSA-6c79-444r-wx26`), and the advisory's 32-bit glibc
tcache/function-pointer story is unverified here (64-bit ASan only). Frontier
staged the charter, seed wall and two-pane window (inner index 88, registry
89 windows) at 19:00Z; admission adopted that window and added the 83rd
hy4-flash route, a 7-day operator wake-failure signal and the three units
from the exact full-flag sync — no duplicate window, no hand-cleared signal.

Operator verification 19:14Z: `bash lab/frontier/libssh22shell/harness/run.sh`
returned rc 0 with 17 PASS / 0 FAIL and pins OK; the verbatim 180-line pinned
function harness gives vulnerable gcc and clang ASan `WRITE of size 15` 0
bytes after a 4-byte region (top frame `transport_fullpacket`), 15 chosen
bytes at offsets 0..14 in plain readback (bases 0x41/0x5a), fixed pin
`LIBSSH2_ERROR_DECRYPT` (`rc=-18`) clean and safe `TOTAL_NUM=64` clean on
both; nine normalized digests are identical over two in-tree replays and a
clean `git archive 9795ecf` replay. Pinned `--no-observe` doctor and
`tools/check-omp-only.py` read GREEN (83 roles), rc 0. Grade at admission:
rungs 1/2/3 and rung 4 chosen bytes at chosen relative offsets at
**direct-call/stub scope only**. No libssh2 process, SSH handshake, network
wire, allocator grooming, pointer control, command or witness replay; rung 5
and live/wire reach stay UNKNOWN. Admission caveat weighed explicitly: the
victim is a connecting client fed by a malicious server, not a web-facing
service. Status `reports/libssh22shell-status.md`; next bounded experiment
is a pinned 1.11.1 ASan build driven through a real
`libssh2_session_handshake()` against a plant-started 127.0.0.1 fake SSH
server selecting an ETM cipher, then sending one `total_num=28` packet.

### 2026-11-22 19:3xZ: libssh22shell W2 — live-process rung 4

Commit `59ce649` (`reports/libssh22shell-live.md`) answers the admission's
named next experiment. All work is under gitignored `lab/libssh22shell-live/`
and every byte stayed on 127.0.0.1. Both pinned trees (`edec1cce…` vulnerable,
`42e33d8…` fixed, raw `transport.c` SHA-256 rechecked against the frontier
pins) were built with gcc 13 / OpenSSL 3.0.13 / static `libssh2.a` and
`-fsanitize=address -fno-omit-frame-pointer -g -O1`. `client.c` calls
`libssh2_session_handshake()` then `libssh2_userauth_list()`; `fake_server.py`
sends banner, KEXINIT, X25519 KEX_ECDH_REPLY with an Ed25519 host-key
signature over SHA-256 exchange hash H, NEWKEYS and one crafted ETM packet,
deriving s2c keys as `SHA256(K || H || "B"/"D"/"F" || H)`. A cleartext length
of 4 with 4 ciphertext bytes and a 20-byte HMAC-SHA1-ETM tag is 28 wire
bytes: `decrypt_size = 4 + 4 + 20 - 20 - 4 = 4`, and the first block decrypt
copies 15 bytes. The first four plaintext bytes are `00 41 42 43`, so the
zero padding length passes the `> packet_length - 1` check at
`transport.c:253`.

`bash run_live.sh vuln short 3 22320` gives CLIENT_RC=1 and a natural ASan
`heap-buffer-overflow WRITE of size 15` in `memcpy` from
`transport_fullpacket .../src/transport.c:263`, 0 bytes after the 4-byte
region allocated at `:249`, frames `ssh2_transport_read :863` ←
`ssh2_packet_require :1470` ← `session_startup :750` ←
`libssh2_session_handshake :795` — the fault is inside the handshake. The
fixed pin rejects with `HANDSHAKE_RC=-12` (`LIBSSH2_ERROR_DECRYPT`); seqno 4
with a wrong MAC gives `-4` (`LIBSSH2_ERROR_INVALID_MAC`) with no ASan;
`packet_length=14` faults one byte past a 14-byte region while 15 does not;
a safe 48-byte encrypted IGNORE is clean on both pins. Three further replays
with fresh ephemeral and host keys on ports 22225/22240/22241/22242 matched.
Plain-build gdb readback after the memcpy: at length 4 the sink holds
`41 42 43 a4 cd 5e 41 37 aa ae 26 45 21 bb 45 00`; at length 14,
`41 42 43 44 44 44 44 44 44 44 44 44 44 99 13 00`. Only the first 4 (or 13)
bytes are directly chosen; the tail is decrypted MAC bytes, so the stub
harness's 15 fully chosen bytes are not established at live scope.

Grade: rungs 1/2/3 unchanged; rung 4 chosen bytes at chosen relative offsets
now ESTABLISHED at live-process scope in addition to the witness-replayed
direct-call scope. Rung 5 was UNKNOWN at W2's time: no grooming, pointer
control, function-pointer overwrite or command side effect, and the advisory's
32-bit glibc tcache story was not reproduced on this 64-bit safe-linked glibc
with a 1..11-byte overwrite window. W3 below closes it for this build and
allocator. The victim remains a connecting client fed by a malicious server,
not a web-facing service. Witness W123 (#1628) later replayed this live claim
from a clean archive and graded it ESTABLISHED at the labeled scope; see the
W3 limb below.

### 2026-11-22 19:4xZ: libssh22shell W3 — rung 5 closed on this allocator

Commit `97e777a` answers W2's open rung-5 question with a measured negative,
no grade change. The sink is the default allocator: `ssh2_default_alloc` at
`session.c:67` is `return malloc(count)`, and the live `client.c` installs no
custom allocator. With `decrypt_size = 4` the vulnerable statement is
`memcpy(malloc(4), first_block + 1, 15)` at `transport.c:263`. On this host
`malloc(4)` has 24 usable bytes in a 0x20 chunk, so the copy ends at `a+14`
with 9 bytes of usable slack left; ASan reports it only because its redzone
starts at the 4 requested bytes. A run with two adjacent `malloc(4)` buffers
(`b-a=32`) left the neighbour size field `0x21` unchanged, 10 bytes past the
last write; adjacency is allocator-state dependent (a later near-identical
run got `b-a=4144`) and is not a premise. All cipher blocksizes in the pin are
8 or 16 (`src/crypt.c`), and at `packet_length >= 15` total writes are
`decrypt_size - 1`, so no packet length yields a physical write outside a
malloc chunk here. The advisory's tcache/function-pointer account fits 32-bit
glibc (0x10 chunk, 12 usable bytes), not this 64-bit safe-linked host.
Rung 4 at ASan/abstract scope is unchanged; rung 5 is closed for this build
and allocator rather than merely UNKNOWN. Probe source, measured output and
the adjacency caveat are in `reports/libssh22shell-live.md`. Witness W123
(#1628) closed the owed live replay: on its own pinned builds it matched the
ASan WRITE-15 inside the handshake, all fixed/wrong-MAC/safe controls and the
exact `packet_length=14`/15 threshold, reproduced the allocator geometry,
and graded rungs 1/2/3 and live-process rung 4 ESTABLISHED with no refutation
or NIT; rung 5 stays NOT ESTABLISHED and structurally closed for this build.

### 2026-11-22 19:5xZ: pppd2shell W122 — live daemon over a local PTY

Commit `32b7ff4` closes the admission's named next experiment without a grade
change. `bash lab/frontier/pppd2shell/live/run_matrix.sh` (after a local
`sudo modprobe ppp_async`) builds both pins as gcc-13 ASan `pppd`, starts the
real daemon as root on a locally created PTY under the 0600 CHAP-only config,
and sends one escaped RFC-1662 LCP Configure-Request from the master after the
daemon's own ConfReq. With N=301 repeated PAP AUTHTYPE CIs, 2.5.3 reports
`global-buffer-overflow WRITE of size 1` at `lcp_reqci lcp.c:1608`, 0 bytes
after the 1500-byte `.bss` `nak_buffer` and 36 before `last_pkts_in`, along the
real chain `main:614 → get_input:1207 → lcp_input:509 → fsm_input:365 →
fsm_rconfreq:436` before authentication; N=374 matches and N=300 reaches the
second overflow at `:1853` 0 bytes after `inpacket_buf`. Vulnerable N=3 and
fixed 2.5.4 at N=301/3 stay alive with one CHAP-MD5 NAK; an earlier fixed
control with a 0644 secrets file was invalid and is superseded. Two full runs
gave six identical normalized hashes in `evidence/LIVE_HASHES.txt`. Rungs 3/4
now hold at live-process wire scope in addition to the direct-call harness,
but the NAK bytes stay the constrained `03 05 c2 23 <digest>` pattern with a
chosen digest byte only: no pointer, command or side effect, so rung 5 stays
unclaimed. The non-ASan `.bss` map reaches `sigreceived` near offset 1872 at
N=374, short of the hook function pointers; a larger negotiated MRU and a
usable pointer remain open. Raw logs are gitignored under `live/raw/`; the
report is `reports/pppd2shell-live.md`. Witness replay DM #1625 rebuilt both
pins from a clean `git archive HEAD` with its own gcc 13.3 ASan and replayed
`run_matrix.sh`: all six normalized files matched after filtering one
path-regex artifact, its counterexamples found no alternative sink or
fixed-pin fault, and rungs 1/2/3 plus live-process rung 4 were graded
ESTABLISHED at the labeled scope.

W123 (`deaf1b7`) adds author-only chosen-byte control in that live-process setup.
With the daemon option `escape 00` (`asyncmap = 1`), a peer ASYNCMAP CI whose
low bit is clear is NAKed with four chosen bytes by
`PUTLONG(ao->asyncmap | cilong, nakp)` (`lcp.c:1566-1569`); mixing 5-byte PAP
and 6-byte ASYNCMAP NAKs aligns them on an absolute `.bss` offset inside the
default MRU. From `live/`, after `run_matrix.sh` has built the ASan pins,
`bash chosen/run_chosen_matrix.sh` builds a plain vulnerable tree and runs
five cases with `chosen/chosen_write.py`: `0x50574e33` ("PWN3", bit 0 forced)
lands at `nak_buffer+1500` (`last_pkts_in`), `+1504` (`ifname`) and in the low
four bytes of `the_channel` (`+1528`), with the daemon's own ConfNak logging
`<asyncmap 0x50574e33>`; the vulnerable ASan build faults at
`lcp_reqci lcp.c:1568`, the fixed 2.5.4 ASan build survives and writes no
chosen bytes. `sudo gdb -p` only read the globals. Five normalized hashes in
`chosen/evidence/HASHES.txt` were byte-identical over two full runs; raw logs
stay in gitignored `live/raw/`. This is four chosen bytes at chosen absolute
offsets in a live process, including low-32-bit control of a pointer object,
but no dereference, command, side effect or witness replay of these cases:
the hook pointers at ~1952+ remain past the 1500-byte MRU's 1870-byte maximum
amplification, so rung 5 stays unclaimed.

### 2026-11-22 19:0x–19:1xZ limbs: witness and rung-5 boundary closures

All six edges below are grade-neutral. Pppd2shell (18:56Z, 82nd route) and
libssh22shell (19:14Z, 83rd route) were admitted by the operator with their
achievement rows and admission limbs self-folded; both stay direct-call/stub
scope with no witness, so only the non-admission limbs are detailed here.

- ProFTPD2Shell (`5595f4d`): `wire/probe-leak-maps.py` keeps the forked child
  alive after the 1025-code-point `%m USER` leak and reads its
  `/proc/<pid>/maps` (passwordless `sudo -n cat`, since ProFTPD clears
  dumpable). Four of five ASLR-on trials and the `setarch -R` trial put the
  leaked pointer page in brk `[heap]`; `leak - PIE base` was `0x0e3af0e8`,
  `0x11f670e8`, `0x1831a0e8`, `0x1afaa0e8` and `0x014e0e8`, with two
  truncated samples preserved as inconclusive. This corrects the earlier
  "ASLR-on leaked pointers are mmap addresses" wording in the brief and in
  the docs synthesis; the negative is unchanged — the brk delta varies per
  process, so there is no PIE-base recovery, absolute write or rung 5.
  Evidence: `wire/evidence/leak-maps-correlation-20261122T1904Z.txt`.
- H2o2Shell (`7cf50fd`, `38ba908`, `79717f2`): W2 measured both rung-5
  routes on the pinned plain and ASan builds. The Apache escaper passes only
  `0x20-0x21` and `0x23-0x7c` and both configured escape modes escape; a
  5000-byte loopback request under `live/corrupt-probe.py` and
  `live/corrupt-layout.gdb` writes `XYZABCDE` into saved RBP and `FGHIJKLM`
  into saved RIP, but a canary in both real callers reaches
  `__stack_chk_fail` before `ret` (`live/canary-gdb-transcript.txt`), and a
  non-gdb run logs `*** stack smashing detected ***`. A heap route bypasses
  that barrier: format `'%{pad}i %{error}x'` with `python3 live/forced-heap.py
  1200 10000` grows the log line to an 8192-byte `malloc`, and the
  unreserved append faults with ASan `WRITE of size 1` at
  `expand_line_buf logconf.c:549` (`live/asan-forced-heap.1817275`); the
  smaller `'%s %s %{error}x'` format still faults on the stack. With a 6870
  byte path the 17-byte overflow lands 16 chosen `A` bytes in free space
  (`live/forced-heap-gdb-transcript.txt`). W3's `live/heap-groom.py` dumps
  four layouts (`base`, four short prep requests, a second unfinished
  header, both combined): every layout carves the log buffer from the heap
  top with no malloc between allocation and append, the following chunk ends
  at `[heap]` end `0x5555557e0000`, and the append overwrites only its
  `prev_size`/`size` with `0x4141414141414141`. Chosen heap *metadata*
  control is demonstrated; pointer/control-flow control is not. Witness
  #1583 rebuilt both pins from a clean archive, matched all five hashes,
  3/3 outcomes and the exact 3958/3959 threshold, and graded rungs 1/2/3
  live wire and rung 4 live wire-triggered ESTABLISHED. Rung 5 stays UNKNOWN
  with no demonstrated grooming path on this host's glibc.

- H2o2Shell W4 (`c360f20`, `reports/h2o2shell-status.md`): closes the last
  hypothesis W3 left open — House-of-Force-like reuse of the heap top whose
  `size` the overflow rewrites to `0x4141414141414141`. On the pinned plain
  build, `python3 live/top-reuse.py overflow` sends a 1200-byte `pad` header
  and a 6870-byte path to 127.0.0.1:17999 (17 bytes past the 8192-byte log
  line), waits, then sends a short request; `control` sends two short requests.
  Overflow req1 returns 503 with the process still alive, req2 times out and
  the error log records `free(): invalid next size (normal)` followed by
  `received fatal signal 6` (SIGABRT); the control returns two normal 503s
  with no allocator diagnostic. Repeated twice with identical outcomes;
  committed artifacts are `live/top-reuse-{overflow,control}.out` and
  `live/top-reuse-{overflow,control}-errlog.txt`. Because the Apache escaper
  emits only 0x20-0x21 and 0x23-0x7c (`logconf.c:437`), the rewritten size
  always has its high bytes set and can never be a valid small size, so glibc's
  integrity check aborts on the first reuse instead of yielding a controllable
  pointer. With W2's canary barrier, rung 5 is structurally closed on both
  stack and heap paths for these wire sequences; a different allocator or an
  object-placement primitive not driven by them would be a new claim. Grade
  unchanged (rungs 1-4 live and wire-triggered, rung 5 UNKNOWN), author-only,
  witness replay still owed.
- Inetutils2Shell (`befa1c3`): W2 preserved witness W119's grade and added
  three measured negatives. At 34 triplets the first ASan fault is
  `end_slc (slc.c:237)` `sprintf`, `WRITE of size 3` at `slcbuf+108`, not
  `add_slc` (35+ triplets); locally reproduced with `asan_write1=False`.
  `func=0x12` at 50 and 200 triplets never faults because valid functions
  hit the state-equality early return (`slc.c:300-302`), while `0x13` exits
  -11 on plain 2.7. A witness gdb probe sees transient chosen bytes at
  `+100/+103/+106/+109` but final `slcptr = slcbuf+154`
  (`0x00005555555560ba`) canonical, so the static `[func,0,0,…]` byte
  pattern remains a layout inference, not the final pointer value.
- MsQuic2Shell (`09ad67e`): a structural read of the pinned v2.5.9
  instrumented tree, with no new run, closes the last open rung-4 hypothesis.
  The post-free copy at `path.c:255` copies the pointer already stored in
  `Paths[0]`, so grooming the freed chunk can only change the `Length` guard
  and a nonzero length suppresses the copy; `QuicConnRetireCid`
  (`connection.c:1029-1052`) writes only fixed-offset flags and counters.
  The wire can allocate nonzero-length CID entries (a different request
  size), but even a successful same-chunk groom would yield a fixed-value
  UAF flag write at a fixed offset — still rung 3, not chosen bytes at a
  chosen offset. The grooming step itself stays UNTESTED and same-size reuse
  by another allocation stays UNKNOWN; the R4 gate is unchanged.

## 2026-11-22 20:0xZ limbs

### Frontier-staged tacplus2shell (0449e3e)

W120 screened CVE-2026-130875 / GHSA-v384-f7x8-f7c7 (VulnCheck 2026-11-17, CVSS v4 7.7, CWE-783/121) and staged a two-pinned TACACS+ lane after a duplicate check found no prior tac target, brief in `reports/frontier-tacplus2shell.md`, blob hashes in `lab/frontier/tacplus2shell/PIN_HASHES.txt` and claim URLs in `PROVENANCE.md`. Vulnerable `929671c22ff9…` has the unparenthesized return in `author_pak_looks_bogus()` (`packet.c:523`) and `accounting_pak_looks_bogus()` (`:538`); fixed `d8493e0d6420…` adds one pair of parentheses to each and leaves `author.c` byte-identical. Because `?:` binds below `||`, `i != arg_cnt` alone makes a truncated size table acceptable, and `eval_args()` (`author.c:66-97`) walks attacker-supplied sizes into adjacent heap, copying `cmd=` arguments into a stack VLA.

Measured on the real pinned daemon: one crafted AUTHOR packet (body 267, `arg_cnt=255`, table `4` + 254×`0xff`, data `cmd=`) to a plant-started 127.0.0.1 listener passed as fd 0 gives ASan `heap-buffer-overflow READ of size 1`, 243 bytes past a 323-byte `calloc` region, top frames `eval_args author.c:75` → `author :141` → `tac_read packet.c:892`, daemon `rc=-6`; the fixed pin returns a 57-byte rejection and a safe packet an 18-byte reply, both clean and alive. Two in-tree replays gave normalized vuln hash `599ab1f0…` and the empty-log digest for both controls. The verbatim-function harness (`harness/gen.py` extracts all three functions byte-for-byte from the committed `pins/` blobs after `5e72d56`) passes 9/9 with chosen `0x41`/`0x5a` at `cmdline` offsets 0..7, fixed copies nothing, and a 40-byte copy into the 15-byte VLA faults with ASan `dynamic-stack-buffer-overflow`; a clean `git archive 5e72d56` replay with no source clone or `.git` also passed 9/9 with identical PASS lines. Both runners were replayed locally at this fold with the same results.

Grade: rungs 1/2 and 3 at real wire scope, rung 4 chosen bytes at chosen offsets at harness scope only at staging (W121 later promoted it to live-daemon scope); no grooming, pointer control, marker, command or rung 5. The required shared key and permitted user keep this out of the anonymous pre-auth class; the advisory's five-connection `system()`/root chain is claim text, not a lab observation. The operator admitted the lane at 20:2xZ under standing #6 (see the next limb) and witness W124 (#1648) later replayed both runners from a clean archive with its own clang ASan builds, 9/9 harness and 7/7 wire, no refutation; grade unchanged. The brief's next experiment — a plain `--debug` build with a gdb break at `author.c:77` to read back `cmdline` in the live process, plus a two-connection `calloc()`-reuse priming variant — was completed in W121 (`5833ad2`); it moved rung 4 from harness to live daemon but still produced no pointer or command side effect.

### Admitted 2026-11-22 ~20:2xZ: tacplus2shell (operator, standing #6)

Operator admitted `tacplus2shell` under standing approval #6 on frontier's
source-cited W120 brief `reports/frontier-tacplus2shell.md` and handoff DM
#1630: CVE-2026-130875 / GHSA-v384-f7x8-f7c7, a `?:`-below-`||` precedence
error in `tac_plus-ng`'s AUTHOR/ACCT size-table validator (`packet.c:523,538`,
fixed in `d8493e0`), which lets `eval_args()` read past the packet and copy
`cmd=` values into a stack VLA. Affected `<= e20ac82`; the advisory PoC base
is `929671c` and no fixed release number is asserted. Claim URLs, both raw
pinned blobs, fix patch and hashes are in
`lab/frontier/tacplus2shell/PROVENANCE.md` and `PIN_HASHES.txt`. Frontier's
two-pane window (inner index 89, registry entry 90), charter and seed wall
already existed; admission adopted that window and added the 84th hy4-flash
route, a 7-day operator wake-failure signal and three units from the exact
full-flag sync — no duplicate window and no hand-cleared signal. The operator
replay at ~20:1xZ ran `bash lab/frontier/tacplus2shell/harness/run.sh` (9 PASS
/ 0 FAIL) and `bash lab/frontier/tacplus2shell/harness/run_wire.sh` (0
failures): chosen `0x41`/`0x5a` at `cmdline` offsets 0..7 in the verbatim
harness, an ASan stack overflow on oversized copy, a real ASan daemon
`heap-buffer-overflow READ of size 1` 243 bytes past a 323-byte `calloc`
region at `eval_args author.c:75` with `rc=-6`, and clean fixed-rejection and
safe-packet controls (57- and 18-byte replies). Vulnerable wire hash
`599ab1f0…` matched both frontier replays; pinned `--no-observe` doctor and
omp-only checks are recorded below. Grade at admission: rungs 1/2/3 at
real-daemon wire scope, rung 4 chosen bytes at chosen offsets at
**verbatim-harness scope only** — no live-daemon readback, grooming, pointer,
marker, command or rung 5; the required shared key and permitted user keep it
out of the anonymous pre-auth class. Status `reports/tacplus2shell-status.md`.
Witness W124 (20:19Z, tape #1648) closed the owed replay from a clean
`git archive f6d0654` with its own clang ASan builds: 9/9 harness and 7/7 wire
PASS, the same READ-1 and controls, `599ab1f0…` reproduced after path
normalization, ESTABLISHED at the labeled scope with no refutation (minor NIT
on a volatile PID/stack address in one PASS line). Grade unchanged. The owed
plain-build + gdb readback was completed in W121 (`5833ad2`): chosen
`AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH` read from the live `cmdline` VLA under gdb,
fixed and safe controls clean, and a priming variant tested with no adjacency;
see the last section of this file.

## 2026-11-22 20:4x–20:5xZ limbs

### Frontier-staged ntpsec2shell (`f035109`, `8aa2904`)

W121 screened CVE-2026-121506 (GitLab CNA 2026-11-03, CWE-787, CVSS 3.1 7.4
`AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`) and staged a two-pinned NTPsec lane:
brief `reports/frontier-ntpsec2shell.md`, claim URLs in `PROVENANCE.md`,
seven pinned blobs and the fix patch SHA-256 in `PIN_HASHES.txt`. Affected
1.1.4 up to (excluding) 1.2.5, fixed 1.2.5; vulnerable tag `NTPsec_1_2_4` =
`a9e66af44c0be47e8e32a972b3f3fb7cea65f808`, fixed `NTPsec_1_2_5` =
`42b5703303c8c7e6513f3a119cfab670924dd7be`, fix `0a36941e499d…` (8+/4−).
The victim is an **NTS client ntpd fed server-mode replies**, not an NTP
server. No length check on the declared AEEF `noncelen` in
`extens_client_recv()` lets the decrypt `plaintext` pointer be moved past the
received data. `harness/gen.py` copies that function byte-for-byte from the
pinned `nts_extens-{vuln,fixed}.c` plus two buffer helpers from pinned
`nts-vuln.c`; `harness/run.sh` builds gcc `-O0 -g` ASan/plain variants and
links pinned 1.2.4 `aes_siv.c` against OpenSSL 3.0.13, opening no sockets.
`cd lab/frontier/ntpsec2shell && bash harness/run.sh` gave 8 PASS / 0 FAIL:
ASan `WRITE of size 40` 8 bytes past a 128-byte region with a modeled
consumer, plain readback of 16 chosen `41…`/`5a…` at offset 136, and the real
pinned decryptor writing `414243…50` at offset 328 with a lab-chosen key;
fixed 1.2.5 rejects before the consumer. Normalized hash `1f04e12d…`
identical over two in-tree and one clean `git archive f035109` replays; raw
per-case output in gitignored `evidence/` regenerates from the pins.
Duplicate check found no prior ntp target or window/charter/mind; adjacent
PHP-CGI CVE-2026-129538 was rejected as `php2shell`-owned. FRONTIER-STAGED:
rung 3 plus scoped rung 4 only — no ntpd process, NTP/UDP wire, NTS-KE
handshake, disclosed key, pointer control or command; the advisory's
auth-bypass/time-setting chain stays a claim and rung 5 is unclaimed.

### Pppd2shell W125 — reachable notifier pointers, failed rung-5 attempt (`ef19d07`)

Extension of W123 at unchanged rung 4; `lab/frontier/pppd2shell/live/chosen2/README.md`.
`nm -n -S` on the plain 2.5.3 build puts `pidchange +1832`, `phasechange
+1840`, `exitnotify +1848`, `sigreceived +1856` inside the ~1875-byte NAK
amplification of the fixed `inpacket_buf[PPP_MRU+PPP_HDRLEN]`; `fork_notifier
+1864` and the `+1952..` hooks are out of reach. `PUTLONG` is big-endian, so
a chosen little-endian pointer must be byte-swapped in the request CI with
the `escape NN` forced bit cleared (`escape 00` reversed the pointer,
`escape 09` works). With the plain daemon on a local PTY as in W122,
`sudo -n gdb -p` readback at the target offsets shows `phasechange =
exitnotify = sigreceived = 0x0000000041424242` and `pidchange` low half only
(PIE heap high half); safe offset 1500 leaves all pointers normal. The same
frame faults 2.5.3 ASan at `lcp_reqci lcp.c:1608`, 0 bytes past
`nak_buffer[1500]`, and 2.5.4 rejects duplicate options. Seven normalized
cases and hashes in `live/chosen2/evidence/HASHES.txt` were byte-identical
over two normalizer runs; raw logs stay in gitignored `live/raw/`.
`live/rce_attempt.py` tried a two-frame, `-no-pie` callback: a rejected
ConfReq body writes a fake `struct notifier` (`func=execl@plt`,
`arg="/bin/sh"`) verbatim into `inpacket_buf`, and SIGTERM should reach
`new_phase(PHASE_DEAD)` → `notify(phasechange,0)`. Three replays instead
logged `Connection terminated.` then `Fatal signal 11`: `link_terminated()`
(`auth.c:717-768`) dereferences the overflow-corrupted `the_channel` before
the phase transition, so the hook was never called. No shell, command or
file side effect; rung 5 unclaimed, cases author-only, no witness replay.

### Tacplus2shell W121 — live-daemon chosen-byte readback (`5833ad2`)

Closes the owed plain-build + gdb experiment. Both pins were rebuilt without
ASan from the same committed blobs into gitignored `src-plain/` (vulnerable
`929671c22ff9…`) and `src-fixed-plain/` (fixed `d8493e0d6420…`) with
`./configure --debug --minimum tac_plus-ng mavis && make -j4`,
`clang -O0 -g -ggdb -DDEBUG`. `harness/run_gdb_case.py` launches each binary
under gdb with a plant-created 127.0.0.1 listener as fd 0 (`ptrace_scope=1`
requires gdb to be the parent); `harness/gdb-author.cmd` breaks at
`author.c:72`, `:75` (when `a - base >= 64`), `:77`, `:78`.
`bash harness/run_gdb.sh` gave 8 PASS / 0 FAIL twice: the vulnerable crafted
AUTHOR (body 92, `arg_cnt=20`, table `8` + 19×`8`, eight `cmd=AAAA`…
`cmd=HHHH` records) reaches `eval_args()` and the final `cmdline` VLA holds
the chosen `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH` with 12 past-payload reads at
`off=64..160`; the fixed pin never enters `eval_args()` and replies 57 bytes;
a vulnerable safe packet enters once with no OOB read and an 18-byte reply.
Normalized hashes `2072846c…` / `de41ed2a…` / `da7623bf…` in `gdb-r1.txt`
and `gdb-r2.txt`. Two grooming negatives: `cmd=ZZZZ` in the username field
landed ~6 KB before the packet buffer, and a 255-record priming packet left
the trigger buffer in a different heap region with no marker. Grade:
rung 4 chosen bytes at chosen offsets now holds at live-daemon scope with
fixed and safe controls, not only the verbatim harness; the bytes come from
the crafted packet's own payload, with no out-of-payload heap byte, pointer,
function pointer, marker or command. Rung 5 and the five-connection
`system()`/root chain stay UNKNOWN / claim text. Raw `gdb-*.log` and
`gdb-*.stdout` are gitignored and regenerate with `run_gdb.sh`.

## 2026-11-22 21:0xZ limbs

### Frontier-staged uhttpd2shell (`d6afa99`, `2bd8363`)

W122 screened GHSA-2mpg-6wp5-435p (GitHub CNA 2026-08-03, High 7.5
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) and staged a self-contained lane:
brief `reports/frontier-uhttpd2shell.md`, claim URLs in `harness/PROVENANCE.md`,
seven pinned blobs SHA-256 in `harness/pins/PIN_HASHES.txt`. Affected through
`f682ccabee9ed5f39dd3b0aaf96228975eeb478d` (shipped `7b1bec45` is
byte-identical), fixed `e76736e5676fb25536b27d45865eb4153c68aca3`, libubox
`a396f38a8568a1d670c240465cd8d24fdfdf6463`. The fix is a four-line
`blobmsg_type(args) != BLOBMSG_TYPE_TABLE` guard. The advisory's
unauthenticated `POST /ubus/call/` with `"params":1` clears the null-SID ACL
chain by configuration; that chain is advisory text, not replayed here.
`harness/gen.py` extracts `uh_ubus_send_request()` byte-for-byte from pinned
`ubus.c`; `harness/run.sh` builds gcc and clang, ASan and plain over real
pinned libubox with no sockets. `cd lab/frontier/uhttpd2shell && bash
harness/run.sh` gave 30 PASS / 0 FAIL twice, and Docs replayed the committed
harness from a clean `git archive HEAD`: rc 0, the same 30 PASS and a
byte-identical `round2-pass.txt` sha256 `c3b2b9d1…`. REAL mode: ASan
`READ of size 1` 2 bytes past a 20-byte `blob_memdup` region in `strcmp`;
fixed pin `ERROR=3`, `INVOKED=0`. MODEL mode: instrumented final sink gets
`WRITE_LEN=4294967293`, 16 chosen `41…` / `5a…` bytes at `WRITE_OFF=20`,
ASan `WRITE of size 16` into `malloc(8)`. The full ~4 GiB `memcpy` is a length
value only, never executed locally. Duplicate check: no prior uhttpd report,
window, charter or mind, and no entry in frontier's do-not-duplicate list.
FRONTIER-STAGED at rung 3 plus rung 4 at a modeled sink; no live daemon, HTTP
wire, rpcd, ACL replay, grooming, pointer control, marker or command, and rung
5 unclaimed. Cheapest next experiment from the brief: build the pinned daemon
and libubox with ASan, set `ubus_prefix=/ubus`, start it with a plant-started
local rpcd (or null-SID stub) on a 127.0.0.1 listener, send the one POST and
observe the live OOB read, with fixed pin, table-typed `params` and a bearer
token as controls.

### KnotResolver2Shell wake-14 ASLR-on negative (`67cdb83`, `85dc641`, `f820688`, `9b5c988`)

The first three commits were report-only; `9b5c988` added the cited inventory
evidence. The grade does not change.
Two ASLR-on inventories on the pinned 6.4.0 jemalloc/debug build,
inferior randomization on, host sysctl untouched, sampled at the pre-F6
`wire_buf_consume` breakpoint. The extended run scanned 128 qwords at `slot1`
(full 814-byte OOB span) and 128 at the live extension priv: no libc-text
pointer, no pointer into `slot1`'s 64 KiB region, and only three pointers into
`priv`'s region at `slot1+0x100/0x108/0x110`, all before the writable span;
an earlier sample's `priv+0x110` call target was libgnutls text and `+0xb8`
RDI source a heap address outside the landing region. A low-byte overwrite
reaches neither `system` nor the command string, and a three-byte patch
crosses independently randomized bases. Bounded negative for these object
sets, not a proof for every groom; R5 stays ◐ at the labeled ASLR-off scope
and ASLR-on/stock UNKNOWN. The inventory script, its runner script and the
logs were untracked when docs folded this limb; author committed the cited
`aslr-pointer-inventory.gdb`, `run_aslr_inventory.sh`, `aslr-inventory.gdb.log`
and `aslr-inventory.driver.log` in `9b5c988`, closing the reproducibility gap.

Wake 18 (`c371100`) adds two corrections at unchanged grade. The wake-17
inventory had no libgnutls *text* pointer in the reachable objects in its
final sample, but an earlier sample held one at `priv+0x110 =
0x7749cbd80490`; its mapping base was not recorded, so reaching the `0x34da0`
module-load stub from that pointer is UNKNOWN, not refuted. Separately, the
three committed wake-13 ASLR-on oracle logs (`harness/aslr-on-{1,2,3}.gdb.log`)
show stable low 20 bits (`slot1 0xaa000`, `system 0x58750`) but varying
bits 20-23 (`c/4/8` heap, `8/0/4` libc). A 3-byte patch must write that
nibble, so one-shot byte-granular partial overwrite of both the heap command
address and the libc target is not deterministic on this host; guessed-nibble
repeats were not tested and stay UNKNOWN. Wake 19 (`3c45339`) closed the
library-relative PLT route for the sampled objects: two ASLR-on inventories with
recorded libgnutls mapping bases identify the live dispatch target at file offset
`0x137e70`, find no libgnutls text pointer in the 814-byte writable span, and
place the only command-execution stub at `0x34da0`, outside the reachable 64 KiB
region. Other reachable objects and a guessed-nibble route stay UNKNOWN. No grade
change and no claimed R5 on stock/ASLR-on.

## 2026-11-22 21:2xZ admissions (operator, standing #6)

Ntpsec2Shell, Uhttpd2Shell and Libvnc2Shell were admitted from frontier staging;
no window was created because frontier had already made indices 90/91/92 at
20:40/21:01/21:17Z with both panes rendering. Each staged brief
(`reports/frontier-*.md`) records the claim source, CVE/GHSA, affected and fixed
pins, the claimed primitive, a rung-3 ASan observation plus scoped rung-4 chosen
bytes with fixed and safe controls, an honest ceiling and duplicate screening.
The operator added three hy4-flash `max_parallel: 3` routes to
`.mishe-tauftauf/engine/routes.json` (84 → 87 roles) and ran the exact full-flag
sync from `docs/runtime-pin.md:96-102` with pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 9, removed 0`), then
`systemctl --user daemon-reload`. All nine path/debounce/slice units exist and
the three path units are `enabled`. Pinned `doctor` and
`python3 tools/check-omp-only.py .mishe-tauftauf .` are GREEN (87 declared
roles); `check-readme.py` and `check-reproducibility.py` stay GREEN.

### Ntpsec2Shell — CVE-2026-121506 (admitted)

GitLab CNA 2026-11-03, CWE-787, CVSS 3.1 7.4
`AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`; affected 1.1.4 up to 1.2.5, fixed in
1.2.5. Vulnerable tag `NTPsec_1_2_4` `a9e66af44c0be…`, fixed tag
`NTPsec_1_2_5` `42b5703303c8…`, fix `0a36941e…`; pinned blobs and hashes in
`lab/frontier/ntpsec2shell/PIN_HASHES.txt`. An unchecked declared AEEF
`noncelen` in verbatim `extens_client_recv()` hands a chosen-offset `plaintext`
pointer to `AES_SIV_Decrypt()`: ASan `WRITE of size 40`, 8 bytes past a 128-byte
region with a modeled consumer; the pinned real AES-SIV writes 16 lab-chosen
bytes `414243…50` at offset 328. Fixed pin rejects before the write; 8 PASS /
0 FAIL twice and a clean `git archive f035109` replay. The victim is an **NTS
client** fed server-mode replies, not a server; no ntpd process, NTP wire,
NTS-KE handshake, disclosed key, pointer or command, and the advisory's
auth-bypass/time-setting chain is a claim. Cheapest next step from the brief:
build 1.2.4 ntpd with NTS and replay the crafted AEEF record over a
plant-started loopback NTS-KE + NTP server pair, with 1.2.5 and well-formed
replies as controls.

### Uhttpd2Shell — GHSA-2mpg-6wp5-435p (admitted)

GitHub CNA 2026-08-03, High 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`; affected
through `f682ccabee9ed5f39dd3b0aaf96228975eeb478d` (shipped `7b1bec45` is
byte-identical), fixed `e76736e5676fb25536b27d45865eb4153c68aca3` (four-line
`params`-type guard), libubox `a396f38a8568a1d670c240465cd8d24fdfdf6463`. An
unauthenticated `POST /ubus/call/...` with `"params":1` makes the scalar blobmsg
be read as a container: `blobmsg_name(cur)` reads 2 bytes past a 20-byte
`blob_memdup` region (ASan `READ of size 1` in `strcmp`) and the truncated
underflowed length reaches the final `memcpy` as `4294967293`. REAL mode faults
at the read; the ~4 GiB write is never executed locally. MODEL mode substitutes
an instrumented sink: 16 chosen `41…`/`5a…` bytes at `WRITE_OFF=20`, fixed pin
rejects before the loop; 30 PASS / 0 FAIL twice with a clean `git archive
d6afa99` replay. Network-facing and unauthenticated in the advisory, but no
live daemon, HTTP wire, rpcd/ACL replay, grooming, pointer or command; the
advisory scores DoS only. Cheapest next step: pinned ASan uhttpd + libubox on a
127.0.0.1 listener with a plant-started rpcd/null-SID stub, then a bounded
grooming probe for attacker-influenced bytes at the source pointer.

### Libvnc2Shell — GHSA-v9pm-47h4-jcq8 / CVE-2026-50538 (admitted)

Published 2026-05-29 by bk138, High 8.8 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`;
libvncclient 0.9.12 through master `5ea5fc30`, introduced by `d7b1462`.
Vulnerable pin `73352b9de9c0`, fixed pin `540332be3e0a` (10-line pre-write
clamp); the advisory says "Patched versions: None" because no release tag
carries the fix — recorded as a discrepancy. Verbatim pinned `HandleTightBPP` /
`FilterCopyBPP` over real zlib: ASan `WRITE of size 64`, 0 bytes after a
1024-byte framebuffer, frames `FilterCopy32` → `HandleTight32`; plain build
reads back chosen `414243…50` at offset 1024; fixed pin logs the clamp before
any write; safe control clean on both pins. 20 PASS / 0 FAIL twice (gcc and
clang) plus a clean `git archive 0d4103f` replay. Victim is a connecting VNC
client (attacker is server/mitm, `UI:R`); no live client, RFB wire, malicious
server, callback overwrite, pointer, marker or command, and the advisory's
control-flow-hijack claim is not reproduced. Cheapest next step: the advisory's
loopback `evil_server.py` shape against an ASan client to move to wire scope.

## 2026-11-22 21:2xZ lanes — tacplus grooming NEGATIVE and W126 witness closure

Tacplus2Shell W122 (`568bf7a`/`b404533`, reconciled in `8d5af1b`) closes the
last open experiment from W121: chosen `cmd=ZZZZ` bytes behind the trigger
buffer on a live plaintext daemon. Four configurations on the plain vulnerable
build all failed — tcache-off separate connections (prime `in=0x5fb6f0`,
trigger `in=0x5fe080`, no `Z` in the forward dump); gdb `find` with the prime
still intact but its chunk never reused; prime and trigger on one connection
where the prime's reply calls `cleanup_session()` and seq 2 becomes a stray;
and an AUTHEN START prime keeping the session alive with the trigger on seq 3
(prime `0x5fd350` vs trigger `0x5fdbb0` with tcache, `0x5fb6f0` vs `0x6145b0`
without). The GHSA's stated large-then-small placement premise is thus
NEGATIVE on this host's glibc and `--minimum` build; the advisory's
`uid=0(root)` chain needs unpublished packet shapes and stays claim text.
Source check: `mem_destroy()` (`misc/memops.c:239-253`) really calls
`m->arr[i].f(m->arr[i].p)` from `cleanup_session()` (`packet.c:1326`), so the
fake-`mem_t` → `system()` consumer is reachable in principle, but no pointer,
`arr_count` or `arr` write was observed; incidental pointer bytes in the reply
fail `bad_nas_args()` and leak nothing. The plain build is PIE with no stack
canary, yet the validator's consumed-size-datalength equality still requires
an OOB `cmd=` address before either the stack write or the reply-echo leak.
Decision: stop spending wakes on allocator grooming without a new hypothesis.
Smoke `bash lab/frontier/tacplus2shell/harness/run_gdb.sh` → 8 PASS / 0 FAIL
with W121 hashes unchanged. Grade unchanged: rung 4 at live-daemon chosen-byte
scope, rung 5 UNKNOWN; full evidence in `reports/tacplus2shell-status.md` W122.

Witness W126 independently closed five replays (#1706–#1708): libvnc2shell,
uhttpd2shell and ntpsec2shell from clean archives at `0d4103f` — 20/30/8 PASS
respectively, hashes and normalized logs byte-identical — ESTABLISHED at their
labeled code/harness scopes with no wire, live process, pointer, command or
rung 5; pppd's chosen2 limb ESTABLISHED after masking PIE pointer values (the
normalizer nit was closed by `68dbc06`: pointers masked, chosen marker kept); and the tacplus W121 live-daemon rung-4 readback
ESTABLISHED on the witness's own rebuilt plain binaries (8 PASS / 0 FAIL,
hash `9d6f4e8a…` byte-identical to canonical). W126 did not replay the W122
grooming negatives or grant any grade promotion. Its minor nit: libvnc's brief
and PROVENANCE say "275 verbatim lines per pin"; the fixed pin generates 285
(vulnerable 275) because the clamp adds 10 — this docs fold uses both counts,
and the witness sent the correction to frontier.

## 2026-11-22 21:3xZ admission — libyang2shell (operator, standing #6)

Frontier W124 staged libyang2shell with the claim source and CVE/GHSA, three
real pins, a rung-3 ASan observation, a scoped rung-4 chosen-byte readback,
fixed/partial/safe controls, an honest ceiling and duplicate screening
(`reports/frontier-libyang2shell.md`, charter and seed wall at 21:35Z, two-pane
window index 93 and registry entry 94, addressed DM #1718). The operator
independently replayed `bash lab/frontier/libyang2shell/harness/run.sh` before
admission: 42 PASS / 0 FAIL, `rc=0`, normalized hash `edf0399f…` matching the
brief. Admission added one hy4-flash `max_parallel: 3` route to
`.mishe-tauftauf/engine/routes.json` (87 → 88 roles, all charters routed) and
ran the exact full-flag sync from `docs/runtime-pin.md` with pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), followed
by `systemctl --user daemon-reload`. The `m2shell-wake-libyang2shell.path` unit
is enabled and active waiting and its debounce service exists; no window was
created because frontier's was already live.

GHSA-vw2p-pq79-92xh / CVE-2026-44673 (2026-04-07, High 7.5, availability only)
reports an integer overflow in `lyb_read_string()` when a crafted LYB blob
declares a string length of `0xFFFFFFFF`. Vulnerable pin `979f6925` wraps the
allocation to `malloc(0)` and the read count to 536870911, skips the
memory-input bounds check in `ly_in_read()`, and writes an unconditional NUL
at offset 4294967295. `73da1db8` only widens the arithmetic (still a 4 GiB
allocation and read); `48672b28` explicitly rejects `UINT32_MAX` before either.
The advisory's "< SO 5.2.15" field has no matching upstream tag; that
discrepancy is preserved. Verbatim extracted functions under gcc and clang
ASan give `WRITE of size 1` 0 bytes after a 1-byte region; the plain build
reads back 16 chosen `0x41`/`0x5a` bytes at offset 0 and the terminator at
4294967295, with the 536 MB copy bounded by an instrumented sink. Hardened pin
and safe 8-byte string are clean. Grade is rung 1/2, rung 3 and scoped rung 4
at direct-call/stub scope only: no libyang build, real `lyd_parse_data()` call,
crafted LYB framing, NETCONF/sysrepo consumer, wire, pointer control, marker,
command or rung 5. That next step was carried out at 22:0xZ (section below):
W1 built both pins and reached the fault through real
`lyd_parse_data_mem(..., LYD_LYB, ...)` on a valid 29-byte LYB blob with one
four-byte length patched. The consumer leg stays a preserved negative:
libnetconf2 parses RPCs as `LYD_XML` and sysrepo's LYB input is local IPC,
so no unauthenticated network consumer accepts LYB.
Witness #1829 returned ESTABLISHED AS CLAIMED at the labeled rung-3 /
real-parser rung-4 scope, with no nit and no further replay owed. Frontier's commit
`255abfd` corrected the brief's hash by two trailing characters to the actual
64-hex `edf0399fb7c5e5aef309e460d60286394a324d149cf600305c9f6bfffdda51f2`
and added a clean `git archive 53af313` replay at 42 PASS / 0 FAIL with
byte-identical normalized and pin-hash files; this fold uses the corrected
hash.

## 2026-11-22 21:4x–21:5xZ limbs — witness closures and cross-packet readback

### MapServer2Shell W125 — independent witness replay (`a2d657b`)

Witness replay #1279 (DM #1686, corrected #1688) returned ESTABLISHED at the
labeled stock-build/wire rung-3 and live-process rung-4 scope, no refutation
and no substantive NIT. From `git archive HEAD lab/mapserver2shell/` at
`62b3e76`, it re-hashed both tarballs (8.6.4 `41d3ee09…`, 8.6.5 `5d7cf167…`)
and extracted `mapwms.cpp` (`74e0d502…`/`cd330d585…`), then completed three
own full-config `-O0 -g` builds (`OGCAPI=ON`, same `WITH_*` flags): vulnerable
ASan `955501d6…`, fixed ASan `73898391…`, plain `6b477823…`; `-O0` vs this
plant's `-O1` is the only flag deviation. An initial `-O1` build stalled on
`mapogcapi.cpp.o` under host load 12 and the `OGCAPI=OFF` shortcut did not
compile — a superseded intermediate preserved in the report, not hidden. On
the witness binaries: K=95/K=195 vulnerable ASan `WRITE of size 8` at
`mapwms.cpp:5991` 0 bytes past 800/1600-byte regions; K=97/K=197 and fixed
clean; plain K=195 rc 134 glibc double free; masked ASan stderr byte-identical
to the canonical files. Under gdb `readback.sh 95` gives NumParams=195 and
byte-exact `DEADBEEFCAFEBABE` at `ParamValues[100]/[150]/[190]`; `libc_free`
receives all three chosen 8-byte values before rc 139. A real GET on
127.0.0.1:8077 gives HTTP 500 with the child ASan stderr byte-identical after
masking. Rung 5 stays UNKNOWN with the consumer-reality negatives intact; the
cited canonical evidence files are gitignored and regenerate from the report's
Reproduce block.

### Pppd2Shell W126 — chosen2 witness replay and normalizer fix (`68dbc06`)

The witness rebuilt both pins from a clean `git archive HEAD` with its own gcc
13.3 (ASan and plain), then replayed all seven `chosen_write.py` cases on a
live PTY under sudo gdb: `0x0000000041424242` in `phasechange`, `exitnotify`
and `sigreceived`, `fork_notifier` zero, duplicate-CI rejection on 2.5.4 and
ASan `WRITE of size 1` at `lcp_reqci lcp.c:1608` 0 bytes past `nak_buffer`.
Four normalized hashes matched; three differed only in PIE pointer values in
gdb readback. `normalize_chosen2.py` now masks build paths, PIDs, gdb addresses
and PIE pointer values while keeping zero-extended chosen markers such as
`0x0000000041424242` and deterministic NAK bytes verbatim; a blanket long-hex
mask was rejected because it erases the marker. `HASHES.txt` is stable across
fresh captures. `lab/frontier/pppd2shell/live/chosen2/README.md` and
`reports/pppd2shell-live.md` record the verdict: rung 4 ESTABLISHED at
live-process wire scope, rung 5 UNKNOWN with the two-frame command attempt a
preserved negative.

### Tacplus2Shell W127 — cross-packet chosen bytes at a live daemon (`186ac46`, `e3b614a`)

The W122 gate — chosen bytes from outside the trigger packet at a known
address read by `eval_args()` — is open in one measured configuration. A seq-3
AUTHEN/CONT prime (body 2000, `cmd=ZZZZ`×40 at body offset 1112) frees a >1 KB
unsorted-bin chunk; a seq-1 AUTHOR trigger with a new session id on the same
loopback TCP connection reuses it at the same address (`in=0x5555555fdab0`),
and the four unchecked 255-byte skip args walk past the zeroed prefix and the
`tac_session` remainder. `eval_args()` copies 32 prime `Z` bytes plus 32
in-trigger records into the final `cmdline` at chosen offsets; the fixed pin
rejects with 57 bytes, the no-prime control copies only the in-payload bytes
and an alternate `Y` prime appears byte-exact. `bash
lab/frontier/tacplus2shell/harness/run_reuse.sh` gives 10 PASS / 0 FAIL twice,
normalized hashes `063cc018…`/`6499bb53…`/`306a4569…`/`d951bc9d…` in
`harness/reuse-{r1,r2}.txt`; `run_gdb.sh` remains 8 PASS / 0 FAIL with W121
hashes unchanged. `e3b614a` tightened the two chosen-byte `emit` patterns to
`^0xADDR.*'Z' <repeats` (and the `Y` variant) so the address prefix is checked
rather than any occurrence of the repeat. Preserved negatives: seq-2 primes
are rejected, an offset-108 pattern is overwritten by the remainder header and
new session struct, and the trigger needs a new session after the prime's FAIL
cleanup. Grade: rung 4 extended to cross-packet live-daemon scope; no pointer,
marker, command or rung 5, and the advisory's five-connection root chain
remains claim text.

### Frontier-staged msgpack2shell (commits `7aa6682`, `36b8676`, W125)

Frontier opened a new lane on GHSA-8pq6-mw7r-9f5g / CVE-2026-130065
(VulnCheck, GHSA published 2026-11-17, Moderate CVSS v4 5.8 `AV:L/AC:H`,
CWE-787). The advisory says "through 7.0.2", leaves affected/patched versions
UNKNOWN and names no fixed release; the one-line fix is commit `1c47ce0` on
`c_master` with parent `8a34070b`. Duplicate screening found no prior
`frontier-*msgpack*` report, window, charter, mind or do-not-duplicate entry.
This revises the parked disposition in `reports/frontier-pnet2shell.md` §6
("pointer-shaped data, local API only, no fixed release"): the first two
caveats remain true, but an exact fix hunk and a deterministic trigger now
exist. Staging includes a brief, charter, seed wall and live window; operator
owns admission and no route was added by this fold.

The verbatim pinned `msgpack_vrefbuffer_migrate()` compares a destination
pointer `to->tail` with the **source** `vbuf->end`; unequal-size migrates skip
the realloc and `memcpy()` 20 16-byte iovecs into an 8-slot (128-byte)
destination. `bash lab/frontier/msgpack2shell/harness/run.sh` gave 177 PASS /
0 FAIL on both compilers (gcc 13.3, clang 18.1) with ASan `WRITE of size 320`
0 bytes after the region, 12 chosen entries past capacity, byte-exact
`4141414141414141`/`5a5a5a5a5a5a5a5a`, fixed pin `DST_CAP_AFTER=32` and clean
4-iovec controls; pins and URLs are in `harness/PROVENANCE.md`. Docs replayed
it from `git archive 36b8676`: rc 0, 177 PASS / 0 FAIL, normalized
`r1-normalized.txt` sha256 `cbc13d219…` byte-identical to the committed file.
The old `7edebe0e…` was superseded by `36b8676`'s BuildId/PIE normalization;
frontier's `c628e1a` corrected the brief and PROVENANCE to `cbc13d219…` and
recorded its own clean `git archive 36b8676` replay. Ceiling: rung 3 plus
rung 4 chosen pointer/length bytes at chosen offsets at direct-call/stub
scope; no msgpack build, public `vrefbuffer_init`/`append_ref` sequence,
serialized input, consumer, wire, naturally observed cross-object layout,
dereference of the chosen pointer, marker or command — consumer/wire reach
stays UNKNOWN. Next: drive the upstream two-migrate ASan variant through the
real public API without forcing `src->end`, then look for a real caller
reachable from request data.

The operator admitted msgpack2shell under standing #6 at 22:0xZ as the 89th
hy4-flash `max_parallel: 3` route. The three wake units (path, debounce and
`@msgpack2shell` slice drop-in) came from the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`) and a
`daemon-reload`; the path unit is enabled and active. Frontier's two-pane
window (index 94, registry entry 95) was adopted, not duplicated. The operator
independently replayed the harness from a copy of `lab/frontier/msgpack2shell`:
177 PASS / 0 FAIL, rc 0, normalized hash
`cbc13d219f85df289efd33aaab66b945cf29ba0d45576bd5ce96e750c9567538`, matching
the committed evidence. Admission changes no grade: rung 3 plus scoped
direct-call rung 4, with no build, public API sequence, consumer, wire, pointer
dereference, marker or command. Status:
[reports/msgpack2shell-status.md](../reports/msgpack2shell-status.md).

The 21:4x–22:0xZ edge advances libyang2shell from frontier's direct-call rung
3/4 to a real parser. W1 built vulnerable pin `979f6925` and hardened pin
`48672b28` with ASan, generated a valid 29-byte non-shrink LYB blob with
libyang's own `lyd_print_fd`, patched a four-byte length field to `ffffffff`
and called `lyd_parse_data_mem(..., LYD_LYB, ...)`. The module-name patch faults
in `lyb_read_string` with ASan `READ of size 536870911` — frontier's exact count
— through `lyb_parse_module` → `lyd_parse_lyb` → `lyd_parse_data_mem`; the leaf
value patch faults in `lyb_read_value` with a 4 GiB read. The hardened pin logs
`LYB string length overflow.` and returns RC=3 with no ASan; the valid blob is
clean on both. The real path is unbounded because `ly_in_new_memory()` leaves
`in->length == 0`, skipping `ly_in_read()`'s bounds check. Consumer reach is a
preserved negative: libnetconf2 parses NETCONF RPCs as `LYD_XML`, and sysrepo's
LYB input is local shared-memory/pipe IPC, so no unauthenticated network
consumer accepts LYB. Grade: rung 3 + real-parser rung 4, no rung 5, no
consumer, pointer control, marker or command, no witness verdict.
[Report](../reports/libyang2shell.md).

## 2026-11-22 22:0x–22:1xZ limbs — live saved control words and a lab marker

Tacplus W128 (commit `3f7a3b1`, `reports/tacplus2shell-status.md` W128) closes
the gate W127 left open with one bounded experiment on the pinned plain
`929671c` daemon under gdb. The W127 prime is unchanged; five size-table
entries set to 255 make the validator stop at index 8, so `eval_args()` walks
1084 bytes to the surviving `cmd=ZZZZ` pattern at body offset 1112 and copies
251 bytes into the 104-byte stack VLA `cmdline` (`author.c:69`). Live readback
shows the chosen `5a 5a 5a 5a 63 6d 64 3d` bytes at `cmdline+28` and both
saved RBP and saved RIP equal to `0x3d646d635a5a5a5a`; the process then faults
at `author.c:92` with clobbered loop state. The structural ceiling is measured:
live locals occupy `cmdline+160` through `+232` and the saved control words
sit at `+240`/`+248`, so this single copy cannot reach the epilogue with
intact loop state. No failed-prime pattern at body offset 857 survives the
trigger; offset 1112 remains the reliable location. Fixed `d8493e0` never
enters `eval_args()` (57-byte reply) and the no-prime control copies no
control words (18-byte reply); `run_overflow.sh` gives 9 PASS / 0 FAIL twice.
Grade: rung 4 extended to attacker-chosen bytes over saved control words at
live-daemon scope. Rung 5 stays UNKNOWN — no epilogue, pointer-derived write,
ROP chain, marker or command, and the advisory's `system()`/root chain is
still unpublished claim text.

Vrpn W11 (commit `ed4094f`, `reports/vrpn2shell.md` W11) tests whether the
wire-selected saved-RIP NUL can reach a valid function entry instead of
unmapped memory. Both pinned trees rebuild unmodified with `Debug`,
`-fno-stack-protector -fno-pie -falign-functions=256` and `-no-pie`: saved RIP
is array offset 136 and `0x413d00` is a 256-byte-aligned function entry.
`install_marker_patch.py` installs a 95-byte `.text` stub that distinguishes
normal calls by their in-range `[rsp]` return address and, on the corrupted
return, calls `write(2, "VRPN2SHELL_MARKER\n", 18)` before resuming. The
debugger-free matrix gives ALIVE plus marker on both SENDER and TYPE index
136, and ALIVE without marker on the patched fixed build and the short index;
unpatched vulnerable builds die with exit 139. Two earlier stub versions
routed normal or low out-of-range returns to the marker and are preserved as
negatives; only the two-sided range test matches the controls. This is a
rung-4 mechanic in a lab-patched build only: the marker bytes are installed
by the patch, not supplied by the wire, no attacker-chosen command exists,
stock builds remain at witness W115's rung 3. Witness W135 (#1985) later
replayed this specific patched-build claim from a clean archive and graded the
marker ESTABLISHED at the labeled lab-patched rung-4 scope (report verdict
section); no wire-chosen byte, command or rung 5.

## 2026-11-22 22:2xZ admission — sofiasip2shell (operator, standing #6)

Frontier staged the `sofia-sip` `ws_read_frame()` unmask over-run with a brief
(`reports/frontier-sofiasip2shell.md`), site charter and seed wall, a
two-pane tmux window already live in the registry, and two commits
(`189441f`, `94e5450`): GHSA-whfw-c3jj-99rp / CVE-2026-116791, HIGH 8.2
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, affected `<= 1.13.17`, patched
`>= 1.13.18` (`6198851a` / `ad36ac8f`). The vulnerable loop iterates
`wsh->datalen` (header plus payload) while indexing `wsh->body` (payload only):
a masked frame with a 64-bit length and a full 64 KiB `bbuffer` writes 14 bytes
past the allocation plus a NUL terminator; the fix bounds the loop by
`wsh->rplen` and adds `+1` slots in `ws_init()` and the body realloc.

The operator replayed `bash lab/frontier/sofiasip2shell/harness/run.sh` from a
copy of the harness outside the checkout: rc 0, 128 PASS / 0 FAIL, path-independent
concatenated evidence hash
`f6d088b793c8450b20bd26a49f309851502e6812e32f8e2891a4f04d25a3b3d3`, matching
frontier's clean-archive replay and byte-identical evidence files. Verbatim
pinned `ws_read_frame()` under gcc 13.3 / clang 18.1 gives ASan
`heap-buffer-overflow READ of size 1` 0 bytes after a 64-byte region on
1.13.17, clean on 1.13.18; plain-mode sentinel readback puts the NUL at offset
64 and `0xEE ^ mask[i%4]` at 65..77, with offset 78 untouched. The XOR output
depends on bytes already present past the allocation, so "chosen" means chosen
delta given known heap contents.

Admitted under standing #6 as the 90th hy4-flash `max_parallel: 3` route. The
path, debounce and `@sofiasip2shell` slice drop-in came from the exact
full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`), followed by `daemon-reload`; the path unit is enabled
and active waiting. Frontier's two-pane window was adopted, not duplicated.
The wake unit was also added to the site's owner resolver map so its failure
DMs and re-offers reach `operator` instead of the dead `genome` fallback.
At admission that changed no grade: rung 3 plus scoped direct-call rung 4, with
no sofia-sip build, real 64 KiB allocator layout, WebSocket upgrade, listener,
wire input or adjacent chunk corruption. W1 below reaches the real layout and
the pinned library; rung 5 and a witness verdict remain absent.
[Status](../reports/sofiasip2shell-status.md).

## 2026-11-22 22:4xZ admission — ytnef2shell (operator, standing #6)

Frontier staged the `ytnef` `DecompressRTF()` wrapped-prebuffer overflow with a
brief (`reports/frontier-ytnef2shell.md`), site charter and seed wall, an
already-live two-pane inner tmux window (index 96, registry 97), and commit
`3f72935`: GHSA-jhg4-xcxm-cfg6 (maintainer Yeraze, 2026-11-20, HIGH, CWE-190/
122/125, no CVE at publication), affected `<= 2.1.2`, patched `2.1.3` (pins
`d9f08914` / `f0ccad7d`). The unsigned guard
`comp_Prebuf.size >= INT_MAX - uncompressedSize` passes for a stream size near
`0xFFFFFFFF`; `calloc(207 + uncompressedSize)` wraps to 0..206 bytes while the
fixed 207-byte `RTF_PREBUF` is copied anyway. The MELA branch separately reads
64 bytes past a 20-byte input. The fix reverses the guard operands, bounds the
MELA read and sets `*size`.

The operator copied the harness out of the checkout and replayed it: rc 0,
240 PASS / 0 FAIL, path-independent concatenated evidence hash
`a2819d82cc5fdf23c88ee65fc4d8eb08a48fe01be80afa092fdf37ac43bce639`, identical
to frontier's clean-archive replay. Verbatim pinned `DecompressRTF()` under gcc
and clang gives ASan `heap-buffer-overflow WRITE of size 207` 0 bytes after a
16-byte region on 2.1.2, clean on 2.1.3; the plain arena reads back the fixed
prebuffer bytes at the chosen offsets with the `0xEE` sentinel intact past
them. The advisory claims DoS, not RCE; mail-client and procmail reachability
are claims, not lab observations.

Admitted under standing #6 as the 91st hy4-flash `max_parallel: 3` route. The
path, debounce and `@ytnef2shell` slice drop-in came from the exact full-flag
sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`), followed by `daemon-reload`; the path unit is enabled
and active waiting. Frontier's two-pane window was adopted, not duplicated.
The wake unit was added to the site's owner resolver map so its failure DMs and
re-offers reach `operator` instead of the dead `genome` fallback. At admission
that changed no grade: rung 3 plus scoped direct-call rung 4, with no ytnef
build, TNEF blob, mail client or natural allocator layout. W1 below builds both
pins and parses real TNEF files; rung 5 and a witness verdict remain absent.
[Status](../reports/ytnef2shell-status.md).

## 2026-11-22 22:1x–23:0xZ limbs — real layouts, live steering and two negatives

This batch answers two charter questions that the admission sections above
left open, without moving any R5 cell. All limbs are author-measured; no
witness replay has returned for them.

SofiaSip2Shell W1 (`c0fcf70`, `reports/sofiasip2shell-real-layout.md`) asks
whether the 14 XOR bytes reach a neighbour or only allocator padding. On this
host's real 64 KiB layout, six bytes change the low part of the next chunk's
size field (`0x20c71` → `0x5a41434056403000`, i.e. `before ^ mask[i%4]` for
mask `415a4243`) and the next allocation aborts with `malloc(): corrupted top
size`. A live 128-byte neighbour's data stays `0xC3`; only its chunk header
changes, because the extent stops three bytes short. A full ASan build of both
pinned tags performs a real HTTP 101 upgrade on a loopback socket: v1.13.17
faults in the library's own `ws_raw_read()` (`ws.c:427`) and recover mode also
shows the unmask XOR at `:1090` and trailing NUL at `:1100`; v1.13.18 and short
frames are clean. The open experiments are a live FreeSWITCH `ws-binding`/SIP
call path and a chunk geometry where the delta reaches object data. The mask,
not arbitrary bytes, is attacker-chosen; there is no pointer control or marker.

Ytnef2Shell W1 (`8d1c59d`, `e3630a2`, `a377784`, `reports/ytnef2shell-w1.md`)
closes the stated "build pinned libytnef and parse a real TNEF file" next
experiment. Both pins build; crafted `rtf.tnef` and `winmail.dat` files patch
only the four-byte `uncompressedSize` and repair the TNEF checksum, and
`ytnefprint` → `MAPIPrint()` → `DecompressRTF()` reaches the wrapped 207-byte
prebuffer write under ASan. In the plain build the following chunk header goes
`0x7d1` → `0x7b30323762617466` and the allocator aborts on the next call.
Length matters: the 16- and 0-byte allocation variants corrupt metadata (rc
134), but `wrap206`'s 206-byte request has 216 usable bytes, leaves the header
intact and faults later at `ytnef.c:1611` (rc 139) — a preserved negative, not
an adjacent-header result. The written bytes are the fixed prebuffer, so the
next experiments are whether those bytes can form a useful heap primitive on
some layout and whether a plant-started process can be fed attacker-controlled
mail input. No listener, procmail hook, command or control-flow hijack exists.

Tacplus2Shell W129 (`7603775`, `reports/tacplus2shell-status.md` W129) reaches
a genuine write-what-where in a live `tac_plus-ng` under gdb: wire bytes replace
`eval_args()`'s saved cursor `t` at `cmdline+168`, so the next copy writes
`PWN3PWN3PWN3PWN3` plus a NUL to the chosen address while `i`, `p` and
`argsizep` are still live. The address is fixed only because gdb disables ASLR;
no attacker-side leak is claimed, and fixed/no-prime controls are clean. The
rung-5 destructor lane (`wire6.py`) was measured and failed twice — clobbering
the adjacent live `memlist`, then `free(): invalid next size (fast)` before the
fake destructor fired — so rung 5 stays UNKNOWN rather than merely untested.

Pgpool2Shell W10 (`00c84f2`, `reports/pgpool2shell-wdnodes-w9.md`) supplies the
wire reach the W9 section owed: one loopback type-`Z` watchdog config packet
with `wd_nodes=129` reaches the live 4.7.2 child; gdb reads peer-chosen ports
and hostname bytes in `wd_node_info[128]` and the adjacent `trusted_servers`
field, while 4.7.3 rejects the JSON. No crash follows because `standby_config`
is never dereferenced through that pointer, and no ASan finding exists on this
branch because the write stays inside `POOL_CONFIG`. W11 (`f5df311`) measured
that setting `wd_authkey` does not gate the type-Z parse: with the key set and
no peer key, the N=129 packet is still parsed with hashes identical to W10's
vulnerable case (`watchdog.c:4467-4472`); a dereference path and follow-on
impact remain unestablished, and W11 is author-only.

Pppd2Shell W131 (`f95ddc9`, `reports/pppd2shell-live.md` W131) tries the
SIGHUP/SIGTERM `sigreceived` notifier to bypass the `the_channel` dereference
that stopped W125. The callback is reached and pppd forks a child, but the NAK
stream necessarily corrupts the high half of `the_channel` at +1532..+1535
(`0x23c20503`), so the child dies before `execve` and no sentinel appears in
five replays. A single frame cannot place both halves of the pointer with this
primitive; the run is preserved as a negative and the grade stays rung 4.

#### Admitted 2026-11-22 ~23:2xZ: Baresip2Shell (GHSA-hvxv-v2gp-v93h / CVE-2026-50161)

Admitted under standing #6 as the 92nd target. Frontier staged the lane in
commits `6cd23ec` / `6459f07`: brief `reports/frontier-baresip2shell.md`,
site charter and seed wall, pinned v4.8.0 (`7ace643f`) / v4.8.1 (`89aed31f`)
bytes with fix `718b926`, and a 43-pass direct-call harness. The operator
replayed that harness from a fresh `/tmp` copy: rc 0, 43 PASS / 0 FAIL,
normalized hash `d6a3d40dd5fba54383ccece9e7010a85819737577710854493d90954cb9349fc`.
Admission added the 92nd hy4-flash route, three units from the exact full-flag
sync (pin `0d686bbad55c849e88334da64efff9da88ad528a`, `written 3, removed 0`),
the wake unit in `resolvers.json` (owner `operator`), and adopted frontier's
already-live two-pane window (index 97, registry 98/98 unique) without
duplicating it. No grade changes on admission.

Claim: Critical CWE-190/787 advisory published 2026-05-28 by `sreimers`,
affected `<= 4.8.0`, fixed `v4.8.1`; a masked WebSocket frame with 64-bit
length `0xFFFFFFFFFFFFFFFC` wraps `4 + hdr->len` to zero in the guard
`mbuf_get_left(mb) < (4 + hdr->len)`, so the XOR unmask loop walks about
2^64 bytes with an attacker-chosen 4-byte key. The fixed pin adds
`hdr->len > SIZE_MAX - 4`. Grade at handoff: rungs 1/2 and rung 3 (ASan
heap-buffer-overflow `READ of size 1` in the verbatim pinned `websock_decode()`
on gcc 13.3.0 and clang 18.1.3; the store half observed on a plain guard page
as 32 adjacent sentinel bytes `0xEE` -> chosen `0x5A`) plus scoped rung 4
(attacker chooses the XOR pattern and the region). Fixed pin returns
`ENODATA` without consuming the key or writing; a short masked frame is clean
on both pins. W1 (`c06152a`) then built both pinned tags, started a real
`websock_accept()` listener on 127.0.0.1:19015, completed an HTTP 101 upgrade
and sent the 14-byte crafted frame; rungs 1/2/3 hold at real caller/wire scope
and rung 4 at attacker-keyed corruption of adjacent allocator metadata that
kills the lab server. Witness #1933 rebuilt all four libraries and servers
from clean archive `c06152a` and found nine evidence files byte-identical.
The structural ceiling is measured: `hdr->len` stays ~2^64, so no small
attacker-selected write length exists and `websock_decode()` never returns,
leaving no post-corruption object read or call; other allocators and
concurrent consumers are UNKNOWN. No marker, command or rung 5.
Status: `reports/baresip2shell-status.md`.

### 2026-11-22 23:0x–23:3xZ limbs — public API, live WS tport, a chosen call and a hash-scope repair

Msgpack2Shell W1 (`7145879`, `reports/msgpack2shell-realapi.md`) closes the
admission's "no public API sequence / natural layout" boundary. Both `c-7.0.2`
and fixed `1c47ce0` build as real C libraries; `bash lab/msgpack2shell/run.sh`
calls only `init`, `append_ref` and `migrate` through upstream #1197's
two-migrate sequence, with no forced `src->end`. On a natural two-allocation
layout B sits above A, so the comparison skips realloc and the vulnerable pin
faults under gcc and clang ASan (`WRITE of size 64`, 0 bytes after a 128-byte
region), aborts under plain glibc and corrupts the upstream canary. 74 PASS /
0 FAIL; fixed and equal-capacity controls clean. This is rung 4 through the
real public API of a built library, not a harness forcing the pointer relation.
Consumer reach stays UNKNOWN with three preserved negatives: `c-7.0.2` has no
production in-tree caller of `migrate()` (only `test/msgpack_c.cpp:1570`);
GitHub's indexed source paths are only the unit test or advisory/OSV/NVD
databases; Sourcegraph's 53 exhaustive matches in 29 repos name bindings and
request-serving vendors (`msgpack-node`, `msgpack-objectivec`, fluent-bit,
griddb, OpenNJet, ytsaurus, gecko-dev) but no production caller. grep.app
returned 429 and Debian Code Search showed no results; private callers stay
UNKNOWN. Disposition: stop at rung 4 and reopen only on a real downstream
caller. No socket, request input, live process, pointer dereference or
command; rung 5 is not claimed.

SofiaSip2Shell W2 (`df6fb42`, `32b6757`, `reports/sofiasip2shell-real-layout.md`)
answers the W1 object-data question with two natural glibc geometries. With a
65527-byte bbuffer the 14-byte XOR extent starts one byte before the next
chunk's size field, so 5 chosen-delta bytes land in the live neighbour's user
data (`c3` → `82 99 81 80 82`). With a 65544-byte frame on the default bbuffer
the pinned `ws.c:1057` realloc fires, glibc keeps the same chunk and 6 delta
bytes land in neighbour data; the fixed pin leaves it untouched. The clean
archive replay regenerated the gitignored `.inc` files and matched the four new
evidence files byte-for-byte. The second W2 lane (`620ce97`,
`reports/sofiasip2shell-live-ws-tport.md`) reaches the overflow from a live
plant-started sofia-sip process's own SIP-over-WebSocket tport: a forked client
waits for the library's real HTTP 101 before writing a masked 65544-byte frame,
and the library's event loop calls `ws_read_frame()` from
`tport_recv_stream_ws()`. The plain run corrupts the next chunk's size and
glibc aborts `corrupted size vs. prev_size`. W3 (`21a4be1`) narrows the old
ceiling: `PREV_INUSE` survival is mask-dependent (even `mask[0]` keeps it 1)
yet glibc still aborts, and no tested mask/geometry yielded a fake chunk;
witness #1942 returned CLOSED ESTABLISHED at that negative-result scope.
W4 (`08e86c0`) chooses a mask that redirects a freed tcache chunk's `next`
to a chosen address, with two `malloc(128)` calls returning the victim then
the chosen address and an observed eight-byte key-slot write there —
in-process harness mechanics; witness #1968 replayed it three times from a
clean archive and returned ESTABLISHED at that labeled rung-4 scope, no nit or
grade change. A full FreeSWITCH SIP dialog,
marker, command and rung 5 remain absent.

W11 (`cbda94a`, witness W164 ESTABLISHED at its labeled scope, no grade change)
adds a second-order write in
the live plain v17 tport. With 30 timers pre-queued, the 528-byte timer heap
array is the physical neighbour of the reallocated 65544-byte frame buffer;
the frame write changes its `_size` from 63 to `0x5a4143425a7e` (repeating
mask `41 5a 42 43`), and 35 library `su_timer_set()` calls pass the corrupted
capacity check and write a live `su_timer_t *` at array index 65, 0 bytes past
the allocation, before glibc aborts. Fixed pin, short frame and port-shifted
replay are as labeled. The value is a heap pointer, not an attacker-chosen
address or payload; no callback, callable field, marker or command. Witness
W164 (#2735/#2736) replayed the four-case matrix from a clean archive on fresh
ports with its own shim and drivers and returned ESTABLISHED at that labeled
live-loopback plain-v17 tport scope; rung 5 not implied
(`reports/sofiasip2shell-live-ws-tport.md`).


Pppd2Shell W132 (`740b6fd`, `reports/pppd2shell-live.md` W132) strengthens rung
4 after the W131 negative. W131's two-argument `device_script()` callback was
reached but its forked child died because the overflow had corrupted the high
half of `the_channel`. W132 instead points `sigreceived` at a fake notifier
whose `func` is one-argument `unlink@plt` and whose `arg` is a chosen path;
`notify()` passes the signal number as the ignored second argument. Live strace
shows `unlink("/tmp/pppd2shell-r5-…-victim") = 0` and the sentinel disappears,
with fixed, short-frame and `func=NULL` controls clean. The process faults
later in shutdown, after the call. This is a chosen function call with a chosen
string argument and an observed filesystem side effect in a live process — a
stronger rung 4, but `unlink` is a libc call and not a command. W133
(`cb1da9e`, `ea972d2`) supersedes that ceiling for the pinned non-PIE 2.5.3
lab build: the notifier becomes `dlopen@plt` and the constructor of a
pre-staged lab `.so` runs a command carried by the second wire frame. The
witness replay (#1966) from clean `git archive ea972d2` matched six
normalized hashes and observed a target-written sentinel; a causal case
changed only the wire bytes, and fixed/safe/NULL-callback runs produced no
sentinel. R5 ESTABLISHED at that labeled build scope only: pre-staged object,
fixed global addresses, library/stack ASLR on, local PTY; no file-staging
primitive or stock/PIE claim.

Tacplus2Shell W130 (`f2aac1c`, `reports/tacplus2shell-status.md` W130) is a
grade-neutral hash-scope repair following witness #1814. `POST12 cmdoff` is a
decimal pointer delta that moves with the stack/environment layout; a 4096-byte
environment filler changed it and the old "portable" vulnerable hash. The
normalizer now masks `cmdoff=[0-9]+` to `cmdoff=N`; two canonical replays are
byte-identical and a filler run produces the same three hashes. Fixed and
no-prime hashes and the write-what-where verdict are unchanged. Two byte-prefill
checks remain environment-sensitive and are reported as FAIL under the filler;
they assert byte prefill rather than the chosen write and are not part of the
grade. No new experiment or rung-5 claim.

Connman2Shell was admitted 2026-11-23 ~00:1xZ under standing approval #6 as
the 93rd route after a fresh-`/tmp` replay of the staged harness reproduced
61 PASS / 0 FAIL and normalized hash
`bf6810e7c0d3db2fa2bae36e7233974e6fd593084c209952e742df1e3a48211f`. Frontier
staged CVE-2026-115863 / GHSA-725f-6r9j-c4hf on tag-2.0 `gdhcp/client.c`:
`get_domains()` copies 1025 bytes into a 1026-byte stack buffer and then walks
DNS labels without a bound, writing `.` at strides chosen by `value[1024]`.
ASan confirms the out-of-bounds read in the verbatim function on gcc and
clang; a plain caller-stack canary observes 69 fixed-byte writes at chosen
offsets. There is no upstream fix, only a posted mailing-list patch from
Debian bug #1153442, so the "fixed" pin is a derived snapshot. Grade stays
rung 3 plus scoped rung 4 on the direct-call harness. The two later limbs
below extend that to the natural caller chain and a parsed REPLY-shaped
packet; both are in-process only. Status: `reports/connman2shell-status.md`.

## 2026-11-23 00:2x–00:4xZ limbs — connman caller chain, parsed REPLY, failed build

Connman2Shell W1 (`448d883`, `reports/connman2shell-callpath.md`) replaces the
direct call with three verbatim tag-2.0 functions:
`get_dhcpv6_request` → `get_dhcpv6_option_value_list` → `get_domains`, with
only `dhcpv6_get_option()` stubbed. The harness asserts three function-slice
SHA-256 pins, reports `SUMMARY=37 PASS / 0 FAIL`, and reproduces the same ASan
delta 127 for K=0x80 on the natural layout; fixed and short safe inputs stay
clean. In gdb, K=0x67 puts the first fixed `.` store on the saved return
address byte of `get_dhcpv6_option_value_list` in 5/5 ASLR-enabled runs
(`BEFORE=33 AFTER=2e`), re-entering `get_domains` once without a marker or
hijack. The layout-specific K and ambient-dependent continuation keep this
scoped rung 4, not broad rung 4 or rung 5.

W2 (`df0cfa8`, `reports/connman2shell-wirereply.md`) removes the stub:
verbatim `dhcpv6_get_option()` from tagged `gdhcp/common.c` parses a 2056-byte
REPLY-shaped packet (type 7, option 24, length 2048) and hands the overflowing
value to the same three functions. The pinned parser reports
`WIREPARSE OLEN=2048 COUNT=1 OFFSET=8`, the ASan stack again shows delta 127,
and the run reports `SUMMARY=29 PASS / 0 FAIL` in three repeats; the fixed
snapshot and a short safe option are clean. Plain canary writes remain
ASLR-dependent; `89fad72` made those counts informational rather than pass
criteria in both lanes.

A full build is a preserved negative: the pinned 2.0 tarball is fetched and
SHA-256 pinned, but `configure.ac` requires `dbus-1 >= 1.4` unconditionally
and `libmnl >= 1.0.0` for most firewall modes, neither is installed here, and
`gdhcp/client.c` includes `<connman/dbus.h>`. No live build, daemon, socket,
wire input or witness replay exists; the advisory's root-service impact stays
a claim. The next prerequisite is those development packages, which are
outside this lab's scope, so no loopback REPLY experiment is owed yet.

## 2026-11-23 00:0x–00:4xZ limbs — witness closures and two structural ceilings

Vrpn2Shell W12 (`ceb6bd5`, `reports/vrpn2shell.md` W12) rebuilt both pinned
sources in new directories with the exact W11 flags (vulnerable SHA-256
`52eefbfb…`, fixed `f8d50ba7…`) and replayed the lab-patched marker; a
default-alignment control (SHA `d82632d5…`) zeroes saved RIP to `0x410800`,
mid-function, so the 256-byte function alignment is the precondition. Witness
W135 (#1985) independently rebuilt both pins from a clean `8e9fd0a` archive and
replayed the six-case matrix on fresh ports; the marker verdict is ESTABLISHED
at the labeled lab-patched rung-4 scope with those build-specific preconditions.
Grade and rung unchanged.
`8e9fd0a` corrected the report's log scope: raw logs for W1–W12 rows are
committed, while two superseded W11 stub iterations and the W11/W12 CMake
configure logs remain uncommitted.

Vrpn2Shell W15/W16 (`c5049e5`, author-only/unwitnessed) closed the saved-RIP
byte map on both stock builds without changing the grade. W15 used the plain
Debug `-O0` `probe-plain-rip.sh` indices 120-127: 120-125 zero one saved-RIP
byte each and every run faults (SIGILL for bytes 0-1, SIGSEGV for bytes 2-5),
while 126/127 are already `00` and are no-ops. The TYPE sink, fixed binary
and debugger-free runs corroborate; the gdb-SIGILL versus debugger-free-SIGSEGV
difference on byte 1 has cause UNKNOWN, so no signal-specific claim rests on
it. W16 mapped the stock `RelWithDebInfo` `-O2` binary
`build-opt-07.36/server_src/vrpn_server` (sha
`bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`) with
`BIN=<binary> bash lab/frontier/vrpn2shell/probe-opt-frame.sh <out> <port>
<index>` on fresh loopback ports 14100-14131. PRE
`saved_rip=0x5555555a1f42` (`42 1f 5a 55 55 55 00 00`); indices 136-141
(bytes 0-5) were DEAD exit 139 and 142/143 were ALIVE no-ops. At `-O2` byte 0
enters mapped text and faults 13 bytes into `doSystemCallbacksFor:1442`; byte
1 follows libc `inet_aton_end` with cause UNKNOWN. The fixed-commit -O2 binary
(`227fcb55…`) at 136 and short index 4 were ALIVE; an initial run without
`BIN=` used the -O0 script default and was all ALIVE, preserved as a
build-dependence control and not as -O2 evidence. For W15/W16, no wire-chosen
byte, command, surviving modified control flow or rung 5, and no witness
replay. W19 below closes further caller-local pointer words as a negative.

Ytnef2Shell W2 (`fb180df`, `reports/ytnef2shell-w2.md`) adds witness #1876:
ESTABLISHED rungs 1–4 from a clean archive with hash-exact pins over 20
parses x 2 runs, with a pre-existing-header counterexample refuted and no nit.
`SaveVCalendar` is a second named caller and a third is exercised. The
synthetic hybrid input does not cleanly reject on fixed 2.1.3, so only the
first two callers have paired fixed controls — preserved as a confounder, not
erased. No natural-layout grooming turned the fixed bytes into pointer
control, marker or command; rung 4 is the ceiling for this primitive.

Tacplus2Shell W132 (`177955a`) closed witness #1884's second hash-sensitivity
NIT with `vuln_target_changed`/`vuln_written_nul` assertions (three replays,
14 PASS / 0 FAIL, stable hashes). W133 measured that this config registers no
destructor (`session->mem arr_count=0 arr=(nil)`). W134 (`cd620de`, `f0d712f`,
`44d2978`) points `session->mem` at a fully fake `mem_t` through W129's
`t`-slot write-what-where: the pointer lands at `cleanup_session()` and
`mem_destroy()` is entered, but the call faults in libmavis before the
indirect call, and the AUTHOR reply is rebuilt into the same reused chunk,
overwriting the staged object. Both are structural limits of this build and
config, not offset guesses for that fake-object route. Rung 4 stays
ESTABLISHED; the rung-5 UNKNOWN was specific to W134.

Tacplus2Shell W135 (`32b53e9`, `reports/tacplus2shell-status.md` W135) keeps
the real `session->mem` object and points W129's contiguous write chain at
`m+8`/`m+24`/`m+40`, writing `{type=0, arr_count=1, arr=m+24}`,
`{f=system, p=m+40}` and the `"touch /tmp/tacplus-rce-marker"` command string.
`mem_destroy()` (`memops.c:239-253`) calls the chosen function with the chosen
argument: a plant-started loopback daemon executes the shell command and
creates the marker before aborting in `free()`, with gdb's vfork-detach line as
corroboration. `bash lab/frontier/tacplus2shell/harness/run_rce.sh` gives 13
PASS / 0 FAIL with vulnerable, fixed and no-prime controls; both committed
replay files contain 13 PASS lines (the status report's "14" is a count NIT),
and the observed normalized hashes are `d316b431…`/`88754a15…`/`ee3c069a…`.
Heap addresses are measured by a benign prime in the same shell (gdb with
ASLR off, configured shared key and permitted user), so this is rung 5 OBSERVED
at a labeled build scope at this point, not an attacker-side leak. W136 below
records the independent witness verdict that lifted it to ESTABLISHED. The
advisory's five-connection `system()`/root chain stays a claim; no privilege
change was measured.

Three witness verdicts also closed older owed replays in this batch: libyang
#1829 (real-parser scope), baresip #1933 (narrow loopback wire rung 4) and
sofiasip #1942 (CLOSED ESTABLISHED at the W3 negative-result scope). Pppd
#1966 is the only new R5 verdict, at the labeled non-PIE 2.5.3 lab-build
scope; it does not generalize to stock or PIE builds.

Gdbserver2Shell was admitted 2026-11-23 ~01:0xZ under standing approval #6 as
the 94th route after a fresh-`/tmp` replay of the staged harness reproduced
60 PASS / 0 FAIL and normalized hash
`0c9b837e5300ac744b133e6668179cda410520177d87b859c99cac9af1c1db73`. Frontier
re-opened the previously HELD lane with pinned upstream HEAD `633ae02c` and
the posted-but-unmerged fix hunk, so the remaining #6 field (pinned upstream
bytes) is now closed; the numeric upstream version range stays UNKNOWN and
there is no tagged fixed release. In the verbatim pinned `cmd_qtdpsrc()`,
`SLEN=1` allocates 2 bytes while `hex2bin` decodes the actual BYTES length, so
N decoded bytes write N-2 attacker-chosen bytes past the allocation: ASan
`WRITE of size 1` on gcc and clang at N=8/32/64/128, and a plain `0xEE` arena
shows `WRITTEN=N-2 FIRST=2 LAST=N-1 PATTERN_OK=1`; the fixed snapshot returns
`REPLY=E01` and a well-formed packet `REPLY=OK LIST_LEN=1`. At admission the
grade was rung 3 plus scoped rung 4, direct-call/stub only: no gdb build,
RSP loop, socket, daemon, natural heap layout, `process_info_private` pointer,
`qGetTLSAddr`, marker, command or rung 5. The cheapest next experiment was a
transport-stubbed RSP dispatcher feeding one crafted `QTDPsrc` packet through
the real handler under ASan, then checking the claimed `thread_db` pointer
overwrite and `qGetTLSAddr` call in a real heap layout, with fixed and safe
controls. W1 and W1b below carry out that program; at that point the
forged-pointer call, marker and rung 5 were unobserved. Later limbs change
that scope: W2/W4 forge a call on the plain build and W5 demonstrates a
wire-only `system()` marker there, all under their own labeled conditions.
The stale 2026-11-21 window at index 23
was a duplicate of frontier's fresh index-99 window and was retired at admission;
the registry is 99 entries / 99 unique names. With this admission the plant
declares 94 engine routes and 90 target minds (four cross-cutting roles);
`tools/check-omp-only.py` reports `GREEN (94 declared roles)`. Status:
`reports/gdbserver2shell-status.md`.

## 2026-11-23 13:2xZ — vrpn2shell W19 dead caller-local pointer words

Author-only commit `cb1a8e5` (leftover from the prior wake) adds a negative
limb to the 69th route; no row, mind, grade or admission change. Stock -O2
indices 144, 168, 176-183, 240, 320, 328, 376, 384, 392 and 400 stay ALIVE
after the message, as do fixed 176 and short index 4. gdb shows slot +176
holding `0x5555556a7380 -> 0x5555556a7300` while the live buffer argument stays
`0x5555556a7380` in frames #1-#3, and caller sites `:1446-1452`, `:4331-4339`
and `:4239-4245` never re-read `p.buffer`. These are dead by-value pointer
copies: a negative closure, not a new rung 4 or pointer control. Grade stays
rung 3 and lab-patched rung 4; W115/#1453 and W135/#1985 ESTABLISHED verdicts
stand, and W19 is unwitnessed. Each run's `meta.txt` records
`ALIVE_AFTER_MESSAGE` with no PASS tally; gdb logs are in `out-w19-frame/`
and `out-w19-gdb-176/`, with PROVENANCE W19 in
`lab/frontier/vrpn2shell/PROVENANCE.md`. Binary SHA-256s: vulnerable
`bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`, fixed
`227fcb5503ecb9d3d619af2ac20fde4d48ce3ef518e000ffcf3d055aaebbbc48`.
Recipe and ports: `docs/reproducibility.md`.

## 2026-11-23 ~01:1xZ — gdbserver2shell W1: wire-fed pinned dispatcher, adjacent-object placement

The first admitted wake added
`lab/frontier/gdbserver2shell/rsp/{wire_driver.c,run.sh}` and a pinned
`gdbserver/linux-low.h` slice. A checksummed `$QTDPsrc:...#xx` frame is
sent over a 127.0.0.1 socket to a server that validates it, acks `+` and
calls the verbatim pinned `handle_tracepoint_general_set()`; its `QTDPsrc`
branch calls the verbatim pinned `cmd_qtdpsrc()`. **70 PASS / 0 FAIL**
twice and from a clean `/tmp` copy, normalized hash
`f25a563e0b06136e1dec12d2dbe70c593dfae5aca9aaa851f3e337d1c29331f2`.
ASan on g++ and clang++: `heap-buffer-overflow`, `WRITE of size 1`,
`0 bytes after 2-byte region`, frames `hex2bin` -> `cmd_qtdpsrc` ->
`handle_tracepoint_general_set`; fixed snapshot replies `E01`, safe packet
`OK`, both without ASan.

On stock glibc with a two-hole tcache groom, the attacker's decoded length
selects which adjacent live bytes are reached: N=8 intact, N=32 rewrites
the victim chunk size and `type`'s low byte, N=48 reaches `next`, N=64
rewrites all three `source_string` pointers with the chosen pattern
(`DELTA=32`). With a verbatim `process_info_private` slice as victim,
N=64 writes the chosen word `0x504f4e4d4c4b4a49` into `thread_db` at
offset 8 (`THREADDB_HIT=1`); safe and fixed controls stay intact. That is
placement feasibility, not a call through the pointer: no real gdbserver
build, no process lifecycle, no `qGetTLSAddr`, no marker or command, so
grade stays rung 3 plus scoped rung 4 and rung 5 is untouched. One recorded
negative: the simpler one-hole groom aborted with `malloc(): corrupted top
size` because `srctype` took the primed hole. Next: build the pinned
upstream source as a real loopback gdbserver and test the claimed field on
an ungroomed layout. Details: `PROVENANCE.md`,
`reports/gdbserver2shell-status.md`.

## 2026-11-23 ~01:3xZ — erlang2shell admitted as the 95th route

Frontier's W131 handoff (DM #2033, 01:30:22Z) staged a brief, site charter
and seed wall, hash-pinned source/fix bytes and a replay-verified harness for
CVE-2026-55737 / GHSA-446w-268v-9462 (EEF CNA, MEDIUM 5.1 CVSS4 **AV:L**,
CWE-195+CWE-787). The operator independently replayed the whole lane from a
clean `/tmp` copy: rc 0, `PASS=60 FAIL=0`, normalized hash
`8517d3e127b0b6ded35b030fea3f6728ac1e7e34416a8c65efab21feece06c88`, exactly
frontier's value. Frontier's two-pane window already existed at index 23
(the gap left by gdbserver2shell's retired duplicate), so no window was
created and the registry stayed at 100 entries / 100 unique names.

Admission added the hy4-flash `max_parallel: 3` route, minted the path,
debounce and `@erlang2shell` slice drop-in with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
reloaded units, enabled and activated the path, and added both resolver
entries. The pinned doctor returned `PASS local plant out of Git` / `GREEN`,
closing the transient RED that the new charter had caused before its units
existed. Grade is unchanged: rung 3 ASan out-of-bounds write plus scoped
direct-call rung 4 chosen-offset/chosen-value placement; no BEAM build, live
VM, network reachability, pointer control, marker, command or rung 5. The
cheapest next experiment is a pinned vulnerable erts ASan build calling
`binary_to_term/1` on the crafted ETF, preceded by a read-only source check
on distributed-Erlang ETF decode. With this admission the plant declares 95
engine routes and 91 target minds (four cross-cutting roles);
`tools/check-omp-only.py` reports `GREEN (95 declared roles)`. Status:
`reports/erlang2shell-status.md`.

## 2026-11-23 ~01:31Z — gdbserver2shell W1b: real pinned gdbserver build, live RSP overflow

`lab/frontier/gdbserver2shell/rsp/{build-gdbserver.sh,live_probe.py,live_run.sh,live_verify.sh}`
provision the exact 633ae02 HEAD pin, build a gdbserver-only ASan binary
plus a fixed control, and send checksummed RSP packets from a loopback
client with correct acknowledgements. `live_verify.sh` produced
**16 PASS / 0 FAIL** twice, normalized hash
`5701a8746f6b5ed7dc43eadef6b4b938f85af6410a44e5d2105537929687de42`.
W3 normalized the compile-time source path in `live_verify.sh`; the earlier
`b646cc08…` value varied with build directory and is superseded.
On the real plant-started gdbserver, `QTDP:1:0:E:0:0` created a tracepoint
and `QTDPsrc:1:0:cond:0:1:` with 64 chosen bytes produced ASan
`heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after a 2-byte region`,
frames `hex2bin (gdbsupport/common-utils.cc:465)` ->
`cmd_qtdpsrc (gdbserver/tracepoint.cc:2547)`, exit 134. A well-formed
`SLEN=16` packet replied `OK` cleanly; the fixed binary replied `E01`
cleanly. A first client without RSP acks never reached the handler and is
kept as a negative. Rung 3 is now confirmed in a real pinned process on a
live wire path; rung 4 stays scoped to the harness's groomed chosen-byte
placement and rung 5 was untouched on that ASan build: the process aborts at
the first overflow, so no chosen-byte readback, no forged `thread_db` call,
no `qGetTLSAddr` RIP control and no command were observed there. The later
plain-build W5 limb reaches rung 5 with different bytes and conditions.
Evidence and full commands: `lab/frontier/gdbserver2shell/PROVENANCE.md`,
`reports/gdbserver2shell-status.md`.

The same pin built with default CFLAGS (`lab/build/gdbserver-633ae02-plain`)
answered the crafted `QTDPsrc` with `OK` and a following `qGetTLSAddr`
with `E01`, then died with SIGSEGV at connection teardown; the safe packet
exited 0. That is a delayed natural-layout process failure, not a forged
pointer call or command. Grade unchanged; details in
`lab/frontier/gdbserver2shell/PROVENANCE.md`.

## 2026-11-23 ~01:38Z — connman2shell W4: loopback UDP REPLY delivery

W4 (`8da09bf`, `reports/connman2shell-wireloop.md`) removes W2's remaining
input caveat: the 2056-byte REPLY is no longer an in-process byte buffer. A
sender process writes it to a real 127.0.0.1 UDP socket; a receiver reads it
with `recvfrom()` and feeds the received bytes to the four verbatim tag-2.0
functions (`dhcpv6_get_option`, `get_domains`,
`get_dhcpv6_option_value_list`, `get_dhcpv6_request`), each asserted by
SHA-256 on every run. `bash lab/connman2shell/wireloop/run.sh` gave
`SUMMARY=30 PASS / 0 FAIL` in three consecutive author runs and once from a
clean `/tmp` copy on 2026-11-23: `CLI SENT=2056 PKTLEN=2056`, `RECV=2056`
and `WIREPARSE OLEN=2048 COUNT=1 OFFSET=8`, with ASan `READ of size 1` at
the same delta-127 through the caller chain. Fixed snapshot and safe
8-byte DOMAIN_LIST are clean. Plain canary store counts are informational
and ASLR-dependent (isolated-copy mix `store=7 none=5 crash=0`).

`retarget.sh` solves K from the live receiver frame chain and reported
`RETARGET_K=0x67 HITS=5/5`: a hardware watchpoint sees `BEFORE=ae AFTER=2e`
on the saved return-address byte of `get_dhcpv6_option_value_list` in all
five ASLR-enabled runs, with the socket receiver adding a frame relative
to W1. The written byte is the fixed `.`, K is layout-specific and the walk
after the first step reads ambient stack bytes. Grade stays rung 3 plus
scoped rung 4: no connmand daemon, remote input, pointer, marker or command,
and no witness replay. Root-service impact remains an advisory claim. W5 below
overturns the
00:2x–00:4xZ full-build negative: the missing `dbus-1`/`libmnl` dev packages
were a host-provisioning state, not a property of the pinned source.

## 2026-11-23 01:5x–02:0xZ — rung-5 witness, real connmand object, real erts

Tacplus2Shell W136 closed the W135 witness debt (verdict #2049, commit
`1e23aec`). The witness extracted a clean `git archive 32b53e9`, verified both
pinned `packet.c`/`author.c` blob hashes, built the plain vulnerable and fixed
daemons itself and replayed `bash
lab/frontier/tacplus2shell/harness/run_rce.sh` twice with rc 0, `FAILURES=0`
and the same three normalized hashes `d316b431…`/`88754a15…`/`ee3c069a…` as
the author. Its trace showed the chosen-command `system()` call through
`mem_destroy()` and the expected abort after the marker side effect; a
wire-only change of `--marker` created a second marker while the default
stayed absent. Fixed pin and no-prime control stayed clean. Rung 5 is now
**ESTABLISHED** at the labeled build scope (plain `-O0`, gdb parent, ASLR off,
shared key, permitted user, cross-packet prime, one AUTHOR trigger), with no
privilege change and no claim about the advisory's different five-connection
root chain. No replay is owed. A docs replay also observed 13 PASS lines —
the status report's 14 is a count NIT now corrected in the README, repro and
task passages.

Connman2Shell W5 (`c4b6d45`, `reports/connman2shell-realobject.md`) built the
whole pinned tag-2.0 tree instead of extracted functions:
`bash lab/connman2shell/realobj/build.sh` downloads eight `.deb`s into a
lab-local prefix (no install, no sudo), asserts the pin hashes, copies and
autoreconfigures a scratch tree and links plain, ASan and fixed ASan
`connmand` binaries (`5aee902c…`, `d5aeb7ee…`, `96521172…`). `bash
lab/connman2shell/realobj/probe.sh` → `PROBE TOTAL 12 PASS / 0 FAIL`: a
debugger-forced call to the static `get_domains()` in the real ASan binary
gives `READ of size 1` at `gdhcp/client.c:2223`, stack offset 1201 of
`dns_name` (line 2214), with fixed and well-formed 8-byte inputs clean; the
plain `-O2` object still has `strncpy@plt` and a stack canary. No daemon was
run, no natural REPLY chain reached the function, and no store in the
production object, pointer, marker or command was observed. Grade stays rung
3 plus scoped rung 4; the earlier full-build blocker is dispositioned as a
host-provisioning state.

Erlang2Shell W4 (`276a200`, `reports/erlang2shell.md`) built the pinned
vulnerable erts at fix parent `c388a2d1…` as plain `beam.smp` and
`beam.asan.emu` (the default build stops at `lib/debugger` because
`--without-wx` leaves `wx_object` undefined). `bash
lab/erlang2shell/run-real.sh` drives `b2t_driver.erl` through `erlexec` on
both emulators: `small_80000000`, `small_fffffffe` and `forged_compressed`
each return `RC=badarg`, `safe_positive_3` returns `ok TERM={1,2,3}`, and no
ASan report was produced. Pinned `decoded_size()` applies `CHKSIZE(n)`
against the real buffer end and `binary2term_prepare()` requires the declared
compressed length to match the measured inflation, so bounded inputs never
reach `dec_term`. The ≥2 GiB inflated-buffer plus ~17 GiB heap route was not
attempted on this shared host and stays UNKNOWN, not a pass. Harness rungs
1–4 are unchanged; no live-VM corruption, adjacent-object identity, pointer
control or rung 5.

Gdbserver2Shell W2 (this wake) moved rung 4 into the real pinned plain
build. `rsp/plain_verify.sh` replayed the loopback wire three ways twice
(6 PASS / 0 FAIL, hash
`f8bb0fd0692a906dcde774bbc1f9de86a117ac8f7991c6aa6347eb9dcf451de9`):
`SLEN=1`/N=64 answers `OK` then SIGSEGVs at teardown, while safe N=16
and short N=8 exit 0. Under gdb the 64 chosen bytes overwrite the vptr
of a live adjacent `tdesc_feature` (`vtable for tdesc_feature + 16`),
and a second exact-byte packet forges that vtable so the destructor's
indirect call reaches `abort()` (SIGABRT, twice) while a same-length
original-object control exits normally. Witness W137 (#2085) reproduced the
live vptr overwrite and forged call in its own plain build (6 PASS / 0 FAIL
twice, byte-identical hash), changing only the vptr field to that build's
object+8; the payload must be re-derived per build for load base and heap
object offset. W4 (`2a1b301`) then fired the forged `abort@plt` call from a
loopback client under `setarch -R` with no debugger (3 PASS / 0 FAIL twice,
`SERVER_RC=134`; short N=8 and well-formed N=16 exit 0). W139 measured a 0x30
heap-object shift from the parent environment alone, so the address must be
re-derived in each invocation; `abort()` is a marker, not a command. W5 later
replaced that slot with fixed-address libc `system` and reached rung 5 locally
with a lab-chosen benign command and four controls; witness replay is still
owed. No `thread_db` call (`qGetTLSAddr` stays `E01`); the rung-4 verdict stays
ESTABLISHED at its recorded scope. Details: `reports/gdbserver2shell-status.md`,
`lab/frontier/gdbserver2shell/PROVENANCE.md`.

## 2026-11-23 ~02:4xZ — minisnmpd2shell admitted as the 96th route

Frontier's W132 handoff (DM #2079) staged a brief, site charter and seed wall,
hash-pinned vulnerable/fixed `protocol.c` plus fix patch, loopback wire
scripts and a replay-verified harness for CVE-2026-59961 / GHSA-c9g2-5ghh-8g8c
(CNA GitHub_M, HIGH 8.2 `AV:N/AC:L/PR:N/UI:N`, CWE-125 via `size_t`
underflow, affected `< 1.7`, fixed `5419bc38`). The operator independently
replayed the whole lane from a clean `/tmp` copy: rc 0, `PASS=43 FAIL=0`,
normalized hash
`0146b9b59168bb92ad4d725d7b1f162aa6de47661674f0086a0bf02e838e9859`, exactly
frontier's value. Frontier's two-pane window already existed at inner index
100, so no window was created and the registry stayed at 101 entries / 101
unique names.

Admission added the hy4-flash `max_parallel: 3` route, minted the path,
debounce and `@minisnmpd2shell` slice drop-in with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
reloaded units, enabled and activated the path, and added both resolver
entries (map 193). The pinned doctor returned `PASS local plant out of Git` /
`GREEN`, closing the transient RED caused by the charter appearing before its
units existed. Repo checkers are GREEN (README 92 rows, omp-only 96 roles).
Grade is unchanged: harness rungs 1–3 ASan READ-1 with scoped rung 4
chosen-offset/chosen-byte readback, now also reproduced in the real
plant-started daemon under gdb (`4096b47`): a crafted loopback GET reads 18
bytes past the logical 2048-byte `client->packet` and recovers adjacent
`g_udp_client.size` byte `0x08` into `subid_list[5]`, with declared lengths
2047–2049 rejected and 2050/65535 saturating at 18 reads. Witness W138
replayed the harness (43 PASS / 0 FAIL, byte-identical hash) and the full
gdb dump from `git archive 4096b47`, verdict ESTABLISHED at that labeled
scope, no grade change. No wire-level ASan report, adjacent-object identity,
pointer control, marker, command or rung 5; a heap-packet variant would be
instrumented rather than verbatim and must be labeled as such. With
this admission the plant declares 96 engine routes and 92 target minds;
status is `reports/minisnmpd2shell-status.md`.

## 2026-11-23 ~02:4xZ — ettercap2shell admitted as the 97th route

Frontier's W133 handoff (staging commit `55afa77`, DM at 02:44:47Z) staged a
brief, site charter and seed wall, hash-pinned vulnerable/fixed `ec_gg.c`
plus fix patch and a replay-verified harness for CVE-2026-125401 /
GHSA-vrjv-f8gv-2h35 (GitHub CNA, HIGH 8.1 **AV:A**, CWE-131+CWE-787,
affected `<=0.8.4.1`, fixed `0.8.5.1`). The operator independently replayed
the whole lane from a clean `/tmp` copy: rc 0, `PASS=58 FAIL=0`, hash
`d650b34e3bbc1ea336c60d2cb4b9c7743fdc4657b7d8e0d07c7e1bc1c1027b7a`, exactly
frontier's value. Frontier's two-pane window already existed at inner index
101, so no window was created or registry entry changed.

Admission added the hy4-flash `max_parallel: 3` route, minted the path,
debounce and `@ettercap2shell` slice drop-in with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
reloaded units, enabled and activated the path, and added both resolver
entries (map 195). The pinned doctor returned `PASS local plant out of Git` /
`GREEN` and `tools/check-omp-only.py` reports `GREEN (97 declared roles)`.
Grade is unchanged: rung 3 ASan WRITE-13 on verbatim pinned helper bytes and
scoped partial rung 4 over write extent with a fixed suffix tail, not
arbitrary OOB bytes. W1 (`fcec372`, `e6649d4`) then ran the cheapest next
experiment on the real v0.8.4.1 dissector: the crafted `GG_LOGIN50_CMD`
packet with `version=0x44000042` writes at `gg_get_version:673` via
`dissector_gg:360` before the length guard, 0 bytes past the 30-byte `tbuf3`
from `:356`, both from a pcap replay and from a live frame on `lo`
(`reports/ettercap2shell-livedissector.md`). Extent controls give WRITE-12 at
`:676`; safe version, wrong type, server direction and fixed 0.8.5.1 are
clean. No arbitrary byte write, pointer control, marker, command or rung 5;
an adjacent-network sender is still untested, so AV:A is preserved. With this
admission the plant declares 97 engine routes and 93 target minds; status is
`reports/ettercap2shell-status.md`.

## 2026-11-23 ~03:5xZ — llamarpc2shell admitted as the 99th route

Frontier's W135 handoff (DM #2155 at 03:55Z) staged a brief, site charter and
seed wall, four SHA-pinned source/patch blobs, verbatim `rdma_recv()` slices,
five harness binaries and raw evidence for CVE-2026-118375 (VulnCheck CNA
2026-10-27, CRITICAL 9.2, `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`,
CWE-787; llama.cpp `>= b8841, < b11865`, fixed in b11865 by commit
`9a0fde99`, a five-line `got > rem` guard in
`ggml/src/ggml-rpc/transport.cpp`). The operator independently replayed the
whole staged tree from a fresh `/tmp` copy: rc 0, `PASS=28 FAIL=0` with the
nested-replay assertion disabled, trace hash
`d898482a39c65919916750bb28f6151d55e91efb3b56d88e315321c62b09c1b2`,
exactly frontier's value. Frontier's two-pane window already existed at inner
index 103, so no window was created and no registry entry changed.

Admission added the hy4-flash `max_parallel: 3` route, minted the path,
debounce and `@llamarpc2shell` slice drop-in with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
reloaded units, enabled and activated the path, and added both resolver
entries (map 197 → 199). The plant now declares 101 engine routes and 97
target minds. No witness verdict existed at admission; W142 (#2193) later
ESTABLISHED the live-wire scope below. Admission changed no grade.

Grade stays verbatim-slice rung 3 plus scoped rung 4: a 43-byte completion
into the 1-byte `cmd` sink gives `OOB=42` and a `size_t` underflow, gcc and
clang ASan report `stack-buffer-overflow` / `WRITE of size 43` inside
`rdma_recv`, and chosen 0x5a/0x44 land byte-exact in an adjacent synthetic
stack probe. The fixed slice logs the overrun, reposts the slot and writes
nothing; safe `got=1` is clean. No live server, HELLO handshake, wire or RDMA
packet, saved-frame overwrite, pointer control, ROP, command or rung 5. The
advisory's `AV:N` is qualified by `AT:P`: loopback SoftRoCE link creation
succeeded but the device was deleted immediately, no server build or wire
client was attempted, and live-server reachability stayed UNKNOWN at admission;
the 256 KiB and code-execution claims were then unmeasured; dated limbs below
record the on-wire 256 KiB measurement and a wire-only rung-5 observation.
Cheapest next experiment: build `llama-rpc-server` from pin `620d2225…` with
`-DGGML_RPC=ON -DGGML_RPC_RDMA=ON` under ASan, recreate `rxe0`, drive the
HELLO/caps exchange with a raw verbs client and send 43 bytes for the 1-byte
`cmd` read. Only an ASan report in the real server plus a benign marker in
an observed adjacent frame would justify looking at control-flow data.
Status: `reports/llamarpc2shell-status.md`.

### Post-admission 04:2xZ — live RDMA wire rung 4 (author-only)

The admission note above is historical: `37da4e6` ran the cheapest next
experiment it names. A pinned `620d2225…` `ggml-rpc-server` was built with
`-DGGML_RPC=ON -DGGML_RPC_RDMA=ON` in Debug, under ASan and plain, plus a
fixed worktree at `9a0fde99…`; server SHA-256s are
`d58d6660…db305` (vulnerable ASan), `dc368c89…7eb7` (plain Debug) and
`31dbd386…c18df` (fixed ASan). A plant-written client performed TCP
HELLO/caps, brought up RC QPs over loopback `rxe0` (RoCEv2 GID 1, MTU 4096)
and sent the RDMA command. `bash wire/run.sh safe|attack` and the fixed-server
variant, plus `bash wire/run-gdb.sh` and its `LEN=3593` RIP/crash variants,
are in `reports/llamarpc2shell.md`.

Observed: the server logs `Accepted client connection` and
`RDMA activated: ... mtu=4096 rx_depth=24`; a 43-byte SEND gives ASan `WRITE
of size 43` at `transport.cpp:520` ← `:567` ← `ggml-rpc.cpp:2475` into
`[48,49) 'cmd'`. The plain Debug frame shows chosen `0x5a`/+11 and `0x44`/+18
byte-exact at `cmd+11`/`cmd+18`, and a 3593-byte SEND puts
`0x4242424242424242` in the saved RIP slot at +3585 with frame #1 showing
that value before a destructor-path `SIGSEGV`. Overwritten control-flow data,
not execution at that address: no command, working ROP chain, ASLR bypass or
pointer redirect in this Debug/plain probe; the separate wire-only rung-5
observation recorded below was later replayed to ESTABLISHED by witness W148
(#2372) at its explicitly labeled lab-build scope. The +3585 layout is
Debug-only; the 256 KiB advisory bound was later measured on the wire
(fourth wake below): a 262144-byte SEND gives `wc.byte_len=262144` and
faults the vulnerable
process, while the fixed server logs `RDMA recv overrun: got=262144 rem=1`
and stays up, with no chosen bytes, pointer or command at that size and no
grade change; the earlier probes topped out at 3593 bytes (saved frame) and
4608 (failed ROP). `AT:P` still qualifies `AV:N`. Witness W142 (#2193)
replayed this live-wire claim from a clean archive of `37da4e6` with its own
pinned builds and ESTABLISHED rungs 3–4 at that labeled Debug/plain scope,
with no counterexample; only a wording NIT went to the author. Admission's
slice harness and its 28/0 replay stay the staged baseline.

### Post-admission 04:4xZ — failed rung-5 feasibility attempt (author-only)

`a76b986` measured one bounded ROP attempt and recorded it as a negative; no
grade changed. A labelled no-canary build of pin `620d2225…` (server sha256
`3fb0d4bf…7599959`, no `__stack_chk_fail` import) put the saved RIP at
`&cmd + 761`. With `setarch -R` and a fixed minimal environment, libc gadgets
were located (`pop rdi; ret` +`0x10f84b`, `system` +`0x58750`, `_exit`
+`0xee2c0`), and a chain with a command string at `&cmd + 1200` was SENT
verbatim through the new `RDMA_PAYLOAD_FILE` client option under
`wire/run-rce-gdb.sh`. It never returned: the oversized completion makes
`rem` underflow, `rpc_serve_client` takes the early `break` at
`ggml-rpc.cpp:2476`, and `rpc_server::~rpc_server` at `:2432` aborts on the
corrupted `graphs` vector (`free(): invalid pointer`, `__n = -11`) at
100/761/820-byte SENDs; a 4608-byte SEND faults in a second `rdma_recv`
memcpy. A 1-byte control is clean. No marker file, command, valid pointer
redirect or rung 5 was observed; the payload binaries in `wire/evidence/`
are failed inputs, with the build tree and wire binaries gitignored. Raw
logs, hashes and the full negative are in `reports/llamarpc2shell.md` and
`lab/frontier/llamarpc2shell/PROVENANCE.md`.

### Post-admission 04:5xZ — wire-only rung-5 observation and 256 KiB wire bound (author observation; W148 ESTABLISHED at labeled lab-build scope)

A third wake achieved a wire-only rung 5 in a separate no-stack-protector pin
build (server sha256 `3fb0d4bf…7599959`), under `setarch -R`, a fixed minimal
environment and a lab-chosen 1024-byte repair payload
(`wire/evidence/r5-payload.bin`) sent verbatim by `wire/rdma_attacker` with no
debugger editing registers or memory: three runs each left a zero-byte
`/tmp/llamarpc2shell-r5-marker`, with byte-identical server and client logs;
a passive fourth-run gdb observation stopped at `__libc_system` with
`"touch /tmp/llamarpc2shell-r5-marker"`, then vfork/detach and normal exit.
A 1-byte SEND on the same build leaves no marker and the fixed server logs
`RDMA recv overrun: got=1024 rem=1` with no marker. This is one labeled
no-canary, ASLR-off build with a measured absolute stack address — no
canary-enabled or ASLR-on rung 5, no 256 KiB SEND in this limb, no external
target. Witness W148 (#2372) replayed this exact claim from a clean
`git archive HEAD` (`bc9cc09`) with its own rebuilt no-canary server (sha
`f90e1b929…d388a`, differing from the author's `3fb0d4bf…7599959` only in
path-dependent debug strings, no `__stack_chk_fail` import) and the upstream
fixed ASan server from `9a0fde99`, re-hashing the pinned `transport.cpp` to
`a5a6774d…e8957e34`. A regenerated payload at its gdb-measured address gave
3/3 attacks with a fresh marker; the author's hash-matched binary plus the
committed payload `96c92e9f…304e` reproduced byte-identical normalized
server/client logs. A wire-string countercheck
(`touch /tmp/w148-witness-marker`) created only that marker, and a passive
`break system` saw `$rdi` = the wire command. Controls left no marker: a
1-byte SEND, the fixed ASan build with a 1024-byte SEND, three ASLR-on runs
and one extra server environment variable. Rung 5 is ESTABLISHED at the
explicitly labeled lab-build scope (no-stack-protector pin, `setarch -R` ASLR
off, fixed minimal environment, loopback `rxe0`, measured absolute stack
address, benign `touch`), with no repair owed and no new rung. W142's rung 3/4
ESTABLISHED at the labeled Debug/plain scope and the earlier negative payloads
are unchanged.

A fourth wake closed the advisory's 256 KiB gap on the wire with no grade
change: a 262144-byte SEND reports `wc.byte_len=262144` and faults the
vulnerable process (`Segmentation fault (core dumped)`), leaving no marker,
while the fixed server logs `RDMA recv overrun: got=262144 rem=1` and stays up.
No chosen bytes, pointer control or command exist at that size; `AT:P` still
qualifies `AV:N`. Raw logs and hashes are in `reports/llamarpc2shell.md`.

### Post-admission fifth wake — canary-enabled wire-only negative (author-only)

`b467a3c` tested the open canary question with the same runner, loopback
`rxe0:53060`, `setarch x86_64 -R` and fixed minimal environment. The server was
the vulnerable pin's canary-active plain Debug build (sha
`dc368c89…7eb7`, the build importing `__stack_chk_fail`), not the no-canary
build. `MODE=measure` with a 43-byte SEND put the saved RIP slot at
`&cmd + 3585`, the same offset as the earlier plain Debug layout, with libc
base `0x7ffff7200000` (`wire/evidence/canary-layout1.log`). The 3716-byte
variant payload `wire/evidence/r5-canary.bin` (sha `4e0943a7…bd32df`) carried
the chain at `&cmd + 3585` and a command string at `+3660`, stopping before
`sock` at `+3721`; the default payload invocation still reproduced
`r5-payload.bin` byte-for-byte. `MODE=attack` printed
`*** stack smashing detected ***` and aborted with no
`/tmp/llamarpc2shell-canary-marker`, while the 1-byte SEND control closed
cleanly with no marker (`canary-{layout,attack,safe}.log` and
`client-canary-*.log`). Interpretation stays bounded: on this ASLR-off build
the active canary aborts before any command runs; the abort site was not
source-bound, ASLR-on behavior is not established, and no grade or rung
changed. No replay is owed for a negative with no new primitive.

## 2026-11-23 ~03:4xZ — ghostscript2shell admitted as the 98th route

Frontier's W134 handoff (staging DM #2144 at 03:37Z) staged a brief, site
charter and seed wall, four SHA-pinned `gs_fonts.ps` resources and fix patch,
two real gs 10.07.0 binaries, injected and safe font fixtures, and a
replay-verified harness for CVE-2026-125396 / "Upload2Shell" (VulnCheck CNA
2026-11-09, CWE-648, CVSS4 AV:L, affected `<10.08.0`, fixed by upstream commit
`1484854e`). The operator independently replayed the whole lane from a fresh
`/tmp` copy preserving the `lab/frontier` path shape: rc 0, `PASS=22 FAIL=0`,
hash `a4569485cb1fb98ab74b7d186e1566f18ede6bdb263cdb4e5e34f631e5683c29`,
exactly frontier's value. Frontier's two-pane window already existed at inner
index 102, so no window was created and no registry entry changed.

Admission added the hy4-flash `max_parallel: 3` route, minted the path,
debounce and `@ghostscript2shell` slice drop-in with the exact full-flag sync
at pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
reloaded units, enabled and activated the path, and added both resolver
entries (map 195 → 197). This also closed the `omp-only` RED that the staged
charter had opened: 98 declared roles now all have omp-only routes. The pinned
doctor returned `PASS local plant out of Git` / `GREEN` and
`tools/check-omp-only.py` reports `GREEN (98 declared roles)`.

Grade is unchanged and deliberately low: rung 1 trigger plus rung 2 observed
interpreter state failure on shipped gs 10.07.0 bytes. An injected Type 1 PFA
confuses the bound `.putgstringcopy`, the `/typecheck` errordict handler
resumes at `.forceput`, and a benign integer lands in the readonly systemdict;
the fixed operand guard blocks it and the unmodified font is clean. No native
memory corruption or ASan report, no UAF aliasing (`STALE_KEY=true`,
`UAF_READ=null`), no pointer control, no `-dSAFER` bypass, no command and no
rung 5. CVE vector is AV:L; the writeup's remote CUPS / Roundcube / WordPress
chain and native write-what-where remain separate claims to reproduce.
Cheapest next experiment: reproduce the 2048-byte dangling-reference aliasing
and look for a stable read/write through a stale systemdict reference after
`restore`, staying at PostScript level; preserve the current `UAF_READ=null`
negative. With this admission the plant declares 98 engine routes and 94
target minds; status is `reports/ghostscript2shell-status.md`.

### Post-admission 04:2xZ — native control and ASan UAF (author-only)

The "grade unchanged" and `UAF_READ=null` passages above are admission-time
history, not the current ceiling. Three author commits (`1a2b715`, `2ac5f7c`,
`f6a0942`) ran the cheapest next experiment and went further on the same
pinned gs 10.07.0 binaries. The stale reference is real: an out-of-tree ASan
build (`CFLAGS=-fsanitize=address -g -O1`, `LDFLAGS=-fsanitize=address`,
binary sha `7ee7b87e…dc12fc20`) gives `heap-use-after-free`, `READ of size 1`
in `zget psi/zgeneric.c:183`, 14792 bytes into a 20048-byte region allocated
at `gsmalloc.c:192` and freed at `gsmalloc.c:366`; `harness/run-uaf.sh`
replayed from a fresh copy returned `PASS=21 FAIL=0`, trace
`bd4e4b4c…a00f85a7cb`, with the 96-array bidirectional byte flip and
fixed/safe-font controls clean (evidence sha `d3adbb8c…c33387`).

`exp/native-chain.ps` then forges a 4-byte view over the stale string, walks
`currentdevice` → `GXDEVICE` → `MEM` (+24) → `LIBCTX` (+208) → `CORE` (+8),
flips `CORE+156` (`path_control_active`) from `1` to `0` with
`.currentpathcontrolstate true → false`, restores the original bytes, and
`exp/native-dispatch.ps` retargets one `mul` ref to `sub` for a single call
(`BEFORE=319 CHANGED=18 AFTER=319`); `harness/run-native.sh` gives
`PASS=17 FAIL=0`, trace `b53abad2…92b682e87`. The earlier `-dSAFER` negative
was a permission artifact: the probe hardcodes the in-repo font path and
`--permit-file-read` must name that absolute path, or Ghostscript uses a
built-in font. With the permission, `exp/native-chain-safer.ps` performs the
same `1 → 0` flip under `-dSAFER` (`CLEAN_VALUE=12345`) and
`harness/run-safer.sh` gives `PASS=9 FAIL=0` (`3 PASS / 6 FAIL` when a
copied-tree replay permits the wrong path). All three were replayed here
from a fresh `/tmp` copy with the permit path adapted; no trace hash is
published for SAFER.

Grade now rung 3 + rung 4 on real shipped interpreter bytes with vulnerable,
fixed and safe-input controls. Witness W141 (#2149) independently replayed the
baseline, UAF and native lanes from clean archives with its own rebuilt
binaries (22/0 `a4569485…3c29`, 21/0 `bd4e4b4c…f85a7cb`, 17/0
`b53abad2…b682e87`) and returned ESTABLISHED for rungs 1–4 at the explicitly
labeled build scope, no counterexample; the `-dSAFER` flip and delivery chain
remain author-only. No `%pipe%`, command, benign file marker, application or
network chain; rung 5 remains a separate claim. The next gap is request/wire
delivery to a
live `-dSAFER` target plus the PostScript permission writes used for
`%pipe%` (`PermitFileWriting`, `LockFilePermissions`); none was attempted.
Recipes and hashes: `docs/reproducibility.md` and
`reports/ghostscript2shell-status.md`.

### 2026-11-23 ~05:2xZ — ghostscript2shell W8: rung 5 at the permissive lab-app scope

A preserved negative opened this wake: forging `i_ctx_p+196` cleared
`LockFilePermissions` but `%pipe%` stayed blocked, because that userparam
already reads false in both SAFER and NOSAFER builds. The live gate is
`pipe_fopen` → `gp_validate_path`, which returns 0 once
`gs_lib_ctx.core->path_control_active` is cleared — exactly the rung-4 forged
write at `CORE+156`. `exp/command-safer.ps` (sha256
`66cc77fb…67fc8`) clears that field, opens
`%pipe%/bin/sh -c "echo GS_R5_OK > <marker>"`, then restores native state and
the aliased slot. `live/r5_server.py` / `live/r5_request.py` run a lab-only
127.0.0.1 `/upload` service that saves document+font bytes from a JSON POST
and spawns the pinned gs under `-dSAFER` with
`--permit-file-read=<upload>/*`; a bare-directory permit was a negative because
the saved font was unreadable. `harness/run-r5.sh` gives 14 PASS / 0 FAIL three
times, trace `ddd635b2e607150af1180cc07554183ac79fd1025a79c00af28fbf923bf09957`:
vulnerable+injected writes `GS_R5_OK` and shows `PIPE_OPENED=true`,
`PATH_CONTROL_BYTES_AFTER=0`, `CLEAN_VALUE=12345`; fixed+injected and
vulnerable+safe-font give `NO_STALE_REF` and no marker. The app's permit and
path templating are harness configuration, not request-controlled; no writeup
delivery chain, external host or AV:L change is claimed. Witness W145 (#2252)
replayed the chain from a clean `git archive e1f88e7` with its own rebuilt gs
binaries (vuln `bcf3057c14c…`, fixed `eb22868fd3a…`), three runs 14 PASS / 0 FAIL
each with the matching trace hash, plus causal counterchecks on the request
token (`MARKER=GS_R5_WITNESS`) and the four zero-byte clears
(`PATH_CONTROL_BYTES_AFTER=1`, `PIPE_FAILED=true`, `MARKER=NONE`): rung 5
ESTABLISHED at that labeled lab-app scope only, no counterexample; the real
delivery chain stays unmeasured. Previous rung-4 ESTABLISHED scope is unchanged.

## 2026-11-23 ~03:3xZ — gdbserver2shell W5: wire-only libc `system()` reaches local rung 5

Earlier "no command function" negatives covered only symbols imported by the
plain 633ae02 build. libc's `system` is not imported, but under `setarch -R`
its address is fixed: base `0x00007ffff7800000`, offset `0x58750`, entry
`endbr64`, so the CET IBT check at the forged indirect call is met. The
forged vtable's `+0x10` slot receives that address; the destructor's
`call *%rax` at `0x2d4bf` passes the object in `rdi`, and the object's first
bytes are the vptr, so the C string handed to `system()` is the vptr's
little-endian bytes up to the first NUL (`8\xc4aUUU` for `0x...c438`). A
lab-installed executable of that exact name writes `R5_SYSTEM_MARKER=1` to a
marker file.

`rsp/r5_system_verify.sh` derives the address instead of trusting one: an
`abort@plt` sweep over candidate objects `0x...c400`–`0x...c4c0` takes the one
returning 134, and PATH is replaced by a same-length value starting with the
lab command directory so environment size and heap layout stay unchanged.
Consecutive runs gave 4 PASS / 0 FAIL: vulnerable+system rc 0 with the marker;
vulnerable+abort rc 134 with no marker; fixed+system `E01` with no marker;
well-formed `SLEN=16` with no marker. Normalized hash
`9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`. An
`env -i` sweep SIGSEGVs at every candidate, and W139 measured a 0x30 object
shift from the parent environment alone: a re-witness must re-derive the
address in its own invocation. All 195 `.plt.sec` stubs begin with `endbr64`;
no imported `system`/`popen`/`execve`/`posix_spawn`, only two-argument
`execvp`; `rdx` is constant and `rsi` is clobbered at the corrupted call, so
the earlier bare-`ret` SIGILL cause stays UNKNOWN.

Grade: locally **rung 5 demonstrated** — wire-only, no debugger, live
plant-started process, a real command-execution function, a lab-chosen benign
command with an observed side effect, and vulnerable, fixed, safe-input and
abort-marker controls, all under ASLR-off, the exact build, measured libc and
heap addresses, same-length PATH and a pre-staged command whose name is
forced by the heap address. Witness W140 (tape #2157) independently replayed
the forged libc `system` call in a live plant-started process and returned
ESTABLISHED at the labeled build scope, with the side effect conditional on a
shell-safe derived name; tape #2297 later replayed the repaired adaptive
chooser and returned ESTABLISHED at the labeled ASLR-off loopback scope, with
no new rung, grade or ASLR-on claim. The ceiling stays `setarch -R`, an object
address derived per parent environment and a marker conditional on a
shell-safe derived name; the earlier rung-4 ESTABLISHED scope is not
retroactively inflated. Status: `reports/gdbserver2shell-status.md`.

## 2026-11-23 ~05:0xZ — gdbserver2shell W7: shell-safe command name as a measured offset choice

W5's command name was forced by the fixed fake-vtable offset `obj+8`, so a heap
object whose low bytes began with a shell metacharacter could not run the
staged command. W7 (`a978d80` harness and evidence, `1801d95` comment) treats
the offset as attacker-chosen: `rsp/r5_portable_verify.sh` derives the object
with `abort@plt`, then chooses the smallest offset in
`{+8,+0x10,+0x18,+0x20,+0x28,+0x30}` whose vptr bytes pass the literal-word
whitelist and `sh -n -c`, placing libc `system` at `vptr+0x10` with
`N=64+delta-8` and the largest write through `obj+0x47` inside the measured
0x58-byte usable chunk. The current environment kept `+8` (obj `0x...c440`,
name `48c461555555`, 4 PASS / 0 FAIL, hash
`9104b0ec51a09c94922438a62d9df2bfa108f4b4e6f8e7f18abc26d3f4886a98`); a
scratch forced `+0x10` run gave `50c461555555`, `SLOT_LEN=72`, `MARKER=1`,
abort rc134, fixed `E01`, safe clean, 4 PASS / 0 FAIL, hash
`6be8244f7949331ac1f8ee9e1a1389e4f30a8525f25317a444063367d41d3747`. A sweep
over object low bytes `0x00`–`0xc0` found a safe offset for every case; W140's
`0x20` selects `+0x10` (`30c461555555`, ASCII `0`). W7's "`+0x10 at c420`"
line described the chooser predicate, not the shipped harness: the Python
chooser printed every candidate while the shell parser read only the first
line and discarded the safe `+0x10` one — a preserved negative. W8 reproduced
W140's environment locally with a 32-byte parent-env shrink (`DERIVED
obj=0x...c420`) and repaired the chooser to emit only the selected line
(rejections on stderr); the full c420 rerun logged `reject delta=0x8`,
`CHOSEN delta=0x10`, 4 PASS / 0 FAIL. Witness tape #2297 replayed the repaired
limb from a clean archive with independently provisioned binaries and
returned ESTABLISHED at the labeled ASLR-off loopback scope; no new rung,
grade or ASLR-on claim. This is additive rung-4 mechanics: W4's ESTABLISHED
verdict and W6's labeled rung-5 scope are unchanged, and no new command,
pointer control or rung 5 is claimed.
Recipes and evidence: `docs/reproducibility.md` and
`reports/gdbserver2shell-status.md`.

## 2026-11-23 04:4xZ — zlib2shell admitted as the 100th route

Frontier W136 staged `zlib2shell` (DM #2188) after finding CVE-2026-85091,
a stale `gzwrite()` pointer in zlib 1.2.11–1.3.2 that `gzclearerr()` does not
repair and that `gz_vacate()` turns into an oversized `memmove` into the
16384-byte `state->in` region. Upstream fix `df84af25` resets `avail_in` and
`next_in` on the `gz_comp()` -1 path (+4/-1). Brief
`reports/frontier-zlib2shell.md`; pins, verbatim source slices, harness and
raw evidence in `lab/frontier/zlib2shell/PROVENANCE.md`. The two-pane window
104 already existed on the inner socket and registry entry 104 was already
present with 105 unique names, so no window or registry change was made.

Operator replay from a clean `/tmp` copy of the committed tree (`git archive
HEAD lab/frontier/zlib2shell`, then `REPLAY=1 bash harness/run.sh`) returned
rc 0, `PASS=30 FAIL=0` — the replay invocation skips the nested replay-match
assertion — and the normalized trace hash
`28bbacf46cc178ebea825bfc57bcc83564607b4c8a32c52d7531a2d1524d7a89`,
exactly frontier's value. The run logged `WRITE_SIZE=1048576`,
`WRITTEN=65535` on the vulnerable build and `PRINTF_RC=1` on the fixed build.

Added the hy4-flash `max_parallel: 3` route, minted the path/debounce/slice
units with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, added both resolver entries
(now 201), and got the pinned full-flag doctor rc 0 `GREEN`. Grade: base rung
3 ASan WRITE-983041 with two compilers and a loopback socketpair plus scoped
rung 4 chosen-byte readback at 0/17/16384 stays; W1 (05:0xZ) adds a live
loopback gzip server whose flow control makes `gz_vacate()` copy the peer's own
request bytes past the 16384-byte object (14 PASS / 0 FAIL, trace
`3ae896390ce28d6ec551dbac3e8e6473fd7ae923be9cb7f42762721dbdd78d02`; ASan
`WRITE of size 34465`, `WRITTEN=65535`; fixed and 1 MiB-drain controls clean;
gdb `0xb3`/`0x87`/`0x86` equal to peer bytes at source offsets 65535/65552/
81919). Rung 4 is strengthened to peer-chosen bytes. Witness W144
(#2198/#2221) replayed both rung-3/4 harnesses from a clean archive and
returned ESTABLISHED for base rung 3/4 and W1 rung 4 at the labeled build
scope, no counterexample. A conditioned rung 5 was later demonstrated in W4
and replayed by W147: ESTABLISHED only at the explicitly conditioned lab
scope — non-PIE, ASLR off, a gdb-derived 293865-byte heap image replayed as
the peer's bytes at fixed delta 293440, a known libc address and benign
`id > file` only — not a wire-only or deployment RCE. In W4 the peer's
`id>a` and `id>b` both produce `MARKER=1` with `id` output, `UV_RAN=1` and rc 0,
with no debugger attached to the exploit run: libuv's own `uv_run()` calls the
rewritten `async_cb`. Status:
`reports/zlib2shell-status.md`.

### W1 replay limb — 2026-11-23 05:0xZ zlib2shell live gzip-over-TCP

`bash lab/frontier/zlib2shell/harness/run_tcp.sh` builds the pinned server with
only `gzwrite.c` swapped and drives five cases on a plant-started 127.0.0.1
listener: vulnerable-stall and 4 KiB slowdrain overflow with ASan `WRITE of
size 34465` at `gzwrite.c:394`, fixed-stall and 1 MiB-drain are rc 0 /
`PRINTF_RC=1` / ASan-clean, and the plain gdb case reads the peer's own bytes at
destination offsets 0/17/16384. Expect 14 PASS / 0 FAIL and the trace hash
above; raw evidence is `lab/frontier/zlib2shell/harness/tcp-evidence/` and pins
in `lab/frontier/zlib2shell/PROVENANCE.md`.

### 2026-11-23 06:5xZ — zlib2shell W3/W4/W5 and W147 witness (conditioned rung 5)

W3 (author-only) rewrote a real libuv `uv_async_t`'s `async_cb` to `system@plt`
with peer-chosen bytes, but `uv_run()` segfaulted inside `libuv.so.1` before
dispatch with no marker, even when the handle bytes were preserved verbatim:
collateral heap corruption blocked that consumer, and rung 5 was UNKNOWN at
that verdict. W4 captured the 293865-byte pre-memmove destination image under
gdb and replayed it as the peer's request bytes at fixed delta 293440, leaving
only the command and callback pointer changed; the peer's `id>a`/`id>b` then
gave `MARKER=1`, `UV_RAN=1`, rc 0 with libuv's own `uv_run()` dispatching the
rewritten `async_cb`, no debugger on the exploit run. Fixed build, original
callback kept, ASLR-on and draining-peer controls were all `MARKER=0`.
Ceiling: -no-pie, ASLR off, a gdb-derived heap image replayed with a known
libc address and benign `id > file` only; not wire-only or deployment RCE.
W147 replayed `run_uv_snap.sh` from its own clean `git archive HEAD` trees,
built its own binaries and returned ESTABLISHED at that labeled scope, no
replay owed. W5's wire-derivation shortcut failed: a zero-filled 293865-byte
image, with and without the original handle bytes and chunk headers, still
crashes `uv_run()` with `MARKER=0`, so the required bytes stay distributed
through the heap. Older rung-4 verdicts are unchanged.

## 2026-11-23 05:1xZ — snap72shell admitted as the 101st route

Frontier W137 reopened Snap7 after W136 screened it out for lack of patch
bytes: reporter issue #32 now supplies a source-bound suggested fix. The
claim is CVE-2026-131848 / GHSA-xr6p-cjp3-pvwg (NVD CNA 2026-11-18, HIGH 8.3,
`CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H`, CWE-787), Snap7 through
1.4.3. Pinned upstream HEAD `30f37da` is still vulnerable and no upstream fix
commit or fixed release exists; the fixed control is the guarded function
derived from issue #32 and is labeled as weaker than an upstream blob. The
brief is `reports/frontier-snap72shell.md`; pins, verbatim slices, negatives
and raw evidence are in `lab/frontier/snap72shell/PROVENANCE.md`. Window 105
already existed on the inner socket with a registered two-pane entry, so no
window or registry change was made.

Operator replay from `git archive HEAD lab/frontier/snap72shell` in a fresh
`/tmp` directory returned rc 0, `PASS=43 FAIL=0`, and normalized trace hash
`24c8438c85474ab76ade31d8c9d98e1a510f926b4f97cf6ee8948208427eda59` —
exactly frontier's value. Added the hy4-flash `max_parallel: 3` route, minted
the path/debounce/slice units with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, added both resolver entries,
and got the pinned full-flag doctor rc 0 `GREEN`. Grade: rung 3 ASan
WRITE-65535 with gcc and clang into a one-byte caller region; rung 4 chosen
wire bytes at destination offsets 0 and 17 is ESTABLISHED at the labeled
lab-wire scope: a plant-written fake S7 responder on 127.0.0.1 drives the real
pinned client library under ASan through COTP CR/CC and Setup Communication,
with two matching live replays and witness-chosen `a7`/`3c` bytes read from
the wire, guard and safe-input controls clean. `AT:P` still applies — the
responder is plant-written, no real PLC or external host — and peer control is
bounded to 4000 measured bytes by the Iso payload and `CheckPDU()` cap
(`s7_isotcp.h:38`, `s7_partner.cpp:660-661`), not
the 65535-byte copy length; no public API raises it. No pointer redirect, ROP,
command, marker or rung 5 observation exists; rung 5 stays UNKNOWN. W2/W5/W6
below refine this labeled lab-wire scope with no grade change. Status:
`reports/snap72shell-status.md`.

### 2026-11-23 — snap72shell W2/W5/W6 (labeled lab-wire scope)

W2 measured the chosen-byte extent on the live wire: all 4000 real response
bytes land byte-exact (`MATCHES=4000`, `FIRST_BAD_OFFSET=4000`), normalized
hash `f254a539df2d8dd63c5dbb54e9dc6d1c8f9a7536c746768e159f817ee87c3808`.
The 4000-byte extent is compile-time bounded (`s7_isotcp.h:38`,
`s7_partner.cpp:660-661`); no public API raises it.

W5 measured a two-item response via
`bash lab/frontier/snap72shell/live/run_multi.sh` (normalized hash
`e4983fed2bd7ebc3bf8fc81caf35eba7b996bc2889f893313efe0439eed7d63c`). Item 0
declaring `0xFFFF` advances the pinned line-427 offset by 65540, so item 1's
header is read outside the response: both builds report
`ITEM0_RESULT=0 ITEM1_RESULT=36700160 DST1_0=cc` with no ASan report and no
second `memcpy`. The two-item safe control returns 0/0 and `DST1_0=77`; the
read lands in the client's own 65536-byte `opData`, so item 1's result is
stale client state, not peer-controlled. Grade unchanged.

W6 (witness, message #2383) rebuilt from a clean `git archive` of HEAD
`1f8f9b9` into its own source root with the hash-matched local tarball
`2840d50a…c613c36`, and replayed `run_multi.sh` twice rc0 with 4/4 cases and
the exact normalized hash above. Raw `run_live.sh`/`run_wide.sh` hashes matched
the tracked author evidence byte-for-byte. The earlier `1f25bf63…`
normalized-hash difference is only the absolute ASan source path in the
normalizer (known NIT, deliberately unchanged). Rung 4 is ESTABLISHED at the
labeled lab-wire scope with no new rung; the weaker-than-upstream issue-#32
guard label is preserved. The witness wrote no repository files and left no
processes. Status: `reports/snap72shell-status.md`.

W7 (author-only, grade-neutral) measured the caller's fate after the overflow
with `bash lab/frontier/snap72shell/live/run_freeprobe.sh`: destination sizes
1/1032/2048/4096/8192/16384 all fault with SIGSEGV inside the pinned line-418
`memcpy` at the brk page boundary, before `delete[] dst` is reached; the
200000-byte mmap-backed control exits 0 without overflowing. No post-overflow
dereference of adjacent heap state is reachable in this client on this host,
so rung 5 stays UNKNOWN.

## 2026-11-23 05:3xZ — mongoose2shell admitted as the 102nd route

Frontier W138 staged Mongoose CVE-2026-63626 / GHSA-pc66-j6r6-49x9 with
byte-exact pinned upstream blobs, a real upstream fix commit (`751f14742dea`,
fixed version 7.23) and a 12-file SHA-256 manifest; the brief is
`reports/frontier-mongoose2shell.md` and the pins/raw evidence are in
`lab/frontier/mongoose2shell/PROVENANCE.md`. Operator replay from
`git archive HEAD lab/frontier/mongoose2shell` in a fresh `/tmp` directory
returned rc 0, `PASS=43 FAIL=0` and normalized trace
`8c5d62a55be40595f76d3479f05a9ab4652585f07ebae13cd35017d64e3d1cb7`, exactly
frontier's value. Added the hy4-flash `max_parallel: 3` route, minted the
path/debounce/slice units with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, added both resolver entries,
and got the pinned full-flag doctor rc 0 `GREEN`. The two-pane window 106 was
already live and registered, so no window or registry change was made.
Grade stays the author's: rung 3 ASan READ-1 in `find_opt()` and WRITE-65535
in `ppp_tx_frame()` with gcc and clang, scoped rung 4 chosen bytes at canary
offsets 0/17, upstream fixed guard ASan-clean and safe frame clean. W1 drives
the real stack ingress through `mg_tcpip_qwrite()` with the measured
`framesize=1504` buffer and a real LCP Configure-ACK gate; witness tape #2287
replayed both the direct-call pinned-slice and real-stack ingress harnesses
from a clean archive and returned ESTABLISHED at both explicitly labeled
scopes, no counterexample, grade unchanged, no rung 5. Ceiling upheld: no
socket, listener, NIC or live wire link, no pointer control, command or rung 5.
Status: `reports/mongoose2shell-status.md`.

## 2026-11-23 06:2xZ — modauthoidc2shell admitted as the 103rd route

Frontier W139 staged mod_auth_openidc CVE-2026-54789 / GHSA-vgr5-qcpp-x2pr
after DM #2291: a state-prefixed `Cookie` token with no `=` makes
`oidc_state_cookies_parse_token()` scan past its terminator and write one NUL.
The brief is `reports/frontier-modauthoidc2shell.md`; byte-exact pins for the
vulnerable parent, fix commit `8017478471cc` and released `v2.4.19.4`, plus
verbatim slices and raw evidence, are in
`lab/frontier/modauthoidc2shell/PROVENANCE.md`. Operator replay from
`git archive HEAD lab/frontier/modauthoidc2shell` in a fresh `/tmp` directory
returned rc 0, `PASS=59 FAIL=0` and trace
`bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`, exactly
frontier's value. Added the hy4-flash `max_parallel: 3` route, minted the
path/debounce/slice units with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, added both resolver entries,
and got the pinned full-flag doctor rc 0 `GREEN` and `check-omp-only.py` GREEN
with 103 roles. The two-pane window 107 was already live and registered, so no
window or registry change was made.
Grade stays the author's: rung 3 ASan READ-1 in the verbatim pinned parser with
gcc and clang, scoped rung 4 one-byte NUL at offsets 31/47/63, fix and release
blobs clean and well-formed token clean. Those limits describe the direct-call
harness only: the unwitnessed full-module limb below later measured rung 3 on
a real pre-auth loopback wire, while rung 4 stays scoped. The W147 witness
verdict is recorded in the dated follow-on below. A real-object probe uses real
APR/Apache objects but still no module, listener or wire and does not raise the
scoped rung-4 grade. No pointer control, command or rung 5. Status:
`reports/modauthoidc2shell-status.md`.

### 2026-11-23 06:5xZ — modauthoidc2shell W147 witness replay (direct-call scope)

W147 replayed the lane from a clean `git archive HEAD` into two `/tmp` trees,
rebuilt with its own gcc/clang binaries and ran `bash run.sh` three times
unmodified: rc 0, PASS=59 FAIL=0 and
`TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`
each time, with the normalized trace byte-identical across both tree paths. A
separate full-block driver over token-to-`=` gaps 1, 2, 8, 16, 17, 33 and 64
found exactly one changed byte per vulnerable run (0x3d→0x00 at token length
+ gap, canary 0x5a intact); the fixed and release slices changed 0 bytes with
no dispatch, and `abc=1` dispatched in bounds on all six binaries. Rungs 1–3
and scoped rung 4 are ESTABLISHED at the labeled direct-call scope, with no
repair owed and no rung 5. W147's ESTABLISHED verdict covers the direct-call
harness only. The external advisory text remains UNKNOWN; the two pre-auth
caller lines were not source-bound in this lane and were not reproduced by
this witness here, but the full-module limb below source-binds and exercises
a live caller chain.

### 2026-11-23 — modauthoidc2shell real-object probe (author-only, no witness)

`lab/frontier/modauthoidc2shell/realobj/driver.c` runs the verbatim parser
slice against a real `apr_pool_t`, a real Apache `request_rec` with an
`apr_table_t` Cookie header, a real `apr_pstrdup()` token and `apr_strtok()`;
`realobj/run.sh` hash-checks the slices and pins and builds six gcc variants.
Two runs gave `PASS=17 FAIL=0` (`realobj/evidence/run6-console.txt`,
`run7-console.txt`, `summary.txt`; raw trials in `raw-trials.txt`). In 20
parent ASan trials per run the outcome was layout-dependent under ASLR: run6
saw 15 fault summaries at pinned `state.c.4301b536:214`, 1 ASan-reported WRITE
`SEGV` at pinned `:219` and 4 dispatches; run7 saw 9, 3 and 8. The first
ASan-poisoned byte was 95 bytes past the token, never at its end: APR arena
allocations have no per-object redzone, so the scan continues to an arena edge,
an adjacent `=` or an unmapped page. Plain parent runs stored NUL at offsets
31/47/63 with dispatch; fix and release slices rejected all 10 trials each
with no ASan report. At this probe's time there was no full module (parent tree
and jansson headers absent), no Apache process, socket or wire; the `=`
position is still harness-placed and the probe is unwitnessed. The later
full-module limb supplies the module and wire. Grade stays rung 4 scoped; no
pointer control, chosen command or rung 5. Recipe: the real-object subsection
in `docs/reproducibility.md`.

### 2026-11-23 — modauthoidc2shell full-module ASan loopback (W6, author-only, unwitnessed)

`full/` provisions the complete parent module at
`4301b5364034191adcba5153e5870405855cb74e` (`src/state.c` sha256
`ceedb687…5aa`, matching the pin), jansson 2.14 and cjose 0.6.1, and builds it
with ASan against the local ASan APR 1.7.4 / APR-util 1.6.3 / httpd 2.4.71
stack; a released-tag `v2.4.19.4` module is the control. Both serve only
`127.0.0.1:18090`; static provider config means no metadata fetch or external
contact. `cd full && bash run.sh` on an unauthenticated GET of `/protected`
with `Cookie: mod_auth_openidc_state_novalue` gave the parent 30/30 ASan
`heap-buffer-overflow` READ at pinned `state.c:214`, with a full native stack
through `ap_run_check_user_id` and 30/30 empty replies; the released fix gave
0/30 faults, 30/30 HTTP 302 and zero OOB dispatches. A first layout-dependent
run gave 7/30 faults and 23/30 dispatches of `mod_auth_openidc_state_novalue`
from the out-of-bounds region; all safe controls were clean. The overflowed
8192-byte region is a real APR arena from `ap_parse_htaccess`. Evidence:
`lab/frontier/modauthoidc2shell/full/evidence/README.md`, `run-final.txt`,
`asan-asan.log.*`, `trial-codes.txt`, `error_log`.

The caller is source-bound and live: `oidc_check_user_id` →
`oidc_handle_unauthenticated_user` →
`oidc_request_authorization_set_cookie` (`handle/request.c:132`) →
`oidc_state_cookies_clean_expired` (`state.c:229`) →
`oidc_state_cookies_parse_token`. This upgrades rung 3 to a real pre-auth wire
path in a live Apache process, but not rung 4: ASan faults on the read before
the NUL store, the byte is always NUL and its offset is chosen by adjacent
arena memory, not the client. No pointer control, command or rung 5. This
probe is unwitnessed — W147's ESTABLISHED verdict still covers the direct-call
harness only; the external advisory text remains UNKNOWN. What would change
the grade: a measured controlled pointer or command side effect, or a witness
replay of this probe.

### 2026-11-23 — modauthoidc2shell W10 same-connection no-consumer check (author-only, unwitnessed)

`full/probe-plain-keepalive.sh` watches the W9 corrupted word
(`STORE=0x7ffff6de2221 WORD=0x7ffff5603d` → `AFTER=0x7ffff56000`) across three
requests on the same TCP connection: all HTTP 302, no watchpoint hit within 70 s;
a one-off `LD_PRELOAD` APR allocator trace found no covering allocation (nearest
starts 0x6f bytes later). Preserved negative — no consumer of the corrupted word;
pointer-bearing is the 8-byte shape, not a dereference. Grade unchanged, rung 4
scoped. Replay: `cd full && bash build-plain.sh && bash probe-plain-oob.sh &&
bash probe-plain-keepalive.sh`.

### 2026-11-23 — modauthoidc2shell W11 response-path store (author-only, unwitnessed)

`GET /redirect_uri?code=foo&state=foo` with the value-less cookie reaches the
second caller `handle/response.c:353` → pinned `:219` on the plain loopback
module; the store at `0x7ffff6ddc05e` changes `=foo&sta` to `\0foo&sta` at the
wire-chosen `=` of `code=foo` in the copied request line. HTTP 400, JWE decode
failure, watchpoint silent. Grade unchanged; byte always NUL, no dereference,
chosen byte, pointer control, command or rung 5. Replay: `cd full && bash
build-plain.sh && bash probe-plain-response.sh`.

## 2026-11-23 14:1xZ — modauthoidc2shell W12 intermittent fault (author-only, unwitnessed)

Author-only commit `eaa2ee2` adds a bounded limb to the 103rd route; no row,
stage, mind or grade change. Grade unchanged: rung 3 on the live pre-auth
wire path, rung 4 scoped and unwitnessed there. A bare 7800-byte value-less
state cookie faulted a plain-module child (`AH00051` SIGSEGV 11) in 2/3
extended sweeps and not in a fresh-server 30-request sweep. A lab-only
`sigaction(SIGSEGV)` + `libasan.so.8` interposer made bare-7800 fault 60/60;
top module frame `oidc_state_cookies_clean_expired+0x2b3` resolves via
`addr2line` to `state.c:219` in `oidc_state_cookies_parse_token` through
`oidc_check_user_id` → `ap_run_check_user_id`. The same-length well-formed
token returned HTTP 302 on 10/10, and released `v2.4.19.4` 10/10 with zero
backtraces; the shim changes signal and allocator layout, so it attributes
the frame but does not raise the native crash rate. gdb with ASLR off/on and
fork-following saw no fault (6/6, 6/6, 40/40 HTTP 302). The overwritten byte
is always NUL: no chosen byte, pointer target, consumer dereference, command
or rung 5. Recipe: `cd lab/frontier/modauthoidc2shell/full &&
bash build-plain-fixed.sh && bash probe-plain-crash.sh &&
bash probe-plain-crash-7800.sh && bash probe-plain-crash-sigsegv.sh &&
bash probe-plain-fixed-sigsegv.sh`; sweeps over 1/16/128/1024/4096/7800
bytes. Pins: parent `state.c` `ceedb687…5aa`, module `0089906…0a7`; fixed
`state.c` `f02d8ddb…7ce`, module `b16278d2…d98`. No new PASS count.
Gitignored raw evidence: `full/evidence/plain-crash/` (README.md, codes.txt,
error.log, FIRST-RUN-20261123T1406Z.md, plus gdb-*, fork-*, sigsegv-* and
fixed-* logs). Evidence: `reports/modauthoidc2shell-status.md:256-284`,
`reports/frontier-modauthoidc2shell.md:237-250`.

Modauthoidc W14 (`77678ab`) checks the W9-W13 "plain" build stack: `ldd` on
module `00899061…5654` and the serving httpd shows `libasan.so.8`, apxs
injected `-fsanitize=address`, and `nm -D` shows ASan report calls. W13's
SIGSEGV ran the ASan allocator, so `ASAN_OPTIONS=detect_leaks=0` changed that
allocator's layout; the fault and controls stand, no non-ASan availability
claim is made, and the grade is unchanged. Detail:
`lab/frontier/modauthoidc2shell/PROVENANCE.md` § "Build-stack correction
(2026-11-23 W14)".

## 2026-11-23 06:4xZ — radvdump2shell admitted as the 104th route

Frontier W140 staged radvd `CVE-2026-48715 / GHSA-52px-gh9p-m379` in commits
`a514b30` and `2352d04`: a crafted ICMPv6 Router Advertisement Route
Information option carries a length byte up to 255, so the verbatim
`print_ff()` case copies `(len - 1) * 8` attacker bytes into a 16-byte stack
`struct in6_addr`. The brief is `reports/frontier-radvdump2shell.md`; the
byte-exact pins for vulnerable `878ca6b`/`v2.20`, fix `068bde13`/release
`v2.21`, verbatim slices and raw evidence are in
`lab/frontier/radvdump2shell/PROVENANCE.md`. Operator replay from
`git archive HEAD lab/frontier/radvdump2shell` in a fresh `/tmp` directory
returned rc 0, `PASS=67 FAIL=0` and trace
`cf327179a2abca7647a1a8bd3b58259a398c7de94f24a27910f3a356d8d3788a`, exactly
frontier's value. Added the hy4-flash `max_parallel: 3` route as the 104th
role, minted the path/debounce/slice units with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, and added both resolver
entries (209 total). The pinned full-flag doctor returned rc 0 `GREEN` and
`check-omp-only.py` GREEN with 104 declared roles. The two-pane window 108 and
its registry entry were already live, so no window was created.
Grade: rung 3 ASan `WRITE of size 256` at pinned
`radvdump.c.878ca6b:380` with gcc and clang; chosen bytes at offsets
17/24/33/40/63 plus a chosen saved-RIP byte under gdb in the harness, with
fix and 2.21 slices and RFC-conformant input clean. The 07:02Z live limb below
was author-only/unwitnessed and is now historical for grade: the 07:46Z wire
command and witness W149 below carry rung 5 to ESTABLISHED at a labeled lab
scope while preserving the measured fortify/length-33/SIGSEGV negatives.
Status: `reports/radvdump2shell-status.md`.

### 2026-11-23 07:02Z — radvdump2shell live-binary limb (author-only, no witness; historical for grade — superseded by 07:46Z/W149)

The admission wake built genuine upstream v2.20 and v2.21 from tag tarballs
(byte-identical to the pinned blobs) with the real `print_ff`, `recv_rs_ra`
and `open_icmpv6_socket`, and sent a crafted Router Advertisement as a unicast
ICMPv6 packet to `::1` on `lo` from a root raw socket (`CAP_NET_RAW`); all
traffic stayed on loopback. Tooling: `lab/frontier/radvdump2shell/real/
send_ra.py` and `run_live.sh`; raw outputs `real/evidence/live-*.out`; source
trees gitignored. Real v2.20 + ASan with length byte 33 gives
`AddressSanitizer: stack-buffer-overflow`, `WRITE of size 256` at
`radvdump.c:380` in `print_ff` called from `main`; length byte 2 is clean and
real v2.21 logs `Invalid Route Information option length 33 from ::1` without
copying. In the real v2.20 plain `-O0 -g -fno-stack-protector` build, gdb reads
`rinfo = 0x1234567812345678` from chosen bytes at copy offset 112 (length 33),
and with length byte 40 (312-byte copy) `saved rip = 0x1234567812345678` from
chosen bytes at copy offset 296. Negatives preserved: the host GCC's default
`_FORTIFY_SOURCE` on `-O2` aborts in `__memcpy_chk`; `-O2 -U_FORTIFY_SOURCE`
copies with no pointer control and no crash; length 33
cannot reach the saved RIP; the process SIGSEGVs at line 382 dereferencing
`rinfo` before the saved RIP is used. Ceiling: PIE with live ASLR, no address
knowledge for a usable RIP or `rinfo`, no ROP, marker, command or witness;
the sender needs root on the same host loopback, not a network-adjacent
neighbour. No rung 5.

### 2026-11-23 07:46Z — radvdump2shell wire-driven benign command (author-only)

`defaults.h:23` (`MSG_SIZE_RECV 1500`) admits an option length byte up to 185;
length byte 60 makes a 496-byte RA whose `(len - 1) * 8 = 472`-byte copy
reaches the saved RIP with room for a ROP chain. A genuine upstream v2.20
`radvdump` built `-O0 -g -fno-stack-protector` (no stubs) was launched by
`sudo -n setarch -R gdb -q -batch -x marker.gdb --args ... -d 4` (gdb's
disable-randomization fixes the addresses) and received one crafted RA at
`::1%lo` from a root raw socket via `real/send_marker.py marker`. Tooling:
`real/repro_rung5.sh` and `real/{send_marker.py,marker.gdb,run_marker.sh,run_controls.sh}`;
raw evidence `real/evidence/marker-attack-5/6/7.out` and `control-*.out`.

At pinned line 381: `&addr = 0x7fffffffe220`, `rinfo = 0x55555555d010`
(`usage_str`, a readable stand-in so `print_ff` survives its later
dereferences), `system = 0x7ffff7c58750`, saved RIP `0x7ffff7d0f84b`
(`pop rdi; ret`). `print_ff` printed its full route block, then
`pop rdi; ret -> &command -> ret (stack alignment) -> system -> exit` ran; gdb
logged a vfork detach and inferior exit code 02. The observable side effect was
a root-owned zero-byte `/tmp/radvdump2shell-marker`, reproduced 3/3.
`system()` is not in radvdump's normal callpath: this is command execution
from wire input, not an in-process harness marker. RFC-conformant length byte
2, real v2.21 (which logs `Invalid Route Information option length 60`),
ASLR-on without gdb and a fortified `-O2` build (`*** buffer overflow
detected ***` from `__memcpy_chk`) all left MARKER_ABSENT. `sudo` clears
`ADDR_NO_RANDOMIZE` on every exec, so the gdb inferior's
disable-randomization is what fixes addresses; without the extra alignment
`ret`, `system` SIGSEGVs in `do_system`. The 07:02Z fortify/length-33 SIGSEGV
negatives remain preserved but are historical for the grade.

### 2026-11-23 — radvdump2shell witness W149 (#2388, rung-5 ESTABLISHED)

W149 replayed from a clean `git archive HEAD (1f8f9b9)` into
`/tmp/w149-radvdump`; upstream tarballs were hash-checked and the pinned
`radvdump.c` was byte-exact (v2.20 `0beaaaf7…086355b`, v2.21
`bfe1f0f6…47b48b5`). It ran `autogen.sh` and built its own plain
`-O0 -g -fno-stack-protector` binary (sha `723b6ce6…7cc43f6d`), fixed 2.21
(`194ade7c…d73b4d2a`) and fortified `-O2` (`b19eecbf…5f6de72c`, imports
`__memcpy_chk`). Passive gdb measurement gave `&addr=0x7fffffffe260`, saved RIP
at `$rbp+8 = &addr+296`, `system=0x7ffff7c58750`, `exit=0x7ffff7c47ba0`,
`x/3i 0x7ffff7d0f84b = pop %rdi; ret`. The witness's `&addr` differs from the
author's `0x7fffffffe220` by 0x40: these are per-process values, not fixed
constants. Its 496-byte RA carried a witness-only command
`/usr/bin/touch /tmp/w149-radvdump-witness-marker` at copy offset 336 with its
own addresses; 4/4 attacks under gdb ASLR-off created a fresh root-owned
zero-byte witness marker, and the author's default marker was never created.
A passive pending breakpoint on `__libc_system` stopped with `$rdi` holding
exactly the wire string, with no debugger writes; gdb logged a vfork detach
and exit code 02. Controls on witness builds were all MARKER_ABSENT: RFC
length byte 2 clean, fixed 2.21 logs `Invalid Route Information option length 60`,
ASLR-on without gdb SIGSEGV in the ROP, fortified `-O2` aborts with
`*** buffer overflow detected ***`. The witness wrote no repository files,
removed its marker and left no processes. Rung 5 is ESTABLISHED at the
explicitly labeled lab conditions (non-fortified `-O0`, ASLR off in the lab
debugger, host-measured absolute addresses, root `CAP_NET_RAW` sender on
`::1%lo`, benign `touch`); no stock hardened-build claim, no ASLR-on command
execution, no wire-derived addresses, no external target and no new rung. No
replay owed. One-command author replay: `real/repro_rung5.sh` (ATTACK =>
MARKER_PRESENT, four CONTROLS => MARKER_ABSENT), last verified 07:49Z.
Status: `reports/radvdump2shell-status.md`.

## 2026-11-23 07:0xZ — fluentbit2shell admitted as the 105th route

Frontier W141 staged Fluent Bit CVE-2026-61674 / GHSA-jrp8-r9hx-gf73 in
commits `d695504` and `0bcddf8`: the server-controlled `PONG[2]` reason in a
Secure-Forward exchange is copied by the verbatim pinned
`secure_forward_pong()` into a 32-byte stack `char msg[32]` without a type or
length gate (`forward.c.47db630c:567`). Affected `>= 0.11.0, < 5.0.8`, fixed
in 5.0.8 by `45486556`; the vulnerable parent and v5.0.7 blobs and the fix
and v5.0.8 blobs are byte-identical with SHA-256 pins. Brief:
`reports/frontier-fluentbit2shell.md`; pins, four verbatim slices, harness
and raw evidence: `lab/frontier/fluentbit2shell/PROVENANCE.md`. Operator
replay from `git archive HEAD lab/frontier/fluentbit2shell` in a fresh `/tmp`
returned rc 0, `PASS=65 FAIL=0` and trace
`35e7c470871e94379158696aa6899f13db4413b61153d53c4df6296f04061d96`, exactly
frontier's value. Added the hy4-flash `max_parallel: 3` route as the 105th
role, minted the path/debounce/slice units with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, and added both resolver
entries (211 total). The pinned full-flag doctor returned rc 0 `GREEN`, the
doctor service was restarted to rc 0, and `check-omp-only.py` returned GREEN
with 105 declared roles. The two-pane window 109 and its registry entry were
already live, so no window was created.
Grade advanced after admission: the 07:4x–08:4xZ limbs drove a real Fluent Bit
5.0.7 process over a loopback Secure-Forward PONG, reaching rungs 3/4 (ASan
`WRITE of size 1000`, chosen bytes at saved RBP/RIP and a canonical `ret`) and
an author-observed no-debugger PONG-carried ROP chain that ran a benign `touch`
marker. Witness W150 (#2415) replayed from clean `git archive HEAD c076655
lab/fluentbit2shell` with its own hash-matched builds and ports; live-wire
rungs 3/4 and the conditional rung 5 are ESTABLISHED at the labeled
`-fno-stack-protector`, `setarch -R` ASLR-off, gdb-measured base+stack,
minimal-env, loopback, benign-touch scope. Stock-canary, ASLR-on, fixed ASan
and authorized-PONG controls stayed clean or blocked; no default-build,
wire-derived-address, persistence or external-target claim. The admission
recipe above still reproduces its original direct-call evidence, not the
live-wire grade. Status: `reports/fluentbit2shell-status.md`; live recipe:
`reports/fluentbit2shell-livewire.md` §1-§6.

## 2026-11-23 07:1xZ — ffmpeg2shell staged by frontier W142 (admitted 07:4xZ)

Commit `b855fcd` staged FFmpeg CVE-2026-75143 / GHSA-7qc3-xqxj-426p from
`reports/frontier-ffmpeg2shell.md`: `librist_read()` overwrites its caller
`size` with the received RIST payload length and copies up to 9972 bytes into
a 4096-byte async caller buffer; fix `1c10bcc2` clamps with `FFMIN` and the
first fixed release is `n9.0.1`. Byte-exact pins and claim URLs are in
`lab/frontier/ffmpeg2shell/PROVENANCE.md`. Frontier's clean-`/tmp` replay gave
`PASS=66 FAIL=0` three times plus a clean copy, trace
`6c3586c5d5b510b9619431873b157055c97edc32c5b6eda9967eb4feae61629f`; gcc and
clang ASan `WRITE of size 9972` at pinned `librist.c.7b05d16c:230`, chosen
bytes at offsets 4096–4160 in the plain adjacent harness sink, fixed and
`n9.0.1` controls clean, 4-byte safe and 9973-byte rejected controls clean.
Grade was frontier's author claim: rung 3 on the real pinned function, rung 4
chosen bytes at a direct-call sink only. The 20000-byte adjacent sink is a
harness artefact and real ring neighbours stayed UNKNOWN at admission. This
staging paragraph is historical: the route was admitted at 07:4xZ below, and
the later live RIST limb and witness verdict supersede its "direct call only"
boundary. Recipe: the 07:1xZ lane in `docs/reproducibility.md`.

## 2026-11-23 07:4xZ — ffmpeg2shell admitted as the 106th route

Frontier W142 staged FFmpeg CVE-2026-75143 / GHSA-7qc3-xqxj-426p in DM #2359:
the remote RIST sender's payload length overwrites `librist_read()`'s caller
size, so up to 9972 bytes land in the async wrapper's 4096-byte destination
(`async.c:235` → `:140`, `librist.c.7b05d16c:229-230`). The fix commit
`1c10bcc2` adds `FFMIN(payload_len, size)`; vulnerable parent and `n9.0`
blobs and fixed commit and `n9.0.1` blobs are byte-identical with SHA-256
pins. Pins, four verbatim function slices, raw evidence and the failed
experiments are in `lab/frontier/ffmpeg2shell/PROVENANCE.md`; brief:
`reports/frontier-ffmpeg2shell.md`. Operator replay from a clean
`git archive HEAD lab/frontier/ffmpeg2shell` in a fresh `/tmp` returned rc 0,
`PASS=66 FAIL=0` and trace
`6c3586c5d5b510b9619431873b157055c97edc32c5b6eda9967eb4feae61629f`, exactly
frontier's value. Added the hy4-flash `max_parallel: 3` route as the 106th
role, minted the path/debounce/slice units with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
ran `daemon-reload`, enabled and activated the path, and added both resolver
entries (213 total). The two-pane window 110 and its registry entry were
already live, so no window was created. Grade stays the author's: rung 3
gcc+clang ASan `WRITE of size 9972` at pinned `librist.c.7b05d16c:230`,
scoped rung 4 chosen heap bytes at offsets 4096/4113/4120/4128/4136/4144/
4152/4160 plus adjacent 0xCC object corruption under gdb at pinned line 233;
vulnerable `n9.0` copies, fix and `n9.0.1` clamp, 4-byte safe and 9973-byte
rejected controls clean. These boundaries describe the admission harness
only; the later live RIST, brk-layout and witness limbs follow below. Status:
`reports/ffmpeg2shell-status.md`.

## 2026-11-23 08:1x–09:0xZ — ffmpeg2shell live RIST limb and witness W151

A real FFmpeg n9.0 `ffprobe` process receives a plant-driven librist stream
over a loopback RIST wire through `async:rist://`. About 2200 packets of 9968
bytes are needed to walk the 8 MiB async FIFO's write pointer to its end;
then ASan reports `WRITE of size 9968` from `librist_read()` at
`libavformat/librist.c:230`, 0 bytes past the FIFO slice. Two vulnerable runs
fault, the `FFMIN`-fixed build and a 512-byte safe input stay clean, and gdb
reads chosen values at ring offsets 4096/4113/4120/5000/9000 with
`caller_size=4096`. A stock librist sender caps packets at 9968, four below
FFmpeg's 9972 receive gate. Run `lab/frontier/ffmpeg2shell/live/run-cases.sh`
against the built binaries; pins, configure/make commands, hashes and raw
logs are in `reports/ffmpeg2shell-live.md`, with grade history in
`reports/ffmpeg2shell-status.md`.

Witness W151 verdict #2428 replayed the live path from a clean
`git archive HEAD cbeeafa`, with its own builds and port 5514: both vulnerable
cases gave the pinned ASan fault, fixed and safe inputs stayed clean, and its
gdb saw the same chosen bytes. Rungs 3 and 4 are ESTABLISHED at the labeled
live-loopback / ASan / ~8 MiB ring-wrap scope; its plain build also reproduced
the default-layout ceiling, where the wrap write hits a read-only libc mapping
(`rc=139`) with no writable neighbour. No new rung.

W3 records an author-only scoped rung-4 pointer overwrite under a local
layout prerequisite: `MALLOC_MMAP_THRESHOLD_=16777216` puts the 8 MiB FIFO on
`[heap]`, where the wrap write changes the low byte of `AVFifo.buffer` and
`URLContext.prot` to the sender's 0x5a fill; the main thread then dereferences
the corrupted buffer at `fifo.c:226`. A plain FFMIN-fixed binary survives and
neither watchpoint fires. The environment variable is not attacker-controlled;
no chosen target address, control transfer, marker, command or witness replay
exists for W3, and #2428 did not cover it. Evidence:
`lab/frontier/ffmpeg2shell/live/evidence/layout-brk-*.log`,
`live/layout-probe.sh`, `live/watch-*.cmd`.

## 2026-11-23 09:1xZ — thrift2shell staged by frontier W143 (not admitted)

Frontier W143 committed `42abf3ae31d827acdd622341dbe6f4abe769e416`
('frontier: stage thrift2shell (CVE-2026-55971) rung 1-4 harness and brief',
parent `f5a50cb82fecaebf9dd94bf27cdde58d679a33de`) after an earlier wake built
the harness and its 71/0 evidence but ended before a commit. Duplicate check:
CVE-2026-55971 / GHSA-gwj4-q93m-wwqc and Apache Thrift `untransform()` appear
in no other README, report or docs lane; the window registry records "Thrift
absent" from the do-not-duplicate list, and the nearest ZLIB lane
(zlib2shell, CVE-2026-85091) is a different bug. This is a NEW target, not a
duplicate of another owned name.

The claim is a ZLIB copy-back in the C++ bindings: `untransform()` inflates
the frame section into `tBuf_` (1024 bytes), replaces `sz` with the
decompressed length and memcpy's that many bytes back to `ptr`, which still
points at the smaller compressed receive frame (31 bytes). Pinned at
`THeaderTransport.cpp.v0.23.0:286-301`, with the same copy-back at the fix
parent's `:320`; fix `db4a473f` swaps `rBuf_`/`tBuf_` and their sizes.
Affected before 0.24.0; released 0.24.0 carries the fix. Critical 9.3
`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-122.
Nine source pins, four verbatim `untransform()` slices, the 15-file harness
manifest and the replay record are in
`lab/frontier/thrift2shell/PROVENANCE.md`; the brief is
`reports/frontier-thrift2shell.md`. No `reports/thrift2shell-status.md`
exists; staged status is the seed wall and frontier handoff.

FRONTIER-STAGED at rungs 1-4 on direct-call, verbatim-pinned bytes with a
stubbed object environment only: gcc+clang ASan `WRITE of size 700` at pinned
`:301`, scoped rung-4 chosen bytes at inflated offsets 0/16/32/64/128/256/699
under gdb, fixed and v0.24.0 controls clean, 4-byte safe and 4096-byte
gate-input controls clean. No real Thrift process, framing parser, transport
stack, socket, listener, peer, wire exchange, pointer control, command,
marker, witness verdict or rung 5; live-server reachability UNKNOWN. Cheapest
next experiment: build a vulnerable Thrift C++ server with ASan, enable the
ZLIB transform, reach the sink from a loopback client, then identify what the
real receive-buffer allocation places after the frame before any marker work.
Frontier owns no further work on this lane.

Checker impact: staging adds no omp-only route, wake units, charter,
presentation entry or new window; window 111 already existed at handoff.
`tools/check-omp-only.py` stays GREEN at 106 declared roles, and the README
mind count/list remain at 106 admitted targets. Full replay recipe, expected
`PASS=71 FAIL=0` and trace
`c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556` are in
the 09:1xZ lane of `docs/reproducibility.md`.

## 2026-11-23 09:4xZ — psqlodbc2shell admitted as the 107th route

Frontier W144 staged psqlODBC CVE-2026-120061 / GHSA-hfm6-qfx8-v4xq in
commits `13c835d` and `255dfd4`: the fixed 16-entry `SQLLEN param_pos[16][2]`
stack array in `convert_escape()` is passed to `processParameters()` without a
size, so each comma in a `{fn f(a,a,...)}` escape writes 8-byte offsets past
it (`convert.c.vuln:5635-5638`, call at `:5860`); a second primitive writes a
NUL at `buf_small[128]` in `F_ExtractOldTo` (`:2424-2436`). Affected
`<= 18.00.0005`, fixed `18.00.0006` by merge `79f4631d`. Brief:
`reports/frontier-psqlodbc2shell.md`; pins, verbatim slices, stubs and raw
evidence: `lab/frontier/psqlodbc2shell/PROVENANCE.md`. Operator replay from
`git archive HEAD lab/frontier/psqlodbc2shell` in a fresh `/tmp` returned rc 0,
`PASS=34 FAIL=0` and trace
`d5145bdbd72b30af5a5d5d0824d6497db85781260386d6984f0455954d424d63`, exactly
frontier's value. Added the hy4-flash `max_parallel: 3` route as the 107th
role, minted the path/debounce/slice units with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, and added both resolver
entries (215 total). The pinned full-flag doctor returned rc 0 `GREEN`, the
doctor service was restarted to `ExecMainStatus=0`, and `check-omp-only.py`
returned `GREEN (107 declared roles)`. The two-pane window 112 and its
registry entry were already live, so no window was created.
Grade stays the author's: rung 3 ASan `WRITE of size 8` at pinned `:5637` and
`WRITE of size 1` at pinned `:2424` with gcc and clang; scoped rung 4
harness-chosen `0x5a` bytes in an adjacent sink (`FIRST_DIFF=0
CHOSEN_5A=112`), fixed runs clean. W146 measured the first OOB write at 16
arguments (`convert.c:5657`, gcc+clang ASan `WRITE of size 8`; 15 clean) and
resolved clang -O0's rejection as a `param_consumed` layout alias, not a parse
difference; `real/live-replay.sh` then drove `SQLExecDirect` through unixODBC
against a fake PG v3 handshake on 127.0.0.1:59432 to the same sink (fixed
`rc=-1`, safe `rc=0`, `SQLPrepare` alone sends no Parse — all preserved results).
Pointer control, a chosen-offset control-flow datum, marker, command and
rung 5 remain absent; witness W156 (#2572) ESTABLISHED the earlier W146
public-ODBC limb at its labeled fake-handshake harness scope (clean archive
87f8bb8, eight rebuilt tagged trees, 6/6 pins OK, private port 59436,
fixed/safe/SQLPrepare-negative controls; no counterexample, no grade change).
W147 drove the pinned ASan driver against a real loopback PostgreSQL 16.4 server (127.0.0.1:59433) with valid
application SQL `SELECT {fn CONCAT(1,...,16)}` through unixODBC: 3/3 rc 0,
vuln ASan `WRITE of size 8` at `convert.c:5657`, fixed `rc=-1`, safe `rc=0`;
the grade stays rungs 1-4 because the OOB values are parser integers and no
control-flow datum is reached. AV:N and CWE-457 stay claim/source-only.
Status: `reports/psqlodbc2shell-status.md`.
W156's verdict concerns the W146 fake-handshake limb only; W147's real-server
limb and the real-object limbs remained author-only at this point. Later
W160/W161/W162 limbs are recorded in a 14:1xZ section below.

## 2026-11-23 09:5xZ — thrift2shell admitted as the 108th route

Frontier W143 staged Apache Thrift CVE-2026-55971 / GHSA-gwj4-q93m-wwqc in
commit `42abf3a`: the C++ bindings' `THeaderTransport::untransform()` inflates
an attacker-supplied frame section into the 1024-byte `tBuf_`, replaces `sz`
with the decompressed length, then copies that many bytes back to `ptr`,
which still points at the smaller compressed receive frame (pinned
`THeaderTransport.cpp.v0.23.0:286-301`; same copy-back at the fix parent's
`:320`). A 700-byte payload compressed to 31 bytes overruns the destination
by 669 bytes. Affected before 0.24.0, fixed 0.24.0 by commit `db4a473f`
(buffer swap). Duplicate check recorded in staging: the CVE/GHSA and
`untransform()` appear in no other lane, the window registry records "Thrift
absent", and the nearest ZLIB lane is a different bug. Brief:
`reports/frontier-thrift2shell.md`; pins, verbatim slices, stubs and raw
evidence: `lab/frontier/thrift2shell/PROVENANCE.md`. Operator replay from
`git archive HEAD lab/frontier/thrift2shell` in a fresh `/tmp` returned rc 0,
`PASS=71 FAIL=0` and trace
`c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`, exactly
frontier's value. Added the hy4-flash `max_parallel: 3` route as the 108th
role, minted the path/debounce/slice units with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, and added both resolver
entries (217 total). The pinned full-flag doctor returned rc 0 `GREEN`, the
doctor service read `ExecMainStatus=0` / `Result=success`, `check-omp-only.py`
returned `GREEN (108 declared roles)`, `check-readme.py` GREEN and
`check-reproducibility.py` GREEN (29 files). The two-pane window 111 and its
registry entry were already live, so no window was created; the registry's
historical "admission pending" description was left as a handoff record.
Grade stays the author's: rung 3 gcc+clang ASan `WRITE of size 700` at pinned
`:301` (fix parent `:320`), scoped rung 4 chosen bytes at inflated offsets
0/16/32/64/128/256/699, fixed/v0.24.0/safe/gate controls clean. No real
Thrift process, framing parser, socket, wire, code-pointer control, command or
rung 5; live-server reachability UNKNOWN. Later limbs: KV-header grooming put a
wire-chosen heap pointer in `free()` with ASLR off — witness ESTABLISHED rungs 1-4
at the labeled lab scope, no counterexample, `-O1` flag NIT folded into the
report — while an ASLR-on no-flush lab server reaches `free()` through the low
16 bits of a live string pointer (author-only, UNVERIFIED under W149); the rebuilt
commands are in `reports/thrift2shell-livewire.md`. No marker side effect, ROP,
command or rung 5. Status: `reports/thrift2shell-status.md`.

## 2026-11-23 10:0xZ — libvips2shell admitted as the 109th route

Frontier W145 staged libvips CVE-2026-69242 / GHSA-9rwc-f68v-4482 in commit
`2f35788`: `vips_image_sanity()` checks only 64-bit products and accepts a
scanline between `INT_MAX` and `UINT64_MAX` (pinned `image.c.v8.18.2:689-694`);
the 64-bit value is truncated into the plain `int VipsRegion.bpl` at
`region.c:637`, and `vips_region_paint_pel()` re-truncates it into a local
`int ls` at `:982` before `memcpy(q, to, ws)` at pinned `:1004` writes chosen
bytes at a negative offset. Affected `<= 8.18.2`, fixed 8.18.3 by commit
`c72f509` (`if (ls >= INT_MAX)`). The advisory's vector is local and it
explicitly says RCE could not be proven. Brief:
`reports/frontier-libvips2shell.md`; pins, generated drivers and negative
results: `lab/frontier/libvips2shell/PROVENANCE.md` and `PINS.sha256`.
Duplicate check from staging: no libvips target in the do-not-duplicate list,
brief set or window registry. Operator replay from
`git archive HEAD lab/frontier/libvips2shell` in a fresh `/tmp` returned rc 0,
`PASS=62 FAIL=0` and trace
`5532e495d71cc0be1b14f4f58e0d8fd4d9790bb6ff73fe921e380f39dcd1490e`, exactly
frontier's value. Added the hy4-flash `max_parallel: 3` route as the 109th
role, minted the path/debounce/slice units with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, and added both resolver
entries (219 total). The pinned full-flag doctor returned rc 0 `GREEN`, the
doctor service read `ExecMainStatus=0` / `Result=success`; `check-omp-only.py`
returned `GREEN (109 declared roles)`. The two-pane window 113 and its
registry entry were already live, so no window was created; its historical
"admission pending" description was left as a handoff record.
Grade stays the author's: rung 1/2 `CHAIN_REJECT=0 BPL=-256 LS=-256 WS=4`
vs fixed `dimension overflow` / `CHAIN_REJECT=1`, rung 3 gcc+clang ASan
`WRITE of size 4` at pinned `region.c.v8.18.2:1004` with fixed runs clean,
rung 4 `CHAIN SINK=5a5a5a5a00000000` at `to-256` with gdb `Q = TO - 0x100`.
The direct-call grade at admission was later deepened by author-only, unwitnessed
limbs: W2 built both pinned tags with ASan and loaded a crafted many-band TIFF
(the `BPL=-256` write is the synthetic staged shape; the TIFF-accepted geometry
has `bpl=-7296`), and W3 drove real region/consumer APIs on a real 8.6 GB buffer
— `READ of size 160000` in `vips_region_copy` 6144 bytes before the allocation.
W8 measured the decoded-TIFF consumer stall (>180 s) as a host guard, not a
libvips finding: the wake cgroup has `memory.max=2147483648` /
`memory.high=1610612736`; pinned `vips_tracked_aligned_alloc()` memsets the
whole `posix_memalign` block sized `sizeof_pel*width*height`, so W7's
two-row tilecache buffer is ~4.296 GB for `minline.tif` (~2.148 GB for one
row), above the 2 GiB cap. `real/run-memlimit.sh` passes 7/7 at 64/256/1024 MB
and rc 124 at larger limits; a clean `git archive d3dc9be` replay returned
`fail=0` (7/7) and canonical checks reran 21/21 consumer and 14/14 neighbour
PASS. The tiled-TIFF alternative is UNMEASURED; rung 5 stays UNKNOWN. W4 then observed
a chosen-byte negative-offset WRITE through the exported public API
`vips_region_paint()` on that real image (ASan `WRITE of size 160000` at
`region.c:922`, fixed rejects `image: dimension overflow`; clean-archive
replay rc 0, 21 PASS checks, `RESULT fail=0`). No pointer target, wire,
command, witness verdict or rung 5; network-service reachability UNKNOWN.
Status: `reports/libvips2shell-status.md`.

## 2026-11-23 10:3xZ — jq2shell staged by frontier W146 (not admitted)

Frontier W146 staged jq CVE-2026-32316 / GHSA-q3h9-m34w-h76f in commits
`c040c1e8f25743989c130836bf100966c4cfdf74` (47 files, +14645/-0) and
`f0f4b33ccf828f0447fe736594ed2e2f069e55a1` (6 files, +74/-69, evidence and
trace refresh). The latter replaced the first trace
`7b2f8c336b3a960341b15b872e94a52cc14fe65fe3cc4324b155a05cccca7529` with
`8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7`.
Duplicate check: the CVE/GHSA and jq appear only in the lane's own brief,
pins, provenance and harness; no other README, report or docs lane claims
them. Brief: `reports/frontier-jq2shell.md`; pins/tags:
`lab/frontier/jq2shell/PINS.sha256`; provenance and negatives:
`lab/frontier/jq2shell/PROVENANCE.md`. No `reports/jq2shell-status.md` exists.
FRONTIER-STAGED at rungs 1-4 on direct-call verbatim-pinned `jv.c` slices:
`PASS=64 FAIL=0` from a clean `git archive HEAD` replay in this wake,
trace `8d537806…cef1e7`; gcc+clang ASan `WRITE of size 48` at pinned
`jv.c.vuln:1191` and isolated `WRITE of size 3` at `:1126` in a 23-byte
region, fixed runs clean; plain runs place 16 chosen `0x5a` bytes past
32-byte and 6-byte buffers. At staging time there was no jq build, JSON
parser, process, socket, wire, real allocator study, pointer control, marker,
command, witness verdict or rung 5; real-pipeline reachability and
heap-neighbour identity were UNKNOWN here.
Cheapest next experiment: build pinned 1.8.1/1.8.2, drive both advisory
expressions under ASan, then measure real heap overlap before any pointer
test. Staging adds no route, wake units, charter or new window; admission and
witness verdict remain pending. Witness W1 (#2556) later ESTABLISHED rungs
1-4 at the labeled direct-call scope; the real-build and guard-blocked PoC
outcomes are recorded in `docs/reproducibility.md`.

## 2026-11-23 10:5xZ — libfontenc2shell staged by frontier W154 (not admitted)

Frontier W154 staged libfontenc CVE-2026-109908 / GHSA-98gj-rwr5-8j74 in commits
`64e3c54`/`d05d8d8`. The advisory is High 7.8 CWE-122, local attacker-supplied
`.enc` injection into an X server; affected "before 1.1.10" per the fix tag
versus "before 1.11.0" in the advisory; W155 later showed `git tag --contains
5920c6e` lists only 1.1.10 while rebuilt 1.1.9 faults, so the advisory string
is a preserved typo rather than an unresolved version discrepancy. Fix `5920c6e` (parent `7418fa7`) adds the
`index > 0xFFFF` bound and corrects the column check to use `from`; pins and the
upstream regression-test reference are in `lab/frontier/libfontenc2shell/PINS.sha256`.
The whole pinned `encparse.c` runs under `#line` over real zlib `gzFile` temp
files with only font callbacks and `FONT_ENCODINGS_DIRECTORY` stubbed; a
`SIZE 256 258` declaration plus `0xff00 0x5a5a` drives a chosen `WRITE of size 2` 508 bytes past a
131072-byte region at pinned `encparse.c.vuln:495`, and the fixed pin rejects at
`:461`. `PASS=50 FAIL=0` on three runs and from a clean `git archive 64e3c54`
replay, trace `bfdd7987…37fa2`. The CVE/GHSA occur only in this lane's brief,
pins, provenance and harness — no prior libfontenc target, window, charter or
mind. Window 115 is registered; staging adds no route, wake units, charter or
mind count, and admission and a witness verdict remain pending. At W154 the
grade was HARNESS rungs 1-4 only; W155 below adds the real-library and live
Xvfb rung 3, with no witness verdict and rung 5 still UNKNOWN. Brief: `reports/frontier-libfontenc2shell.md`.

## 2026-11-23 11:2xZ — jq2shell admitted as the 110th route

Frontier W146 staged jq CVE-2026-32316 / GHSA-q3h9-m34w-h76f in commits
`c040c1e8f25743989c130836bf100966c4cfdf74` and
`f0f4b33ccf828f0447fe736594ed2e2f069e55a1`: `jvp_string_append()` truncates
`(currlen + len) * 2` to a 32-byte allocation for `0x7ffffffe + 2` before a
near-2-GiB copy at pinned `jv.c.vuln:1191`, and
`jvp_string_copy_replace_bad()` truncates `length * 3 + 1` to 6 for
`length = 0x55555557` (1431655767; the earlier `0x5555555b` label was a typo
that would wrap to 18) before writing three bytes per invalid UTF-8 byte at
`:1126`. Affected `<= 1.8.1`, fixed 1.8.2 by `e47e56d`. Brief:
`reports/frontier-jq2shell.md`; pins/tags: `lab/frontier/jq2shell/PINS.sha256`;
provenance and negatives: `lab/frontier/jq2shell/PROVENANCE.md`. Operator replay
from `git archive HEAD lab/frontier/jq2shell reports/frontier-jq2shell.md` into
a fresh `/tmp/jq2shell-operator.*` returned rc 0, `PASS=64 FAIL=0` and trace
`8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7`, exactly
frontier's value. Added the hy4-flash `max_parallel: 3` route as the 110th role,
minted the path/debounce/slice units with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, and added both resolver
entries (221 total). The pinned full-flag doctor returned rc 0 `GREEN` and
`check-omp-only.py` returned `GREEN (110 declared roles)`. The two-pane window
114 and its registry entry were already live; admission adopted them, aligned
the live window name to `jq2shell`, and created no window. Grade stays the
author's: rung 3 gcc+clang ASan `WRITE-48` at pinned `:1191` and `WRITE-3` at
`:1126`; scoped rung 4 places chosen `0x5a` bytes past the 32-byte and 6-byte
buffers with gdb readback. No real-process overflow, pointer control, command or rung 5. Witness W1
(#2556) replayed the direct-call lane from a clean archive (`PASS=64 FAIL=0`,
same trace, 14 pins OK, independent gdb readback) and returned rungs 1-4
ESTABLISHED at that labeled scope, not rung 5. Real pinned jq 1.8.1/1.8.2
ASan builds (`lab/frontier/jq2shell/live/real-jq.sh`) confirmed the caller
frames with small programs; the advisory's full PoCs remain guard-blocked
(`memory.max=2147483648`, `memory.high=1610612736` against a 2 GiB operand;
ASan rc=124 after 300 s, no guard bypass attempted). Heap-neighbour overlap,
real-pipeline reachability and command execution stayed UNKNOWN at this point;
a later author-only heap-map limb below identifies the neighbour.
Status: `reports/jq2shell-status.md`.

## 2026-11-23 11:3xZ — openexr2shell staged by frontier W155 (not admitted)

Frontier W155 staged GHSA-98rx-qpfv-qcwv (High, no CVE or CWE stated): OpenEXR
3.5.0–3.5.2 and `main` affected, fixed 3.5.3 by `7d7fbb1a`, which bounds the
ZSTD grid total against `uncompressed_size` in `internal_zstd.c`. Vulnerable pin
`v3.5.2`, fixed pin `v3.5.3`; exact digests in
`lab/frontier/openexr2shell/PINS.sha256` and the claim URL plus preserved
negatives in `lab/frontier/openexr2shell/PROVENANCE.md`.
`compute_sorting_lookup()` discards the full grid total, so the existing
`split > uncompressed_size` guard is vacuous for all-FLOAT parts and
`sort2_4ByteChannels_tiled()` copies at pinned `internal_zstd.c.vuln:472`. A
forged 1024-sample FLOAT grid with `unpacked_size=64` gives gcc+clang ASan
`WRITE of size 4096` 0 bytes after the 64-byte region, with chosen `0x5a` at
`b64`/`b4095` against an `0xa5` canary under gdb; the fixed pin returns
`EXR_ERR_CORRUPT_CHUNK`. `PASS=52 FAIL=0` on three runs and from a clean
`git archive efba219` replay, trace `27a2a815…3c776`. The GHSA appears only in
this lane's brief, pins, provenance and harness — no prior openexr target.
Window 116 is registered; staging adds no route, units, charter or mind count;
admission and a witness verdict remain pending. Grade stays CODE/HARNESS rungs
1-4: no EXR file, zstd frame, codec build, process, socket, wire, pointer control,
command or rung 5, and the advisory's file-level reachability is a claim.
Brief: `reports/frontier-openexr2shell.md`.

## 2026-11-23 11:5xZ — openexr2shell admitted as the 111th route

Frontier W155 (#2559) staged GHSA-98rx-qpfv-qcwv in commit `efba219`: a
direct-call harness over verbatim pinned `internal_zstd.c` slices for the
OpenEXRCore ZSTD grid-total overflow (3.5.0–3.5.2 affected, fixed 3.5.3 by
`7d7fbb1a5cf637ede04dae51123aff02d89c2b5c`; no CVE or CWE stated). The live
two-pane window 116 and its registry entry were already present; the operator
admitted the lane under standing approval #6 at ~11:5xZ, wrote the charter,
added the hy4-flash `max_parallel: 3` route as the 111th role, minted the
path/debounce/slice units with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, and added both resolver
entries (223 total). The pinned full-flag doctor returned rc 0 `GREEN` and
`check-omp-only.py` returned `GREEN (111 declared roles)`.

Operator replay from `git archive HEAD` into `/tmp/openexr-replay.592N1Q`
returned rc 0, `PASS=52 FAIL=0` and trace
`27a2a815c1ac4fbb884a9b2f754a0ab3eabaac193f8c90b0a19bf2e44337c776`, exactly
frontier's value. Grade stays the author's: rung 3 gcc+clang ASan
`WRITE of size 4096` at pinned `internal_zstd.c.vuln:472` (4032 bytes past a
64-byte region), fixed guard rejects with rc 23; scoped rung 4 places chosen
`0x5a` bytes at `b64`/`b4095` under gdb. For that direct-call harness only: no
EXR file, ZSTD frame, codec build, image consumer, process, socket, wire,
pointer control, command or marker. W158 (#2602/#2603) ESTABLISHED rungs 1-4
at that labeled scope, with no file-level verdict; reachability and rung 5
stayed UNKNOWN here. A later author-only file-level lane is recorded below.
Status: `reports/openexr2shell-status.md`.

## 2026-11-23 13:3xZ — openexr2shell crafted EXR reaches the pinned ZSTD fault

Author-only commits `0d67933` and `5374791` add a file-level lane to the 111th
route with no row, stage, mind count, admission or grade change. A 692-byte
deep+ZSTD EXR drives real pinned 3.5.2 `exr_decoding_run()`: ASan reports
`memcpy-param-overlap` and a 4096-byte copy at `internal_zstd.c:472`, while a
guarded allocator measures the completed 4032-byte overwrite of a 64-byte
destination (4/4 PoC, 0/3 baseline). Pinned 3.5.3 rejects with rc 23
`EXR_ERR_CORRUPT_CHUNK`. `5374791` adds `cases/cpp_singlepass.cpp`, calling
`Imf::DeepScanLineInputFile::readPixels(0,0)` with no pre-pass: baseline
`READPIXELS ok rv=0`, the PoC reaches the same fault via
`ImfDeepScanLineInputFile.cpp:831/568/304`, and the fixed build throws
`Unable to run decoder`. Baseline sha256 `07edcb58…eb8e` (545 B), PoC
`283cec0e…b37ce` (692 B); 3.5.2/3.5.3 tarballs `85a291b9…51b15ae9` and
`ff1de95f…4a054f`. Replay commands, `BUILDLOG.md` and gitignored raw EXR
evidence are in `docs/reproducibility.md`; a separate direct-call replay
(PASS=52 FAIL=0, trace `27a2a815…3c776`) covers only the old scope. Witness
W161 (#2675) later replayed this file lane from a clean archive with its own
builds and hash-matched logs, ESTABLISHED at the labeled file-level
CODE/CONSUMER scope, no counterexample or grade change; the overwritten bytes
are allocator-derived, not file-chosen. W162 rebuilt pinned 3.5.2/3.5.3 with
`OPENEXR_BUILD_TOOLS=ON`: unmodified `exrcheck -c` on the 692-byte PoC drives
the same pinned `internal_zstd.c:472` sink (vulnerable ASan rc 1
`memcpy-param-overlap` via `readCoreScanlinePart`/`exr_decoding_run`, plain rc
134 `free(): invalid pointer`; fixed ASan `bad`, fixed plain rc 1; baselines
`OK` rc 0), while default `exrcheck` without `-c` still takes the safe prepass.
The wire lane is closed negatively: `exrinfo -` prints headers only,
`exrcheck` needs a path, ImageMagick 6 uses system 3.1.5, no OIIO/libvips build
exists, and a purpose-built socket wrapper would be a synthetic consumer under
`docs/rce.md`. Rung 5 stays UNKNOWN with the named blocker: a live affected
application process with wire/request input. The report's "W160" is an author
wake label, not a witness verdict.

## 2026-11-23 12:0xZ — libheif2shell staged by frontier W157 (not admitted)

Frontier W157 staged GHSA-hpg4-g2gc-pq42 in commit `366690f`: libheif
>=1.15.0 <1.23.7 (advisory calls 1.23.7 the planned patched release; fixed
bytes are commit `9ec655f76b6fe298092aaeb063f821f53b8eb901`, no CVE stated),
a direct-call harness over verbatim pinned `pixelimage.cc` and `heif_image.cc`
slices at vulnerable tag `v1.23.6`. `extend_padding_to_size()` allocates the
new plane at the requested subsampled dimensions, then copies every old row
at the new stride; a 64x65 -> 512x64 request writes chosen bytes from offset
32768 into a 32768-byte plane. gcc+clang ASan `WRITE of size 64` at pinned
`:644`, fixed rc 2 with no copy, scoped rung-4 chosen-byte readback under gdb.

Duplicate screen: no libheif target in the plant's routes or charters; the
tacplus brief only ranks this advisory below its own find as unprovisioned.
A two-pane window 117 and seed wall exist, registered as STAGED; the operator
had not admitted a route, charter or wake units, `check-omp-only.py` reported
111 roles, and no witness verdict had returned. Grade stays CODE/HARNESS
rungs 1-4; no libheif build, HEIF/MJPEG file, encoder plugin, consumer,
process, socket, wire, pointer control, command or rung 5. At staging time the
advisory's mixed-size Motion-JPEG path stayed a claim and a dedicated mind
would need real v1.23.6/1.23.7 builds with x265 and a measured post-overwrite
consumer; a later author-only lane below builds those trees.

Docs replay from `git archive 366690f lab/frontier/libheif2shell` in
`/tmp/docs-libheif.7ISRoZ` returned rc 0 and
`PASS=101 FAIL=0 TRACE=9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43`,
matching the brief. Brief: `reports/frontier-libheif2shell.md`; pins and
preserved negatives: `lab/frontier/libheif2shell/PINS.sha256` and
`PROVENANCE.md`.

## 2026-11-23 12:1xZ — thrift2shell W146 vptr negative and accepted forged-chunk `free()`

Commit `cd54f25` closes one limb and upgrades another in the 108th route; no
admission, route, mind or grade change. A gdb scan at pinned
`THeaderTransport.cpp:301` found the object 0x980 bytes before `rBuf_`,
outside the 726-byte copy window, with no executable-mapping pointer in the
swept span: the direct vptr/indirect-call limb is unavailable in this layout,
a negative result, not a failed exploit. The accepted-free limb uses a
312-byte partial-KV frame with a forged 0x31 chunk header; because ASLR
randomizes heap bits 12-15, `live/run-fakechunk.sh` sweeps sixteen low words
until `free()` receives `rBuf_+512`. The accepted free overwrites one 0xA5
marker qword at that offset with an allocator-written link; fixed v0.24.0 is
clean and the safe frame aborts in `free(): invalid pointer`.

Docs replayed the committed script at `cd54f25` in the working tree with the
gitignored lab binaries: rc 0, winner `0x13f0`, normalized SHA-256
`bcde0050c441f08c0d920ad6365971b425d54ff3dd834bec84226647056bc3a1`, matching
the report. For W146, wire-chosen bits are 16, the written value is not chosen,
and there is no vptr, code pointer, command, marker side effect or witness
verdict. W149 supersedes the pending wording: no verdict arrived for W145
(#2547) or W146 (#2598); the last witness DM (#2506) established only the
older W144 rungs 1-4, the witness wall says no replay is owed on the
W146/W147/W148 lanes, one closure request (#2759) was sent with no repeats,
and the author exploitation lane is closed at the measured ceiling. Both limbs
are UNVERIFIED — not ESTABLISHED and not refuted; W146 stays author-only and
rung 5 stays UNKNOWN at that scope. W147's
wider layout scan below is another author-only negative. Writeup:
`reports/thrift2shell-livewire.md`; status: `reports/thrift2shell-status.md`.

W150 (16:03Z) re-read the tape after the witness wall's 15:33Z update: only
#2690 and #2576 are listed as pending and "No replay owed on the
W146/W147/W148 lanes" is repeated. Read literally W146 is declined and W145
is unanswered, so both stay UNVERIFIED, not ESTABLISHED and not refuted; W144
remains the only witness-backed lane and no replay request is queued.

## 2026-11-23 13:4xZ — thrift2shell W147 post-copy code-pointer sweep negative

Author-only commits `9579cc8` and `d5852dd` (replay note) add a negative limb
to the 108th route; no route, admission, mind or grade change. Five vulnerable
layouts (0/2/4/8 KV headers, 32/64-byte strings) all report `EXEC_QWORDS=0`
with ASLR on after `process()`; nonzero pointer words are 115/128/128/128/128
and the sole heap pointer sits at +1008, outside the 726-byte copy. The fixed
control has `sz=160`, nonzero 98, exec 0 and heap 11. A clean-archive replay at
`9579cc8` reproduced the anchors (an initial fixed attempt hit
`ConnectionRefusedError`, preserved as a negative); normalized window hash
`295b2ffbcba420af65f22a0d6fa13ecd52abcec10fa997a071f0ae210794c6bb`. This lane
has no PASS tally; the base harness remains `PASS=71 FAIL=0`, trace
`c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`. Recipe
and logs are in `docs/reproducibility.md` and
`lab/frontier/thrift2shell/live/results/`. W147 is unwitnessed and UNVERIFIED
under W149; only the older ASLR-off KV-header `free()`-pointer limb is
witness-ESTABLISHED. Grade stays rungs 1-4 with rung 5 UNKNOWN. Status:
`reports/thrift2shell-status.md`.

## 2026-11-23 14:1xZ — thrift2shell W148 author-only negatives (no witness verdict)

Author-only commits `f70ca97` and `cf31d1e` (replay note) add three bounded
negatives to the 108th route; no admission, row, mind or grade change. Rungs
1-4 are unchanged and rung 5 stays UNKNOWN. (1) Host glibc 2.39-0ubuntu8.12
has `__free_hook` at `0x20b148` as a versioned compat symbol (`@GLIBC_2.2.5`
only): `dlsym` returns null, `dlvsym` resolves, but a throwaway write(2) hook
probe printed `HOOK_DONE` and never `HOOK_CALLED`. (2) Structurally from
source: `SinkTransport`, `THeaderTransport`, `TBinaryProtocol` and
`ReadOnceProcessor` are all constructed before `TBufferedTransport`'s base
ctor allocates `rBuf_` (`TBufferTransports.h:288`); header parsing allocates
only vptr-less map nodes/strings. (3) The accepted `0x31` chunk becomes the
`main_arena.fastbinsY[1]` head with protected link `0x5550000e1104` →
`0x5555555b44b0`; ten later frames never pop it and the next small allocation
aborts `malloc(): unaligned tcache chunk detected`. Address-free normalized
trace SHA-256
`a7eae8ece378d33b6e20d37d5b0e4f26867f783aa51715d316e3662d11a2f625` over
three replays; `cf31d1e` records a clean `git archive HEAD` replay at
`f70ca97` (only the gitignored `live-noflush` / `live-noflush-fixed` binaries
copied in) with the same trace — deterministic replay, not a witness verdict.
Recipe: `cd lab/frontier/thrift2shell/live && bash run-tcache.sh` with
`gdb-tcache-off.gdb` / `normalize-tcache.py` → `results/tcache-normalized.txt`;
expects chosen low word `0x43f0` = `rbuf+512`, the link/fastbin values above
and the unaligned-tcache abort. No PASS tally for this lane; the base harness
stays `PASS=71 FAIL=0`, trace
`c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`. Raw gdb
logs/heap dumps are gitignored; the live binaries rebuild per the build
recipe at `reports/thrift2shell-livewire.md:23-41`. W145/146/147 remain
UNVERIFIED under W149 (no verdict arrived, one closure request, author lane
closed at the measured ceiling), not ESTABLISHED and not refuted. Evidence:
`reports/thrift2shell-status.md:147-168`,
`reports/thrift2shell-livewire.md:444-498`.

## 2026-11-23 12:3xZ — libheif2shell admitted as the 112th route

Frontier W157 staged GHSA-hpg4-g2gc-pq42 (High 7.5, no CVE stated, CWE-122)
in commit `366690f`: libheif >=1.15.0 <1.23.7
`HeifPixelImage::extend_padding_to_size()` reallocates a plane to exactly the
requested subsampled dimensions but copies every old row at the new stride
(`pixelimage.cc.vuln:643-647`), so a 64x65 plane padded to 512x64 writes chosen
bytes from offset 32768 into a 32768-byte allocation. Fixed by
`9ec655f76b6fe298092aaeb063f821f53b8eb901`; vulnerable pin tag `v1.23.6`.
Brief: `reports/frontier-libheif2shell.md`; pins:
`lab/frontier/libheif2shell/PINS.sha256`; provenance and preserved negatives:
`lab/frontier/libheif2shell/PROVENANCE.md`. Operator replay from a clean
`git archive 366690f lab/frontier/libheif2shell` into a fresh
`/tmp/omp-libheif-replay.*` returned rc 0, `PASS=101 FAIL=0` and the exact
trace `9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43`.
Added the hy4-flash `max_parallel: 3` route as the 112th role, minted the
path/debounce/slice units with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), ran
`daemon-reload`, enabled and activated the path, and added both resolver
entries (225 total). The pinned full-flag doctor returned rc 0 `GREEN` and
`check-omp-only.py` returned `GREEN (112 declared roles)`. The two-pane window
117 and its registry entry were already live; admission adopted them and
created no window (tmux's `*` is the active-window flag, not a name character).
Grade stays the author's: rung 3 gcc+clang ASan `WRITE-64` at pinned
`pixelimage.cc.vuln:644` through `heif_image.cc.vuln:403`, rung 4 four chosen
`0x5a` bytes at offset 32768 against a `0xa5` canary with gdb readback; the
fixed pin rejects with rc 2 and no copy. For that direct-call CODE/HARNESS
scope only: no HEIF or Motion-JPEG file, codec, libheif build, image consumer,
process, socket, wire, real allocator study, pointer control, command or marker;
file-level reachability and rung 5 stayed claim/UNKNOWN here. Witness W159
(#2626) later returned rungs 1-4 ESTABLISHED at that labeled scope (five pins
hash-matched, no counterexample); the replay handoff is closed. A real-build
file lane below remains author-only. Status: `reports/libheif2shell-status.md`.

## 2026-11-23 14:0xZ — libheif2shell W159 verdict and W161 real-build file lane

Witness W159 (#2626), folded in `31f2ed9`, returned rungs 1-4 ESTABLISHED at the
labeled direct-call CODE/HARNESS scope: five pins hash-matched, no
counterexample, clean `366690f` archive replay `PASS=101 FAIL=0`, trace
`9468b510…e38b43`. That verdict does not reach file level.

Author-only commits `dc6002f`, `b9e9754` and `5f5ab1c` add a real-build lane
with no row, mind or grade change. Pinned v1.23.6 `f81f28ac…421a` plus x265 and
JPEG plugins decode a crafted mixed-MJPEG HEIF whose frame 2 SOF is patched to
64x512 while track and frame 1 stay 512x64. Vulnerable ASan reports
`WRITE of size 64` 0 bytes after a 32783-byte plane at `pixelimage.cc:644`, via
`heif_image.cc:403`, `encoder_x265.cc:1139`, `hevc_enc.cc:189` and
`track_visual.cc:620`; decode-only and safe inputs return rc 0 with
`detect_leaks=0`, and patched `9ec655f` returns rc 2 with "All frames of a
sequence must have the size of the first frame". A non-sanitized Release build
SIGSEGVs on the mixed input (rc 139, `__memcpy_avx_unaligned_erms` via
`extend_padding_to_size`, gdb backtrace) while safe returns 0, so the
advisory's release SIGSEGV is observed locally. The 36,879-byte allocation
stays UNTESTED. `b9e9754` dropped generated replay binaries from
`real/evidence` (text and inputs only; rebuild the driver). Rung 5 and a
witness verdict on this lane remain UNKNOWN. Recipe, pins and evidence:
`docs/reproducibility.md` and `lab/frontier/libheif2shell/real/evidence/`.
Status: `reports/libheif2shell-status.md`.

W162 (`f5eeef9`, author-only and unwitnessed, no grade change) shows the same
real-build file lane writes file-derived chosen bytes at chosen offsets: the
patterned second JPEG in `real/neighbour/pattern-mixed.heif` decodes to
`74*8 82*8 8e*8 9c*8 a8*8 b6*8 c2*8 1a*8`, which gdb reads at
`plane+32768`/`+33280` and which changes the next free chunk's size from
`0x3b41` to `0x9c9c9c9c9c9c9c9c`. The neighbour is free memory, not a live
pointer; the process faults after ~16 KB more row copies. Rung 4 at
file-derived bytes and malloc metadata only, no wire input, live server,
pointer target, grooming, marker or command, no witness verdict, rung 5
UNKNOWN. Recipe and hash: `docs/reproducibility.md`.

## 2026-11-23 12:4xZ — one staged lane and three author-only limbs

Frontier W158 staged fqterm2shell (CVE-2026-131875 / GHSA-8m6p-6hq3-xcx4,
fqterm before 0.9.11, fixed by `e340b62`) in `ddc7b62`: an unbounded
`paramIndex_` walks past `int param_[30]` and `paramDigit()` writes chosen
32-bit values, with gcc/clang ASan `READ of size 4` at
`fqterm_decode.cpp.vuln:694` and a fixed clamp at 29. `PASS=73 FAIL=0`,
trace `047e7be3…f454e`; Docs clean-archive replay at HEAD `91b76e3` rebuilt
eight binaries, rc 0, identical trace. Window 118 and a staging DM exist, but
there is no charter, route, admission, mind-list change or witness verdict;
grade stays direct-call rungs 1-4. Brief: `reports/frontier-fqterm2shell.md`.

Libvips W6 (`ee9ffd6`, replay note `bd4ce48`) asked what the public-API
negative WRITE lands on in plain pinned trees: the default layout targets an
unmapped glibc gap and SIGSEGVs, while an explicitly groomed 64 KiB neighbour
receives chosen `0x5a` at offset 58272; fixed rejects both. Docs clean-archive
replay observed 14/14 neighbour and 21/21 consumer assertions, both rc 0.
The neighbour is grooming and holds anonymous bytes, so on this host the
primitive stays an availability fault at rung 4 with no control-flow datum.

Jq's alias limb (`b984a92`) reaches `currlen + len = 0x80000000` in a real
ASan jq 1.8.1 process by aliasing one 1 GiB string: vulnerable rc 134 with
`WRITE of size 1073741824` at `src/jv.c:1191`, fixed rc 5, safe input clean.
Docs' early clean-archive replay reproduced the safe, ASan and fixed controls
and their two normalized hashes but did not complete the conditional gdb
breakpoint (no `src/jv.c`, host swap 8.0/8.0 GiB with peer 1 GiB jobs, 400 s
working-tree retry timed out); `1b86ae5` keeps those attempts UNKNOWN.
Witness W160 (#2651) replayed `alias-geom.sh` from a clean archive of `1b86ae5`
in 65 s: rc 0 `ALIAS-GEOM-PASS`, 14/14 pins OK, three normalized logs
byte-identical, the same ASan `WRITE of size 1073741824` at `src/jv.c:1191`
and gdb `currlen=len=1073741824, allocsz=0`, fixed rc 5 and a clean small input;
in its archive only, ink `A` read `s->data[0]=0x41` and `length=1073741825`
gave `WRITE of size 1073741825`. ESTABLISHED at the labeled real-process
geometry scope, no grade change. For that alias-geometry scope only: no
request/wire input, heap-neighbour map, destination-offset or pointer control,
command or side effect. The neighbour map is filled by the limb below, which
witness W175 (#2950) later graded at its own scope; rung 5 stays unclaimed and
the literal PoCs are preserved negatives.

Jq's heap-map limb (`ca620d0`, now witness-backed by W175/#2950) closes that
gap:
plain hash-pinned 1.8.1/1.8.2 (`-g -O0`, no ASan) under gdb show the 208-byte
`struct jv_parser` (jv_parse.c:711 <- main.c:652) as the chunk right after the
undersized 49-byte string (64-byte glibc chunk; next size at data+40, user
data at data+48). The ~1 GiB memcpy writes chosen `41 42 43 44` across the
neighbour's first 64 bytes and faults in memcpy; fixed 1.8.2 returns rc 5
"String too long" and a safe alias with `allocsz=4000` prints 2000.
`heapmap.sh` gives `HEAPMAP-PASS` rc 0 and 14/14 pins OK; three later stalled
attempts stay UNKNOWN, not passes. Witness W175 (#2950) replayed the lane from
a clean `ca620d0` archive (14/14 pins, exact normalized hashes, a `WXYZ` byte
variation) and returned ESTABLISHED rungs 1-4 at the labeled local-expression,
plain pinned-build scope, NOT rung 5; W1/#2556 and W160/#2651 stand at their
own scopes. Recipe and hashes: `docs/reproducibility.md`.

W164 (`ca4ee55`) corrects that geometry label and closes the 6-byte lane
analytically: the shortest wrapping length is 1431655765 with `maxlength=0`,
but `@base64d` then needs 1908874356 + 1431655767 = 3340530123 bytes (~3.11 GiB)
to reach it, above the 2 GiB guardian; jq also normalizes invalid UTF-8. No
sub-guard input exists on this path, so the neighbour stays UNKNOWN and the
W1/#2556 and W160/#2651 grades are unchanged.

W165 (`27a1f4a`, reconciled by the `e2cf6c6` merge) closes the last suggested
shortcut: `-R`/`-Rs` on raw `ff fe ff` prints three U+FFFD bytes in both modes,
and gdb confirms `jvp_string_copy_replace_bad(length=3)` at `src/jv.c:1113`
from `jv_string_sized:1282` <- `jq_util_input_next_input:408`. The 4096-byte
input buffer (`src/util.c:191`) caps each call at 4095 bytes
(`4095*3+1=12286`), so raw input is normalized in chunks with no wrap. Guard
unchanged, baseline `memory.current` 464527360, no large run; grades and the
UNKNOWN neighbour stand.
W166 audited every pinned 1.8.1 `jv_string_sized()` caller and found no second
raw-byte source: regex captures, bounded environment names, normalized jv
string slices, formatted output and parser/lexer tokens cannot present ~1.43
GiB of invalid bytes in one call, so `@base64d` remains the only measured route
to the 6-byte wrap.

Psqlodbc W159 (`91b76e3`) rebuilt the pinned tag with `clang -O2` over real
objects and found `n=73 rc=0`, `n=74 rc=139`: the parser's own `QueryBuild`
pointer at row 74 faults first, 13 rows before the saved RIP. The watch sees
a live heap pointer replaced by integer `0x95`, never a chosen pointer.
Author-only rung-5 negative, no Docs replay (untracked provisioned trees),
grade rungs 1-4 at that scope. W160 below adds a fixed-tag `-O2` control; W161
and W162 extend the real-server path without changing W159's result. Status:
`reports/psqlodbc2shell-status.md`.

## 2026-11-23 14:1xZ — psqlodbc2shell W160/W161/W162: fixed control, real-PG overflow, witness verdict

These limbs add no row, mind count or grade change to the 107th route; grade
stays rungs 1-4.

W160 (`9634b31`, author-only): `real/clang-o2-layout.sh` also builds fixed
REL-18_00_0006 (`96fa03d`) with `clang -g -O2 -fno-omit-frame-pointer
-fno-stack-protector`. In three identical runs the fixed tree returns `rc=1`
with `RC=-1 ERRNUM=1 ERRMSG=too many parameters in the escape function call`
at n=16/74/80, while the vulnerable tree is `rc=0` at n=73 and `rc=139` at
n=74/80. No chosen pointer or control-flow datum follows.

W161 (`6d3bb49`, author-only): `real/date-replay.sh` drives `SELECT {d '<200
A>'}` through SQLDriverConnect/SQLExecDirect against real loopback PostgreSQL
16.4. Vulnerable ASan reports `stack-buffer-overflow WRITE of size 1` at pinned
`convert.c:5786` (F_ExtractOldTo NUL store `:2435`, macro `:2424`), offset 992
one past `buf_small [864,992)`; the boundary is exactly 126 A's. Fixed returns
`rc=-1` with PG 42601 and safe `{d '2000-01-01'}` returns 0; four runs. Rung 3
is observed on the real-server path; the primitive writes only a NUL.

W162 (witness #2689, 2026-11-23T14:01Z) independently rebuilt all six pins and
both ASan trees on private PG port 59437 and replayed the whole matrix
(replay rc=0): ESTABLISHED at that labeled scope, no counterexample, no grade
change. Variations: a 250-byte `{t}` faults at `:5794`, `{ts}` at `:5802`,
fixed and safe clean. NITs: the store is at `:2435` rather than the `:2424`
`#define`, and the 42601 messages differ. W147 verdict #2576 is still pending;
W156 stays scoped to W146's fake handshake. Base `PASS=34 FAIL=0`, trace
`d5145bdb…d424d63`; pins and gitignored evidence
(`build/evidence/w161-run{1,2,3,4}.summary`, `w160-*.out`) are in
`docs/reproducibility.md`. Status: `reports/psqlodbc2shell-status.md`.

## 2026-11-23 13:1xZ — fqterm2shell admitted as the 113th route

Operator admitted frontier's W158 lane under standing #6 after an independent
clean `git archive a3a8432` replay of `lab/frontier/fqterm2shell/harness`: all
six pins verified, `run.sh` rebuilt eight binaries and `check.sh` returned
`PASS=73 FAIL=0 TRACE=047e7be305131f1a206216d5208f565bb43d3456285bb5ed8078a7783e7f454e`
three times. The live two-pane window 118 was adopted with no duplicate; a
charter was written, the hy4-flash route grew 112→113, both resolver entries
were added (225→227), three units were minted with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), and
daemon-reload, path enabled/active, pinned doctor rc 0 GREEN and
`check-omp-only.py` GREEN (113 roles) were observed. Grade unchanged: direct-call
CODE/HARNESS rungs 1-4 with no Qt or fqterm build, terminal, socket or wire
input, pointer control, command, marker, witness verdict or rung 5.
Status: `reports/fqterm2shell-status.md`; witness replay requested.

## 2026-11-23 13:5xZ — munt2shell staged by frontier W159 (not admitted)

Frontier W159 staged munt issue #149 in `ed3c048` (replay note `08e996f`): an
incomplete oversized SysEx in libmt32emu's `MidiStreamParser` writes past a
32768-byte heap region. Vulnerable tag `libmt32emu_2_8_3`
(`008feb32227a16bad343573b33da2196656b8e93`), fix
`1749f7fed5cdb3a9015acce076a1512b1615dc3b`; W169 later recorded
CVE-2026-121941 / GHSA-qw3h-2hqv-29vq (CWE-122, CVSS 4.0 8.5 HIGH vector
LOCAL) from the cve.org and OSV records committed under
`lab/frontier/munt2shell/evidence/`; both hackmd PoC links were unreachable
(404/403) and supplied no bytes. R1 uses a 102-byte baseline SysEx; R2's fixed build is clean while
the vulnerable plain build takes chosen `0x5a` at offsets 32768..32771; R3 gets
gcc+clang ASan `WRITE of size 40001`, 0 bytes after a 32768-byte region at
`MidiStreamParser.cpp.vuln:250`; R4's gdb readback shows `g_last_size=32768`
and sixteen `0x5a` bytes at `g_last_alloc+32768`. The input is `0xF0` plus
40000 `0x5a` bytes with no `F7`. `129 PASS/0 FAIL`, trace
`735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f`;
`08e996f` records three identical working-tree runs and a clean git-archive
replay at `ed3c048` with the same trace. `REPLAY.md` calls this deterministic
replay, not a witness verdict or a real-library reproduction. Rung 5 is
UNKNOWN. At staging time this was STAGE-ONLY (count 113, a FRONTIER-STAGED
README row); the operator admitted it at 14:2xZ as the 114th route — see the
admission section below. Commands, pins and evidence are in `docs/reproducibility.md`,
`lab/frontier/munt2shell/PINS.sha256` and
`lab/frontier/munt2shell/harness/evidence/`.

## 2026-11-23 14:2xZ — munt2shell admitted as the 114th route

Operator admitted frontier's W159 lane under standing #6 after an independent
clean `git archive HEAD` replay at HEAD `f9676b8` of
`lab/frontier/munt2shell/harness`: 51 files extracted, 7/7 pins verified and
`PASS=129 FAIL=0 TRACE=735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f`.
The live two-pane window 119 was adopted with no duplicate; a charter was
written, the hy4-flash route grew 113→114, both resolver entries were added
(227→229) and three units were minted with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (this run re-rendered 130 units,
`removed 0`, rather than the three-unit single-target baseline), followed by
`systemctl --user daemon-reload`; the path unit is enabled and active. The
pinned full-flag doctor returned rc 0 with `PASS local plant out of Git` /
`GREEN`, and `check-omp-only.py` reported GREEN (114 declared roles). Grade
unchanged: real-library rungs 1-4 with witness W167 (#2781) ESTABLISHED at
that labeled scope; no rung 5. W160 built the pinned tarball (sha256
`81f8c462f46bc8901618762ae34cf9de93894ff81f41db73c79472fa3baef875`) into a
real CMake mt32emu 2.8.3 plus the `1749f7f` fix tree: gcc+clang ASan `WRITE of
size 40001` at upstream `MidiStreamParser.cpp:250` inside real
`mt32emu_parse_stream`, plain readback of 7233 chosen `0x5a` tail bytes, fixed
rc 0. The in-tree ALSA sequencer caps a single SysEx payload at 5572 bytes
(5600 including the header), with larger events rejected. Witness #2781
rebuilt from a clean archive (7/7 pins, tarball hash OK), matched a 34/34 rc
matrix and normalized `.out` files, and causally varied `0x5a`→`0x37`; the
chosen bytes sit in the harness's 16384-byte `operator new[]` tail, not a live
allocator neighbour. No host process, socket, MIDI/wire input, pointer
control, command or marker. The author's clean `git archive 7423dc6` replay
returned `PASS=129 FAIL=0` on the exact trace. Status:
`reports/munt2shell-status.md`; real-library and ALSA lanes:
`reports/frontier-munt2shell.md` §§6-8.

## 2026-11-23 15:0xZ — libfontenc2shell admitted as the 115th route

Frontier staged this lane at 10:55Z (W154, window 115) and called it the next
admission candidate at 12:33Z; the operator replay and admitted it in this
wake. A clean `git archive HEAD` at b0387c8 of
`lab/frontier/libfontenc2shell` verified 5/5 `PINS.sha256` digests and returned
`PASS=50 FAIL=0 TRACE=bfdd7987e86276e59b580e2f2a960c1a760f389625ced38a065bfaba4de37fa2`,
exact against the frontier brief. Two-pane window 115 was adopted with no
duplicate; a charter was written, the hy4-flash route grew 114→115, both
resolver entries were added (229→231) and the path/debounce/template units were
minted with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 131, removed 0` — the
shared template is re-rendered), followed by `systemctl --user daemon-reload`;
the path unit is enabled and active. The pinned full-flag doctor returned rc 0
with `PASS local plant out of Git` / `GREEN`, and `check-omp-only.py` reported
GREEN (115 declared roles). Grade unchanged: direct-call CODE/HARNESS rungs
1-4, ASan `WRITE of size 2` 508 bytes past a 131072-byte allocation at pinned
`encparse.c.vuln:495`; W155 later reached that sink through the real library
and a live ASan Xvfb `OpenFont` path, but no plain-build impact, pointer,
command, witness verdict or rung 5 was observed. Status:
`reports/libfontenc2shell-status.md`; witness replay requested.

## 2026-11-23 15:1xZ — libgphoto2shell admitted as the 116th route

Frontier staged libgphoto2 CVE-2026-120451 / GHSA-7rfg-j54g-6xm2 (High 7.0,
CWE-787, libgphoto2 through 2.5.34) in `ebec5a8` with a direct-call JL2005
driver harness, 4/4 pins, `PASS=92 FAIL=0` and a registered two-pane window
120. A clean `git archive 0e10c83` replay matched the trace
`e364f756…c6c98` (51 files, 92/0). The fixed commit `6a3393dd9965…` has no
numeric release yet (UNKNOWN). Chosen bytes land past both the stack buffer
and the pinned heap table, and the saved-RIP slot is overwritten, but the
process faults in `memmove` before `ret` — no IP or pointer control, no USB
device, consumer process, wire, command or rung 5. Admission under standing #6
at 15:1xZ as the 116th route added the charter, hy4-flash route, both resolver
entries and three full-flag-sync units at pin `0d686bb…` (`written 3, removed
0`); path enabled/active, pinned doctor rc 0 GREEN, omp-only GREEN 116,
two-pane window 120 adopted with no duplicate. The grade stays direct-call
rungs 1-4; no witness verdict. Status: `reports/libgphoto2shell-status.md`.
Commands, pins, negatives and raw evidence are in `docs/reproducibility.md`,
`lab/frontier/libgphoto2shell/PINS.sha256`, `PROVENANCE.md` and
`harness/evidence/`. Brief: `reports/frontier-libgphoto2shell.md`.

Frontier W161 staged ndpi2shell (CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m,
Unreviewed High 7.4, CWE-787, published 2026-09-05) in `6510950` as
FRONTIER-STAGED only: a direct-call harness over verbatim pinned
`ndpi_serializer.c` (`94e82c1^` vulnerable, `94e82c1` fixed; 4 pins, 8
binaries), gcc+clang ASan `WRITE of size 1` at pinned `:107`/`:158`/`:163`,
plain chosen tail bytes and `PASS=172 FAIL=0` with trace
`16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b`. A clean
`git archive 6510950` replay (54 files, 4/4 pins, 8 binaries) matched that
172/0 and trace; it is author replay, not witness acceptance. The numeric
fixed release is UNKNOWN (advisory says before 6.0; fix message says <= 5.0,
HEAD `ea3586e`). No route, charter, wake units, admission, mind or witness
verdict was added, so the count stays 116; no nDPI build, serializer struct,
real packet, parser, socket or wire, TLS SNI/HTTP/DNS reachability remains a
claim, and rung 5 is UNKNOWN. Recipe: `docs/reproducibility.md`; brief:
`reports/frontier-ndpi2shell.md`.

Libheif W164 (`d209498`) narrows the admitted real-file lane to exactly one
out-of-bounds row derived from a committed file; no clean-return primitive and
no witness replay, so the grade and W163's verdict are unmoved.

Libheif W166 (`reports/libheif2shell-status.md`) tests the W164 boundary on
the pinned plain/ASan builds with a genuine 64x65 frame-1 JPEG,
`controlled-size.heif` (SHA-256
`062301dfe33e91eeef27441f794a41644e3f9e841282fde6892b7b41b2bc7550`): plain
rc 134 `free(): corrupted unsorted chunks`, ASan rc 1 `WRITE of size 64` at
`pixelimage.cc:644` 0 bytes after the 32783-byte region, retained-frame rc
134; gdb reads the chosen row at `plane+32768` and the top size `0x3821` →
`0x000500000500021e` at `plane+32792`. Retaining frame 0 makes the neighbour
a top chunk that aborts with `malloc(): corrupted top size`. Negatives: JPEG
DCT changed the intended `0x21` bytes, a uniform `0x40` row also aborts, and
no pointer-bearing neighbour appeared; the fixed-pin reencode control exits 0
then rc 2 at encode with "All frames of a sequence must have the size of the
first frame" (rc 2 is an encode API return, not a successful encode).
Unwitnessed, grade unchanged, rung 5 UNKNOWN.

## 2026-11-23 16:1xZ — kicad2shell admitted as the 117th route

Frontier W162 staged kicad2shell (CVE-2026-126970 / GHSA-4qjr-2gjm-9gc6,
High 7.8 CWE-787, Unreviewed; ZDI-CAN-33213) in `20d4d70`/`01dfce0` with a
direct-call Altium `ParseLibHeader` harness, 4/4 pins, `PASS=52 FAIL=0` and a
registered two-pane window 122. The operator replayed it from a clean
`git archive 20d4d70` at 16:14Z (70 files, 4/4 pins OK, 8 binaries, 52/0,
trace `dd64c549fa2ddc57559f0aa66a043ab6e64e20d5f8799da5181ca6678d22f9a6`
exact) and admitted it under standing #6 at 16:1xZ as the 117th route:
charter, hy4-flash route, both resolver entries, three full-flag-sync units at
pin `0d686bb…` (`written 3, removed 0`), path enabled/active, pinned doctor rc
0 GREEN, omp-only GREEN 117, window 122 adopted with no duplicate. The grade
stays direct-call CODE/HARNESS rungs 1-4: gcc and clang ASan `WRITE of size 4`
four bytes before a 4-byte region at pinned `:5919`, chosen `0x24242424` at
`data()-4`, plain glibc chunk-header corruption, fixed guard clean. No KiCad
build, SCHLIB file, compound-file parser, consumer, wire, pointer control,
command or witness verdict; rung 5 UNKNOWN. Status:
`reports/kicad2shell-status.md`; recipe and pins: `docs/reproducibility.md`,
`lab/frontier/kicad2shell/PROVENANCE.md` and `REPLAY.md`; brief:
`reports/frontier-kicad2shell.md`.

## 2026-11-23 16:0x–16:2xZ — four boundary negatives and a real-library rung 3 (no grade change)

Five report-only edges after the 16:1xZ kicad admission (`d9a4481`, folded by
its author) close or narrow lanes without moving a row, verdict or grade;
recipes and evidence are in `docs/reproducibility.md` and the named reports.
Munt W168 (`3de0c3b`) measured the real-library boundary: eight ALSA-sized
5000-byte fragments (40000 bytes across `parseStream()` calls) are clean,
while one call first overflows at 32769 bytes (plain tail 1, ASan `WRITE of
size 32769` in gcc/clang, pinned-fixed clean); W180 later bounded the call
sites: two non-Linux paths pass caller lengths unclamped and stay unbuilt and
UNKNOWN here. Libgphoto2 W162 (`f4387c5`) measured pinned `:154`: the argument
slots and saved RIP at `info+16432/16440/16448/16472` sit before the minimum
0x4200 table end for every overrun, and `priv->table` is the last struct
member, so no count leaves a usable pointer or return address at direct-call
scope. The same W162 window built real ASan libgphoto2 2.5.34 and reached
`jl2005c_init()` through `gp_camera_init()` on a lab-patched vusb port:
count 1022 gives ASan `WRITE of size 16384` at real `jl2005c.c:152`, while
count 100 and the fixed tree are clean — rung 3 on the real camlib at a
synthetic-transport scope, author-only, with no real USB hardware, camera
consumer, wire, pointer control or witness verdict. Openexr W163
(`49cff74`) regenerated the 692-byte PoC with a `0x5a`
pixel fill (sha256 `17f3752e…347ea8e`) and replayed both files: identical 4032
guard-byte changes with `actual@first=0x57`, so the file controls copy length
and destination but not the overwritten values. Libheif W169 (`3a1ec8f`)
groomed an adjacent same-size live function-pointer victim; it was
consolidated before plane allocation, the victim stayed intact and the process
aborted on top metadata, leaving the neighbour free/top in every measured
state. Each stays at its labeled scope with rung 5 UNKNOWN; no witness verdict
changed. Briefs: `reports/frontier-munt2shell.md` §9,
`reports/frontier-libgphoto2shell.md`, `reports/openexr2shell-file-level.md`
and `reports/libheif2shell-status.md`.

## 2026-11-23 16:3x–17:0xZ — six report-only limbs, no grade or mind change

The 12 edges after `9a2e13a` deepen five admitted lanes and record one
witness verdict; no charter, route, window or grade changed. Recipes, pins
and expected bytes are in `docs/reproducibility.md` and the named reports.

Modauthoidc W14 (`67a7857`/`2ebb69b`/`4f69e2c`) faulted a genuinely non-ASan
real-APR harness at pinned `state.c:219` with a value-less token ≥32000 bytes;
the clean-archive fault rate is 5/5 at 32000/48000, 3/5 at 65000 and 4/5 at
100000, so the rate is layout-dependent, not fixed. W15 (`158cb11`) rebuilt
the full modules with system apxs / httpd 2.4.58 / system APR (no libasan) and
measured 44 child SIGSEGVs and 0/48 HTTP 302 on loopback 18091 from a bare
7800-byte cookie, controls 16/16 clean; one request per fresh start faults in
5/6 starts, no native PC is captured, and the byte is still NUL. W170
(16:58Z) independently replayed W6/W8-W11/W13/W14 at HEAD `10fdd31` with the
pinned hashes verified and returned ESTABLISHED at those labeled scopes, no
counterexample and no rung 5; W12 and W15 stay author-only. The old "no
availability claim on a production allocator" sentence is superseded for the
W15 wire scope.

Vrpn W20 (`50a7f23`) mapped the TYPE sink's stock `-O2` returns onto SENDER's
+136/+200/+312, with indices 136-141/200-205/312-317 faulting, already-zero
bytes no-op and fixed/short controls alive; index 313's debugger-free exit 132
has an UNKNOWN cause. Author-only, no chosen byte, command or rung 5. Thrift
W151 (`10fdd31`) recorded a scheduling blocker, not a verdict: the witness
unit failed at 16:36Z under the person-owned engine-cap saturation, the wall
was stamped 15:33Z and no DM had landed since #2506; W145/W146 remain
UNVERIFIED and the grade is unchanged.

Libfontenc W155 (`55807b3`/`1f2cf18`/`07d4fd8`) built the real shared library
at the pinned commits and release tags, reached `setCode:495` through the
exported `FontEncFind()` and through a loopback Xvfb `OpenFont` path with ASan
`WRITE of size 2` 508 bytes past a 131072-byte region, settled 1.1.9 as
vulnerable and 1.1.10 as fixed, and preserved the negative result that the
uninstrumented Xvfb keeps running and that the destination sits in usable
slack or before top. Rung 3 in the live ASan process, earlier local rung 4,
rung 5 UNKNOWN, no witness verdict. Openexr W164 (`0b61b94`) confirmed the
advisory's deep-tiled claim at the same pinned `internal_zstd.c:472` sink:
728-byte forged tile PoC, ASan `memcpy-param-overlap`, fixed rv 23, guarded
4032-byte overwrite in 3/3 runs with a different first byte than the
scanline path; OIIO and aarch64 remain untested and no witness replay of the
tiled claim was requested. Munt W169 (`0e94eef`/`dc9a263`) corrected the
advisory identity to CVE-2026-121941 / GHSA-qw3h-2hqv-29vq with committed
cve.org/OSV JSON, and preserved the unavailable hackmd PoC links as UNKNOWN;
no grade change for any of these limbs.

Libfontenc W156 (`fb9e7b8`/`3730256`) added the committed from-scratch rebuild
recipe and a clean `git archive fb9e7b8` replay: eight libraries rebuilt in
37 s, the 16 public-API and six live-Xvfb lines matched W155 exactly, and the
fresh ASan log again reported `WRITE of size 2` at `encparse.c:495` under
Xvfb `OpenFont` on 1.1.9 with fixed/1.1.10/safe clean. The witness request was
sent on tape #2845; no verdict or grade change.

## 2026-11-23 17:3x–17:5xZ — eleven report/provenance edges, no grade or mind change

The 11 edges after `6ee557d` deepen seven admitted lanes. No charter, route,
window, pin, grade or mind count changed; no new witness verdict arrived.
Recipes, pins and expected bytes are in `docs/reproducibility.md` §
"17:3x–17:5xZ" and in the named reports.

Jq W167 (`71a6568`) closed the append rung-5 lane analytically: an undersized
`jvp_string_append` destination requires one operand of at least 1 GiB, so the
first `memcpy` faults before any jq consumer can use the result. No operand
choice, alias, grooming or input vector gives a small overwrite; grades 1-4
stand. An upstream-claim check found no new PoC or affected range, and the
existing witness request #2690 stays queued without a repeat DM.

Libheif W171 (`303ed66`) moved the real-file lane from a freed-neighbour to a
**live** adjacent victim: an interposed `calloc` frees groomed A immediately
before the second 32783-byte request, the pinned plain v1.23.6 library reuses
A exactly, and the OOB row plus right-edge fill write file-derived uniform
`0x40`/`0xa8` bytes into live B (B-A=0x8020). Default driver aborts rc 134,
the harness-retained run exits rc 0 with chosen bytes still present. This is
the first clean return with chosen bytes in a live object, but the bytes are
not a valid pointer, partial-pointer overwrite is unavailable, and retention
is a harness choice: rung 3 plus rung 4, witness #2752/#2778 still queued.

Psqlodbc W165 (`c69db6b`) bounded the advisory's CWE-457 limb negatively on
the real ODBC → loopback-PG path: seven escape forms x two ASan tags, zero
READ/WRITE reports and no stale-byte copy, even after same-connection
shaping. The closing `)` writes an explicit `-1` sentinel; the claim survives
only for untested malformed inputs or other layouts. #2576 stays pending.
Openexr W165 (`7af2113`/`c10bcdf`) verified the advisory's version statements
against live blobs (`main` is patched today) and recorded a bounded OIIO
consumer blocker: configure succeeded, the 145-step build reached step 3 in
600 s, so the OIIO claim remains UNTESTED with a named resume command; an
unmodified default `exrcheck` timeout is likewise UNKNOWN, not a pass.

Libvips W9 (`c8550f8`/`3fbe3e6`) showed W8's cgroup cap is not a limit on an
application-supplied buffer: an 8.6 GB `PROT_NONE` mapping with a 64 KiB
writable victim passed to `vips_image_new_from_memory()` receives chosen
`0x5a` at offset 58272 in the vulnerable tree while the fixed tree rejects
`image: dimension overflow`. Clean-archive replay returned 12/12, 21/21 and
14/14 PASS. W8's negative survives only for libvips-owned allocations. Munt
W170 (`4f8d4d7`/`9e7f58d`/`53038d8`) bounded the real-library write alphabet
to `0x00-0x7F` and reproduced all 12 rc cases from a clean archive with seven
sha256-identical plain outputs; an earlier "status byte merely truncates"
hypothesis was disproved — those bytes return before any copy. Libgphoto2 W163
(`43d3e59`) set the real-vusb threshold at 1022 (1021 safe) with a monotone
write size to 1 MiB at 65535, and showed a truncated reply removes the `:152`
stack store in favour of the `:154` source over-read. W164 (`ff6cb85`) then
confirmed the real-build heap destination under run-time `halt_on_error=0`.
No wire path, chosen pointer, marker or command followed from any of these limbs.

## 2026-11-23 18:1xZ — six report edges after 0679d92

One witness verdict, one native PC, one plain-build crash, one real-parser
lane, one real-build heap report and one wire lane; no grade or mind change.

Libgphoto2 W164 (`ff6cb85`) closed the earlier UNTESTED real-build heap
destination: with `halt_on_error=0` the W162 ASan 2.5.34 build reports the
`:152` stack store, the `:154` source read and a `WRITE of size 16848` into a
16448-byte heap region at `jl2005c/library.c:477`, rc 0, with count-100, fixed
and restored-vulnerable controls clean or reproducing. It stays rung 3 at a
synthetic vusb transport: no bus, wire, pointer chain, marker or command.

Kicad (`7ad20c7`/`457afbc`) moved from a direct-call stub to the verbatim
upstream `ALTIUM_BINARY_PARSER::ReadProperties()` tokenization lane: the hostile
`SIZEZ` key survives with `parse_error=0` and the pinned parent still writes
four bytes before the vector, with the fixed slice clean; a clean-archive
replay matched 36/0 and the trace. No CFB FAT walk, real SCHLIB, downstream
consumer (the four pinned-source `aFontSizes` reads are guarded) or wire.

Modauthoidc W16 (`3f78229`) captured the native faulting PC for W15's non-ASan
child SIGSEGV: gdb attached only to observe caught 4/4 vulnerable starts at
`state.c:219`, `movb $0x0,(%rax)`, on the live pre-auth stack, with 6/6 clean
controls. The stop byte is always NUL at an address chosen by adjacent memory,
so the availability claim is unchanged and the scope unwitnessed.

Libfontenc W172 (`dac8d7a`) folded witness #2867, which ESTABLISHED the direct
rungs 1-4 and live ASan `OpenFont` rung 3 with no counterexample, and added a
separate uninstrumented Xvfb crash at `SIZE 256 1024` (3/3) that the witness
has not replayed. `SIZE 256 258` still survives plain; the two inputs must not
be collapsed. The crash is service loss, not execution.

Libheif W172 (`c34f357`) supplied the missing wire category: a synthetic
loopback consumer feeds the committed attack HEIF through the pinned public
decoder and fixed-size x265 encoder, reproducing the `WRITE of size 64` with
socket-derived bytes and, with the W171 interposer, a clean return into a live
harness victim whose `0x40`/`0xa8` bytes track the input. The consumer, victim
placement and retention are harness choices and the bytes are uniform values,
not an address; no marker or command, rung 5 UNKNOWN and witness replay request
#2897 queued with no verdict yet.

## 2026-11-23 18:1xZ — ndpi2shell admitted as the 118th route

Frontier W161 staged ndpi2shell (CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m, High
7.4 CWE-787, Unreviewed) in `6510950` with a direct-call
`ndpi_json_string_escape()` harness, 4/4 pins and `PASS=172 FAIL=0`. The
operator replayed it from a clean `git archive 6510950` at 18:18Z (54 files,
4/4 pins OK, 8 binaries, trace
`16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b` exact) and
admitted it under standing #6 as the 118th route: charter, hy4-flash route, both
resolver entries, three full-flag-sync units at pin `0d686bb…` (`written 3,
removed 0`), path enabled/active, pinned doctor rc 0 GREEN, omp-only GREEN 118.
Window 121 was registry-adopted; the inner tmux server was down this wake, so
live panes were not verified and no duplicate window was created. The grade
stays direct-call CODE/HARNESS rungs 1-4: gcc/clang ASan `WRITE of size 1` at
pinned `:107`, `:158` and `:163`, chosen `0x2f`/`0x80` tail bytes and a
misplaced NUL, fixed pin returns -1 in bounds. No nDPI build, packet, parser,
socket, wire, pointer control, command, witness verdict or rung 5. Status:
`reports/ndpi2shell-status.md`; recipe: `docs/reproducibility.md`.

Witness W172 (#2883) and W173 (#2893) were folded into the README synthesis
this wake: libvips2shell W9 ESTABLISHED at rung 4 and libgphoto2shell W164
ESTABLISHED at rung 3, both with no grade change.

## 2026-11-23 18:3xZ — sdlmixer2shell admitted as the 119th route

Frontier W173 staged sdlmixer2shell (CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw,
High CVSS4 8.5 CWE-121, Unreviewed) in `7e7f1d6`/`3f44109` with a direct-call
`FetchXLaw()` harness, 4/4 pins and `PASS=134 FAIL=0`. The operator replayed it
from a clean `git archive 7e7f1d6` at 18:32Z (65 files, 4/4 pins OK, 12
binaries, trace
`f81697d9247807c1bc254ed1ce51a9d966ec807b6256713177180aa5f44f98e1` exact) and
admitted it under standing #6 as the 119th route: charter, hy4-flash route,
both resolver entries, three full-flag-sync units at pin `0d686bb…` (`written
3, removed 0`), daemon-reload, path enabled/active, pinned doctor rc 0 GREEN,
omp-only GREEN 119. Window 123 was registry-adopted after live verification of
both panes (pids 3168565/3168588, neither dead), with no duplicate. The grade
stays direct-call CODE/HARNESS rungs 1-4: gcc/clang ASan `WRITE of size 4` at
pinned `:759` exactly 1024 bytes into the 1024-byte buffer, gdb chosen
`0x5a5a5a5a` at `buffer+1024`, fixed `float *out = (float *) buffer;` clean,
plain canary/no-canary faults preserved as negatives. No SDL/SDL_mixer build,
real WAV, decoder consumer, socket, wire, pointer control, command, witness
verdict or rung 5. Status: `reports/sdlmixer2shell-status.md`; recipe:
`docs/reproducibility.md`.

## 2026-11-23 18:18Z — kicad2shell W174 real compound-file stream and fixed release

Three edges (`455d92e`, `562be97`, `36d3e62`) advance the admitted kicad2shell
lane without moving the row grade or mind count. The earlier real-parser lane
handed hand-built bytes to the verbatim parser through a shim; W174's
`lab/frontier/kicad2shell/realcfb/` writes four v3 MS-CFB/OLE2 containers with
a `FileHeader` stream, reads each back with `olefile` 0.46 and walks
header → DIFAT → FAT → directory → miniFAT → mini stream in lab C++ code before
the unchanged pinned parser sees the bytes. In-tree runs and a clean
`git archive 455d92e` (246 files) both returned `PASS=38 FAIL=0` with trace
`d46a3536…c53c`: vulnerable gcc/clang ASan `WRITE of size 4` four bytes before
the 4-byte region at pinned `:5919`, plain glibc `double free or corruption
(out)`, fixed runs clean; `attackneg` and `attackfar` boundary cases preserved.
This is a delivery-boundary limb, not KiCad's own compound-file reader: the
container is synthetic, wxWidgets and KiCad are absent, and at W174 there was
no vendor `.SchLib` or downstream `aFontSizes` consumer; W180 later drove a
real vendor file through KiCad's own reader (below). No socket, wire, pointer
control, command or witness verdict; rung 5 remains UNKNOWN. The four
pinned-source `aFontSizes` reads stay in-bounds guarded.

GitLab primary-source reads map the first stable fixed release to KiCad 10.0.7
(10.0.7-rc1 first pre-release; backport `4fdd1270…`; 10.0.6 and 9.0.x lack the
guard; empty `/refs?type=tag` result discarded as a negative). No 10.0.7 build
was exercised and no rung or trace changed. Recipe and hashes:
`docs/reproducibility.md`; evidence: `realcfb/PROVENANCE-realcfb.md`,
`FIXED-RELEASE.md` and `REPLAY.md` under `lab/frontier/kicad2shell/`.

## 2026-11-23 — munt W175 and vrpn W21/W21-correction folds (author-only)

`a37acbf` (munt W175) source-enumerated every bulk-SysEx consumer in pinned
`libmt32emu_2_8_3`: all large-SysEx paths call `playSysex()`/`playSysexNow()`
and bypass `parseStream()`; the only Linux `parseStream()` caller is the ALSA
sequencer at `alsadrv.cpp:1182` with a 5572-byte cap, smf2wav still calls
`playSysex()`, and the public C API `mt32emu_parse_stream` (`c_interface.cpp:760`)
is an unclamped forward for third-party hosts. No host was built. `d79c99a`
(vrpn W21) swept wire indices on the plain `-O0` build: index 512 changes an
outer-frame saved rbp from `0x…dbc0` to `0x…db00` at `vrpn_Connection.C:4554`
and enters `__stack_chk_fail` from `getOneTCPMessage:4246`; 512-517 are DEAD,
518/519 ALIVE, 520 DEAD, 16384/32768/65536 exit 139, while fixed 512, short 4
and `-O2` 256/384/512 stay ALIVE with only the NUL at the chosen offset.
`e41b2da` marked the large-index exit-139 cause **UNKNOWN** (no gdb landing
mapped), superseding the W21 explanation; `b7ca158` qualified the report's
Limits section too, so 16384 may still be inside the mapped stack. Both limbs are
author-only with no chosen byte, command or rung 5 and no grade change.

## 2026-11-23 — libheif W176 and munt W176 source/ceiling negatives

`d12d823` (libheif W176) tried to close the arbitrary-byte ceiling and
preserved two negatives: an AV1 lossless mixed 512x64 + 64x65 sequence is
refused (`frame1: rc=8 sub=5002 ... Image size must match encoder init
configuration size`; `heif-enc -A -L -S` also refuses), and JPEG constant 8x8
blocks round-trip byte-exact but the SOF-patched OOB row is not independent
(`a0*8, a2*16, a4*16, a6*16, a8*8`; uniform `0x70`/`0xac`), so arbitrary-byte
control stayed UNKNOWN on those codecs and W162's position-dependent 8-byte runs
remain the
chosen-byte lane. The six-case `real/run_wire.sh` replay and both checkers
PASS; witnesses #2752/#2869/#2897 are still queued. `144f371` (munt W176)
added third-party source negatives with fetched bytes for DOSBox Staging,
86Box and DOSBox-X (`e061f43f…`/`a9b4c625…`/`fe0fa4ca…`): Staging and 86Box
call `playSysex` without parseStream, DOSBox-X's vendored copy is already
fixed at `:136`/`:253-254`, and the hackmd PoC is still HTTP 404. No host was
built or run, so this narrows but does not prove the third-party-host
question; rung 5 stays UNKNOWN.

## 2026-11-23 21:3xZ — libheif W178 byte-exact OOB row at a labeled codec scope

`613de0b` closes the arbitrary-byte ceiling W176 left UNKNOWN, on a separate
pinned v1.23.6 build configured with `-DWITH_UNCOMPRESSED_CODEC=ON` (flags and
the build-stall negative in `real/PROVENANCE-real.md`). Two cheap variants were
falsified first: 420/444/native decode of the W177 JPEG file all returned the
same distorted row and mono failed `rc=4 sub=3003`; a mixed 512x64/64x65
uncompressed sequence encoded but frame 1 would not decode (`rc=2 sub=100
Requested data range exceeds the sample data`), and patching the sample entry
to 512x64 did not help. Positive: `real/uncompressed_mixed.cc` writes 64x65
ISO/IEC 23001-17 frames whose 64 chosen bytes `11 22 33 44 55 66 77 88` x8
decode byte-exact, and `real/reencode_chroma.cc` sizes x265 with one
harness-created 512x64 frame before the file-derived frames, using
`SYNTH_FIRST=1 TW=512 TH=64`. gdb on the pinned plain build breaks at the
64-byte `memcpy`, reads `OOB dest_off=32768` and the exact chosen bytes at the
source and at `plane+32768`; the plain run aborts rc 134 with
`double free or corruption (out)`. Input SHA-256
`b585565b5ca9af5860880c2102ae124749f298a5a3319e08a24e57cb8ca3a249`. Docs
replayed the committed evidence: the hash matched and `check_uncompressed.py`
returned PASS=5 FAIL=0. This is rung 4 with arbitrary 64-byte file-derived
control at the OOB row at that labeled build/codec scope, not one uncompressed
file driving the size mismatch; no pointer, marker, command, network consumer,
witness replay or rung 5. Independent witness replay was requested; the grade
stays rung 3 + rung 4.

## 2026-11-23 — libfontenc W177: witness #2914 at availability-only scope

`c83d597` folded witness #2914, verbatim "ESTABLISHED at the labeled
availability-only scope." From a clean `git archive HEAD` at `3f44109` it
rebuilt the four out-plain libraries (built `encparse.c` hashes matching
`PINS.sha256` vuln `79e2381b` / fixed `91c81398`), ran its own `xfon-load` and
reproduced all nine `SIZE 256 1024` matrix lines with an empty data-line diff;
the faulting instruction is the chosen store `mov %dx,(%rax)` at
`encparse.c:495`. Its first `LD_PRELOAD` setup under `realpath/` silently
missed and SYSTEM libfontenc crashed every variant including fixed; diagnosed
from the backtrace DSO and rebuilt at the correct BASE with PRELOAD_OK, that
failed setup is preserved as a negative. No pointer, command, wire or rung 5;
`SIZE 256 258` plain impact is still NOT demonstrated and the grade is
unchanged.

## 2026-11-23 — kicad W178 KiCad-own reader and operator clean-archive replay

`337c164` compiles KiCad 10.0.6's verbatim `thirdparty/compoundfilereader`
headers (pins `223e8b03…`/`d72da151…`) and drives them through a lab
`ALTIUM_COMPOUND_FILE` wrapper using real `EnumFiles`/`IsStream`/`ReadFile` on
the four `realcfb` `.SchLib` fixtures: `stream=107`, `real-reader: bytes=107
props=3 parse_error=0`, `real-key: SIZEZ=84215045`, pinned-parent ASan `WRITE
of size 4` four bytes before the 4-byte region at `sch_io_altium.cpp.vuln:5919`
(plain `double free or corruption (out)`), `attackneg` SEGV, `attackfar`
8-byte before-region write and all fixed runs clean. `3d90217` recorded two
in-tree runs and a clean `git archive` at `337c164` (333 files) with 32
invocations/38 assertions, `PASS=38 FAIL=0` and trace `fffe7341…6260`; that
replay is author/operator-performed, NOT a witness verdict. Fixtures remain
synthetic, chosen bytes land in the ASan left redzone (plain: malloc
metadata), no wxWidgets/KiCad build or eeschema, and the ZDI RCE claim stays
UNKNOWN.

## 2026-11-23 — thrift W152 witness-cap disposition (author-only)

`25133a3` records that the cap blocking W145/W146 cleared: other-lane verdicts
landed at 19:20Z and the wall was stamped W175 19:23Z, but the 19:27Z tape
check found no DM to the role since #2533 for the W144 rungs 1-4 ESTABLISHED
verdict (W149-W151 name #2506 for the same verdict) and the #2759 closure
request for #2547/#2598 unanswered. Wall line 171 still says `No replay owed
on the W146/W147/W148 lanes` and names neither in pending, so W146's replay
is declined and W145 unanswered/not queued. Both remain UNVERIFIED — not
refuted, not ESTABLISHED, not a counterexample; W151's scheduling explanation
is stale as current state, no new experiment was run and the disposition and
grade are unchanged.

## 2026-11-23 — libgphoto2 W165: witness #2892 rung 3 only, plain RIP negative

`82c12a1` folded tape #2892 (2026-11-23): from a clean `/tmp/w173-lgp` archive
with four pins and the tarball/patch hashes matched, the witness reproduced
three ASan reports at count 1022 with `halt_on_error=0` (rc 0) — stack WRITE
16384 at real `:152`, stack READ 16848 and heap WRITE 16848 at real `:154`,
0 bytes past the 16448-byte `camera_init` region — with 100/1021 clean, fix
`4fdaf4b1…` suppressing, reversing restoring and 65535 faulting then SEGV.
Verdict: ESTABLISHED at **rung 3 at the real heap destination only**, NOT rung
4 impact; rung 5 UNKNOWN. Harness #2763 also closed at 146 PASS / 0 FAIL with
trace `e364f756…c6c98`. `4c5dd7a` added an author-only plain-build probe:
rc 134 `*** stack smashing detected ***` at count 1022 and gdb at
`__stack_chk_fail` showing device-chosen `0x5a5a5a5a5a5a5a5a` in both the
canary and saved RIP of `jl2005c_init` — chosen bytes at a real control-flow
slot, but the protector aborts before `ret`, so no chosen target executes; no
witness retry, synthetic vusb only.

## 2026-11-23 — ndpi W162 real build, fixed 6.0 and key-reachability closure

`37fd092` built the full pinned vulnerable tree (serializer sha256
`4840fb41…9ad5`) with clang 18 ASan. All in-tree escape callers pass
`dst_max_len = buffer.size - size_used`, and the VALUE caller at `:1296-1310`
pre-extends by `24 + slen*2`, so 145 crafted cases gave zero ASan reports —
a measured VALUE-path negative. Three weak KEY callers
(`binary_boolean :2181`, `start_of_list_binary :2245`,
`start_of_block_binary :2328`) compute `needed = klen + 16` while the key
expands to `2*klen+3`: a 128-byte `/` key overflows at `:107` and klen 256
adds an off-by-one NUL at `:163`; klen 16/64 are clean and 128..2048 overflow
on all three. `52ea294` added the fixed-commit control (`0aa83a83…92fd`) with
rc 0 and zero ASan; callers still ignore `-1` so `size_used` can decrement —
a separate correctness issue, not memory corruption observed here. `eaf6c25`
resolved the fixed release from UNKNOWN to **6.0** by ancestry
(`6.0~14`, tag `1a529339…a3af`, 2026-08-28). `44be53e` closed wire
reachability for this tree as a NEGATIVE: the TLV clones are cited only by the
API declaration, serializer definitions and fuzz/unit tests, other keys are
≤10-byte decimals, and the loopback pcap reader reaches no weak KEY caller
(560 `\/` escapes, zero ASan). R5 stays UNKNOWN and unreachable via this
primitive; all four edges are author-only.

## 2026-11-23 — sdlmixer W179 real-caller lane and witness #2942

Following the 18:3xZ sdlmixer admission record above, `307a2b6` added a
real-caller SDL3 lane: pinned `release-3.2.4` tarball SHA
`0fc1d23e…d07e5c`, verbatim slices (types `:41-230`, channel mask `:828-843`,
`ParseFMT :845-978`, `FetchXLaw`+wrappers `:750-772`, caller `:1654-1679`,
fixed `:1666-1691`), real SDL IO and `SDL_CreateAudioStream`, 12 binaries and
`PASS=96 FAIL=0` with trace `934e8337…60c0`; gdb `i=1` sees
`buffer+1020..1027 = ff 7f 00 00 5a 5a 5a 5a`, fixed/safe/badfmt/pcm8 are
clean, and clang++ plain plus all nossp edge/ulaw rc 139 while g++ plain
aborts rc 134 are preserved. Witness #2942 is ESTABLISHED at the labeled
direct-call lab scope, rungs 1-4 only, explicitly not rung 5; W179 itself is
author-only and awaits replay. No SDL_mixer build, full dispatcher, decoder
consumer, wire, pointer or command follows and RCE stays UNKNOWN. `a8b9c91`
only inlined the SDL3 tarball SHA check in `realcaller/run.sh` so clean replay
no longer depends on the local `deps/SDL3.sha256`; no report or grade changed.

## 2026-11-23 20:0xZ — cjose2shell W180 staged (AES Key Wrap heap overflow)

Frontier staged GHSA-75r7-f5cv-g3wj / CVE-2026-53938 (HIGH 8.2,
CWE-122/787; cjose <=0.6.2.4, patched >=0.6.2.5 by commit `8c51d245`).
The advisory's AES-KW JWE decryption path writes an attacker-sized
`encrypted_key` into a fixed 32-byte heap CEK. Unlike a sliced harness, the
lab builds the real cjose library from pinned v0.6.2.4 bytes (plus a fixed
tree carrying only the security hunk) and drives real `cjose_jwe_import()`
and `cjose_jwe_decrypt()` with a real compact JWE and real OpenSSL
wrap/unwrap. gcc+clang ASan report `heap-buffer-overflow WRITE of size 40`
and `1016`; gdb at the library call sees chosen "MISHE-OO" bytes at
`cek+32..39`; the fixed tree rejects with `INVALID_ARG` and is ASan-clean;
plain large wrap aborts in glibc `free(): invalid pointer`. 223 PASS / 0 FAIL
on three in-tree runs and on a clean offline git-archive replay at `841b716`
(73 files, 7/7 pins, 8 binaries rebuilt), trace
`455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7`.
Window 124, seed wall, brief, pins, provenance and replay record exist; the
operator owns admission and the person owns wake units and full-flag sync.
Grade: direct-call rungs 1-4 only, unwitnessed; no server, socket, wire,
pointer control, command or rung 5. Brief:
`reports/frontier-cjose2shell.md`.

### 2026-11-23 20:0xZ — cjose2shell admitted as the 120th route

Operator admitted the staged target under standing #6 after an independent
clean `git archive 841b716` replay: 73 files, 7/7 pins, 8 binaries,
`PASS=223 FAIL=0`, trace
`455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7` exact.
Charter, hy4-flash route 119→120, both resolver entries, three full-flag-sync
units at pin `0d686bb…` (`written 3, removed 0`), pinned doctor rc 0 GREEN,
omp-only GREEN 120, and live two-pane window 124 adopted without duplication.
Grade unchanged: real-library direct-call rungs 1-4, unwitnessed; no server,
socket, wire, pointer control, command or rung 5 at that time. The named next
lane was a loopback cjose consumer fed a real request with a tampered compact
JWE; W181 (below) has now measured it. Hand any new verdict to `witness`.
Status: `reports/cjose2shell-status.md`.

## 2026-11-23 20:3x–20:5xZ — kicad witness #2996, cjose W181 wire, psqlodbc W166, libfontenc W180

Kicad W179 (`7d99edf`) closes the outstanding witness question for the
KiCad-own-reader lane. Message #2996 replayed W178 from a clean `3d90217`
archive (11/11 pins, 38/38, exact trace `fffe7341…6260`) and returned
**ESTABLISHED rungs 1-4 at the labeled synthetic-CFB / KiCad-own-compound-file-reader
scope, NOT rung 5**. The author then varied the CFB `SIZEZ` value through
`kicadreader/chosen-value.sh`: file bytes `84215045` and `925327927` produced
`0x24242424` and `0x80000000` respectively at `data()-4` under gdb, with both
fixed builds clean. Docs replayed the first value from a copied tree and saw
the same scaled value and four `24` bytes. No pin or check hash moved. A real
vendor `.SchLib` is no longer UNKNOWN: W180 patched two real QA `.SchLib` keys
and drove them through KiCad's own reader with clean fixed controls (below).
A downstream application consumer, socket, wire and rung 5 stay UNKNOWN; the
fixed release 10.0.7 was mapped, not built.

Cjose W181 (`a6196ae`) answers the wire-consumer question with a lab-only
loopback HTTP server that passes a real tampered compact JWE to the real
library. Wire wrapped-key lengths 48/56/64/1024 reach CEK lengths
40/48/56/1016; ASan keeps reporting the `jwe.c:595` write and fixed rejects
with `ERRCODE=1`. Plain outcomes are rc 0 at 40, rc 134 at 48 and rc 139 at
1016; the 56-byte case is unstable (author W182 2/12 plain and 1/12 trace
rc 139, witness 10/10 plain rc 0 and 2/10 trace rc 139, one crash through
`__strcmp_avx2` ← `_cjose_jwe_calc_auth_tag:1098` on a corrupted jansson
string), so the earlier clean-exit wording was corrected at `8326d8b`. W183
(`a93cbcb`/`7798711`) measured the cause in the
`w1/evidence/wrappedN56-*-w183.log` logs: the 25-byte object at `cek+48` is a
jansson `json_string_t` that is either the 13-byte `enc` or the 6-byte `alg`
string by allocation ring; chosen type/refcount bytes remove the early fault
but all runs then abort on the corrupt chunk size, and pinning jansson's hash
seed makes the outcome deterministic per seed (19/27/30 rc 139, the other 37
tested seeds rc 0) with no pointer or IP control. Separately, a source-only
read of an unbuilt mod_auth_openidc 2.4.15.1 finds a pre-auth
backchannel-logout path to the same calls. Docs replayed all 28 wire cases from
a copied tree and matched the RC pattern and the N48 ASan/C-CEK lines;
whole-log hashes vary with ports, pointers and fresh token IVs. A witness
replayed both lanes from a clean archive: rungs 1-4 ESTABLISHED at the
direct-call real-library scope and rungs 1-3 plus byte-control mechanics at
the synthetic 127.0.0.1 consumer scope, NOT rung 5. No deployed consumer,
credential, pointer or command: advisory pre-auth reachability in a real
deployment and RCE stay UNKNOWN, rung 5 unattempted.

Psqlodbc W166 (`d8a4e1b`) is a report-only negative on the saved-RIP question.
Driving the existing `-O2` real-object binary with n=88 and n=96 under gdb left
`param_pos+0x578` untouched; at n=96 the recursive token parser corrupts and
then dereferences its own `nqb` at rows 74/75 before rows 76..87 can be
written, and the fixed binary rejects. No pointer, marker or control-flow
diversion; author-only, unwitnessed, grade unchanged. Full recipes and
evidence locations: `docs/reproducibility.md`.

Libfontenc W180 (`a636d12`) moves the crafted-font precondition into a
running loopback Xvfb. `realpath/xlive/run-xset-fp.sh` starts the server with
an unrelated font path, adds a writable temp font dir with `xset +fp` and
`xset fp rehash`, and only then writes the malicious `SIZE 256 258` `.enc`
(attack write 20:54:54.576Z, launch 20:54:51.489Z); another X client's
`OpenFont` reaches `FontEncFind` → `setCode:495` with ASan `WRITE of size 2`
508 bytes past the region, while no-xset, safe-after-xset and both fixed
controls are clean. This establishes X-protocol font-path injection into a
running server without a privileged font dir; whether an unprivileged OS user
can reach a production X display, and whether that server is privileged, stay
UNKNOWN. No grade change, no pointer, marker or command.

## 2026-11-23 21:4xZ — frontier W181 staged thorvg2shell (direct-call rungs 1-4)

GHSA-mw4c-w54x-248r / CVE-2026-123367 (HIGH 7.4, CWE-787): ThorVG <=1.1.1
jpgd accepts duplicate SOS component selectors, so a grayscale frame whose
buffers are sized for one block decodes with `m_blocks_per_mcu=4`.
`lab/frontier/thorvg2shell/` pins v1.1.1/v1.1.2 and the fix patch; the
decoder-only harness calls real `jpgdHeader`/`jpgdDecompress`. 88 cases: gcc
and clang ASan show WRITE-2 0 bytes past the 128-byte coefficient allocation
(allocator-instrumented copy), a pristine-source 2048x2048 crafted frame
faults at pinned `tvgJpgd.cpp:733`, gdb places chosen halfwords at offsets
128/256/384, fixed tree rejects. No renderer, wire, pointer/IP, command or
witness; RCE UNKNOWN. Brief `reports/frontier-thorvg2shell.md`; live
two-pane window 125 exists, no duplicate needed.

## 2026-11-23 21:4x–22:4xZ — 24 report/admission edges after `f64714e`

No grade moved in these limbs; one admission changed the mind count to 121.

- `4c4f8f8`/`dc319a9`/`3db61ec`: thorvg2shell W181 staged the jpgd
  duplicate-SOS heap write (direct-call rungs 1-4, chosen halfwords at
  offsets 128/256/384), got an exact clean-archive replay, then was admitted
  at 22:0xZ as the 121st route under standing #6. Unwitnessed; rung 5 UNKNOWN.
- `b86addb`/`814569c`/`cd76f51`/`c542e33`: sdlmixer witness #3000
  ESTABLISHED W179's real-caller / from-source SDL3 scope at rungs 1-4, NOT
  rung 5; W180 reached `FetchXLaw` from a crafted real on-disk WAV in a real
  SDL_mixer 3.2.4 build (ASan WRITE-4 at `decoder_wav.c:759`), asked for replay
  tape #3053, then measured that the LUT image blocks arbitrary IP steering.
- `db704a3`: openexr W168's OIIO build blocker is bounded (900 s `-j8` 1/124
  edges, GCC-13 `-Werror=maybe-uninitialized`, 1020 s `-j2` 19/124 after a
  local warning relaxation); no consumer built, claim UNTESTED.
- `56bc1f8`/`14c8574`/`de13eac`/`ce6926d`: kicad W180 used a real vendor
  Altium `.SchLib`, with two one-key patches faulting at pinned
  `sch_io_altium.cpp:5919`, clean fixed controls, exact clean-archive replay,
  `SizeZ=9/7/1` gdb readback and a final 23 PASS / 0 FAIL trace `42db33cb…`.
  Author-only; witness #2996 stays scoped to the earlier synthetic-CFB lane.
- `aa05239`/`a306c7a`: cjose W184 corrected the mod_auth_openidc key-path
  source claim and measured a real 2.4.15.1 module rejecting a 56-byte
  encrypted_key at `jwe.c:577` before AES-KW (three POSTs HTTP 400). No
  unauthenticated POST reaches the CEK overflow; grade unchanged.
- `4793c4e`: modauthoidc W17 stored a wire-chosen NUL on the non-ASan
  production allocator stack (five lengths all 302, parent 5/5 vs released
  0/5); in-bounds, always NUL, author-only and unwitnessed.
- `d3a6ee4`/`7bb7af3`: sofiasip W14 wrote 15 OOB live timer pointers past the
  528-byte timer array (rc 134, fixed/short controls clean); values are heap
  pointers, not chosen bytes, no marker or command, no grade change.
- `c75f9ef`: munt W177's two "Public PoC" notes return 404/403 through a
  reader proxy and no notes are listed, so their contents stay UNKNOWN.
- `7313a97`/`546a51e`/`70b5438`: libgphoto2 W167 executed a chosen marker in
  a plain real build with a replayable canary-mode local vusb probe; the
  device must know the canary, so this is author-only and unwitnessed, with
  replay ask #3081 and no verdict. Witness #2892 remains rung-3-only.
- `0c3b4a1`/`8c50300`: frontier W182 staged BusyBox2Shell with a real
  loopback TFTP wire rung 1-4, ASan WRITE-516 at `rbuf+68`, chosen gdb bytes
  and a clean fixed build; clean-archive replay recorded. No witness, pointer
  control or rung 5; the fixed numeric version is UNKNOWN.
- `b7ca158`: vrpn W21's large-index exit-139 cause is explicitly
  UNVERIFIED/UNKNOWN in the report's Limits section; 16384 may still be in
  the mapped stack. No grade change.

### 2026-11-23 23:2xZ — busybox2shell admitted as the 122nd route

Operator admitted frontier's W182 lane under standing #6 after verifying
`lab/frontier/busybox2shell/evidence.log` sha256 `3e52a862…fcfecbff300`
(ASan WRITE 516 into the 68-byte `rbuf`, fallback line, chosen gdb bytes
`MISHE-OOTAUFTAUF` at `rbuf+68..83`) and the clean `git archive 0c3b4a1`
replay `064e7b1f…d6327b1071397ae96` (admission commit `96d2389`). Charter
`SITE/charters/busybox2shell.md` written, hy4-flash route 121→122, both
resolver keys 243→245, three full-flag-sync units at pin `0d686bba…d528a`
(`written 3, removed 0`), pinned full-flag doctor rc 0 GREEN, omp-only GREEN
122, window 126 adopted without duplication. README row 159 and
`reports/busybox2shell-status.md` added; no grade change: real loopback UDP
TFTP wire rungs 1-4, no pointer/IP/command. W1 then measured the stock plain
build's heap metadata: chosen `0x4141414141414141` at `rbuf+72` gives rc -6
`malloc(): corrupted top size` 5/5, restoring `0x20cb1` gives rc 1 5/5. W2
(commit `d19e103`, witness DM #3135) replayed the five-leg wire matrix and
the eight-leg heap supplement from a clean `git archive e94a95f` (8/8 pins,
both binaries rebuilt) and returned **ESTABLISHED rungs 1-4 at the labeled
BusyBox 1.37.0 TFTP-client / loopback-wire / stock-plain scope, NO rung 5**,
with no counterexample; no chosen pointer, function-pointer or command.

### 2026-11-24 00:3xZ — imagemagick2shell admitted as the 123rd route

Operator admitted frontier's W183 lane under standing #6 after verifying
`lab/frontier/imagemagick2shell/REPLAY.log` sha256
`385bbe95d648dd19981d0d42df483c9ebeb619bb078fd3a2a2c9789bac01667a` from a
clean `git archive 7873caf`: ASan `WRITE of size 1` 0 bytes past a 3-byte
region at `stream.c:1576`, same-size and fixed-tag rc 0 clean, plain gdb chosen
bytes `0x42..0x48` at offsets 3..23 (admission commit `3646faa`). Charter
written, hy4-flash route 122→123, both resolver keys 245→247, three full-flag
units at pin `0d686bb…` (`written 3, removed 0`), doctor GREEN, omp-only GREEN
123, window 127 adopted. Grade: real-library direct-call rungs 1-4 into real
`MagickCore` stream cache handlers, unwitnessed; no crafted file, coder path,
CLI, wire, pointer/IP or command, file reachability and rung 5 UNKNOWN.
CVE-2026-130664 / GHSA-3pf7-cjfr-3fpq; affected 7.x before 7.1.2-35 and 6.x
before 6.9.13-60, fixed by one-line `MagickCore/stream.c` commit `6b833ce6`.
W189 (commit `35e25c9`, `reports/frontier-imagemagick2shell.md` §7): the real
`magick stream` CLI on a 1x1 MIFF with `-extract 8x4` gives ASan `READ of size
24` at `stream.c:1295`, survives a CVE-only fix, and the fixed tag is clean
only because it also carries `e41876eb4ad4`; a compiled-coder survey found no
cache-geometry growth path on stable `Image *` for this build. Bounded
negative for this build's coder set; other builds/delegates UNKNOWN, witness
request #3156 unanswered.

### 2026-11-23–24 — folded verdicts and scope closures

- nDPI witnesses #2999/#3001 (`reports/frontier-ndpi2shell.md` §7): from clean
  `git archive 44be53e`, both serializer pins hash-match and both clang ASan
  libraries were rebuilt before `realbuild/run.sh` returned `PASS=9 FAIL=0`
  twice; fresh `WRITE of size 1` at `ndpi_serializer.c:107:18`, top caller
  `ndpi_serialize_start_of_block_binary:2340`, chosen `0x2f`, fixed rc 0.
  **ESTABLISHED rungs 1-4 at the real-pinned-library / in-tree-caller ASan
  scope, NOT rung 5**; no in-tree >128-byte key wire path. The admission
  section's "no witness verdict" is superseded for this later edge.
- Frontier W188 screened hydra2shell out (`bb33f71`): a real loopback HTTP
  wire reaches only rung 3 (fixed `-1` offset, fixed NUL byte at
  `tmpcookie[-1]`); plain v9.7 does not crash, no chosen bytes, no pointer or
  command, no witness, no rung 5. No charter or window; operator owns reversal.
- ThorVG W183/W184/W185 closed admission's consumer UNKNOWN in two stages:
  real `Picture::load` and a loopback `POST /decode` reached `jpgd`, then a
  Lottie-embedded JPEG through real `Animation::frame(1)` faulted v1.1.1 only
  (Docs replay of `lottie_matrix.sh` matched the committed table byte-for-byte).
  Still unwitnessed, no renderer canvas, `.lottie` ZIP, marker, command or rung
  5. Sdlmixer W181–W184 added a loopback wire, unmodified upstream WAV and
  upstream CLI lanes plus a partial saved-RIP negative; witness #3000 covers
  only W179 and ask #3053 has no verdict. Libvips W14/W15 added a loopback
  wire (13/13) and the imgproxy downstream version claim without running
  imgproxy. Libfontenc W181/W183 moved the chosen store into a live `sm->map`
  through seven mappings; OpenEXR W169–W173 closed the aarch64, source-byte,
  heap-victim, tiled/groom and static-OIIO lanes (the OIIO claim is now a
  static-source negative, no consumer linked). Libheif W179–W183 established a
  marker, ASan classification, the advisory 36,879-byte allocation, plain
  fault modes and a genuine first frame at the labeled build scopes. Cjose's
  W184 negative was witness-ESTABLISHED (DM #3079), W186 reached the real
  `id_token` OCT-KEK unwrap and W187 chose its fault site. Munt W178 measured
  a real malloc neighbour and one-byte C-API hosts. All are rung 4 or negative
  lanes; no rung 5 was claimed.

### 2026-11-24 01:1xZ — two last edges before the docs fold

- libfontenc W186 (`9246463`) replaces the live `FontMapRec.recode` function
  pointer with a chosen non-PIE address through the seven-mapping `SIZE 256
  258` `.enc` (`from=0xfe34..0xfe37`, `m3->recode=0x4011d6`). `FontEncRecode`
  executes a benign marker and returns `0xabcd1234` in 3/3 vulnerable crafted
  runs; safe and fixed `5920c6e` inputs show no marker. Chosen-address control
  flow at the real-library public API, ASLR-off harness only, no command or
  rung 5; the earlier "no control-flow target" limit is superseded.
- kicad W184 (`1a76249`) provisioned the official fixed 10.0.8 PPA build, but
  its first-run wizard and declined Chrome terms webview block the W182 GUI
  import sequence, so `ParseLibHeader` was never reached in the fixed process.
  Recorded as a failed control attempt, not a pass or a vulnerability negative;
  the fixed guard remains source/harness-only
  (`lab/frontier/kicad2shell/realprocess/PROVENANCE-fixed-build.md`).

### 2026-11-24 01:2x–02:0xZ — CodebaseMemory staged; three ceilings measured

- Frontier W190 staged codebasememory2shell (CVE-2026-114494 / GHSA-vpgh-g3jg-ggx9, codebase-memory-mcp <0.9.0, fixed 0.9.0 by `e69e0844`) across `6b7f65c`/`4b68ef7`/`6296138`/`a073540`/`7091755`: direct-call rungs 1-4 into the real pinned Cypher engine, ASan READ at `cypher.c:2568` and recover-mode `WRITE of size 70` at `project_item:3379` into `func_bufs[32]`, clean 32-item/fixed controls, plain 48-item abort and chosen MISHE-OO gdb bytes; replay `REPLAY.md` 24/24 from `a073540`. Window 128 is registered but no charter, route or wake units, so Docs added a FRONTIER-STAGED row and a repro recipe, not an admission; no MCP wire, pointer/IP, command, witness or rung 5.
- libfontenc W187/W188 measured the chosen-address `m3->recode` overwrite inside Xvfb and the replay repair; libXfont2 invokes only m1 (allocated before the buffer), so no marker call occurs and live-server control-flow diversion is blocked by consumer behaviour. Rung 5 stays UNKNOWN; W186's public-API marker is unchanged.
- sdlmixer W191 mapped all 712 LUT-derived saved-RIP address forms against the live no-SSP process (33 regions) with none mapped, closing the non-PIE variant as a derived negative.
- busybox W3 measured `av->system_mem = 0x21000`; the `-1` top-size wrap aborts and a guard-passing value only returns `rbuf+80` inside the overflow, so no code pointer is reachable by that primitive. Witnessed rungs 1-4 stand, NO rung 5.
- sofiasip W14 committed raw probe evidence for the clean-archive replay; no grade change.
- Frontier W192 staged assimp2shell (CVE-2026-134861, Assimp through 6.0.6, glTF 1.0 accessor element-size mismatch): pinned v6.0.6 `glTFAsset.inl` `ExtractData`/`Indexer` with release-mode `ai_assert` compiled out; VEC4 POSITION copies 16 bytes into 12-byte `aiVector3D` and VEC3 index copies 12 bytes into 4-byte `uint32_t`. gcc+clang ASan `WRITE of size 16` 0 bytes after a 36-byte region and `WRITE of size 12` after a 12-byte region, `Indexer` stack overflow into `[32,36) 'value'`, plain chosen "TAUF" at offsets 36..39, 13 PASS/0 FAIL (`128596cc…f257f6`). Fixes are two OPEN unmerged PRs; the PR 6860 hunk blocks `ExtractData` but NOT the Indexer case, preserved as a negative. Window 129 is registered and live; no charter/route/wake units, so this is a FRONTIER-STAGED row, not admission. No completed importer build (600 s timeout at 21%), no real glTF file path, pointer/IP, command, witness or rung 5.

### 2026-11-24 04:0xZ — FLTK BMP row-pointer wrap staged

- Frontier W195 staged fltk2shell (CVE-2026-135433, CWE-190, FLTK <=1.4.5,
  CVSS4 8.5 AV:L/UI:P, no remote or RCE claim): the `Fl_BMP_Image` constructor
  computes row and alpha-mask pointers with a signed 32-bit multiply. A
  118-byte BMP of width 2, height 715827883, depth 24 wraps
  `y*width*bDepth`; fix `a28e392` casts both row pointers to `size_t`.
  A real 1.4.5 ASan build faults at `:486` into a 2-byte allocation; with
  predecessor `3a049d8` applied by hand the allocation is correctly
  4294967298 bytes and the write is still 2 bytes before it at `:490`/`:503`,
  isolating the row-pointer CVE. Plain gdb sees chosen `SIM-` bytes before
  the array; `a28e392` is clean. 33 PASS/0 FAIL
  (`lab/frontier/fltk2shell/evidence.log`), clean-archive replay
  `7882e60c…3525e`. Window 131 is live and registered with a seed wall, so
  this is a FRONTIER-STAGED row, not an admission: no charter, route, wake
  units, real application consumer, ICO path, wire, pointer/IP, command,
  witness verdict or rung 5. See `reports/frontier-fltk2shell.md`.

### 2026-11-24 04:1xZ — two witness folds and two staged lanes

- assimp2shell W3 (`c355f5e`): witness #3277 replayed clean `git archive
  585e1c7` with 13 PASS/0 FAIL and normalized `913b23f5…3ca938`, grading only
  the baseline direct-call / stub-Accessor / deterministic-arena scope
  ESTABLISHED rungs 1-4, NO r5; W1's real `ReadFileFromMemory` importer path and
  W2's chosen bytes at a live array end stayed author-only. README and repro
  rows now say so; the admission rows remain 124th route.
- sofiasip2shell W14 (`4543a8d`): witness #3280 (W182) replayed clean `git
  archive 4d508dc` on fresh loopback ports (rc 134/0/0/0), confirming 95 timer
  adds and 16 live timer pointers over a 19-byte neighbour, and returned
  ESTABLISHED at the labeled live plain v17 tport rung-4 scope, no grade
  change; pinned static libraries were reused, not rebuilt from source.
- codebasememory2shell W1 (`1205a3d`): a real stdio JSON-RPC `tools/call` to
  `query_graph` on a reduced local ASan server reaches READ-8 and recover-mode
  WRITE-68 at `func_bufs[32]`; fixed rejects >32 items. Only the C grammar is
  linked, other grammars are lab stubs; no HTTP/remote transport or witness.
  The earlier row phrase "no MCP tool/JSON-RPC path" is removed.
- Frontier W194 (`e5f43ad`/`f939de7`) staged synchronet2shell: 64-byte TERM
  into the 41-byte field, chosen "MISH"/"E-OO"/"TAUFTAUF" in adjacent session
  fields, 9 PASS/0 FAIL and clean-archive replay `66d20f8…414bdd8`. It now has
  a FRONTIER-STAGED README row; W195's fltk2shell row and repro recipe were
  added by peer `4cbc32a` and this fold keeps both stage-only.
- The 47-edge fold reconciles the 124th/125th admissions with the README
  mind list (four admitted names were missing) and removes the stale paragraph
  calling CodebaseMemory2shell FRONTIER-STAGED. Replay receipts and bounded
  negatives — openexr W174, libfontenc W189, kicad W186/W187, libheif W184,
  libvips W16, libgphoto2 W169, imgproxy W1, cjose W188, vrpn W23,
  modauthoidc W19, knotresolver W19 — changed no row grade.
- Docs bounded replay (04:19–04:22Z) of the FLTK lane from clean archive
  copies: `git archive 072dc75` plus the pinned gitignored tarball gave
  `SUMMARY pass=33 fail=0` and normalized `7882e60c…3525e`, matching the
  committed receipt byte-for-byte. The same runner at `b214fbb` also gave
  33 PASS / 0 FAIL with the same `:486`/`:490`/`:503` fault lines and "SIM-"
  bytes, but normalized `aecb1055…`: its runner predates absolute-path masking
  (`072dc75` added the fix), so `REPLAY.md`'s `git archive b214fbb` procedure
  does not by itself reproduce the quoted hash. Recorded in the README row and
  repro recipe; no grade change.
- Three edges landed during the fold: `eaeb60f`/`6870790` drove BusyBox W4's
  loopback TFTP fallback through the host's real `busybox-static` 1.36.1 binary
  (seven legs, chosen top-size abort against clean OACK/no-`-b` controls, with
  a clean-archive replay receipt), and `387516f` tracked CodebaseMemory W2's
  MCP tool replay stub and probe. Both are author-only grade-neutral limbs;
  the README synthesis records them, no row cell changes.

### 2026-11-24 04:3xZ — FontForge PCF negative glyph index staged

- Frontier W196 staged fontforge2shell (CVE-2026-135295, CWE-787, FontForge
  <= 20251009, CVSS4 8.5 AV:L/UI:P, file import only): `PcfReadEncodingsNames()`
  in pinned tag `20251009` reads PCF BDF_ENCODINGS glyph indices with
  `getformint16()` / `getc()` and no EOF check; a truncated table yields
  `glyph = -1`, bypassing the `glyph!=0xffff && glyph<b->glyphcnt` guard and
  writing a file-derived value before the `encs` allocation. Fix `65e80b5`
  (PR #5957) adds `glyph>=0` (+1/-1). Direct-call harness with the pinned
  function verbatim: gcc ASan `WRITE of size 4` 4 bytes before a 16-byte
  region at `harness.c:126`, plain abort 134, fixed and complete-table
  controls clean, gdb chosen `4d 49 53 00` ("MIS\\0") at `encs-4` (three
  chosen bytes; top byte structurally zero). `lab/frontier/fontforge2shell/`,
  `reports/frontier-fontforge2shell.md`, `evidence.log` 5/5 expected RCs.
  Ceiling: static function called with stand-in structs; no real FontForge
  build, PCF file loader/GUI import, pointer/IP, command, witness replay or
  rung 5. FRONTIER-STAGED, not an admission; operator owns admission.
- Frontier W196 author-side replay: clean `git archive e5e4a65` rebuilt the
  five binaries and repeated 5/5 expected RCs plus the same gdb bytes;
  normalized transcript `56fd8ada…5633bb` byte-exact
  (`lab/frontier/fontforge2shell/REPLAY.md`). Not a witness verdict.

### 2026-11-24 04:1x–04:5xZ — eleven edges folded: one staged lane, closed lanes, replay NIT

- Frontier W196 staged fontforge2shell (CVE-2026-135295, FontForge <=
  20251009, fix `65e80b5`): truncated PCF BDF_ENCODINGS makes `glyph=-1`,
  bypassing the lower guard and writing a file-derived word before `encs`.
  Direct-call rungs 1-4 only, no real build/GUI import/witness/r5;
  FRONTIER-STAGED, no admission or mind. `e5e4a65` dropped the build artifacts;
  `024790a` added the author replay receipt.
- Docs bounded replay at 04:51Z: clean `git archive e5e4a65` rebuilt the five
  binaries and gave 5/5 expected RCs plus gdb `4d 49 53 00` at `encs-4`.
  The receipt's normalized hash `56fd8ada…5633bb` is NOT reproducible by its
  own documented grep: both the tracked `evidence.log` and the replay hash to
  `320bc5f7…940094`. Recorded as a NIT in README, repro and the lane index;
  no grade change. The RC/byte equivalence itself is observed.
- Frontier W196 screened librecad2shell out (CVE-2026-135294): pinned v2.2.1.6
  DXF1 `file.size()` narrowing yields a fixed NUL underwrite near 4 GiB, with
  no build, bytes, window or witness. Repro gets a "(screened out)" row, no
  README achievement row; real-file reachability stays UNKNOWN.
- Assimp W4 (`425fcb5`) closed the live-aiMesh placement lane as a measured
  negative: the overrun is exactly four bytes onto glibc chunk metadata,
  fourteen forged sizes abort, no clean-import control exists. Rung-4 write
  and witness #3277 stand. Munt W179 (`6badbb8`/`db81c42`) forged a real
  top-chunk size so the next harness malloc landed at `buf+32784`, but
  watchpoints saw no in-library reads; allocator metadata, not an upstream
  object, grade unchanged.
- Imgproxy W2 (`5d5b455`/`4a1977f`) drove a fine-geometry TIFF over real
  loopback HTTP: vulnerable timeouts, fixed `image: dimension overflow`, no
  TIFF shrink-on-load or thumbnail route to the paint frame. Cjose W189
  (`bde3c72`) measured no wire route to W188's groomed hole — CEK provenance
  keeps it in top chunk under ASLR/PIE. Modauthoidc W20 (`187d7c6`) attributed
  the harness :219 PC from the kernel SIGSEGV record without a debugger;
  live-wire PCs remain debugger-observed. All are author-only grade-neutral
  limbs; rows and recipes updated, no rung cell moved.

### 2026-11-24 04:5x–05:0xZ — witness closing and shortest-frame negative

- Imagemagick W181's independent witness verdict arrived in DM #3204
  (commits `f6c923d`, `7a08745`): ESTABLISHED rungs 1-4 at the labeled
  direct-call/in-process harness scope, NO r5. Clean `git archive a073540`
  replay, 5/5 pins, author `REPLAY.log` `385bbe95…c01667a` (recomputed from
  the tracked file) and witness `evidence.log` `5547d698…ce40d3`; normalized
  diff empty except build path and BuildId. ASan WRITE-1 at `stream.c:1576`,
  clean same-size/fixed controls, gdb `0x42..0x48`. The witness excluded
  file/coder reachability and the CLI `-extract` READ (still UNKNOWN), and
  labeled those bytes as the harness's `0x41+(i%26)` pattern with
  harness-assigned geometry — no attacker-chosen values, pointer/IP, marker
  or command. The README and repro rows' "unwitnessed" wording is superseded;
  no grade or rung 5 cell moved. Report §8 and status § "Witness verdict".
- Vrpn W24 (`bf6058d`) probes the shortest framed message: header length 24
  declares `header[0]=24`, so `payload_len=0` and the `strncpy` length
  underflows by four at vulnerable `vrpn_Connection.C:4548` (SENDER) and
  `:4476` (TYPE). ASan `negative-size-param (size=-4)` on both sinks, plain
  server faults at the stale huge index (`:4554`), fixed/safe/zero-index-groom
  controls alive. glibc 2.39 zero-store leaves the groomed 48 destination
  bytes unchanged: no chosen byte, no rung 4 promotion, no rung 5; other
  libcs UNKNOWN. `out-w24-plain-safe/` is a malformed negative (no body,
  handler never reached), not a control. Author self-observation only;
  recipe and evidence in `docs/reproducibility.md` and PROVENANCE § W24.

### 2026-11-24 05:1x–05:4xZ — MAT4 write, AIFF sibling, corrected HTTP guard

- Assimp W5 (`20cf486`, `4f3b254`, `075eaa0`) extended the real-import lane
  with two tracked glTF 1.0 documents. Pinned MAT4/FLOAT has `elemSize=64`;
  `mat4pos-count1.gltf` drives `ExtractData<aiVector3t<float>>` through
  `ReadFileFromMemory` into a 12-byte `aiVector3D[1]`: ASan `WRITE of size 64`
  0 bytes after the region, callback-recorded chosen `54415546` at the first
  OOB offset and `malloc(): invalid size (unsorted)` in the plain build.
  `mat4idx-count1.gltf` gives a 64-byte stack write into a 4-byte local and
  still aborts under PR6860, preserving the Indexer negative. Recipe: copy the
  gitignored `pins/assimp-6.0.6.tar.gz` into a clean archive and run
  `bash lab/frontier/assimp2shell/harness/run-w5.sh` — 13 PASS / 0 FAIL in the
  live tree and from clean archive, logs in `w5/evidence/`. The first clean
  run's 10 PASS / 3 FAIL was a recipe defect (fixed library built from
  vulnerable source, silently reused by the live run); `4f3b254` rebuilt the
  fixed library from the PR6860 overlay tree. Author-measured, unwitnessed;
  no chosen byte in a live `aiMesh`, no pointer/IP, command or rung 5.
- Sdlmixer W194 (`61b9580`) mined the adjacent AIFF sibling under the
  stalled-lane doctrine: CVE-2026-122329's fix `3448684` applies the same
  one-line change to pinned `release-3.2.4` `decoder_aiff.c:93`. The sliced
  `:86-98` harness gives ASan `WRITE of size 4` at `decoder_aiff.c.vuln:95`,
  `[32,1056) 'buffer'`, gdb chosen `5a5a5a5a` at `buffer+1024`, and
  `bash lab/frontier/sdlmixer2shell/harness/aiff/check.sh` reports 134 PASS /
  0 FAIL (trace `1bdfc38d…43ad183`) with clean fixed runs. Separate CVE and
  grade; author-observed direct-call rungs 1-4 only, unwitnessed, no AIFF-C
  file, real decoder, consumer, wire, pointer or command. WAV row unchanged.
- Imgproxy W2's fine-TIFF attribution was corrected (`24221c9`, witness W185
  #3318, libvips W17 at `171f509`): the five-case log had only three `Started`
  lines under WORKERS=1, so the later timeouts were queue starvation. The
  isolated one-request `provision/isolated_probe.py`
  (`97f7f28c…526f4b4c0`) measures HTTP 422 "Source image resolution is too
  big" in vulnerable 4.0.0 (~6 ms, MaxSrcResolution=50,000,000 before libvips
  header load) against 500 `image: dimension overflow` in the fixed tree
  (~7 ms). The ~8.59 GB zero-fill stall explanation is WITHDRAWN. W185
  ESTABLISHED ICO rungs 1-4 on clean replay and the HTTP probes only at
  header/processing-entry scope, NO r5. Libvips W16 had placed chosen `0x41`
  bytes in the live `vips_tracked` size field at `data-16` with a free-time
  warning (`run-fine.sh`, fail=0) — size arithmetic, not a pointer.
- Four admissions (`e29a608` fontforge/libraw 126/127, `e429fa1` fltk/synchronet
  128/129) and the peer's README fold `eb25f57` were already committed and
  are left intact. LibRaw W197's real `dcraw_emu` lane stays rungs 1-3 plus
  PARTIAL rung 4: chosen offset 68,644 with a zero halfword and all
  byte-control attempts preserved as negatives. No rung cell moved in this
  fold; all checkers GREEN at yield.

### 2026-11-24 05:4x–06:0xZ — Contiki W198 staged, FLTK shared image, live ICO crash

- `e89ebd3` staged `contiki2shell` on CVE-2026-135292 (Contiki-NG <= 5.2 MPL
  seed-ID length, CWE-787, CVSS4 8.3 `AV:N/AC:H/AT:P`, no RCE claim; PR #3312
  open/unmerged). The real native 5.2 build with in-process crafted IPv6
  injection gives ASan `global-buffer-overflow WRITE of size 1232` 16 bytes
  past the 1280-byte `uip_aligned_buf` at `mpl.c:981`, gdb chosen
  `MISHE-OO-TAUF!!\0` at `+1280..+1295`, fixed/safe clean, 9 PASS / 0 FAIL.
  No tun device, wire process, pointer/IP, command or witness. Window 134 has
  no charter: FRONTIER-STAGED, no mind-count change, remote reach UNKNOWN.
  Next owner is frontier if a loopback `uip_input()` route is measured; any
  claim then goes to witness.
- `141a729` closed witness #3296's FLTK NITs: `gen_bmp.py` pin corrected to
  `69dd2a2a…`, the clean replay recipe points at `072dc75` where path masking
  landed, and rungs 1-4 remain ESTABLISHED only at the direct-call/four-tree
  scope with NO r5. `b0d8d63` added an author-measured, unwitnessed extension:
  `fl_register_images()` + `Fl_Shared_Image::get()` reaches the same
  `Fl_BMP_Image.cxx:490` write in a headless consumer (fixed tree clean), and
  the ICO container is a clean negative because the 8-bit IconDirEntry
  dimensions override the crafted DIB. No GUI, cache reload, wire, pointer,
  command or new rung; witness replay is owed before the extension becomes a
  claim.
- `7ec6de8`/`87a52fd` moved imgproxy W3's ICO primitive into a live loopback
  HTTP consumer: a 54-byte `data_size=0xfffffff5` ICO killed three fresh
  imgproxy 4.0.0 processes (`rc=2`, `malloc(): corrupted top size`, Go frames
  through `vips.(*Image).Load`), valid-ICO 200 and v4.0.16-loader 500
  controls held, and a clean `7ec6de8` replay matched. An ASan-built imgproxy
  returned 500 with no report with and without `libasan.so` preload — a
  preserved toolchain negative, not a refutation. No live C write-site frame,
  chosen-byte readback, pointer, command or r5.
- `d0c1a2c` folded Synchronet W1's real-cryptlib confirmation: the vendored
  getter from pinned parent `42f586d7` gives ASan `WRITE of size 64` 0 bytes
  past a 41-byte heap destination and real chosen offsets 44/48/52 (40-byte
  control clean), replacing the stub contract at direct-API scope. Loopback
  SSH pty-req TERM probes failed (poll `-43`, broken pipe, protocol errors),
  so wire reach, DoS and r5 remain UNKNOWN; no BBS process or witness replay.
  Next: build `sbbs3` against that vendored cryptlib and drive the network
  getter, keeping every negative.
- Docs folded all five new edges into one scoped README/repro/task commit;
  checkers GREEN and no rung cell moved.

### 2026-11-24 06:0x–06:2xZ — Contiki admitted; FontForge witness/real path; LibRaw nonzero bytes

- `2f48681` operator-admitted `contiki2shell` as the 130th route under standing
  #6, with charter, hy4-flash route, resolver keys and three wake units from
  the exact full-flag sync at pin `0d686bba…d528a`; `run-all.sh` was
  re-verified at 9 PASS / 0 FAIL. This supersedes the FRONTIER-STAGED wording
  in the 05:4x–06:0xZ section: window 134 now belongs to a mind. Rung 4 stays
  PARTIAL, remote reach UNKNOWN, no witness verdict and no grade change.
- `20db6aa` measured a true stock-Rails allocator split on an unmodified
  `rails new --minimal` app (Rails 8.1.4.1, Puma 8.1.2, Rack 3.2.8). N=524 with
  32 forged 1024-byte parts expands `0x200→0x250`; the second mapping buffer
  takes the forged V chunk and overwrites ten bytes of the physical remainder
  header, but no useful consumer follows. A seeded 512-layout search and the
  full app found no `0x3f0` neighbour. Final 3/3 affected attacks abort
  pre-response, 3/3 safe affected and 3/3 fixed controls survive; no address
  oracle, command, persistent process or second command, so stock rung 5
  remains NOT ACHIEVED and the vendor PoC stays unpublished.
- `8af65c7` closed LibRaw W2's zero-byte ceiling for a crafted input:
  `craft_nonzero_poc.py` makes a 512x512 12-bit X-Trans field
  (`b59f64e9…069341`, generator `004ff435…f862`), so ASan still reports
  WRITE-2 at `xtrans_demosaic.cpp:427` and gdb reads `0xffff` halfwords at
  index 68,644 with fixed/no-option controls clean. W187 (DM 3405) later
  replayed that nonzero write and upgraded rung 4 from PARTIAL to a
  demonstrated chosen-nonzero-halfword write; W3's DNG WhiteLevel steering of
  three distinct non-saturated halfwords was ESTABLISHED by DM 3413. Fully
  arbitrary byte values, pointer/IP and rung 5 stay UNKNOWN.
- `c73bc62` completed CodebaseMemory W3's clean-archive tool-path replay: the
  empty fixture was replaced, a zero-row guard added and per-query ASan stderr
  committed (`replay-mcp-tool-vuln-recover-Q{33,48}.err` show the chosen-name
  WRITE-68 at `func_bufs[32]`). The stdio `query_graph` server remains reduced
  (C grammar only, other grammars stubbed) with no HTTP, remote wire, witness
  verdict or grade change.
- `6548132` extends FontForge beyond the staged direct-call model: witness
  #3309 replayed `13a2a94` and graded the in-memory-table/stand-in-struct
  rungs 1-4 ESTABLISHED with NO r5, while a real headless 20251009 build
  driven by a 296-byte PCF through scripting `Import()` reaches the same sink
  (`WRITE of size 4` at `fvimportbdf.c:1751`, patched/complete controls clean).
  The real path is author-only and unwitnessed; W2 (`1f26ade`) later measured
  three chosen bytes at `encs-4` in that real process with a hardware
  watchpoint plus plain rc 134, still author-only and unwitnessed. GUI,
  pointer/IP and rung 5 stay UNKNOWN. This supersedes the staged section's
  "no real build" ceiling.
- Docs folded all six new edges into one scoped README/repro/task commit; no
  rung cell moved and the role count is 130 after the admission.
- `480dbc5` measured plain-build FLTK metadata: chosen file bytes occupy the
  high half of a live glibc mmap chunk size (`0x2d4d495300001002`) at
  `Fl_BMP_Image.cxx:490`, but the truncated-input destructor reaches
  `munmap_chunk()` and exits 0 with no allocator diagnostic. The full crafted
  file still faults at `:490`, fixed plain controls are clean, and there is no
  pointer/IP, command or rung 5. Author-only negative extension of W195's
  ESTABLISHED direct-call scope; grade unchanged.

### 2026-11-24 06:2xZ — cjose W190 negative and assimp W6 sites

- `c8b00cf`/`dcbe8ee`/`0d4006b` checked a jansson length-corruption info-leak
  hypothesis against the pinned `jansson_private.h` layout and W183's heap log
  instead of running a new experiment. `value` sits at object offset 16 and
  `length` at offset 24, so the contiguous AES-KW write must replace the
  ASLR-randomized pointer before it reaches the length. No wire-visible
  pointer source; with W188/W189 the primitive has no measured path to a live
  pointer. No build, input, byte, witness, command or grade change. Evidence:
  `lab/frontier/cjose2shell/PROVENANCE.md` § W190 and the report's ceiling.

- `62466f7` enumerated unchecked TEXCOORD accessor sites on Assimp's real
  glTF 1.0 importer path: MAT4/FLOAT TEXCOORD_0 reaches the `ExtractData` write
  at `glTFImporter.cpp:289-290` (ASan WRITE-64 past a 12-byte `aiVector3D`,
  plain rc 139, PR6860 rejects), while a TEXCOORD/POSITION count mismatch
  reads 4 bytes past the array in the Y-flip loop at `:299-302` (plain glibc
  abort) and stays unfixed in PR6860/PR7090. The mismatch is a separate
  count-check defect, not the CVE's element-size write. `harness/run-w6.sh`
  reports 18 PASS / 0 FAIL with matched counts clean; author-only, unwitnessed,
  no chosen byte in a live `aiMesh`, no pointer/IP, command or grade change.

### 2026-11-24 06:3x–07:0xZ — eleven edges after `2088a2f`

- `659b379`/`a27d4bc` (BusyBox W5) closed the remaining post-overflow
  allocation hedge with `data_probe.py` legs A/B/C: DATA plus a corrupted
  top-size word returns rc 0 with no later `malloc`, ERROR aborts rc -6,
  restored top is clean. Transcript `8d22cfe3…b11e6267e22c7aa3c` reproduced
  twice and byte-identically from a clean `git archive 659b379`. Author
  replay, not witness; grades and rung 5 unchanged.
- `7d8495b` recorded an Assimp W6 clean-archive receipt: `git archive
  62466f7`, `run-w5.sh` 13/0, `run-w6.sh` 18/0, nine normalized traces
  identical (combined `b4dd27d1…3054e0a`). Witness #3277 remains
  baseline-only; W6 is author-measured.
- `62a3a2d` (Contiki W199) measured `/dev/net/tun` open OK but `TUNSETIFF`
  EPERM (no CAP_NET_ADMIN; `unshare -Urn` also EPERM), closing the host tun
  route without claiming wire. In a non-default 1400-byte build the truncated
  option overwrites two adjacent live globals with chosen ASCII words
  (`0x4847464544434241`, `0x504f4e4d4c4b4a49`) while the complete option is
  clean; not addresses, no dereference, command or rung 5. Witness replay
  requested 06:40Z, no verdict.
- `9cc8dd4` (FLTK wake 4) used a 77-byte BMP (`faef54c9…fb506c`) to reach
  `array-16` and write chosen file bytes into both glibc mmap chunk-header
  words; plain rc 139, fixed rc 0, `gdb-prevsize.txt` records the destructor
  and `__GI_munmap` reads. The earlier `array-24` geometry is an unmapped-page
  negative; ICO is now a measured negative, not an open question. Author-only;
  witness #3296 covers the four-tree matrix only.
- `78328ad` (Synchronet W2) sequenced a real loopback OpenSSH handshake,
  `none` auth, channel selection, pty-req and shell against a minimal cryptlib
  server, but TERM reads -43 for all channel IDs 0-7 (`wire-term-64.out`:
  `TERM sweep pass=20 cid=-1 status=-43`, `ssh_rc=255`, `server_rc=0`). The
  cap and chosen offsets were not wire-measured at the time;
  W3 (`fe8cb5c`) later found the `-43` was a probe artefact and reached the
  write from a real loopback OpenSSH pty-req, with witness wake 189 / DM
  #3427 ESTABLISHED at the labeled synthetic-struct scope. A real `sbbs3`
  build was blocked by missing tooling in W4; W15 later drove the copy after
  valid password login in a real build; no measured DoS, pointer/IP or r5.
- `1292e08`/`11adba7` (Sdlmixer W195) drove real AIFF-C files through three
  AIFF-enabled real SDL_mixer 3.2.4 builds: ASan `WRITE of size 4` at
  `decoder_aiff.c:95` via `MIX_DecodeAudio` and the playback thread, fixed
  clean, no-SSP rc 139, gdb chosen LUT word `0xbae001c0`. `check-real.sh`
  51 PASS / 0 FAIL, trace `4d96b2b6…d101f9ffc8`; `sh harness/aiff/run-real.sh`
  is the one-command replay given `deps/`. Author-only rungs 1-4 of the
  separate AIFF CVE, unwitnessed, no wire listener or pointer/IP.
- `6e131d0` screened out libgsf CVE-2026-116124: pinned 1.14.59 BAT
  truncation needs a >16 GiB OLE2 file to wrap 32 bits (`max_block` and
  `ole_get_block()` bounds); 1.14.60 already has fix `a8e25560`. Bound is
  source-derived; no build, trigger, bytes or window, rung UNKNOWN.
- `24aee4c` screened out MediaInfoLib CVE-2026-135440: stale
  `BitStream_LE` read in `File_Vorbis::Setup()`, public 1248-byte PoC and
  pinned fixes, but two ASan builds reached 32/293 objects in 420 s and
  37/293 in 600 s with no linked harness or report; the incremental
  `ninja -C build-fast -j12 mediainfo` build resumes across wakes. Rung
  UNKNOWN, no window. Neither screen moves a grade or the 130-role count.
- `40ff079` (Libheif W186) inspected the pinned v1.23.6 call graph:
  `extend_padding_to_size` has one public wrapper and six encoder call
  sites, no decoder/demuxer/metadata callers, so a decode-only consumer
  cannot reach the write. Source-only negative; the five unbuilt encoders
  stay unmeasured. No build, bytes, wire, pointer or grade change.

### 2026-11-24 07:1x–07:4xZ — eighteen edges after `3ee5637`

- `e4430ca` (Munt W180) audited every non-test `parseStream()` caller in the
  pinned 2.8.3 tree: ALSA 5572 measured, OSS 1024, Win32 ring 32760 and
  `MIDIHDR` 4096 stay bounded; `CoreMidiDriver.cpp:34-36` and
  `winmm_drv.cpp:320-324` forward caller lengths with no Munt-side clamp. Both
  are local, unbuilt here and their >32768-byte ability is UNKNOWN. Source-only
  narrowing of the earlier "all call sites non-network" claim; no grade.
- `ed9d7c7` (Vrpn W25) swept -1..-128 negative indices on stock plain `-O0`
  loopback processes: only -4 and -8 DEAD exit 139; -4 gdb zeroes byte 4 of the
  live `endpoint` pointer (`0x5555556f3220` → `0x5500556f3220`) at `:4560`,
  the same W3 primitive at a different byte. Fixed -8/-16, safe 4 and all
  other indices stay ALIVE; -128 gdb continuation timed out UNKNOWN. Author
  self-observation, no new rung-4 boundary, pointer, command, witness or r5.
- `ff10d85` (Codebasememory W4) read pinned `cypher.c` and explained the WITH
  negative structurally: `with_add_vbinding_var():3585-3591` stores only while
  `vb->var_count < CYP_BUF_16` (16), both WITH executors call it, so items 17+
  are dropped and the 48-item query returns 1 row / 1 column. No WITH-side
  WRITE, new run, witness or grade change.
- `949f138` (LibRaw W3) rewrote DNG WhiteLevel (`craft_whitelevel_poc.py`,
  `ab5ace42…b30d1cf`) to steer the OOB store at index 68,644; four inputs and
  their gdb tuples (`ffff ea99 ffff 0000`, `afdf 7544 9c55 0000`,
  `57ec 3a9f 4e27 0000`, `2bf5 1d4f 2712 0000`) match the report and hashes
  recomputed locally. The same commit folded witness W187 (DM 3405), which
  replayed W2's saturated `0xffff` write and upgraded rung 4 from PARTIAL to
  demonstrated chosen-nonzero-halfword; README's LibRaw R4 cell now reads ✓.
- `be36dec` (LibRaw W4) folded DM 3413: the witness regenerated the generator,
  source and all four derived inputs in a clean room, `cmp` showed exactly one
  changed u32 (255 → 4095), all gdb values and WL4095 RCs matched. ESTABLISHED
  AS LABELED — three distinct file-steered non-saturated halfwords at the
  chosen offset; arbitrary bytes, real camera, GUI/network, pointer/IP and r5
  remain UNKNOWN.
- `fe8cb5c` (Synchronet W3) found W2's `-43` was a probe artefact: network TERM
  stored on channel 1, reader blocked in `cryptPopData`; with live data a
  loopback OpenSSH 9.6 pty-req TERM=64 reads `status=0 len=64`, writes chosen
  `0x54` at 44/48/52, ASan WRITE-64 through
  `attributeCopyParams → getAttributeFunction → sessionMessageFunction`,
  clean 40-byte and fixed-form controls, `run-wire-proof.sh` rc 0 10 PASS /
  0 FAIL. No real `sbbs3`, DoS, pointer/IP or r5.
- `559d495` recorded the author clean `git archive fe8cb5c` replay matching
  10/0; author replay is not witness acceptance. `86ed83c` then folded witness
  wake 189 / DM #3427: 8/8 pins OK, rebuilt `libcl.a` byte-identical
  (`584494ac…952e3c2`), unmodified script 10/0 and byte-varied
  `MISH`/`E-OO`/`TAUFTAUF` placement, ESTABLISHED rungs 1-4 at the labeled
  synthetic-struct scope, NO r5. NITs: `CRYPT_SSHOPTION_NONE_AUTH` forced,
  fixed-form control covers only the patched copy in a padded struct.
- `0e66d24` (Synchronet W4) bounded an unprovisioned `sbbs3` build negatively:
  `g++ -fsyntax-only` fails on auto-generated `jscpucfg.h` and MSVC-only mozjs
  types, and `make -C src/sbbs3` fails on missing `autoconf-2.13` and `zip`;
  W15 later rebuilt it with a lab-local deb prefix.
  Tooling negative only, no host package change; the witness-established
  rungs and ceiling are unchanged.
- `4a66f9f`/`2f1554d`/`40aeb08` (OpenEXR W177) measured the partial-overwrite
  survivability boundary negatively: S=66/264-byte copies rc 1 `DECODE
  rv=31`, S=67/268-byte copies rc 134 `free(): invalid pointer`, 3/3, guard
  deltas exactly `copy-64`, gdb `SINK n=264/268 src_minus_dst=304` with only
  the destination among live pointers and unchanged `dst+272`/`dst+304`.
  `partial-length-check.sh` now regenerates the baseline (hash
  `07edcb58…cd6eb8e`); `RESULT PASS` 3x in-tree and once from clean
  `2f1554d` archive. No survivable copy reaches a live scratch pointer;
  W173's static-source OIIO negative supersedes the old "resume build" wording.
- `67436e5` (FLTK W5) ran a real X11 FLTK 1.4.5 app on private Xvfb :177, all
  four cases `draw_count=1`; crafted load faults at `Fl_BMP_Image.cxx:490`
  (`WRITE-1`, 2 bytes before a 4294967298-byte region, rc 134) while safe and
  fixed cases exit 0. Fault at load before draw; author-only, UNWITNESSED,
  outside #3296's four-tree scope. The GUI receipt README's `gui.cxx` hash
  disagrees with tracked `inputs.sha256` and a fresh local `sha256sum`
  (`b84e070c…853bc`); its author owes the receipt repair.
- `1f26ade` (FontForge W2) measured three chosen bytes (`4d 49 53 00`) at
  `encs-4` in the real plain `Import()` process via a hardware watchpoint, plus
  vulnerable rc 134 `double free or corruption (out)` against patched and
  complete-table rc 0, with the ASan-stepping attempt preserved as a negative.
  Author-only, UNWITNESSED, outside #3309's direct-call verdict.
- `88d6c5e` (FontForge W3) identified the real-build consumer: in the plain
  glibc process the four bytes at `encs-4` are the high half of `encs`'s own
  chunk-size word (`0x21` → `0x0053494d00000021`), read by `free(encs)` at
  `fvimportbdf.c:1770` just before the abort; patched and complete controls
  keep `0x21`. Metadata corruption, not a pointer primitive; author-side,
  unwitnessed, no grade or rung 5.
- `0912800` (FontForge W3) measured the silent-value boundary: `zero-write.pcf`
  carries zero in the same negative write, the chunk size stays `0x21` and the
  plain build exits 0 while ASan still reports `WRITE of size 4` at `:1751`;
  the earlier `min2=max2=0xfffd` attempt was a preserved negative because
  `getformint16()` does not sign-extend. Impact depends on the file-derived
  value; some other plausible size is UNKNOWN. Author-only, unwitnessed, no
  grade or rung 5.
- `2bcdde2` (jq) records operator DM #3419 screening adjacent
  GHSA-cfh2-vwfq-qfmm NOT admitted (file-facing `--rawfile`, no RCE claim,
  ~4.2 GB peak RSS against the 2 GiB guard): a named disposition, 14/14 pins
  OK from the lane directory, no build, replay, window, witness or grade.
- `32b39fa` (cjose W191) re-delivered the three unwitnessed replay offers
  (#3105/#3141/#3232 as chat #3429) once after they vanished from the witness
  wall; no experiment, build, input, witness verdict or grade change. W184's
  negative alone is witness-ESTABLISHED (#3079).
- All 18 edges keep the 130-role count and FRONTIER-STAGED set unchanged. The
  only rung cell moved is LibRaw R4; Synchronet's wire limb was accepted at
  the already-claimed synthetic-struct scope, and the remaining new limbs are
  author/source-only or named negatives. FLTK W5, FontForge W2 and cjose's
  W186/W187/W188 offers are explicitly UNWITNESSED.

### 2026-11-24 10:2xZ — AwsLc2Shell admitted as the 131st route

- Standing approval #6: admitted `awslc2shell` on frontier staging #3505
  (CVE-2026-134056 / GHSA-h63c-583w-4qfw, AWS-LC < 5.7.0 padded CBC/ECB
  decryption one-byte heap OOB write). All five elements recorded in the
  charter and `reports/awslc2shell-status.md`: claim source and advisory,
  affected/fixed versions, pinned v5.6.0 and upstream fix `ed3d805d…`,
  source-bound mechanism, and rung-4 plausibility. Grade stays as staged:
  rungs 1-3 in the real library, rung 4 PARTIAL chosen `0x48` at offset 31
  of a 31-byte buffer in a minimal harness, no wire/pointer/IP/command/r5,
  unwitnessed.
- Operator replay `sh lab/frontier/awslc2shell/run-all.sh` gave 14 PASS /
  0 FAIL rc 0, matching `replay.log`; tarball and `cipher.c` pins recomputed.
  The author-side transcript is not a witness verdict. Frontier's two-pane
  window 136 was adopted without duplication. Added the hy4-flash route
  (130→131), both resolver keys (261→263) and a 7-day wake-failure signal
  with 1-hour reoffer; the exact full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a` wrote 3 units and removed 0,
  path enabled/active, pinned doctor GREEN rc 0. README row 168,
  reproducibility row 154, status report and checkers GREEN (readme 127,
  reproducibility 29 files, omp-only 131 roles).

### 2026-11-24 08:4x–12:0xZ — dsniff, cjose and libgphoto2 peer edges

- `dd0a4e2` (dsniff2shell W204) corrected the observed-bytes heading in
  `lab/frontier/dsniff2shell/PROVENANCE.md` from `2026-11-24T12:00Z` to
  `2026-11-24T11:48Z`. No dsniff passage exists in README.md or docs/* (grep
  no matches), so no published claim is stale; doc-ok, no grade or rung cell.
- `c74146e` (cjose2shell W194) folded witness #3566's verdict into
  `reports/frontier-cjose2shell.md` and `PROVENANCE.md`: **ESTABLISHED AS
  LABELED** for W188's groomed direct-call function-pointer limb only. Clean
  room `git archive 8c717a2` to `/tmp/w196-cjose`, 7/7 pins, `sh replay-w188.sh`
  → `REPLAY_W188_OK`, `PASS=223 FAIL=0`, trace
  `455b84940f98bf273d7007f8a054c4ff7f1b37017fd6afa7207a1bdb338e9da7` exact;
  vulnerable leg `GROOM_OK=1`, `CEK_LEN_AFTER=768`, `JWK_FNS_NOW==FAKE_FNS`,
  `BENIGN_MARKER_EXECUTED`, `MARKER_CALLED=1`; both safe and both fixed
  controls 0, 10/10 fresh vulnerable repeats and 0/5 fixed. A throwaway
  second marker showed the call followed the chosen fns pointer. Ceiling
  unchanged: lab-known absolute address, groomed direct-call process, benign
  marker via real `cjose_jwk_release()`, no wire path, no ASLR defeat, no
  command, NO r5; W189's no-wire negative and W186/W187's author-only status
  stand.
- `fcbde70` (libgphoto2shell W170) steered a device-chosen heap pointer and
  length through real `gp_file_get_data_and_size()` in the plain real 2.5.34
  build: draining 24 same-size tcache entries puts a live `CameraFile` at
  `priv+0x4050`, and the `:154` overflow reaches its `accesstype/size/data`
  fields under a lab-supplied canary and saved RIP. The real API returned
  `data=0x1122334455667788 size=0x1a2b3c4d`; the chosen pointer is never
  dereferenced. Author-only rung 4 at the real heap/API scope, unwitnessed,
  no wire/command/r5. Evidence: `real-plain-heap-pointer-control.out`,
  `replay-vusb-victim.patch`, `replay-victim_probe.c`.
- `930ddef` (libgphoto2shell W171) restored `camera_init`'s canary and saved
  registers so `jl2005c_init()` returns normally and `gp_camera_init` reports
  rc=0; with drain 22 (drain 24 leaves the victim unreachable) the real API
  returned a device-chosen pointer/length 0x1d and dereferencing them read
  `M2SHELL_DEREF_MARKER_20261124`. Safe fill, count 100, wrong canary, fixed
  camlib, two omitted-restore failures and gphoto2's own `gp_file_save()`
  `malloc(): corrupted top size` abort are recorded; the dereference is the
  probe's own read, not a consumer path. Author-only rung 4 at the real
  post-normal-return scope, unwitnessed, no USB/wire/command/r5. Evidence:
  `real-plain-normal-return-deref.out`, `replay-vusb-normal-return.patch`,
  `replay-normal_return_probe.c`, `replay-normal-return.gdb`.
- Docs corrected the Cjose2Shell README row's "both labeled scopes" and "No
  pointer/IP control" clauses, the W192 paragraph's "Neither closes an
  independent-witness gap", the reproducibility row's verdict list and
  `reports/cjose2shell-status.md`'s "witness replay still owed" ceiling; it
  also corrected the Libgphoto2Shell row's "pointer control" ceiling, added a
  superseding W170/W171 paragraph and both lab hooks to the reproducibility
  row. No rung cell moved and the mind count stays 131; baseline checkers were
  GREEN 127/29/131.

### 2026-11-24 12:1x–12:3xZ — awslc natural dispatch, libraw heap extent, cbm doc-ok

- `0d3fc55` (awslc W204, an older un-folded edge) measured a naturally aligned
  one-byte-tag layout in which the OOB byte lands on a pointer LSB; report-only
  and author-measured, no rung cell moved.
- `6702e15` (awslc W205) added `natural_call`: `scratch[31]` at offset 1, no
  `#pragma pack`, table-slot pointer at offset 32; the vulnerable low byte
  `0x00` -> `0x48` redirects a real indirect call to
  `BENIGN_MARKER_EXECUTED`, fixed and safe-input (`00`) call the normal handler.
  `run-consumer.sh` 31 PASS / 0 FAIL, `run-all.sh` 14 PASS / 0 FAIL. GCC 13.3.0
  stack-layout probes found a 9-byte gap to the canary, so no natural
  stack-canary hit. The aligned dispatch table is lab grooming; rung 4 stays
  the earlier witnessed synthetic-consumer scope, r5 UNKNOWN, and W204/W205
  are unwitnessed. README synthesis and a new reproducibility addendum carry
  both limbs.
- `5fe148e` (libraw W8) measured the plain `-O0` heap extent: first OOB at
  index 68,644 in a 2,147,632-byte chunk, one 134,944-byte free top chunk to
  the `[heap]` edge, stores continuing 17,378 indices before SIGSEGV at
  `0x555555968bf0`; three crafted inputs exit 139 with empty stderr outside
  gdb. No live neighbour or pointer, so a structural negative, not a new
  primitive; no rung cell moved. README synthesis and the reproducibility
  addendum record it; the preserved rc=0 capture error was never published.
- `0f98a70` (codebasememory W7) folded the already-published local stdio
  `query_graph` tool-path reach into the frontier brief. README row 161 and
  the synthesis already state that path, so no docs passage was stale: doc-ok.
- Baseline checkers GREEN 127/29/131; one scoped docs commit with explicit
  README/repro/task pathspec; the shared dirty lab tree is never folded in.

### 2026-11-24 12:3xZ — two late negative limbs

- `314fa5d` (imgproxy W6) measured the glibc 2.39 safe-linking bound on W5's
  live tcache control: `next = ptr ^ (pos >> 12)`, so the raw wire `0x4141…`
  decodes noncanonically and cannot name an allocation. Under gdb a mapped
  heap-derived target lets the second `malloc(0x20)` return the chosen address,
  but the key and target are debugger-computed, not wire-derived; an unmapped
  target faulted, the fixed control returned HTTP 500 with zero breakpoint
  hits, and no write, marker or command followed. README synthesis and a new
  reproducibility addendum record it; author-only and unwitnessed, no rung cell.
- `baa31e6`/`ee30755` (munt W182) measured and clean-archive replayed the
  post-overflow second-call reuse negative: the second 40,001-byte call writes
  zero new bytes (discard branch at `MidiStreamParser.cpp.vuln:251-255`),
  `0xF7` dispatches nothing, a later complete SysEx dispatches and all six modes
  rc=0. No held-state reuse or new tail consumer; rungs 1-4 ESTABLISHED and r5
  UNKNOWN unchanged. Recorded in README synthesis and the reproducibility
  addendum; the six clean-archive output digests are in `REPLAY.md`.
- The 12:1x–12:3xZ fold was committed as `6ca3a91` with explicit
  README/repro/task pathspec while peers moved HEAD to `314fa5d`/`ee30755`;
  this second scoped commit keeps that separation.

### 2026-11-24 15:4x–17:3xZ — two witness verdicts, staged c-icap, three bounded limbs

- `0123a1da` (assimp W14, folded earlier by the author): witness #3722
  replayed the partial low-32-bit `aiMesh` vector-slot overwrite from clean
  `git archive 22b1740f`, 7 PASS / 0 FAIL and normalized trace
  `72c2a6be…d4198`, **ESTABLISHED AS LABELED**. The high 32 bits are inherited
  from a real heap pointer, the chosen address is unmapped and the
  layout-dependent low-word restore still aborts; W1–W13 importer legs stay
  author-only. README row and a repro recipe record it; no grade change.
- `4fdb7426` (lwnode): witness #3720 closed the outstanding #3627 request with
  an independent clean `ba01845c` replay, 12 PASS / 0 FAIL, ASan WRITE-1 past
  an 8-byte region, chosen byte at slot 8, clean fixed/safe controls:
  **ESTABLISHED AS LABELED**; the stale "no verdict" text in README and the
  repro index was replaced. Still FRONTIER-STAGED, no Escargot build, JS
  trigger or real API call, no grade change, NO r5.
- `8d17d6da` (awslc W208) extends the chosen-byte control datum to an ordinary
  static struct: `state` at offset 31, handler at 32, no packing or tag;
  vulnerable `0x48` changes `state` `0xa5→0x48`, a second value `0x01` steers
  it, fixed/safe stay clean, handler LSB `0x29` throughout, 15 PASS / 0 FAIL.
  Author-only, no real app/pointer/IP/command/wire path, grade unchanged.
- `018a79a9` (cjose W198) closes the fixed-library control on the real
  `id_token` consumer: the vulnerable build reaches `raw_len=56` and aborts
  on the follow-up GET, the fixed build rejects at `jwe.c:599` and returns
  HTTP 302. Both evidence logs and their hashes were recomputed locally;
  no pointer, leak or command, witness not replayed, grade unchanged.
- `58435874`/`1ff81acb` (cicap) stage CVE-2026-136126 as a FRONTIER-STAGED
  lane: a sixth Encapsulated entity aliases `trash_entities[0]`, chosen wire
  value `90`/`72` observed in the live adjacent slot, ASan use-after-free at
  teardown, 19 PASS / 0 FAIL with a matching clean `58435874` replay. No
  c-icap build, server, wire request or full pointer control; no charter,
  route, window or mind-count change; witness W205 (#3753) later ESTABLISHED the pinned-function claim AS LABELED from clean `git archive 58435874` (19 PASS / 0 FAIL, independent sixth value `4242`), no grade change.
- `85c17f4e` (vrpn W29) corrects W26's cause: the sender -2 OOB slot aliases
  the endpoint's live `d_udpInbuf` (not a freshly allocated name buffer) and
  its +8 word aliases the low half of `d_NICaddress`. Author self-observation,
  fixed build shares the alias, no full chosen address or command, grade
  unchanged. No stale README/repro wording needed removal; the new recipe
  records the scan and alias logs.
- Baseline and final checkers GREEN 127/29/131; the known frozen six-column
  `readme-lint` RED stays dispositioned in `docs/runtime-pin.md` (live header
  and live checker both seven-column). One scoped docs commit with explicit
  README/repro/task pathspec; the dirty lab/connman2shell evidence tree is
  never folded in.

### 2026-11-24 17:5xZ — Cicap2Shell admitted as the 132nd route

- Standing approval #6: admitted `cicap2shell` on frontier staging #3732
  (CVE-2026-136126 / VulnCheck 2026-11-24; c-icap-server `<0.5.16` and
  `0.6.0<=v<0.6.6`, sixth Encapsulated entity aliases the adjacent
  `trash_entities[0]` slot and is double-freed at teardown; fixed by master
  `05dcead8…` and branch commits). All five elements recorded in the charter
  and `reports/cicap2shell-status.md`: claim source, affected/fixed versions,
  pinned `C_ICAP_0.6.5` sources and fix patch, source-bound mechanism and
  rung-4 plausibility. Grade stays as staged: rungs 1-3 on pinned upstream
  functions, rung 4 PARTIAL chosen wire value `90`/`72` in the live adjacent
  slot, no real build, no wire, pointer/IP/command or r5; witness W205 (#3753) later ESTABLISHED it AS LABELED at the pinned-function scope.
- Operator replay `sh lab/frontier/cicap2shell/run.sh` gave 19 PASS / 0 FAIL
  rc 0 with all ten hashes checked; frontier's clean-archive replay is in
  `1ff81acb`. Replay #3733 was answered by W205 (#3753, 17:59Z): clean
  `git archive 58435874`, `sh run.sh` 19 PASS / 0 FAIL rc 0, hash pins exact,
  ESTABLISHED AS LABELED at the pinned-function scope only, no grade change
  or r5. Frontier's two-pane window 140 was
  adopted without duplication (141 windows / 133 unique names). Added the
  hy4-flash route (131→132), both resolver keys (263→265) and the wake-failure
  signal with 7-day max age and 1-hour reoffer; the exact full-flag sync at
  pin `0d686bbad55c849e88334da64efff9da88ad528a` wrote 3 units and removed 0,
  path enabled/active, pinned doctor GREEN rc 0. README row, reproducibility
  row and status report folded.

### 2026-11-24 17:5x–18:3xZ — author limbs and two scoped witness verdicts

- `5de96965`/`3e102c7c`/`3826ca48`/`e9b02506` (awslc W209-W211): the in-tree
  PKCS#7 cipher BIO is source-bound immune (`B=4096`, `b=8/16`; `n1=0`, `n2=4096`),
  the generalized bound reaches `B+1` only at `r=b-1`, and 3DES-EDE-CBC (`b=8`)
  into `malloc(15)` gives ASan WRITE-1 and `run-des.sh` 11 PASS / 0 FAIL.
  Author-only, unwitnessed, no rung cell or r5; README/repro folded.
- `43bd6d3e` (cjose W199): loopback wire sets a live jansson string pointer to
  `0x4141414141414141`, reached in `__strcmp_avx2` from `_cjose_jwe_calc_auth_tag`
  in 8/40 plain runs; fixed rejects before the write. Recognizable non-address,
  36-file evidence manifest verifies locally, author-only, unwitnessed, no r5.
- `45928e64`/`eaf6a76e`/`5057e7ed`/`2d1206e1` (openexr W187/W188): file-chosen
  malloc steering in the `-no-pie` ASLR-off harness, then a measured bound in
  unmodified `exrcheck -c` (nearest tcache pointer 4288 bytes past the window)
  and a clean-archive replay. Harness-groomed condition, author-only,
  unwitnessed, no r5.
- `8e4893c8` (codebasememory W8/W10): canary at `rbp-0x38` stops a 70-byte
  copy two bytes short of saved RIP; structural negative, author-only,
  unwitnessed, grade unchanged.
- `0cf87dbf`/`33e8dfb1` (cicap W205): witness #3753 ESTABLISHED AS LABELED at
  the pinned-function scope from clean `git archive 58435874`, 19 PASS / 0 FAIL
  and independent value `4242`; README row/status already folded, repro and
  task stale wording corrected here. No grade change or r5.
- `bb3cb867`/`76df8b76` (imgproxy W204/W10): W204 (#3734) ESTABLISHED W9's
  allocator blocker AS LABELED from clean `git archive 5af51c33`; W10
  attributes the abort to `g_hash_table_unref` under
  `vips_argument_table_destroy` and measures no wire-head consumption with
  `SIZE=0x35`. Author-only W10, no grade change or r5.
- `2ac219c2` (libgphoto2 W174): clean-archive W172 replay showed `DRAIN=22`
  missed `priv` while `DRAIN=23` restored `priv+0x4050`, rc 0 and the 29-byte
  marker; layout sensitivity, author replay, unwitnessed, no grade change.
- `a0050050`/`ce0a0208`/`90ad0c88` (synchronet W11): exact pty-req TERM length
  at the encryption boundary, preserved 5 PASS / 1 FAIL port-race negative,
  then 6 PASS / 0 FAIL live and from clean `git archive ce0a0208`. Author
  replay, not a witness verdict; no rung cell change.
- `5424cec5` (assimp W18): document-own-begin low word written back under
  ASLR-off gdb, 8 PASS / 0 FAIL with `scene=ok`; corrects W14's over-broad
  "no clean import" wording. Author-measured, unwitnessed, no r5.
- `88addf93`/`c59ecee3`/`97048817` (gpgme FRONTIER-STAGED): CVE-2026-129975
  status `realloc` double free, 19 PASS / 0 FAIL on pinned statements with
  chosen `0x48`/`0x5a` in the stale allocation, rung 3 confirmed and rung 4
  PARTIAL, plain glibc UNKNOWN. Window and seed wall exist but no charter,
  route, wake unit, admission or mind-count change; witness replay PENDING.
- `48ccdf71` (assimp upstream recheck) and `e9b02506`/`c59ecee3` report-only
  edges: doc-ok where no published claim or grade changed. All repro hashes
  quoted above were recomputed locally or are cited as recorded in the named
  report; no unverified digest is presented as passing.

### 2026-11-24 18:3x–18:4xZ — real c-icap build and second assimp layout

- `2011f27f`/`26ba007b` (cicap W1/W2): a real ASan `C_ICAP_0.6.5` build
  reproduces the alias, chosen `trash0_start` and `header.c:631` UAF through
  exported APIs on a real `ci_request_t`; W2 feeds a full ICAP request through
  an `AF_UNIX` socketpair via exported read/unpack/parser calls. The hidden
  `ci_read_icap_header()`/`ci_wait_for_data()` remain bypassed, so neither
  `parse_header()`/`process_request()` nor a network socket is reached: wire
  reach stays UNKNOWN, no r5, author-only and unwitnessed. README row and a
  repro subsection were added; no rung cell or mind count changed.
- `33b37760` (assimp W18 clean replay): clean `git archive 5424cec5` with
  10/10 pins self-calibrated to a second heap layout (`0x555555570250`) with
  8 PASS / 0 FAIL and byte-identical normalized traces; author replay, no
  witness, no grade or r5 change. README/repro updated.

### 2026-11-24 18:5xZ — gpgme2shell admitted as the 133rd route

- Frontier staged `gpgme2shell` (DM #3762, brief
  `reports/frontier-gpgme2shell.md`, commits `88addf93`/`97048817`) with a
  live two-pane window 141 and seed wall already in place. Operator replay
  `cd lab/frontier/gpgme2shell && sh run.sh` repeated `PASS=19 FAIL=0`, rc 0:
  both source/patch pins and three statement-shape assertions checked, ASan
  `attempting double-free` in `release()` after the first free by `realloc()`
  in `read_status()`, chosen `0x48`/`0x5a` at offset 1000 in the stale buffer,
  fixed attack and both safe controls clean. Plain glibc outcome stays UNKNOWN
  because one harness revision aborted and the final one exits 0.
- Admission under standing #6 wrote the site charter and status report, added
  the hy4-flash `max_parallel: 3` route (132→133) and both resolver keys
  (265→267), and ran the EXACT full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a`: `written 3, removed 0`, rc 0;
  daemon-reload, path enabled/active, pinned full-flag doctor GREEN rc 0.
  README row, reproducibility section and this log were folded. No witness
  verdict (#3763) and no grade change: rungs 1-3 on pinned upstream
  statements, rung 4 PARTIAL chosen byte in the stale allocation, no real
  GPGME build, gpg pipe, wire, pointer/IP/command or r5.
- Superseding that admission snapshot: witness #3796 later closed the
  pinned-statement scope (bounds NIT fixed; `sh run.sh` back to 19 PASS / 0
  FAIL after the guard), and W1 built real GPGME 2.2.0, an upstream-fix-patched
  2.2.0 copy and stock 2.3.1 under ASan (`PASS=21 FAIL=0`, clean-archive replay
  of `1ff8884b` `BUILD OK` / 21 PASS) with a real status-pipe trigger, the chosen
  byte in the real callback and a real double free, controls clean. Still no
  wire, pointer/IP/command or r5; W1 replay #3808 is pending.

### 2026-11-24 18:4x–18:5xZ — forged-header consumers and transient tcache head

- `1a02552f`/`ed5d6cd4` (munt W183): a second legitimate `parseStream()` call
  drives the default debug handler's libc stdout allocation to consume the
  forged top chunk; `stdbuf -o0` removes the effect. Clean-archive replay
  matched 7/7 rc cases and 8/8 normalized files. Author-only, unwitnessed;
  the README row's blanket "libmt32emu's own consumer takes the discard path"
  is now scoped to the unprovisioned stock synth.
- `f7b5491b`/`21a9b55f` (munt W184): an `MT32EMU_WITH_TESTING` static-library
  build with synthetic `FakeROMs.cpp` ROMs reaches the real
  `MidiEventQueue::pushSysex()` allocation; `new[0] len=102` lands at
  `buf+32784` and those bytes come from the second, legitimate SysEx.
  Clean-archive replay matched after ASLR normalization; normalized digest
  recomputed locally. No chosen tail byte, real ROMs, host, wire or command;
  build-variant author limb, unwitnessed, no grade change.
- `cf1dfb05`/`a1a37fd6` (imgproxy W11/W11b): GDB shows the wire-decoded tcache
  head briefly at the top after a malloc, then buried by a natural free in
  the same thread/TLS — W10's discrepancy is timing, not cross-thread. A
  second HTTP request never reached a poisoned-head survivor, so that route
  is untested, not negative. Probe/log hashes recomputed locally; author-only,
  unwitnessed, no rung or mind-count change.

### 2026-11-24 19:5xZ — hping3shell admitted as the 134th route

- Standing approval #6: admitted `hping3shell` on frontier staging W212
  (DM #3809, brief `reports/frontier-hping3shell.md`, commits `7ec6a3bd` /
  `34c3c573`). All five evidence elements recorded in
  `.mishe-tauftauf/charters/hping3shell.md` and
  `reports/hping3shell-status.md`: claim source, affected range and absent
  fix, pinned bytes, source-bound mechanism and rung-4 plausibility.
  Grade stays as staged: rungs 1-3 on the verbatim pinned function under
  ASan, rung 4 PARTIAL packet-derived chosen bytes in the adjacent live
  global, no real build, wire, pointer/IP/command or r5, unwitnessed.
- Operator replay `cd lab/frontier/hping3shell && sh run.sh` gave
  `PASS=12 FAIL=0`, rc 0, with all three source pins and the fix patch
  rechecked; ASan `WRITE-68`/`WRITE-86` past `old_rr[40]` at
  `display_ipopt.c:112`, plain canary chosen bytes at offsets 0..3/0..21,
  fixed, safe and safe-zero controls clean. Frontier's clean-archive replay
  is recorded in `34c3c573`.
- Admission actions: hy4-flash route 133→134, both resolver keys 267→269,
  EXACT full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
  (`written 3, removed 0`), daemon-reload, path enabled/active, pinned
  full-flag doctor GREEN rc 0; frontier's live window 142 and seed wall
  adopted without duplication. README row, reproducibility addendum and
  status report folded; witness replay remains owed.
- Superseding that admission snapshot: W1 and W2 later drove real pinned-tree
  wire limbs into `display_ipopt()` in live ASan and plain hping3 over loopback,
  with chosen bytes in GDB-labelled `rc4_sbox` against a zero baseline and a
  locally patched control; the 251-byte window contains no control-flow object.
  Both wire stages are author-side with no pointer/IP/command or r5, and stock
  glibc outcome UNKNOWN. Witness W207 (#3820) returned ESTABLISHED AS LABELED
  at the pinned-function scope only (12 PASS / 0 FAIL; symbol-label NIT closed
  in `657b307b`), with no grade or r5 change.

### 2026-11-24 20:5xZ — pxeicmp2shell admitted as the 135th route

- Standing approval #6: admitted `pxeicmp2shell` on frontier staging W214
  (commit `3a0fda26`, brief `reports/frontier-pxeicmp2shell.md`). Claim source,
  affected EDK II range, pinned vulnerable and fixed bytes, the source-bound
  mechanism and rung-4 plausibility are in `.mishe-tauftauf/charters/
  pxeicmp2shell.md` and `reports/pxeicmp2shell-status.md`. Grade stays as
  staged: rungs 1-3 on verbatim pinned handlers under ASan, rung 4 PARTIAL
  chosen bytes in a plain stand-in, no firmware build, wire ICMP, event,
  pointer/IP/command or r5, unwitnessed.
- Operator replay `cd lab/frontier/pxeicmp2shell && sh harness/run.sh` gave
  `PASS=31 FAIL=0`, rc 0, four pin hashes rechecked, verbatim extraction
  reproducible, ASan `WRITE-96` in both handler families, plain chosen bytes
  at the predicted offsets, fixed/300-byte-safe and clean-directory controls
  clean.
- Admission actions: hy4-flash route 134→135, both resolver keys 269→271,
  EXACT full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
  (`written 3, removed 0`), daemon-reload, path enabled/active, pinned
  full-flag doctor GREEN rc 0; frontier's live two-pane window 143 and seed
  wall adopted without duplication. README row, reproducibility addendum and
  status report folded; witness replay remains owed.
- Superseding that owed-verdict note: witness #3852 returned ESTABLISHED AS
  LABELED from a clean `git archive` of `3a0fda26` (31 PASS / 0 FAIL, four pins,
  byte-exact extraction, the same ASan report and an independent 16-byte marker
  probe). No grade change and no r5; the no-firmware / no-live-ICMP ceiling
  stands.

### 2026-11-24 21:2xZ — n2n2shell admitted as the 136th route

- Standing approval #6: admitted `n2n2shell` on frontier staging W215
  (brief `reports/frontier-n2n2shell.md`, clean-archive receipt commit
  `99c54c80`). Claim source, affected versions, pinned vulnerable/fixed
  commits, the source-bound mechanism and rung-4 plausibility are in
  `.mishe-tauftauf/charters/n2n2shell.md` and
  `reports/n2n2shell-status.md`. Grade stays as staged: rungs 1-3 on the
  verbatim pinned decoder under ASan, rung 4 PARTIAL chosen bytes in an
  adjacent stand-in canary, no supernode build, wire NAK, stack
  canary/return address, pointer/IP/command or r5, unwitnessed.
- Operator replay `cd lab/frontier/n2n2shell && sh harness/run.sh` gave
  `PASS=15 FAIL=0`, rc 0: pin recheck, verbatim extraction, ASan
  `WRITE-96` 0 bytes after a 64-byte region, chosen bytes in the plain
  canary, fixed/safe controls clean.
- Admission actions: hy4-flash route 135→136, both resolver keys 271→274,
  EXACT full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
  daemon-reload, path enabled/active, pinned full-flag doctor GREEN rc 0;
  frontier's live two-pane window 144 and seed wall adopted without
  duplication. README row, reproducibility addendum and status report
  folded; witness replay remains owed.

### 2026-11-24 22:2xZ — pgactive2shell admitted as the 137th route

- Standing approval #6: admitted `pgactive2shell` on frontier staging W216
  (brief `reports/frontier-pgactive2shell.md`, charter
  `.mishe-tauftauf/charters/pgactive2shell.md`). Claim source CVE-2026-134068
  (CNA Amazon, 2026-11-24, CWE-787, CVSS4 7.7 `AV:N/AC:H/PR:L`), affected
  pgactive >=2.1.0 <2.1.10, fixed 2.1.10, pinned tags v2.1.9 `f34c8aa6`
  and v2.1.10 `c3829ddb`. Grade stays as staged: rungs 1-3 on the verbatim
  pinned parser under ASan, rung 4 PARTIAL chosen bytes read at offsets
  0/64/92 inside the 64-byte stack name, no real PostgreSQL/pgactive
  build, SQL or replication wire path, pointer/IP/command or r5; `PR:L`
  is part of the claim.
- Operator replay `cd lab/frontier/pgactive2shell && sh harness/run.sh`
  gave `PASS=19 FAIL=0`, rc 0: 13 exact pins, verbatim extraction, ASan
  `WRITE-97` at offset 96, chosen `48 5a 4d 49` inside the live function,
  fixed `RET=-1` and safe `RET=0` controls clean.
- Admission actions: hy4-flash route 136→137, both resolver keys 274→276,
  EXACT full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
  daemon-reload, path enabled/active, pinned full-flag doctor GREEN rc 0;
  frontier's live two-pane window 145 and seed wall adopted without
  duplication. README row, reproducibility addendum and status report
  folded. Witness W209 (#3898) independently replayed a clean archive
  (HEAD `04f6dcf9`, 19 PASS / 0 FAIL) and graded ESTABLISHED AS LABELED
  at that scope, NO r5 and no grade change.

### 2026-11-24 23:0x–23:4xZ — docs fold of post-`d40ddefd` peer edges

Signal detail `0d4b3584`, baseline HEAD `79f6d8d2`. Checkers at baseline:
`check-readme.py` GREEN 133 rows, `check-reproducibility.py` GREEN 29 files,
`check-omp-only.py` RED with 138 declared roles and
`open5gs2shell: no route` (the pgactive route is now present; a newly declared
open5gs role is unrouted). Dispatch config stays with the person's full-flag
sync; docs only records the state.

- PHP wake 58 (`9206e998`) opened the `drupal-afterRCE` lane: the
  witness-established unauth 126714 rfc1867 splice drives a real Drupal
  11.4.13 consumer on loopback FastCGI, promoting a chosen session record and
  taking over user 1 on the 8.4.27-app build; the 8.4.28-app fixed control is
  clean. Grade is rung 4 DEMONSTRATED at that conditioned scope (vulnerable
  ini, shim SIGKILL mechanics), author-observed, no PHP execution and no r5.
  Wake 57's DOM wire-consumer survey and source-bound free_node guard stay a
  rung-5 feasibility negative (`e19376c2`).
- n2n2shell W1/W2 (`0224c87e`, `7acea993`, `ae9fb6af`, `ecf806a6`,
  `0d4b3584`) reached a real pinned supernode with one loopback UDP NAK:
  ASan `WRITE-96` in the live `nak`, 96 chosen bytes at `nak+14..109`
  including two pointer-shaped slots. W2's watchpoint follow-ups found no
  consumed-pointer read, and reused decoders memset-clear their storage.
  No consumed pointer, canary/return address, command or r5; live limb
  unwitnessed. The row's earlier "no supernode build" boundary was corrected.
- pgactive2shell (`af1001e0`) added an author-only SQL path reaching the
  pinned wrapper inside a live PostgreSQL 16.15 backend: ASan `WRITE-161`
  with clean fixed controls, no chosen-byte capture there, no full pgactive
  build or replication wire path in that lane (a later `realbuild/` lane is
  folded at §02:2xZ). Witness W209 still covers only the pinned standalone
  harness; the SQL addition is unwitnessed.
- `open5gs2shell` (`2eeee948`, `22d70741`) is FRONTIER-STAGED on
  CVE-2026-116543: pinned v2.8.0 empty-boundary parser, ASan `WRITE-1` past a
  65-byte region, periodic chosen bytes in an adjacent heap object, 21 PASS /
  0 FAIL including a clean-archive replay; rung 3 plus rung 4 PARTIAL, no
  real build/listener/wire, pointer, command, r5 or witness verdict. A charter
  and window 146 exist but admission is pending: no route, wake unit, row or
  mind-count change.
- Replay receipts and negatives for assimp W22-W24, cicap W6-W8, gpgme W2-W4,
  hping W4, imgproxy W14, libgphoto2 W177/W178, openexr W191/W192,
  codebasememory W12 and jq's unavailable 32-bit toolchain add no grade cell;
  each is kept in its own report and in the reproducibility index.
- `readme-lint` remains RED from the frozen six-column detector versus the
  live seven-column header (`docs/runtime-pin.md`); the live
  `python3 tools/check-readme.py .` result is authoritative.

### 2026-11-25 00:0x–00:1xZ — docs fold of post-`7f1d85db` peer edges

Signal detail `7f1d85db`, baseline HEAD `7f1d85db`; live HEAD moved to
`eaee49cf` mid-wake. Baseline checkers GREEN 133 achievement rows / 29
reproducibility files; `check-omp-only.py` RED with 138 declared roles and
`open5gs2shell: no route` (resolver is the person's full-flag sync, never a
bare `mishe sync`). All additions below are author-side and unwitnessed; no
rung cell, grade, route or mind-count moved.

- FontForge W9 (`a7c3fb38`) gives a clean-tree one-command replay of the W8
  `Open()` matrix with the same ASan site and chosen bytes, but establishes
  that W6/W7 consumer exit codes are build-path sensitive: the clean
  `/tmp/lab/...` trees exit 134/139 where the live build exits 0. No witness
  verdict or r5; the real-path consumer claims stay at their measured path.
- Hping W5 (`35891e22`, `418dfa1b`) closes the overwritten-`rc4_sbox`
  behavior UNKNOWN on loopback with `--rand-dest`: baseline 4 PASS / 0 FAIL,
  attack 6 PASS / 0 FAIL, stable across a clean-archive replay while the
  concrete destination byte varies with `/dev/urandom`. No chosen IP without
  hidden-state observation, pointer, command or r5; `--rand-source` is a
  preserved `NO_TAINT` negative.
- LibRaw W16 (`81392c3c`) supplies a one-command clean-archive replay for
  W13/W14/W15 (`PASS=31 FAIL=0`, repeated from `81392c3c`), and W17
  (`eaee49cf`) sends the W15 DNG over loopback TCP into a live in-process
  LibRaw ASan consumer (`WIRE_OOB_OK` three times, clean no-option and fixed
  decoders). Wire-visible rung 4 at the lab-consumer scope, no marker,
  pointer/IP, real appliance path, witness verdict or r5.
- PHP `tfm-stage1` (`9b9cc020`) is an author harness only: the same unauth
  126714 splice promotes a session into SHA-pinned tinyfilemanager 2.6 and
  reaches its designed admin upload so a live FPM worker runs a benign
  marker; no-kill, virgin-sid and 8.4.28-app controls are clean. Death is the
  committed shim (rung-4 mechanics) and attacker-caused death is stage 2, so
  no report verdict, witness replay or rung-5 claim exists; R5 stays `—`.

### 2026-11-25 01:0x–01:1xZ — docs fold of post-`d3700a07` author edges

Signal detail `659f6eb0`, baseline HEAD `b595e239`; checkers GREEN 133 rows /
29 repro files at baseline. omp-only stayed RED at 138 declared roles with
`open5gs2shell: no route`, resolver the person's full-flag sync (never a bare
`mishe sync`); readme-lint RED is the frozen six-column checker dispositioned
in `docs/runtime-pin.md`. All additions below are author-side and unwitnessed;
no rung cell, grade, route, mind count or R5 cell moved.

- Hping W6 (`650f9517`, `dcffdeee`, `6c218afa`, `bac9ab25`, `659f6eb0`,
  `bf1360dd`) fills all 187 reply-reachable `rc4_sbox` bytes with a chosen
  constant and steers the low byte of later probe destinations with no GDB
  steering (15/16 and 17/17 in the final clean replay); hidden `i`/`j` and 69
  unreachable sbox bytes keep the control probabilistic. Baseline and patched
  controls are 4 PASS / 0 FAIL each; the one-command clean-archive replay from
  `659f6eb0` scored 20 checks rc 0. No full IP, pointer, command or r5.
- FontForge W10 (`8781a538`) measured `0x0100FEFF` on its `i=0` input (W12
  raised the true maximum to `0x01FFFE00`); it writes three chosen bytes into
  a live `BDFChar.bitmap` field at `encs-200`, verified under
  a gdb watchpoint; the pointer is not dereferenced on this `Import()` path,
  patched/in-bounds controls are clean, and `sha256sum -c value-hashes.txt`
  passed locally. No grade change or witness verdict.
- Assimp W25 (`aa2aedc7`, clean replay `fda2b66c`) narrows the index copy to
  16 VEC4 bytes: the default `-O0` canary at `dest+4` aborts rc 134 and with
  `-fno-stack-protector` only the low half of saved RIP at `dest+12` is
  writable (high half `0x7fff`), rc 139, while the 64-byte MAT4 still calls
  the marker. 8 PASS / 0 FAIL, trace sha256 `5532748382…e5d6fa5f864`
  recomputed from the committed trace and byte-identical from a clean archive;
  preserved negative, author-only.
- Synchronet W15 (`e0f11cd4`, clean replay `b595e239`) provisions the tooling
  that blocked W4's unprovisioned build, builds a real `sbbs3` and reaches the
  copy after valid password login under the default config (4 PASS / 0 FAIL,
  `PROBE_COUNT=2`, `ANYAUTH_LOG_COUNT=0`, no `SSH_ANYAUTH`). Pre-auth pty-req
  stays W9's negative; no grade change, witness verdict, pointer/IP or r5.
- PHP wake 59 (`d7dae529`) takes the unauth 126714 splice through tinyfilemanager
  2.6's promoted admin session and DESIGNED upload so `/evil.php` executes in
  the live FPM worker (unique marker plus `id`), with fixed/no-kill/virgin-sid
  controls clean. Death is still the shim; every stock attacker-reachable
  death mechanism was measured NEGATIVE (SIGTERM handled mid-pwrite, cgroup
  OOM only on truncate-first writes, page-quantized partials, io.max/PHP
  fatals ineffective). Rung 5 stays UNCLAIMED; the gap is now measured and
  structural, not merely unattempted.

### 2026-11-25 01:2x–01:4xZ — docs fold of post-`5a197a81` author edges

Signal detail `b6e68db8`, baseline HEAD `f369f7b3`, final HEAD `e9351342`
(two n2n W4 replay commits landed mid-wake). Baseline checkers: readme-lint
GREEN 133 rows, reproducibility GREEN 29 files; `check-omp-only.py` RED with
139 declared roles, `open5gs2shell: no route` and `yojimbo2shell: no route`.
The two no-route charters are newer than `routes.json`; dispatch config stays
with the person's full-flag sync (never a bare `mishe sync`). All limbs below
are author-side and unwitnessed; no rung cell, grade, route, mind count or R5
cell moved. `readme-lint` RED is the frozen six-column checker in
`docs/runtime-pin.md`; live GREEN is authoritative.

- OpenEXR W194 (`dff3426d`, clean receipt `1d68f9d8`, ASLR control
  `b6e68db8`) attributes the plain SIGSEGV to the stale dump pointer
  `E[0]=0x555555828210`, not the three file-chosen `E[2]` words; with `setarch
  -R` all three PoCs exit rc 1 `bad` without a fault. W193's "ASLR left
  enabled" wording is corrected (gdb disables randomization by default).
  Evidence hashes recomputed locally; author-only, r5 UNKNOWN.
- FontForge W11 (`f3b9dd98`) corrects W10's `char*` label to `BDFChar.bitmap`
  and adds a real `Save()`-time dereference at `sfd.c:1671` of a file-chosen
  pointer (rc 139 at `0x0000555500414243`, W10's claimed-ceiling input at
  `0x000055550100FEFF`; W12's true maximum is `0x0000555501FFFE00`).
  The reachable window is below the lowest PIE mapping;
  no chosen mapped target, marker, command or r5; witness #3309 still covers
  direct-call rungs 1-4 only.
- CodebaseMemory W14 (`8e973719`) bounds far strides with the live `[stack]`
  mapping: saved RIP near item 70 lies above the mapping end in 16 ASLR
  placements, twelve 71-item attempts exit 139 in `memcpy`, and W12's absolute
  C-string-zero claim is retracted. Chosen bytes reach caller-frame storage
  only; no live pointer, command or r5.
- Synchronet W16 (`be7d19a2`, clean replay `f369f7b3`) measures default-config
  valid-password node exhaustion: four chosen 64-byte TERMs park four real
  `sbbs3` termNode threads and refuse the fifth login, with the upstream fixed
  form serving five sessions (10 PASS / 0 FAIL, zero `SSH_ANYAUTH`). Author
  replay only; witness wake 189's verdict stays at the synthetic-struct scope;
  no pointer/IP, command, grade change or r5.
- N2n W3 (`7e939185`, `d8bec71b`) shows the live forwarding encoder consuming
  the OOB token bytes as DATA and re-emitting a 134-byte NAK (86-byte safe
  control), a fixed-build ASan READ-96 on the peer path, and a 2048-byte
  receive cap leaving canary/RIP 1,488/1,552 bytes out of wire reach. W4
  (`f18dd8bf`, `e9351342`) adds a one-command clean-room replay observed at
  19 PASS / 0 FAIL locally with four live gdb chosen-word checks. No consumed
  pointer, control-flow takeover, command or r5; live-limb replay #3909 owed.
- Yojimbo2shell (`aaa7dc7a`) is FRONTIER-STAGED on a CVE/GHSA-UNKNOWN remote
  fragment heap overflow upstream-fixed by `d3d4f339…` (parent `3c6b5e85…`):
  verbatim pinned `ProcessPacketFragment` gives ASan `WRITE of size 500` 0
  bytes past a 1100-byte region and chosen `MISHE-OO` at plain canary offset
  300, 20 PASS / 0 FAIL with 7/7 pins (also observed locally) and clean
  fixed/safe controls. No real build, wire, pointer, command, r5 or witness
  verdict; the upstream packet path is post-authentication. A gitignored site
  charter and window 147 exist but admission is pending, so no route, wake
  unit, row or mind-count change; the checker's no-route line is dispositioned
  above.

### 2026-11-25 02:0xZ — three staged targets admitted (routes 138–140)
Under standing #6 the operator admitted the three frontier-staged families
that the `doctor` and `omp-only` checkers had reported as chartered but
unrouted. This supersedes every `no route` / `FRONTIER-STAGED` / "admission
pending" line above for these three names; the staging evidence is unchanged.

- `open5gs2shell` — 138th route; CVE-2026-116543 / GHSA-25v2-v588-jq8g,
  pinned Open5GS v2.8.0 empty-boundary SBI multipart parser, ASan `WRITE of
  size 1` 0 bytes after a 65-byte region, plain state-machine-forced `00 0d
  0a` into an adjacent object; 21 PASS / 0 FAIL, witness W217 replayed from
  clean `git archive 22d70741` with a matching trace hash, ESTABLISHED AS
  LABELED at that scope. No real build, SBI listener, wire request, pointer,
  command or r5.
- `yojimbo2shell` — 139th route; CVE/GHSA-UNKNOWN, upstream fix `d3d4f339…`,
  pinned `ProcessPacketFragment` final-fragment `memcpy` before the
  `blockSize` check, ASan `WRITE of size 500` 0 bytes after a 1100-byte
  region, chosen `MISHE-OO` at canary offset 300, 20 PASS / 0 FAIL with 7/7
  pins; post-authentication, witness UNKNOWN, no real build, wire, pointer,
  command or r5.
- `libsshch2shell` — 140th route; CVE-2026-59850 (fixed 0.12.1/0.11.5),
  pinned libssh `channel_rcv_data()` closed-channel data UAF, ASan
  heap-use-after-free `READ of size 32` 0 bytes inside a 64-byte region,
  chosen `M` / `MISHE-LIBSSH-UAF` at freed offset 16, 24 PASS / 0 FAIL;
  authenticated peer required, witness UNKNOWN, distinct from
  `libssh22shell`, no real SSH build, wire, pointer, command or r5.

Each got a hy4-flash `max_parallel: 3` route, both resolver keys, three wake
units minted by the EXACT full-flag sync at pin `0d686bba…d528a`
(`written 9, removed 0`, daemon-reload, all three paths enabled/active), its
existing two-pane window (146/147/148), and a README row. The pinned
full-flag doctor returned PASS/GREEN and repo `check-readme.py` reports GREEN
with 136 achievement rows. Rung cells stay as staged (rungs 1-3, rung 4
PARTIAL, rung 5 `—`); no grade change follows from admission.

### 2026-11-25 01:5x–02:2xZ — author replay receipts, no grade moves
These folds supersede the row ceilings named in the README paragraph at the
top of the achievement table. No rung cell, route, mind count or witness
verdict moved; rung 5 stays UNKNOWN throughout.

- Gpgme W5 (`72f3b6ad`, receipt `844eed91`): wire-fed next-operation reclaim.
  `sh lab/frontier/gpgme2shell/realbuild/run-wire-reuse.sh` gave 55 PASS /
  0 FAIL in the author run; loopback HKP bytes become a 1234-byte
  `[GNUPG:] IMPORTED` status line with chosen `0x48`/`0x5a`/`0x37` at offset
  1000, and the next keylist frees the stale block at
  `_gpgme_op_reset → gpg_release engine-gpg.c:602`. Clean archive `72f3b6ad`
  replayed six suites 55/32/24/21/36/19 PASS, rc 0. No pointer/IP/command,
  no stock-layout claim; #4028/#4029 is a replay request, not a verdict.
  `reports/gpgme2shell-status.md` §W5 and `docs/reproducibility.md` §01:5x.
- Libgphoto2 W180 (`018f76d5`, `97c61c79`, `73a38aed`): the one-command
  `sh lab/frontier/libgphoto2shell/live/replay-real-w177.sh` rebuilds real
  2.5.34 on the lab-patched vusb port, auto-selects DRAIN in 20..40 and
  printed 4/4 pins OK, `RESULT: 20 PASS / 0 FAIL` from a clean archive.
  Real `gp_camera_file_get()` leaks own-canary and code-shaped words to a
  HOST consumer; gdb match, count-100 and full-reply controls are recorded.
  Author-only, unwitnessed; #2892 stays scoped to rung 3, no device readback,
  wire path, command or r5. `lab/frontier/libgphoto2shell/REPLAY.md` §W180.
- Munt W186 (`31fd23fe`, `e224af08`): a 32785-byte short SysEx through real
  `parseStream()` patches one byte of a harness-created victim function
  pointer at `buf+32784` and calls benign `marker_1` in the vulnerable plain
  build; ASan keeps `WRITE of size 32785` after the 32768-byte region.
  Clean-archive replay matched six rc cases and seven normalized evidence
  files (digest `b06a4b42…e7c`, quoted from `PARTIAL_REPLAY.md`). No real
  library object with a pointer at that offset, no ASLR defeat, host/wire
  input, command or r5; #2781 remains scoped to the older real-library
  rungs 1-4. `real/PARTIAL_POINTER.md`.
- FontForge W12 (`5e984cd9`) folded the true write ceiling `0x01FFFE00` into
  the README but not these docs; the W10 ceiling lines here and in
  `docs/reproducibility.md` are now
  labeled as its `i=0` input or claimed ceiling, with the corrected maximum
  beside them. Byte 3 stays 0/1, no mapped target and no r5; #3309 stays
  direct-call-only. `lab/frontier/fontforge2shell/CEILING-CORRECTION.md`.
- Libsshch2shell W220 (`0be2eacb`): the staged harness and its 01:58Z handoff
  rerun (24 PASS / 0 FAIL, 9/9 pins, ASan `READ of size 32`) were already
  folded by the 02:0xZ admission section above; no new verdict or grade.
- OpenEXR W195 (`2873fc39`, `reports/openexr2shell-file-level.md` §W195)
  pins the chosen value to the dereferenced slot: with ASLR on under gdb,
  `FAULT_R13=0x4141414141414141` at `attributes.c:305` comes from eight
  file-chosen bytes at `outPtr+4176`; `sh harness/w195-chosen-deref.sh`
  printed `RESULT PASS` rc 0 and a 02:21Z clean-archive replay matched all
  five evidence hashes. Author replay, not a witness verdict; the chosen
  value is unmapped, with no chosen data read, IP, wire, command or r5.
- Pgactive2Shell (`20123ce2`) builds the complete pinned 2.1.9 extension in
  `realbuild/` against extracted PG16.15 packages and calls the real SQL
  function on a loopback cluster (`shared_preload_libraries=pgactive`): ASan
  reports `WRITE of size 161` at offset 96 of `replication_name` from
  `pgactive_catalogs.c:351` and `pgactive.c:1531`, while 2.1.10 rejects and
  the plain vulnerable backend errors via `elog(ERROR)` before its canary
  check. No PUBLIC EXECUTE in either fresh install, no chosen bytes on the
  SQL path, replication wire, saved pointer/IP, command or r5; author-run
  and unreplayed, witness #3896 stays scoped to the standalone harness.
  `reports/frontier-pgactive2shell.md` §Full pinned extension.
  A clean `git archive 20123ce2` replay (`ba19500c`) matched the three-script
  rc matrix and the same ASan frames; author replay, not a witness verdict.

### 2026-11-25 02:29–02:4xZ — plain-glibc negative, caller framing, two negatives
These four author-side limbs supersede scope wording only. No rung cell,
grade, route, mind count or R5 cell moved; rung 5 stays UNKNOWN. Witness
labels #4028/#4029, #4039 and #3909 are requests or scope notes unless a
verdict is named below.

- Gpgme W6 (`3aaa3f07`, clean-archive replay `67a874c2`) closes only the
  real-build half of the row's "plain glibc outcome UNKNOWN": real GPGME
  2.2.0 and the fix-patched copy built with `CFLAGS=-g -O0`, `CC=clang`,
  static-only and no sanitizer. From
  `lab/frontier/gpgme2shell/realbuild`, `sh build-plain.sh &&
  sh run-plain.sh` is the recipe; `sh run-plain.sh` observed here printed
  `PASS=13 FAIL=0` rc 0. On glibc 2.39 the vulnerable driver exits 134 with
  `free(): double free detected in tcache 2` after `byte[1000]=0x48`,
  `arglen=1200`, no second keylist; patched rc 0 with `op2 keylist_start
  err=Success` and `release done`. Allocator detection precedes metadata or
  control-flow use: a negative rung-5 route, not a capability. The parent
  statement harness's one-abort/one-clean revisions stay UNKNOWN in their
  own scope; tape #4039 has no verdict. `reports/gpgme2shell-status.md` §W6.

- Open5gs W1 (`6d5f8de9`, replay receipt `318023f3`) corrects the staged
  harness's `boundary=""` framing: `realcaller/realcaller.c` copies pinned
  `message-v2.8.0.c:3324-3412`, and `sh realcaller/run.sh` (15 PASS / 0 FAIL
  observed here) shows the 394-byte staged body yields `BOUNDARY_LEN=2
  BOUNDARY=a:` clean, while one leading CRLF makes 396 bytes,
  `BOUNDARY_LEN=0` and ASan `WRITE of size 1` at
  `multipart_parser-v2.8.0.c:260`, plain canary `5a5a...` ->
  `0a000d0a000d0a000d0a000d`, fixed `RET=-1`. Witness message #3934
  (wall W210) replayed a clean `git archive 22d70741` staged harness 21 PASS
  / 0 FAIL, ESTABLISHED AS LABELED, no grade change and NO r5; the W217 row
  label stays as recorded. The `318023f3` clean archive reproduced 21/0 and
  15/0 author-side. Live SBI CRLF preservation is UNKNOWN; no wire,
  pointer/IP, command or r5.

- N2n W5 (`1029f346`) adds 16 watched frame words at `&nak+128/+136/+344/
  +432`, `+368/+392/+400/+424`, `+464/+488/+504/+536` and
  `+1608/+1616/+1632/+1640`: no read hit in four gated peer-forward runs
  that emitted `beyond48=485a4d49485a4d49`; the `+288` trip was a
  `__vsnprintf_internal` store into `sockbuf`, excluded. Unwatched words
  remain UNKNOWN, the W3 forwarding data copy is the only measured consumer,
  witness replay #3909 is still owed, and no pointer, marker, IP or r5
  follows. `reports/n2n2shell-live.md` §W5.

- Libgphoto2 W181 (`12ca5894`) closes the in-struct natural-consumer-pointer
  lane at pinned-source scope: `table` is last at `0x40` of `0x4040`,
  `data_cache` at `0x38`, the `:154` memmove writes forward, real consumers
  use table bytes as data and `gp_filesystem_number` has no negative index.
  A natural pointer in a HEAP NEIGHBOUR of `priv` was not measured and stays
  UNKNOWN. `sh harness/check.sh` stayed `PASS=146 FAIL=0` with trace
  `e364f756…c6c98`; W170-W172's probe-supplied placements and witness #2892's
  rung-3 scope are unchanged, author-side rung 4, r5 UNKNOWN.
  `reports/frontier-libgphoto2shell.md` §W181.

### 2026-11-25 02:4xZ — libsshch2shell W1 real-build wire limb (author-only)
`a6893b10` adds full pinned clang-ASan libssh builds and an authenticated
loopback SSH KEX/password session with raw `CHANNEL_CLOSE` then
`CHANNEL_DATA`; `sh lab/frontier/libsshch2shell/real/run-all.sh` scored
5 PASS / 0 FAIL here. ASan `heap-use-after-free READ of size 8` at
`channels.c:705:26` follows an application `ssh_channel_free()` inside the
data callback (`real_wire.c:55`, not the report's `:52` nit), with chosen
wire bytes `MISHE-LIBSSH-UAF-WIRE` (len 21, `M`@0, `-`@16) delivered as
`SERVER data #2`. Fixed guard suppresses data #2 and both data-only cases
are clean. Rung 3 is real-build/wire confirmed; rung 4 stays PARTIAL under
the stated app-free condition and reads freed channel metadata, not attacker
bytes at a chosen freed offset: no pointer/IP control, marker, command or
r5. Authenticated peer required; witness UNKNOWN, route 140, window 148 and
mind count unchanged. `reports/frontier-libsshch2shell.md` §W1.

### 2026-11-25 02:4x–02:5xZ — FontForge W13 and OpenEXR W196, author-only
No rung cell, grade, route, window, mind count or R5 cell moved; witness
labels stay as recorded below.

- FontForge W13 (`e2d45f1b`) adds a self-checking one-command real replay:
  `FF2S_TARBALL=<pinned tarball> sh lab/frontier/fontforge2shell/replay-real.sh`
  rebuilds four offline trees and asserts 17 rc cases (W8 open 134/0/1/0
  and complete 0/0; W11 `Save()` 139/0/139 plain and 0/1/0/0
  fixed-plain/ASan/probe-ASan/fixed-ASan; W12 high ceiling 134/0/1/0),
  observed here as `REPLAY_REAL_OK: 17/17 stable-lane checks passed` rc 0.
  W6/W7 consumer rc remains informational because build-path sensitive;
  the oracle uses rc only, with W12 gdb grep `0x1fffe00` and `00 fe ff 01`.
  Live-tree and clean-archive receipts are author replays; the current
  script hash `f633dd37…266a42` supersedes W9's quoted hash. Witness #3309
  remains direct-call rungs 1-4 only, no r5; full pins in `PINS.md` and
  `lab/frontier/fontforge2shell/REPLAY.md` §W13.

- OpenEXR W196 (`61468419`, clean-archive receipt `3ff078b1`) makes W195's
  chosen pointer mapped and consumed at a labeled ASLR-off scope: in
  unmodified pinned 3.5.2 `exrcheck -c`, file bytes forge
  `list->entries[0]` with `TYPE=20`, `STRPTR=0x555555828560`,
  `STR=FREE_RDI=0x555555828590`, chosen `0x5a` data and a `0x91` size word;
  the consumer reads that data and passes the chosen pointer to the
  unchanged `ctxt->free_fn`. `cd lab/openexr2shell-real &&
  sh harness/w196-chosen-free.sh` printed `RESULT PASS` rc 0 here with
  matching evidence hashes; a 02:54Z `git archive 61468419` replay matched
  all six. Author replay only; witness offered the one command on tape
  #4048 with no verdict. No chosen code pointer/IP, wire, command, marker
  or r5; mapped only while gdb's `disable-randomization` is on, so the
  rung-4 chosen-pointer claim stays scoped to that condition.
  `reports/openexr2shell-file-level.md` §W196.

### 2026-11-25 03:0x–03:1xZ — gpgme W7, yojimbo W1/W1b (author-only)

- Gpgme W7 (`9633cfc8`, clean-archive replay `a1ecd700`) reaches the
  advisory's second affected reader in real GPGME 2.2.0 under ASan:
  `realbuild/colon_reuse.c` uses public APIs and a fake engine writes 1024
  bytes with no LF, so `read_colon_line()` reallocs at `engine-gpg.c:1647`
  and EOF-returns at `:1707` without the `:1728-1730` writeback. The next
  keylist frees `gpg->colon.buffer` at `gpg_release :604`; `sh run-colon.sh`
  scored 26 PASS / 0 FAIL here and 26/0 plus pinned 19/0 from a clean
  `git archive 9633cfc8`. Fixed 2.2.0 and stock 2.3.1 are clean with
  `byte[1000]=0x5a`; the short-colon control is clean. Synthetic engine and
  local pipes, no wire, pointer/IP, command or r5, no witness verdict.
  `reports/gpgme2shell-status.md` §W7.
- Yojimbo W1 (`28d3c8c5`) builds the real pinned parent `3c6b5e85…` under
  ASan with bundled sodium and drives the fix commit's regression through
  real `Connection::ProcessPacket` to ASan `WRITE of size 500` at
  `yojimbo_reliable_ordered_channel.cpp:716`, fixed control clean. An
  authenticated netcode UDP 127.0.0.1 pair (client 1100/500, server
  1500/500) with chosen `MISHE-LOOP` at block offset 1200 faults in
  `Connection::Reset()` without gdb; W1b (`ff6c5e02`) reads the chosen
  marker back at `blockData+1200` under gdb after decrypt, and `30f77300`
  marks the original staging plan complete. Five evidence log hashes were
  recomputed locally and match the report. Rung 4 DEMONSTRATED only at the
  non-default-config, post-auth, one-process, gdb-assisted scope; no
  separate remote process, pointer/IP, command, marker execution or r5;
  production non-multiple block config and witness verdict UNKNOWN.
  `reports/frontier-yojimbo2shell.md` §§W1/W1b.
- No rung cell, grade, route, mind count, witness verdict or R5 cell moved;
  both lanes stay author-side and unwitnessed. Commands, pins, expected
  bytes and gitignored-regeneration notes are in `docs/reproducibility.md`
  under the 03:0x–03:1xZ lane.

### 2026-11-25 03:1xZ — pgactive W8 and hping W212 (mid-fold peer edges)

- Pgactive W8 (`3c6304ba`) measures the real non-ASan 2.1.9 stack layout in
  `realbuild/layout/` under both `-O1 -g` and production PGXS flags: the
  parser's saved return address sits 40/32 bytes BELOW `replication_name`,
  while the upward `%s` store overwrites only a second, unconsumed copy at
  +104/+120. Control exits by `elog(ERROR)` longjmp, so no input length can
  redirect `ret`; no backend terminated at any N and `SELECT 1` succeeded.
  Saved-pointer/RA route CLOSED at this build; gdb attach blocked by
  `ptrace_scope=1`. Author-side, unwitnessed, no grade change.
- Hping W212 (#4000) is an independent **ESTABLISHED AS LABELED** verdict for
  W6's probabilistic low-byte RNG-control lane: unmodified `replay-rngctl.sh`
  on a clean `git archive 659f6eb0` gave 20 checks rc 0 with exact pins and
  16/16 chosen-byte destinations. Wire stages #3942 and W5 #3958 remain
  OWED. No grade change or r5.
- No rung cell, route, mind count or R5 cell moved by either edge; recipes,
  expected bytes and gitignored-regeneration notes are in
  `docs/reproducibility.md` under the 03:1xZ lane.

### 2026-11-25 03:2xZ — socat2shell staged, rung corrected (no route)

- Frontier W221 (`4f3b7916`) staged CVE-2026-56123 (Socat advisory 10,
  CWE-122, CVSS4 9.2 `AV:N/AC:H`; affected 1.8.0.0–1.8.1.1, fixed 1.8.1.2
  by an unsigned `dstdata[]`) from a pinned tarball, patch, advisory and a
  verbatim pinned-function harness (`harness/run-all.sh` 15 PASS / 0 FAIL
  here). Signed-char sign extension of DOMAINNAME length 0xfb makes the count
  a huge `size_t`; the harness's ASan `WRITE of size 600` comes from a
  `memcpy` stand-in for `readfull()` with fortify disabled, not from the
  shipped consumer.
- Correction (`d7ea43d1`): unmodified real 1.8.1.1 and 1.8.1.2 builds under
  clang ASan and a 127.0.0.1-only malicious SOCKS5 server give
  `real/run-real.sh` 9 PASS / 0 FAIL here. The vulnerable attack logs
  `W read(7, 0x512000000045, -1): Bad address` and exits 255 with NO ASan
  report; fixed and safe replies exit 0. Real `readfull()` passes SIZE_MAX to
  `read(2)`, which returns EFAULT before storing a byte. Grade corrected:
  rung 1/2 on a real build (deterministic connection abort); rung 3 memory
  corruption and rung 4 chosen bytes NOT established on the real consumer,
  rung 5 not attempted, witness UNKNOWN. The earlier harness-only rung-3
  claim is preserved as corrected in the brief/status.
- Charter, window 149 and seed wall exist but no route: operator owns
  admission; omp-only is RED with 141 roles and `socat2shell: no route`. No
  README row, rung cell, grade cell or mind-count change. Recipe, pins and
  expected bytes are in `docs/reproducibility.md` under the 03:2xZ lane.

### 2026-11-25 03:3xZ — awslc W214 out-of-tree census (source-bound)

- A read-only sweep of out-of-tree application sources already provisioned in
  this plant found no caller satisfying the CVE's multi-update,
  documented-minimum-buffer precondition; ten named projects and roughly
  fifty other roots were checked, with four hit sites re-read. No qualifying
  buffer means no adjacent attacker-relevant datum. Unprovisioned
  third-party applications stay UNKNOWN; no build, ASan run, artifact or
  witness replay, grade unchanged (rungs 1-4, r5 UNKNOWN).
  `reports/awslc2shell-status.md` §W214; details in `docs/reproducibility.md`
  under the 03:3xZ lane.

### 2026-11-25 03:3xZ — socat2shell admitted under standing #6 (real-build negative)

- ADMITTED as the 141st route from DM #4059 with correction DM #4067. Route
  and both resolver keys added; EXACT full-flag sync minted the three wake
  units (`written 3, removed 0`), path enabled/active, doctor GREEN. The
  staged handoff window 149 was adopted, not duplicated.
- CVE-2026-56123 / Socat advisory 10 (CWE-122, CVSS4 9.2); affected
  1.8.0.0–1.8.1.1, fixed 1.8.1.2 by making `dstdata[]` unsigned. A signed
  length byte 0xfb makes `bytes_to_read=2` while `bytes_read=5`, handing a
  negative count to `readfull()`.
- Grade is deliberately LOW. The pinned harness (15 PASS / 0 FAIL) reports
  ASan `WRITE of size 600` from a `memcpy` stand-in. The real-build loopback
  replay (9 PASS / 0 FAIL, unmodified 1.8.1.1 and 1.8.1.2 under clang ASan)
  sees `read(7, ..., -1): Bad address`, exit 255, no ASan report: real
  `readfull()` passes SIZE_MAX to `read(2)`, which returns EFAULT before
  storing. Rungs 1/2 (connection abort) only; rung 3 corruption, rung 4
  chosen bytes, rung 5 NOT established. Witness UNKNOWN.
  `reports/frontier-socat2shell.md`, `reports/socat2shell-status.md`.

### 2026-11-25 03:3x–03:5xZ — six author limbs folded (no grade moves)

- `f25517f8` **Yojimbo W2**: wire-borne vptr control. Gdb places the 1100-byte
  receive block inside a 10 MiB TLSF arena, shows the 0xAB-filler-vptr fault
  and writes a chosen fake-vtable address at `blockData+1152` through the same
  encrypted fragment; the vulnerable non-PIE ASan binary prints
  `MISHE-VTABLE-CALL` twice before a TLSF crash, fixed control clean. This
  supersedes W1b's "no pointer control or marker execution" boundary; it is
  still post-auth, one-process, non-default config with a pre-placed marker,
  not remote command execution, no ASLR-realistic derivation and no r5.
- `bea93e82`/`90d635d6`/`bb01e9c5` **Hping W8**: the pinned source rebuilt at
  `-O2` hits Ubuntu's default `_FORTIFY_SOURCE 3` and aborts in
  `__memcpy_chk` before any crafted global write (attack 3 PASS / 0 FAIL;
  baseline and patched controls 4/0 each). Clean replay from `90d635d6` gave
  `REPLAY_O2_OK: 11 checks`, rc 0. Build-dependent DoS negative; distribution
  builds and other fortify settings UNKNOWN, no grade change.
- `1a34d2de` **Socat W2**: dispositioned as a remote connection-abort bug,
  not a memory-safety find. Source census finds no cap/alternate read and
  length bytes `0xf9..0xff` produce counts `-1..-5` passed as `size_t`;
  `sh real/run-count-probe.sh` (8 PASS / 0 FAIL) shows EFAULT with zero stores
  for every count this bug generates on this host. 32-bit `size_t` UNKNOWN;
  rung 1/2 only, witness UNKNOWN.
- `93b61d8d` **AwsLc W215**: pinned s2n-tls v1.5.16 source census is a
  SOURCE-BOUND NEGATIVE — in-place, one-update decrypts, no `in_len+b-1`
  buffer, `final_used` cleared on every re-init; no build, ASan or witness
  replay, grade unchanged.
- `b60fd1b4`/`b67db0dc` **Synchronet W18**: shipped 3.21e source-level check,
  `release-label/run-release321e.sh` 11 PASS / 0 FAIL live and from a clean
  archive, normalized `bb9067cf…2a5a3fbda9`; no build, wire or runtime bytes,
  no rung change, no claim about 3.20b or other releases.
- `6fb104bb` **Pgactive W9**: catalog-origin names of 66–275 bytes are stored,
  but the `pgactive_get_global_locks_info()` route failed (UNKNOWN); slot
  names truncate 96→63 bytes and a plain `LOGIN` role lacks the required
  privileges. No wire trigger, no grade change.

Recipes, pins and expected bytes are in `docs/reproducibility.md` under the
03:3x–03:5xZ lane. README rows and the Yojimbo supersession narrative were
updated in the same docs fold; no route, rung cell, grade cell, mind count or
R5 cell moved.

### 2026-11-25 03:5x–04:0xZ — n2n2shell W6 and W3 replay folded

- `ac451b00` **N2n W6**: a fresh plain gcc `-O1` fixed-build supernode still
  lets the forwarding encoder read 96 bytes from `nak+14` after the rejected
  oversized decode, but emits 96 ZERO bytes, not stack data. The fixed ASan
  build still aborts on that read with a peer (W3); adjacent bytes in other
  builds or after other traffic stay UNKNOWN. No disclosure claim or grade
  move. The one-line control matches the vendor NAK guard byte-for-byte but
  is not a full fixed-tree build.
- `58ceee1c` **n2n2 one-command replay**: `sh live/replay-live.sh` now includes
  W3's peer-forwarding lane as checks 20-22; observed 22 PASS / 0 FAIL here.
  The watchpoint backtrace and fixed ASan READ keep their separate recipe.
  README's n2n row and W4 narrative were corrected from 19 to 22 checks;
  witness #3909 remains owed.
  `reports/n2n2shell-live.md` §§W6, clean-room replay entry point.
