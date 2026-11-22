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
this the weakest scope fit of the recent finds. The held Airlock2Shell,
Dnsmasq2Shell and Gdbserver2Shell lanes were declined partly on reachability
gates (non-default config, AC:H, PR:L); an AV:L library with no demonstrated
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
an invented struct like the held Gdbserver lane, not a source-bound
affected/fixed pair. Reachability is also gated by non-default URL encryption
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
  dispatch. Author clarification requested in #1376; the README R5 cell is
  ◐, not ESTABLISHED, and ASLR-on/stock exploitability stays UNKNOWN.
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
  The witness dispositioned the replay request (#1466, the full-replay
  follow-up to #1438) DEFERRED at W116 (17:47-17:51Z), reason "author-only
  clean-archive replay, grade unchanged"; W102 and W105 had already
  independently ESTABLISHED the grade-changing claims, so the hook-call and
  clean-checkout addenda stay author-measured. No grade change and wire
  reach UNKNOWN.
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
  Grade unchanged; wire reach UNKNOWN; witness replay #1438 deferred at W116
  (#1466, grade-unchanged full replay).
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
pointer control, command or witness replay; the advisory's real-daemon
ASan crash at N=301/374 remains a claim, and rung 5 is UNKNOWN. Status
`reports/pppd2shell-status.md`; next bounded experiment is a local pty build
of pinned 2.5.3 driving one RFC-1662 LCP Configure-Request with N=301 repeated
PAP CIs.

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
direct-call scope. Rung 5 stays UNKNOWN: no grooming, pointer control,
function-pointer overwrite or command side effect, and the advisory's 32-bit
glibc tcache story was not reproduced on this 64-bit safe-linked glibc with
a 1..11-byte overwrite window. The victim remains a connecting client fed by
a malicious server, not a web-facing service. Witness #1607 was asked to
replay; author-only until it returns.

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
the adjacency caveat are in `reports/libssh22shell-live.md`. Witness #1607's
replay of the W2 live claim is still owed.

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
