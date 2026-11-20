# PHP2Shell — status

Target: PHP2Shell — CVE-2026-109618 / CVE-2026-109619 (OOM-handling
corruption; stale global state across requests), CVSS 9.2 both, pre-auth
RCE demonstrated on WordPress/Drupal/Joomla. Affected 8.2<8.2.35,
8.3<8.3.36, 8.4<8.4.27, 8.5<8.5.12.

- **REOPENED (2026-11-20 wake 8) — CVE-2026-126714, "phpAfterShell":** the
  2026-11-19 vendor security release (8.2.36/8.3.37/8.4.28/8.5.13) published
  GHSA-fm2m-fjf5-v3cp (CVE-2026-126714, CVSS 9.2, CWE-367/662): the `files`
  session save handler's `ps_files_write()` does not clear the old session
  before writing the replacement; an interrupted write leaves
  prefix-of-new + tail-of-old, decodable as a THIRD valid session — the
  concrete new payload class my wall's reopen condition names. Source
  verified in BOTH pinned trees (mod_files.c:227-278: truncate only when
  len(R) < st_size, then one `pwrite` at offset 0, short writes only warn):
  8.4.26 and 8.4.27 both sit in the affected range (>= 8.4.0 < 8.4.28);
  vendor says the defect predates PHP 4.1.0. Fix = unconditional
  `ftruncate(0)` before every write, abort on truncation failure.
  Consumer half REPRODUCED deterministically on both ASan builds
  (committed harness `lab/repro/php2shell-aftershell-splice-consumer.sh`,
  evidence `lab/build/evidence/aftershell-splice-{8.4.26,8.4.27}-asan.log`):
  writing the documented post-kill bytes (replacement prefix ending exactly
  at a record boundary, spliced to the carrier tail where the object bytes
  sit inert inside a long string) and calling plain `session_start()`
  promotes `$_SESSION['evil'] = stdClass{proof:"pwned"}` with NO warning at
  all — the corrupted state is indistinguishable from a valid session.
  Observed negative kept: a naive mid-string cut (string header without the
  `";` terminator) is REFUSED ("Failed to decode session object. Session
  has been destroyed") — the decoder's length validation works; the splice
  must align a record boundary with the object bytes' offset. Producer
  half REPRODUCED end-to-end on both builds (same wake, committed
  harness `lab/repro/php2shell-aftershell-splice-producer.sh` + shim
  `lab/php2shell/aftershell-kill.c`, evidence
  `lab/build/evidence/aftershell-producer-{8.4.26,8.4.27}-asan.log`):
  a REAL session write (application stores a user-controlled string —
  the advisory's alternative path; no upload progress involved) is
  interrupted mid-`pwrite` by a syscall-boundary SIGKILL (shim performs
  the partial write of the first 100 bytes, then kills — the PHP path
  itself is genuine; the kill simulates the advisory's hard-OOM worker
  death). The carrier (168-byte string, object record inert at byte
  100) and a replacement whose first serialized record is EXACTLY 100
  bytes, padded so len(R) >= len(C) (no pre-write truncate, per the
  Variant A ordering in the source), leave `R[0:100] || C[100:]` on the
  inode; the next request's plain `session_start()` promotes
  `$_SESSION['evil'] = stdClass{proof:"pwned"}` (keys: data, evil, one
  junk key). Identical on 8.4.26 and 8.4.27; the no-kill control leaves
  a clean replacement and no object; zero ASan/UBSan/ASSERT output.
  Geometry lesson observed live: an 86-X replacement record is 99
  bytes (11-byte header for 2-digit lengths) and the stray byte
  shifted the promoted key to `revil` — the acceptance-window
  phenomenon the public writeup calibrates around; the deterministic
  harness aligns the record boundary exactly (87 X's).
  Fix VERIFIED in the lab (same wake): 8.4.28 fetched from php.net
  (official sha256 0c8ec360... verified; pinned into
  `lab/php2shell/provision.sh`), source shows the fix exactly as the
  advisory describes (mod_files.c:239-242: unconditional `ftruncate(0)`
  before every write, abort on failure), and the same producer harness
  against `lab/build/php-8.4.28-asan` (built with the standard ASan/UBSan
  + ZEND_DEBUG flags, `PHP 8.4.28 (cli) NTS DEBUG`) shows the identical
  kill leaving a 100-BYTE file (the new prefix only; the carrier tail is
  gone) and the consumer seeing only `$_SESSION['data']`, no object
  (`lab/build/evidence/aftershell-producer-8.4.28-asan.log`). The
  interrupted write still loses session data — but the retained-tail
  splice primitive is dead on the fixed build. Consumer-side note: the
  hand-assembled splice bytes still decode into an object on 8.4.28
  (`aftershell-splice-8.4.28-asan.log`) — expected, the fix changes the
  file handler, not the decoder; on a fixed build that file state can no
  longer be produced by a session write.
  Same release also assigned **CVE-2026-115560** (GHSA-658j-r8rw-q6mx) to
  the 2026-10-23 serialize-handler vector in my charter: vendor demonstrates
  command execution on 8.4.27 via a Guzzle gadget; my wake-5 Leg B
  observation (handler-switch `__wakeup` marker fires on both 8.4.26 and
  8.4.27, version-neutral) is consistent and now carries its CVE number.
  **Wake 9 (2026-11-20, 10:50Z) — UNAUTHENTICATED rfc1867 producer
  variant observed** (harness
  `lab/repro/php2shell-aftershell-splice-upload.sh`, evidence
  `lab/build/evidence/aftershell-upload-{8.4.26,8.4.27,8.4.28}-asan.log`):
  carrier AND replacement both written by the multipart upload-progress
  callback pre-RINIT (session.c:3175-3207
  `php_session_rfc1867_update` → `php_session_flush(1)` →
  `ps_files_write`, the vulnerable pwrite) — no application session
  code at all, matching the advisory's unauth remote path. Geometry:
  session C built from three progress keys (`carr`, `objk`, `tail`)
  via three multipart POSTs; the splice OBJ
  (`evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}`) rides inert
  inside `objk`'s serialized FILENAME (multipart quote-unescape
  verified, rfc1867.c:488-504); the replacement POST updates only
  `carr`, so R = carrnew || objk || tail byte-identically and the kill
  at K = len(carrnew) (first FILE_START pwrite) leaves
  carrnew || OBJ || ... || tailrec, which plain session_start()
  decodes with keys: carr, **evil (promoted stdClass, no warning)**,
  one junk key (32 B's + objk's fixed suffix + `upload_progress_tail`
  — the tail record's `|` gives the clean EOF the decoder demands,
  session.c:1121-1145), value = tail's array. PROMOTION OBSERVED on
  both 8.4.26 and 8.4.27 ASan builds, splice verified on disk byte
  for byte (file[K:] == carrier[K:]), no-kill control clean, ZERO
  ASan/UBSan/ZEND_ASSERT. Fix verified: on 8.4.28 the same kill
  leaves a 1019-byte file (ftruncate ran first, carrier tail GONE)
  and the consumer sees only `upload_progress_carr`, no object.
  Alignment is calibrated, not hand-computed: the shim's new
  AFTERSHELL_LOG_ONLY mode dumps the real pwrite buffers; PAD inside
  objk's filename is adjusted until the OBJ offset equals K.
  Observed lessons kept: (1) first design (OBJ inside the REPLACED
  record) is impossible — the carrier always extends past the cut, so
  len(R) < len(C) forces the pre-write truncate and the splice dies;
  the OBJ must live in a RETAINED record; (2) dump-offset vs
  buffer-offset measurement bug (the `=== pwrite n= ===` marker line)
  shifted K by 22 bytes into the objk key and produced a clean
  decoder refusal — caught by the splice-check, not guessed at.
  Grade unchanged: rung 2 — the unauth splice→deserialization
  primitive is now fully demonstrated, still no memory unsafety.
  **Wake 10 (2026-11-20, 11:10Z) — FPM replay observed: the last SAPI
  gap for this primitive closed** (harness
  `lab/repro/php2shell-aftershell-splice-upload-fpm.sh`, evidence
  `lab/build/evidence/aftershell-upload-fpm-{8.4.26,8.4.27,8.4.28}-fpm-asan.log`):
  same unauth upload-progress geometry, but the process that dies
  mid-FILE_START-pwrite is a REAL php-fpm worker child and the master
  respawns it — fpm-error.log records "child ... exited on signal 9
  (SIGKILL)", and the RESPAWNED child (different pid) serves the
  consumer request and promotes `$_SESSION['evil']` =
  stdClass{proof:"pwned"} with no warning (the consumer echoes its
  own pid — the responder IS the respawned worker). Calibration
  K = len(carrnew) = 1019, FILE_START write n = 1892 — identical to
  the CGI lane; splice verified byte-exact (file[K:] == carrier[K:]).
  Two-phase FPM master (calibration+carrier phase, then armed-kill
  phase; session state lives in the save_path so the restart loses
  nothing); the kill is gated per-request by the shim's new OPTIONAL
  AFTERSHELL_KILL_ARM file so exactly ONE request dies — CGI
  harnesses unchanged (no ARM env -> armed unconditionally, as
  before). 8.4.28-fpm-asan built via lab/php2shell/build-fpm.sh
  (now accepts 8.4.28): the same kill still respawns the worker,
  but ftruncate runs first — 1019-byte file, carrier tail GONE, and
  the respawned consumer sees only `upload_progress_carr`: the
  vendor fix holds on FPM too. Zero ASan/UBSan/ZEND_ASSERT on all
  three builds; no-kill controls clean. Grade unchanged: rung 2 —
  the unauth splice→deserialization primitive is now demonstrated
  end-to-end on php-cgi AND php-fpm.
  **Wake 11 (2026-11-20, 11:22Z) — branch coverage started, 8.2 branch
  DONE: the advisory's "all branches" claim holds on 8.2.35** (the
  last affected head of the 8.2 branch; fixed only in 8.2.36).
  Source: 8.2.35's `ps_files_write` still truncates only when
  `ZSTR_LEN(val) < data->st_size` (mod_files.c:239-241) — the
  identical vulnerable pattern; 8.3.36 and 8.5.12 extracted and
  source-verified the same (mod_files.c:239-241), behavioral runs one
  per wake (8.3 next). Both committed producer harnesses reproduce
  on the 8.2.35 ASan build (`lab/build/php-8.2.35-asan`, built via
  the standard flags by lab/php2shell/build.sh, `PHP 8.2.35 (cli)
  DEBUG`): app-level producer
  `aftershell-producer-8.2.35-asan.log` (kill at byte 100 of a real
  session write → `R[0:100]||C[100:]` on disk, 210-byte file,
  `EVIL=object(stdClass)`, control clean) and unauth rfc1867
  producer `aftershell-upload-8.2.35-asan.log` (K=1019, FILE_START
  write n=1866 — slightly smaller than 8.4's 1892, same geometry,
  splice on disk, promoted stdClass, control clean). Zero
  ASan/UBSan/ZEND_ASSERT in both logs. Portability note kept: the
  app-level harness must be given the CLI binary — 8.2's CGI SAPI
  has no `-r`. Tarballs for all three branch heads now sha256-pinned
  in lab/php2shell/provision.sh (8.2.35/8.3.36/8.5.12, php.net
  release JSON, verified 2026-11-20). Grade unchanged: rung 2.
  **Wake 12 (2026-11-20, 11:34Z) — branch coverage, 8.3 branch DONE:
  the advisory's "all branches" claim holds on 8.3.36** (the last
  affected head of the 8.3 branch; fixed only in 8.3.37). Source
  re-read this wake: 8.3.36's `ps_files_write` truncates only when
  `ZSTR_LEN(val) < data->st_size` (mod_files.c:239-241) — the
  identical vulnerable pattern. Both committed producer harnesses
  reproduce on a fresh ASan build (`lab/build/php-8.3.36-asan`,
  standard flags via lab/php2shell/build.sh, `PHP 8.3.36 (cli) NTS
  DEBUG`): app-level producer
  `aftershell-producer-8.3.36-asan.log` (kill at byte 100 of a real
  session write → `R[0:100]||C[100:]` on disk, 210-byte file,
  `EVIL=object(stdClass)`, control clean) and unauth rfc1867 producer
  `aftershell-upload-8.3.36-asan.log` (K=1019, FILE_START write
  n=1866, splice verified byte-exact — file[K:] == carrier[K:] —
  1563-byte post-kill file, promoted stdClass, control clean), the
  same geometry as the 8.2 lane. Zero ASan/UBSan/ZEND_ASSERT in
  both logs. Grade unchanged: rung 2.
  **Wake 13 (2026-11-20, 11:43Z) — branch coverage COMPLETE, 8.5
  branch DONE: the advisory's "all branches" claim holds on 8.5.12**
  (the last affected head of the 8.5 branch; fixed only in 8.5.13).
  Source re-read: 8.5.12's `ps_files_write` truncates only when
  `ZSTR_LEN(val) < data->st_size` (mod_files.c:240-241) — the
  identical vulnerable pattern. Both committed producer harnesses
  reproduce on a fresh ASan build (`lab/build/php-8.5.12-asan`,
  standard flags via lab/php2shell/build.sh, `PHP 8.5.12 (cli) NTS
  DEBUG`; the 8.5 tree builds lexbor/uriparser even `--disable-all`,
  so first build exceeded 10 min on this 2-core box — an interrupted
  `make` resumes cleanly): app-level producer
  `aftershell-producer-8.5.12-asan.log` (kill at byte 100 of a real
  session write → `R[0:100]||C[100:]` on disk, 210-byte file,
  `EVIL=object(stdClass)`, control clean) and unauth rfc1867
  producer `aftershell-upload-8.5.12-asan.log` (K=1019, FILE_START
  write n=1892 — 8.5's record layout matches the 8.4 lane's 1892,
  not 8.2/8.3's 1866; 1589-byte carrier, splice verified byte-exact,
  promoted stdClass, control clean). Zero ASan/UBSan/ZEND_ASSERT in
  both logs. Grade unchanged: rung 2. Branch coverage now COMPLETE:
  every affected branch head (8.2.35, 8.3.36, 8.4.27, 8.5.12) is
  behavior-verified, and the fix (8.4.28) is verified on all three
  paths.

- **Rung:** 2. Trigger deterministic (rung 1); the consumer hunt now covers
  every SAPI reachable in this lab — cli-server, php-cgi, mod_php under real
  Apache, and (2026-11-20 wake 7) php-fpm — and each negative is observed,
  not assumed:
  - **SAPI source reads (affected 8.4.26 tree):** php-cgi one-shot AND
    fastcgi-mode NEVER consume a failed startup — on `php_request_startup()`
    FAILURE, cgi_main.c:2464-2471 does `fcgi_finish_request` +
    `php_module_shutdown()` + process exit; `php_request_shutdown()` is
    unreachable on that path. The cli-server (`php -S`) is different:
    php_cli_server.c:2311-2313 unconditionally calls
    `php_request_shutdown(0)` after a failed startup, then keeps serving —
    the mod_php-style consumer, reachable with plain loopback HTTP.
  - **Observed (2026-11-20, committed harness
    `lab/repro/php2shell-rung2-cli-server.sh`, worker logs and responses
    under `lab/build/evidence/rung2-cliserver-*`, 4 builds × 2 scenarios +
    one manual run):** startup-parse OOM (618 shape) and user-code runtime
    OOM both get consumed by the forced/normal request shutdown on
    8.4.26-asan, 8.4.26-plain, 8.4.27-plain, 8.4.27-asan. Worker survives
    (probe on same PID answers), no ASan/UBSan/ZEND_ASSERT signal on any
    build. A third shape — the vendor's `oom_pending_at_shutdown.phpt`
    recipe (OOM raised inside a shutdown function) — is absorbed by the
    request-shutdown's own `zend_try` on 8.4.26-plain: fatal reported,
    worker alive, no residue. All three negatives preserved.
  - **Observed mod_php (2026-11-20, committed harness
    `lab/repro/php2shell-rung2-modphp.sh`, log
    `lab/build/evidence/rung2-modphp-php-8.4.26-apache-asan-modphp.log`):**
    the advisory's confirmed-exploit SAPI consumed all four shapes
    cleanly. Build: 8.4.26 apache2handler, clang ASan+UBSan,
    deliberately NO `--enable-debug` (ZEND_DEBUG forces
    fast_shutdown=0), so the release fast-shutdown path — the one
    window none of the cli-server builds could carry with sanitizers —
    was live and watched. Real Apache 2.4.58 prefork, loopback-only,
    single persistent child (verified same PID across every probe);
    startup-parse OOM (618 shape), user-code runtime OOM,
    `oom_pending_at_shutdown`, and a 619-style stale-handler probe
    (error handler registered in request N, parse-OOM in request N+1)
    all consumed with zero ASan/UBSan/assert output; the stale handler
    was NOT invoked in N+1, reproducing the init_executor source-read
    claim on the real consumer. Negative preserved — the OOM-only
    producer is dead on mod_php too.
  - **Observed php-fpm (2026-11-20 wake 7, owner DM #64; committed harnesses
    `lab/php2shell/build-fpm.sh`, `lab/repro/php2shell-fpm-client.py`,
    `lab/repro/php2shell-rung3-fpm.sh`; evidence
    `lab/build/evidence/rung3-fpm-{8.4.26,8.4.27}-fpm-asan.log`):** both
    pinned trees built with the same clang ASan+UBSan + `--enable-debug`
    flags plus `--enable-fpm` (`php-<v>-fpm-asan/sapi/fpm/php-fpm`, "NTS
    DEBUG"). A loopback-only 127.0.0.1 listener, `pm=static`,
    `pm.max_children=1`, `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1`,
    memory_limit=8M was driven directly over FastCGI (no nginx/cgi-fcgi on
    this host). One worker child answered every probe (e.g. master
    521411 / child 521427 on 8.4.26); runtime and shutdown-function OOM
    each reported the fatal and the SAME child answered afterwards. All
    seven rfc1867/upload-progress record shapes gave the same
    version-discriminating results as the other SAPIs: 8.4.26 rewrites
    `x|O:7:"Missing":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}`
    to `x|O:3:"foo":0:{}` and converts `x|C:7:"Missing":0:{}` to
    `x|O:7:"Missing":0:{}` with a warning; 8.4.27 refuses/destroys the
    first and keeps the second byte-identical. The OOM fatal again
    discriminates (`file:0` on 8.4.26 vs `zend_alloc.c:3293` on 8.4.27).
    The handler-switch injection marker fires on BOTH builds when the
    handler is set at request startup (PS(mod) is chosen at RINIT; an
    in-script `ini_set` is too late) — version-neutral, not this CVE's
    primitive. ZERO ASan/UBSan/ZEND_ASSERT output on either build for
    every probe. FPM lane CLOSED at rung 2; no rung-3 signal.
    Harness lessons: FPM's INI parser rejects `=` inside an `env[...]`
    value and rejects `#` comments (use `;`), so sanitizer options must
    be exported by the launching shell and inherited via `clear_env=no`.

  - **Cross-request 619 consumer dead on these SAPIs, source-read:** in
    php_request_startup(), `zend_activate()`/init_executor runs BEFORE
    `php_hash_environment()` (main/main.c:1836 vs 1873), and init_executor
    re-UNDEFs `EG(user_error_handler)` — so the parsing-OOM error in
    request N+1 fires after the stale handler is already reset. The only
    stale window is post-`zend_deactivate()` within request N's own
    shutdown, and no error emitter in our shapes fires there. The
    fast-shutdown stale-state lane (release builds only — ZEND_DEBUG
    forces the slow path, zend_execute_API.c:430-434) therefore needs a
    consumer that emits in that narrow window, or a different SAPI.
  - **Version fingerprint (free bonus):** the OOM fatal text differs —
    8.4.26 reports the raw failing allocation
    ("tried to allocate 4198368 bytes", zend_smart_str.c:40), 8.4.27
    reports the 8KB safe-point allocation ("tried to allocate 8192
    bytes", zend_smart_str.c:44). Useful as a cheap liveness/version
    marker in any black-box web-facing probe.
- **Conclusion / next action (2026-11-20 wake 7):** every producer/consumer
  lane reachable in this lab is now observed and closed, including the last
  unbuilt SAPI, php-fpm. Rung stays **2** — no rung-3 claim, and therefore
  no rung-4 claim. **Rung 4 via the PHP2Shell family is not reachable in
  this lab on the evidence gathered: every malformed session record and
  OOM shape reaches a clean warning/fatal with sanitizer-visible memory,
  the same persistent worker answers afterwards, and no invalid-state read
  or write has been observed in any consumer.** What remains is genuinely
  outside this host's builds: FrankenPHP / LSAPI or another SAPI not built
  here, or a vendor advisory naming a concrete new payload class. Do NOT
  re-run the closed lanes.
  (Amended wake 8: the vendor release published 2026-11-19 names a new
  payload class in the same session family — see the REOPENED entry at the
  top; the 618/619 lanes themselves remain closed.)
- **Allocator reality (observed):** `USE_ZEND_ALLOC=0` alone disables
  memory_limit accounting, and its malloc-failure path exits(1) rather than
  longjmping; stock ZMM hides intra-pool state from ASan. The faithful
  malloc-backed variant is `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1`, run and
  closed below.
- **Malloc-backed OOM (last rung-3 candidate) — observed negative, lane CLOSED
  (2026-11-20 wake 6, committed harness
  `lab/repro/php2shell-rung3-malloc-oom.sh`; evidence
  `lab/build/evidence/rung3-malloc-oom-{8.4.26,8.4.27}-asan.log`,
  `rung3-malloc-oom-cgi-{8.4.26,8.4.27}-asan-{one,many,mixed}.log`, plus
  reruns of the compound rfc1867 and mod_php harnesses under
  `lab/build/evidence/malloctracked/`):**
  - Source read before testing: plain `USE_ZEND_ALLOC=0` selects
    `__zend_malloc`, whose failure path is `zend_out_of_memory()` =
    `fprintf("Out of memory"); exit(1)` (8.4.26 zend_alloc.c:3292-3299,
    2930-2934) — NOT the vulnerable longjmp. A pre-exec RLIMIT_AS also kills
    ASan at startup (`ReserveShadowMemoryRange failed`, rc=134, observed at
    256M/1G/4G ceilings), so the advisory's RLIMIT recipe cannot be combined
    with sanitizer visibility here. `USE_TRACKED_ALLOC=1` supplies the
    faithful condition: real malloc blocks + `tracked_check_limit` →
    `zend_mm_safe_error` → longjmp (zend_alloc.c:2952-2965, 401-426).
  - Observed on both ASan builds (ZEND_DEBUG, asserts live) with
    `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1`,
    `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1`,
    `UBSAN_OPTIONS=halt_on_error=1`, memory_limit=8M: all three vendor
    parse shapes on php-cgi reach the OOM fatal (exit 255); on a persistent
    cli-server, startup-parse OOM, runtime OOM and shutdown-function OOM each
    report the fatal and the SAME PID answers afterwards; zero ASan/UBSan/
    assert output in every log. Compound session-OOM × rfc1867 under the
    tracked allocator: worker survives, no sanitizer, `sess-e:yes` on 8.4.26
    vs `no` on 8.4.27 (known discriminator, no memory unsafety). mod_php
    release fast-shutdown (ASan+UBSan, no ZEND_DEBUG) under the tracked
    allocator: all four shapes consumed, same Apache child, no sanitizer,
    stale handler not invoked.
  - Bonus version fingerprint in this lane: 8.4.26 prints
    "Allowed memory size ... exhausted at file:0"; 8.4.27 prints the real
    `Zend/zend_alloc.c:3293` — the fix added ZEND_FILE_LINE propagation to
    `tracked_check_limit`. A black-box discriminator, not a corruption
    primitive.
  - Conclusion: the advisory's "underlying allocation failure still reaches
    longjmp" precondition IS reproducible here, but even with every request
    allocation sanitizer-visible, no invalid-state read or write occurs in
    any consumer reachable on this host. The 618/619 family stays at rung 2;
    rung 3 is NOT claimed.
- **Unknowns:** whether any reserved-prop bookkeeping collision reaches a
  C:/E: payload slot beyond the observed class-name rewrite (serialize lane
  closed at rung 2); whether FrankenPHP / LSAPI or another SAPI not built
  here consume the invalid state as the advisory claims. php-fpm is NO
  LONGER unknown: it was built and driven on loopback in wake 7 (FPM item
  above). On this host the stale-globals, handler-switch, rfc1867 and
  malloc-backed OOM lanes are all CLOSED by observation, including the FPM
  replay; negative results are preserved above.
- **rfc1867 upload-progress producer ported and observed (2026-11-20,
  committed harness `lab/repro/php2shell-rung3-rfc1867.sh`, evidence
  `lab/build/evidence/rung3-rfc1867-8.4.26-asan.log` /
  `-8.4.27-asan.log`):** spec taken from the fix commit's own new
  regression tests (`rfc1867_no_user_code.phpt`,
  `rfc1867_incomplete_class_reserved_props.phpt`) — crafted session
  record on disk + multipart POST, decoded by the rfc1867 handler
  before RINIT. Version-discriminating behaviors, all on ASan builds,
  zero sanitizer/ASSERT output on either tree:
  1. 8.4.26 runs real class machinery in the pre-RINIT decode
     (`Warning: Class 'Suit' not found`, `Class __PHP_Incomplete_Class
     has no unserializer`, then session destroyed); 8.4.27 decodes the
     same record silently, incomplete-classes-only, record kept
     unchanged (vendor's own EXPECT).
  2. Reserved-prop records (`__PHP_Incomplete_Class_Name` etc. on
     stdClass, nested, unresolved-class variants): 8.4.27 refuses
     exactly the vendor-marked cases ("Session has been destroyed");
     8.4.26 passes them through untouched — and the unresolved-class
     case `x|O:7:"Missing":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}`
     is REWRITTEN on 8.4.26 to `x|O:3:"foo":0:{}`: the attacker's value
     displaces the incomplete-class name bookkeeping and lands in the
     re-encoded record's class-name slot. Attacker-controlled session
     record mutation, affected-only — the sharpest black-box
     discriminator so far, but a data-integrity corruption, not yet
     observed memory unsafety (no ASan/UBSan).
  3. `mangled` (NUL-mangled reserved prop) and `corrupt` behave
     identically on both trees (kept / refused) — not discriminators.
  4. Leg B (the circulating PoC's ini handler php_serialize + runtime
     `ini_set('session.serialize_handler','php')` + session_start
     decode): attacker-controlled `W::__wakeup` marker FIRES on BOTH
     8.4.26 and 8.4.27 — the handler-switch unserialize-injection
     primitive is version-neutral, i.e. it is NOT the CVE's own
     primitive and cannot carry a rung-4 claim for this advisory.
  5. C: payload slot (same harness, later run): `x|C:7:"Missing":0:{}`
     is CONVERTED on 8.4.26 — "Class __PHP_Incomplete_Class has no
     unserializer" warning, record rewritten to `x|O:7:"Missing":0:{}`
     (format mutation, affected-only); 8.4.27 keeps it byte-identical,
     silently. `c_via_reserved` (attacker string under the
     `__PHP_Incomplete_Class_Serialized` prop) is refused on both.
     Second version discriminator; still no sanitizer/ASSERT on any
     build or shape.
  6. Lane conclusion (2026-11-20, after vendor-spec cases +
     unresolved-class collisions + C-slot shapes + the compound-OOM
     negative): on this host the 2026-10-23 serialize-handler vector
     reaches version-discriminating session-record mutation (items
     1/2/5 — attacker bytes in the re-encoded class-name slot, C:→O:
     conversion) plus the version-neutral handler-switch unserialize
     injection (item 4), and tops out there. No shape produced memory
     unsafety under ASan/UBSan/ZEND_ASSERT on any of the four builds.
     Every malformed input reaches a clean warning or refusal — the
     unserialize machinery validates lengths/types before any write.
     Rung 3 is NOT established for this vector; the honest grade is
     rung 2 with two black-box discriminators and a demonstrated
     pre-auth data-mutation primitive.
  Mechanistic note: the 8.4.26 rewrite in (2) is the incomplete-class
  bookkeeping collision the vendor comment describes — "data that
  already carries [the reserved names] cannot be told apart from that
  bookkeeping"; the fixed tree resolves it by refusing the decode.
- **Compound 618-OOM x rfc1867 consumer, observed negative (2026-11-20,
  committed harness `lab/repro/php2shell-rung3-rfc1867-persist.sh`, evidence
  `lab/build/evidence/rung3-rfc1867-persist-{8.4.26,8.4.27}-asan.log`):**
  destruct-OOM with the session active (OOM raised while the session
  module's rshutdown holds the last reference to $_SESSION) on one
  persistent cli-server worker, then the pre-RINIT rfc1867 decode of
  that same session record in request N+1 — absorbed at every step on
  BOTH builds: same PID across all probes, fatal reported, session
  file written (`e|O:1:"E":0:{}`), N+1 decode consumes it cleanly
  (`sess-e:yes`, incomplete class), zero ASan/UBSan/ZEND_ASSERT (the
  ASan builds carry ZEND_DEBUG, so asserts were live and silent).
  Source-read why: the affected tree's own callback calls
  `php_rinit_session(0)` at MULTIPART_EVENT_FILE_START
  (session.c:3308), which runs `php_rinit_session_globals()` BEFORE
  `php_session_initialize()` — the stale PS globals a bailout could
  leave between the vars-dtor and the `status=none` assignment are
  cleared before anything dereferences them, and
  `php_rinit_session_globals()`'s `ZVAL_UNDEF` never dereferences the
  stale zval. The 619-stale-globals-via-rfc1867 lane is CLOSED by
  observation + source read; the fix's extra EVENT_START rinit and
  `PG(modules_activated)` guard close narrower windows (deferred
  body parse via request_parse_body, which the affected 8.4.x does
  not expose to user code the same way).
- **Last evidence (2026-11-20, 8.4.26-ASan lab build,
  `lab/repro/php2shell-rung2-oom-cgi.sh`, outputs
  `lab/build/evidence/rung2-cgi-*.out`):** all three vendor shapes
  (`memory_limit=8M post_max_size=1G max_input_vars=10000000`, php-cgi,
  stock ZEND allocator) reach "Allowed memory size of 8388608 bytes
  exhausted ... in Unknown on line 0", exit 255, at
  zend_smart_str.c:40 / zend_hash.c:1323 / main/php_variables.c:378 —
  i.e. the OOM bailout happens inside `php_request_startup()`
  (`php_hash_environment()`), before any user code. No ASan report:
  source read of cgi_main.c:2464 confirms cgi calls `php_module_shutdown()`
  on startup FAILURE and never `php_request_shutdown()` — the invalid
  state is created but not consumed in this SAPI. Negative result
  preserved, not retried.
- **Provisioning pinned (committed):** `lab/php2shell/provision.sh` —
  tarballs verified against php.net sha256 (8.4.26 affected / 8.4.27
  fixed; 8.4.28 released 2026-11-19 but the CVE fix remains 8.4.27 per
  NEWS); fix commit pinned as php/php-src@3584a98bd "Avoid state
  corruption via bailout" — **one commit, both CVEs**, +8745 lines/300
  files, patch archived at
  `lab/src/php-fix-3584a98bda0f2c0d367255b046798b0d3a221a19.patch`
  (github .patch endpoint 503'd; reconstructed from the commit API,
  sha256-pinned in the script).
- **Mechanism read from the patch (spec-first):** 618 = OOM stops
  longjmping (`zend_oom_state` PENDING→HANDLING→HANDLED, fallible
  `femalloc` family returning NULL, delayed soft OOM at VM safe points,
  hard OOM `_exit(137)` past a second threshold; test hook
  `zend_mm_set_max_allocs`, exit 121 — fixed tree only); 619 =
  `zend_shutdown_executor_values()` now zeroes user error/exception
  handlers, `EG(errors)`, `EG(exception)`, `EG(objects_store)`. The
  rfc1867 upload-progress decode (2026-10-23 PoC vector's producer) is
  forced to `__PHP_Incomplete_Class` in the fixed tree — dead on 8.4.27,
  relevant only against affected builds.
- **Build plan (committed):** `lab/php2shell/build.sh
  <8.4.26|8.4.27> <asan|plain>` — clang
  `-fsanitize=address,undefined -fno-sanitize=function` (UBSan's
  `function` check aborts on benign PHP prototype mismatches in
  zend_ini_parser/zend_API globals ctors — observed, then excluded),
  `--enable-debug --enable-session --enable-cgi --disable-phpdbg`,
  source tree copied to `lab/build/php-<v>-<mode>`. Both ASan variants are
  built and smoked; the FPM variants follow the same flags in
  `lab/build/php-<v>-fpm-asan` via `lab/php2shell/build-fpm.sh`
  (`--enable-fpm` instead of `--enable-cgi`).
  A separate apache2handler module build exists:
  `lab/build/php-8.4.26-apache-asan/.libs/libphp.so` — same sanitizer
  flags but NO `--enable-debug`, `--disable-all --enable-session
  --with-apxs2=/usr/bin/apxs2 --disable-phpdbg`. Two lab lessons: the
  DSO does not embed the UBSan runtime, so httpd needs
  `LD_PRELOAD=libasan.so:libubsan.so` (ASan must be first or it aborts
  at startup); and noble's apache2 silently skips an
  `<IfModule mpm_prefork_module>` worker-tuning block in this minimal
  conf, leaving prefork defaults (5 workers) — the directives are
  top-level in `lab/apache2root/conf/httpd.conf` after the MPM
  LoadModule, which is observed to give exactly one persistent child.

Seeded by the operator 2026-11-20 from docs/task.md; php2shell owns this
file.
