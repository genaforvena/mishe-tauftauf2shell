# PHP2Shell — status

Target: PHP2Shell — CVE-2026-109618 / CVE-2026-109619 (OOM-handling
corruption; stale global state across requests), CVSS 9.2 both, pre-auth
RCE demonstrated on WordPress/Drupal/Joomla. Affected 8.2<8.2.35,
8.3<8.3.36, 8.4<8.4.27, 8.5<8.5.12.

- **Rung:** 2. Trigger deterministic (rung 1); the consumer
  hunt has now covered every SAPI cheaply reachable, including mod_php
  under real Apache, and each negative is observed, not assumed:
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
    producer is dead on mod_php too; the remaining lane is the
    serialize-handler/upload-progress PoC port.

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
- **Next action (order set by evidence):** both cheap consumer lanes
  (cli-server, mod_php) are now observed negatives, so the remaining
  producer is the circulating 2026-10-23
  serialize-handler/upload-progress PoC against the 8.4.26 builds: its
  producer is RSHUTDOWN-time session decode (php_binary/php_serialize
  handler switch + session.upload_progress multipart), a window none of
  the rung-2 shapes touched. Lab php.ini knobs for it are pre-staged in
  `lab/apache2root/conf/php.ini` (session.save_path,
  session.upload_progress.enabled=1).
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
- **Allocator reality (observed):** `USE_ZEND_ALLOC=0` disables
  memory_limit accounting entirely — no OOM, exit 0, request completes.
  So the OOM trigger requires the stock ZEND allocator, where ASan
  cannot observe intra-pool state. A malloc-backed OOM variant
  (USE_ZEND_ALLOC=0 + RLIMIT_AS forcing malloc/mmap failure — which per
  the advisory also reaches the vulnerable longjmp) is the follow-up that
  would give ASan visibility.
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
  source tree copied to `lab/build/php-<v>-<mode>`. 8.4.26-ASan built
  and smoked; 8.4.27-ASan negative control in flight.
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
- **Unknowns:** whether the circulating
  serialize-handler/upload-progress PoC works against a stock affected
  build at all; consumer behavior on this host's glibc for the
  corrupted shutdown path.

Seeded by the operator 2026-11-20 from docs/task.md; php2shell owns this
file.
