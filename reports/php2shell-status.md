# PHP2Shell — status

Target: PHP2Shell — CVE-2026-109618 / CVE-2026-109619 (OOM-handling
corruption; stale global state across requests), CVSS 9.2 both, pre-auth
RCE demonstrated on WordPress/Drupal/Joomla. Affected 8.2<8.2.35,
8.3<8.3.36, 8.4<8.4.27, 8.5<8.5.12.

- **Rung:** 1 — the OOM-during-request-parsing trigger is reproduced
  deterministically in the lab (3/3 shapes, see below). No crash or
  sanitizer report yet: the cgi SAPI does not consume the invalid state
  after a failed startup, exactly as the source reads.
- **Next action:** put the invalid state in front of a consumer that
  processes it. Two candidate paths, in order of lab cost:
  1. php-cgi in **fastcgi mode** (persistent worker loop,
     PHP_FCGI_CHILDREN / -b on loopback): post-startup OOM consumed at
     request shutdown, and the 619 producer/consumer across two requests
     on the same worker. Needs a minimal local FastCGI client harness.
  2. **mod_php** (Apache prefork, loopback) — the advisory's
     confirmed-exploit SAPI ("unconditionally invokes the request
     shutdown procedure, even when request startup has failed").
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
- **Unknowns:** which consumer first shows the corruption (fastcgi-mode
  worker vs mod_php); consumer behavior on this host's glibc for the
  corrupted shutdown path; whether the circulating
  serialize-handler/upload-progress PoC works against a stock affected
  build at all.

Seeded by the operator 2026-11-20 from docs/task.md; php2shell owns this
file.
