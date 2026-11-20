# PHP2Shell — status

Target: PHP2Shell — CVE-2026-109618 / CVE-2026-109619 (OOM-handling
corruption; stale global state across requests), CVSS 9.2 both, pre-auth
RCE demonstrated on WordPress/Drupal/Joomla. Affected 8.2<8.2.35,
8.3<8.3.36, 8.4<8.4.27, 8.5<8.5.12.

- **Rung:** 0 — suspected vulnerability. Claims read; nothing reproduced
  in the lab yet. Provisioning pinned and verified this wake; first
  ASan build in flight.
- **Next action:** run the `oom_request_parsing` trigger shapes against
  the 8.4.26 ASan build (`USE_ZEND_ALLOC=0`), then build 8.4.27-ASan as
  the negative control.
- **Last evidence:** sources verified against php.net's published
  sha256 (`lab/php2shell/provision.sh`, re-fetched 8.4.26 from php.net
  end-to-end on 2026-11-20); fix commit pinned as php/php-src@3584a98bd
  "Avoid state corruption via bailout" — **one commit, both CVEs**
  (8.4.27 NEWS first entry), +8745 lines/300 files, patch archived at
  `lab/src/php-fix-3584a98bda0f2c0d367255b046798b0d3a221a19.patch`.
- **Mechanism read from the patch (spec-first):** 618 = OOM stops
  longjmping (`zend_oom_state` PENDING→HANDLING→HANDLED, fallible
  `femalloc` family, delayed soft OOM at VM safe points, hard OOM
  `_exit(137)` past a second threshold); 619 = `zend_shutdown_executor_values()`
  now zeroes user error/exception handlers, `EG(errors)`,
  `EG(exception)`, `EG(objects_store)` so stale request-owned state
  cannot survive into the next request. Session upload-progress decode
  (the 2026-10-23 PoC vector's producer) is forced to
  `__PHP_Incomplete_Class` in the fixed tree — that vector is dead on
  8.4.27, only relevant on the affected build.
- **Vendor's own trigger recipe** (Zend/tests/oom_request_parsing.phpt,
  fixed tree): php-cgi SAPI, `memory_limit=8M post_max_size=1G
  max_input_vars=10000000`, POST shapes = one 6MB value / 200k small
  vars / 3MB value + 100k vars → OOM during request parsing at startup.
- **SAPI consumer reality (advisory 618):** mod_php shuts down
  unconditionally after failed startup (confirmed-exploit SAPI); FPM
  exits the child on startup failure; php-cgi is the vendor test's SAPI.
  Lab order: php-cgi first (cheap), mod_php (Apache prefork, loopback)
  if cgi shows nothing.
- **Build plan:** `lab/php2shell/build.sh <8.4.26|8.4.27> <asan|plain>`
  — clang `-fsanitize=address,undefined`, `--enable-debug
  --enable-session --enable-cgi --disable-phpdbg`, tree copied to
  `lab/build/php-<v>-<mode>`; run with `USE_ZEND_ALLOC=0` so request
  memory is malloc-backed and ASan sees stale-state reads; every claim
  labeled with this configuration. Fixed-tree-only OOM-injection hook:
  `zend_mm_set_max_allocs` (exit 121) — not usable on the affected build.
- **Unknowns:** whether the cgi SAPI consumes the invalid state after a
  startup OOM on 8.4.26 (vendor test only asserts the fixed tree
  survives); consumer behavior on this host's glibc for the corrupted
  shutdown path; whether the circulating serialize-handler/upload-progress
  PoC works against a stock affected build at all.

Seeded by the operator 2026-11-20 from docs/task.md; php2shell owns this
file.
