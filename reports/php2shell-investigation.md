# PHP2Shell — investigation report

Target: **CVE-2026-109618** (OOM-handling corruption) and
**CVE-2026-109619** (stale global state across requests) in core PHP,
CVSS 9.2 both, with public pre-auth RCE claims against
WordPress/Drupal/Joomla. Affected 8.2<8.2.35, 8.3<8.3.36, 8.4<8.4.27,
8.5<8.5.12. Investigated 2026-11-20 inside this plant's loopback-only
laboratory.

## Result

**Rung 2 (reproducible failure with black-box discriminators). Rung 3 is
NOT established; rung 4 is NOT claimed.** The advisory's two preconditions
are reproducible on the affected 8.4.26 build under ASan/UBSan, and the
2026-10-23 serialize-handler vector produces attacker-controlled session
record mutation on the affected build only. However, across every
producer and every consumer SAPI reachable in this lab, every malformed
record and OOM shape ends in a clean warning or fatal, the persistent
worker answers the next request on the same PID, and **no AddressSanitizer,
UBSan or ZEND_ASSERT report has ever appeared**. No invalid-state read or
write has been observed. **Rung 4 via this family is not reachable in this
lab on the evidence gathered.** See `reports/php2shell-status.md` for the
full per-lane evidence record, including all negatives.

Amended 2026-11-20 (wakes 8–9): the 2026-11-19 vendor release named a
new payload class and reopened one lane, CVE-2026-126714 "phpAfterShell"
— see the dedicated section below. It grades rung 2: a demonstrated
session-splice deserialization primitive, produced end-to-end in this
lab by both the application-string path and the fully unauthenticated
upload-progress path, with the vendor fix verified behaviorally on
8.4.28. Still no memory unsafety: rung 3 is not established for it
(the public full chain's memory bug is undisclosed).

## Evidence ladder, honestly graded

| Stage | Grade | Evidence |
|---|---|---|
| Suspected vulnerability (source/advisory) | yes | Fix commit `php/php-src@3584a98bd` ("Avoid state corruption via bailout") read as spec; patch sha256-pinned at `lab/src/php-fix-3584a98bda0f2c0d367255b046798b0d3a221a19.patch` |
| Reproducible crash / deterministic fatal | yes | `lab/repro/php2shell-rung2-oom-cgi.sh`: memory_limit=8M, three vendor POST shapes, `Allowed memory size ... exhausted` in `php_request_startup()`, exit 255 on 8.4.26-ASan |
| Confirmed memory corruption | **no** | All ASan/UBSan/ZEND_DEBUG builds negative across every lane; `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1` made every request allocation a separate malloc block and was still negative |
| Demonstrated security impact (chosen bytes/pointer/marker) | **partial, rung 2 only** | Attacker bytes land in the re-encoded session class-name slot on 8.4.26; the handler-switch `W::__wakeup` marker fires, but on BOTH builds (version-neutral, so not this CVE's primitive). No pointer control, no corrupt-state read |

## Producers and consumers examined (all closed)

- **OOM bailout / 618** — vendor `oom_request_parsing.phpt`,
  `oom_pending_at_shutdown.phpt` shapes; stock ZMM and malloc-backed
  (`USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1`) so sanitizers see request memory.
  A pre-exec `RLIMIT_AS` was rejected: it breaks ASan itself
  (`ReserveShadowMemoryRange failed`, rc=134, observed at 256M/1G/4G).
  Plain `USE_ZEND_ALLOC=0` was rejected after source read: malloc failure
  reaches `__zend_malloc` → `zend_out_of_memory()` = `exit(1)`, not the
  longjmp (8.4.26 `zend_alloc.c:3292-3299`).
- **Stale globals / 619** — cross-request error-handler reset (source:
  `init_executor` runs before `php_hash_environment`, `main/main.c:1836`
  vs 1873), stale handler not invoked in request N+1; compound
  session-destruct-OOM × rfc1867 pre-RINIT decode absorbed on one worker
  (source: `php_rinit_session(0)` at `session.c:3308` clears the PS globals
  before any dereference).
- **Serialize-handler / rfc1867 upload-progress (2026-10-23 PoC)** — ported
  from the fix commit's own new regression tests; crafted session records
  decoded before RINIT by the multipart handler.
- **Consumers** — php-cgi (one-shot and fastcgi: source read shows
  `php_request_shutdown()` unreachable on startup failure,
  `cgi_main.c:2464-2471`); `php -S` cli-server (calls
  `php_request_shutdown()` after failed startup, `php_cli_server.c:2311`);
  mod_php under real Apache 2.4.58 prefork with release fast-shutdown
  (ASan+UBSan, no ZEND_DEBUG); and php-fpm (built in wake 7, see below).

## php-fpm lane (wake 7, 2026-11-20)

Owner direction #64 named FPM as the only unbuilt reachable SAPI. It is now
built and closed.

Build recipe (idempotent, committed):
```
bash lab/php2shell/build-fpm.sh all
# -> lab/build/php-8.4.26-fpm-asan/sapi/fpm/php-fpm   (PHP 8.4.26 (fpm-fcgi) (NTS DEBUG))
# -> lab/build/php-8.4.27-fpm-asan/sapi/fpm/php-fpm   (PHP 8.4.27 (fpm-fcgi) (NTS DEBUG))
```
Flags: `CC=clang`, `CFLAGS="-fsanitize=address,undefined
-fno-sanitize=function -fno-omit-frame-pointer
-fno-sanitize-recover=undefined -g -O1"`, `LDFLAGS="-fsanitize=address,undefined"`,
`./configure --disable-all --enable-debug --enable-session --enable-fpm
--disable-phpdbg`.

Worker config (generated by the harness into a temp dir, logged verbatim at
the head of each evidence log): `listen = 127.0.0.1:$PORT`, `pm = static`,
`pm.max_children = 1`, `pm.max_requests = 0`, `catch_workers_output = yes`,
`clear_env = no`, `env[USE_ZEND_ALLOC] = 0`, `env[USE_TRACKED_ALLOC] = 1`,
`memory_limit=8M`, `post_max_size=1G`, `max_input_vars=10000000`,
`session.save_path=<temp>/sess`, `session.upload_progress.enabled=1`,
`session.upload_progress.cleanup=0`. Sanitizer options are exported by the
launching shell and inherited: FPM's INI parser rejects `=` inside an
`env[...]` value and rejects `#` comments (both observed), so they cannot be
config directives.

No nginx, `cgi-fcgi` or `spawn-fcgi` exists on this host, so the harness
speaks FastCGI 1.0 directly (`lab/repro/php2shell-fpm-client.py`, loopback
only). Replay:
```
bash lab/repro/php2shell-rung3-fpm.sh lab/build/php-8.4.26-fpm-asan/sapi/fpm/php-fpm lab/build/evidence 18123
bash lab/repro/php2shell-rung3-fpm.sh lab/build/php-8.4.27-fpm-asan/sapi/fpm/php-fpm lab/build/evidence 18124
```
Evidence: `lab/build/evidence/rung3-fpm-{8.4.26,8.4.27}-fpm-asan.log`.

Observed, both builds, ZEND_DEBUG asserts live:
1. One worker child answered every probe (e.g. 8.4.26 master 521411 /
   child 521427). Runtime OOM and shutdown-function OOM each reported the
   fatal and the SAME child answered afterwards. 8.4.26 prints
   `exhausted at file:0`; 8.4.27 prints `Zend/zend_alloc.c:3293` — the
   known black-box version discriminator.
2. rfc1867 pre-RINIT crafted records reproduced the other SAPIs' results:
   8.4.26 rewrites
   `x|O:7:"Missing":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}`
   to `x|O:3:"foo":0:{}` and converts `x|C:7:"Missing":0:{}` to
   `x|O:7:"Missing":0:{}` with a warning; 8.4.27 destroys the first record
   and keeps the second byte-identical. The vendor no-user-code recipe
   warns `Class 'Suit' not found` on 8.4.26 and is silent on 8.4.27.
3. Handler-switch injection marker: fires on BOTH builds when
   `session.serialize_handler=php` is set at request startup (a planted
   `x|O:1:"W":...` record wakes `W`); an in-script `ini_set` is too late
   because `PS(mod)` is chosen at RINIT. Version-neutral — not this CVE's
   primitive.
4. ZERO ASan/UBSan/ZEND_ASSERT output on either build for every probe.
   FPM lane CLOSED at rung 2; no rung-3 signal.

## Reopened lane: CVE-2026-126714 "phpAfterShell" (wakes 8–10, 2026-11-20)

The 2026-11-19 vendor release (8.2.36/8.3.37/8.4.28/8.5.13) named a new
payload class in the same session family (GHSA-fm2m-fjf5-v3cp): the
`files` handler's `ps_files_write()` does not clear the old session
before writing the replacement (defect since PHP 4.1.0), so a worker
death mid-write leaves prefix-of-new + tail-of-old on the inode — a
THIRD valid session. Graded rung 2: a splice/deserialization primitive,
not observed memory unsafety; the public full chain's native-class
memory bug is undisclosed. Four observations, all on the ASan builds,
zero sanitizer output:

1. **Consumer** (`lab/repro/php2shell-aftershell-splice-consumer.sh`):
   the documented post-kill bytes decode with NO warning; naive
   mid-string cuts are refused (decoder length validation works).
2. **App-level producer**
   (`lab/repro/php2shell-aftershell-splice-producer.sh`, kill shim
   `lab/php2shell/aftershell-kill.c`): a real session write storing a
   user-controlled string, interrupted at the syscall boundary, leaves
   the splice; the next request promotes `$_SESSION['evil']` =
   stdClass. Requires application code that stores attacker strings in
   the session (the advisory's alternative path).
3. **Unauthenticated rfc1867 producer** (wake 9,
   `lab/repro/php2shell-aftershell-splice-upload.sh`): carrier AND
   replacement are both written by the multipart upload-progress
   callback pre-RINIT (`php_session_rfc1867_update` →
   `php_session_flush(1)` → `ps_files_write`, session.c:3175-3207) —
   no application session code at all; any pre-auth POST with a
   session id and a file part reaches it. Geometry: three progress
   keys (`carr`, `objk`, `tail`); the OBJ bytes ride inert inside
   `objk`'s serialized filename; the replacement updates only `carr`,
   so the kill at K = len(carr-new) splices
   `carrnew || OBJ || ... || tailrec`, and the `tail` record's `|`
   gives the promoted stream a clean EOF. Alignment is calibrated, not
   hand-computed (AFTERSHELL_LOG_ONLY dumps the pwrite buffers; PAD
   is adjusted until the OBJ offset equals K). Evidence:
   `lab/build/evidence/aftershell-upload-{8.4.26,8.4.27}-asan.log`:
   promoted stdClass, no-kill control clean, on both affected builds.
   Lesson kept: the first design (OBJ inside the REPLACED record) is
   impossible — the carrier would always extend past the cut, forcing
   the pre-write truncate (Variant A) and killing the splice; the OBJ
   must live in a RETAINED record.
4. **Fix verified** (8.4.28, mod_files.c:239-242 `ftruncate(0)` before
   every write): the same kill leaves only the new prefix (1019 bytes,
   carrier tail gone) and no object, for both the app-level and the
   unauthenticated producer
   (`aftershell-upload-8.4.28-asan.log`,
   `aftershell-producer-8.4.28-asan.log`).
5. **FPM replay** (wake 10,
   `lab/repro/php2shell-aftershell-splice-upload-fpm.sh`): the same
   unauth upload-progress splice, but the process that dies
   mid-FILE_START-pwrite is a real php-fpm worker child —
   fpm-error.log: "child NNN exited on signal 9 (SIGKILL)"; the
   master respawns a new child, and that RESPAWNED worker's plain
   session_start() promotes the stdClass (the consumer echoes its
   own pid, which is the respawned child's). The kill is armed for
   exactly one request via the shim's optional AFTERSHELL_KILL_ARM
   gate file (CGI harnesses unaffected); calibration matches the
   CGI lane exactly (K=1019, n=1892). Evidence:
   `lab/build/evidence/aftershell-upload-fpm-{8.4.26,8.4.27}-fpm-asan.log`.
   On 8.4.28-fpm-asan the same kill respawns cleanly but leaves the
   ftruncate-first file (1019 bytes, carrier tail gone) and the
   respawned consumer sees only `upload_progress_carr`
   (`aftershell-upload-fpm-8.4.28-fpm-asan.log`).

## Black-box discriminators (affected-only, reproducible)

- OOM fatal text: 8.4.26 `exhausted at file:0` vs 8.4.27
  `Zend/zend_alloc.c:3293` (fix propagates `ZEND_FILE_LINE`).
- Session record `x|O:7:"Missing":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}`:
  8.4.26 re-encodes to `x|O:3:"foo":0:{}`; 8.4.27 refuses.
- Session record `x|C:7:"Missing":0:{}`: 8.4.26 warns and converts to
  `x|O:7:"Missing":0:{}`; 8.4.27 keeps it byte-identical.

These are data-integrity mutations, not memory unsafety.

## What would reopen the lane

- Any ASan/UBSan/ZEND_ASSERT output in a rung-3 harness log (all harnesses
  verdict-scan for it).
- A vendor advisory naming a concrete serialize-handler payload class not
  covered here (coverage: vendor phpt recipes verbatim, unresolved-class
  reserved-prop collisions, C: slot, NUL-mangled, compound with OOM).
- A admissible SAPI not built here (FrankenPHP / LSAPI) or corrected
  upstream release checksums requiring re-provisioning.

Negative results and failed hypotheses are preserved in
`reports/php2shell-status.md`; no closed lane has been retried into
existence.
