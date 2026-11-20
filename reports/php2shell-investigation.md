# PHP2Shell — investigation report

Target: **CVE-2026-109618** (OOM-handling corruption) and
**CVE-2026-109619** (stale global state across requests) in core PHP,
CVSS 9.2 both, with public pre-auth RCE claims against
WordPress/Drupal/Joomla. Affected 8.2<8.2.35, 8.3<8.3.36, 8.4<8.4.27,
8.5<8.5.12. Investigated 2026-11-20 inside this plant's loopback-only
laboratory.

## Result

**Original 618/619 lane: rung 2 (reproducible failure with black-box
discriminators); rung 3 NOT established; rung 4 NOT claimed.** The advisory's two preconditions
are reproducible on the affected 8.4.26 build under ASan/UBSan, and the
2026-10-23 serialize-handler vector produces attacker-controlled session
record mutation on the affected build only. However, across every
producer and every consumer SAPI reachable in this lab, every malformed
record and OOM shape ends in a clean warning or fatal, the persistent
worker answers the next request on the same PID, and **no AddressSanitizer,
UBSan or ZEND_ASSERT report appeared in that lane**. No invalid-state read or
write was observed there. The reopened 126714 lane later reached rung 3
through a different native bug — see the wake-17 amendment below; rung 4
remains unclaimed for every lane.
See `reports/php2shell-status.md` for the full per-lane evidence record,
including all negatives.

Amended 2026-11-20 (wakes 8–9): the 2026-11-19 vendor release named a
new payload class and reopened one lane, CVE-2026-126714 "phpAfterShell"
— see the dedicated section below. It grades rung 2 as a demonstrated
session-splice deserialization primitive, produced end-to-end in this
lab by both the application-string path and the fully unauthenticated
upload-progress path, with the vendor fix verified behaviorally on
8.4.28. Its rung-2 behavioral claims are witness-ESTABLISHED (tapes
#98/#103/#108, 2026-11-20); wake 17 adds a separate, patch-sensitive
rung-3 observation for the combined chain below.

**Amended 2026-11-20 (wake 17, operator directive #113 pushing past rung 2):
the reopened lane plus a native Date-class bug reaches rung 3 — confirmed
memory corruption.** The splice-corrupted session state can make a PRE-RINIT
session decode emit a warning while a stale timezone-cache pointer is live;
on the affected 8.4.26/8.4.27 ASan CGI builds the log timestamp formatter
reads a wild pointer and ASan reports `SEGV on unknown address
0x0008a5c3c279` at `Zend/zend_hash.c:945 in zend_hash_str_find_bucket`.
The fixed 8.4.28 build logs the same warning and exits 0. Full chain,
conditions, controls and the per-build evidence are in the dedicated
section below. Rung 4 (chosen bytes at a chosen offset, pointer control or
benign marker execution) is still NOT claimed.

## Evidence ladder, honestly graded

| Stage | Grade | Evidence |
|---|---|---|
| Suspected vulnerability (source/advisory) | yes | Fix commit `php/php-src@3584a98bd` ("Avoid state corruption via bailout") read as spec; patch sha256-pinned at `lab/src/php-fix-3584a98bda0f2c0d367255b046798b0d3a221a19.patch` |
| Reproducible crash / deterministic fatal | yes | `lab/repro/php2shell-rung2-oom-cgi.sh`: memory_limit=8M, three vendor POST shapes, `Allowed memory size ... exhausted` in `php_request_startup()`, exit 255 on 8.4.26-ASan |
| Confirmed memory corruption (reopened lane + native Date cache, wake 17) | **yes (rung 3)** | `lab/repro/php2shell-rung3-tzcache.py`: affected 8.4.26/8.4.27 ASan CGI, splice-decode warning → `AddressSanitizer: SEGV` at `zend_hash.c:945 in zend_hash_str_find_bucket`, wild address `0x0008a5c3c279`; fixed 8.4.28 clean; four controls clean on every build |
| Demonstrated security impact (chosen bytes/pointer/marker) | **partial — rung 2 data mutation; rung 3 invalid read, no rung 4** | Attacker bytes land in the re-encoded session class-name slot on 8.4.26; the handler-switch `W::__wakeup` marker fires, but on BOTH builds (version-neutral, so not this CVE's primitive). The rung-3 memory access is a wild read, not controlled placement. |

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

## Reopened lane: CVE-2026-126714 "phpAfterShell" (wakes 8–13, 2026-11-20)

The 2026-11-19 vendor release (8.2.36/8.3.37/8.4.28/8.5.13) named a new
payload class in the same session family (GHSA-fm2m-fjf5-v3cp): the
`files` handler's `ps_files_write()` does not clear the old session
before writing the replacement (defect since PHP 4.1.0), so a worker
death mid-write leaves prefix-of-new + tail-of-old on the inode — a
THIRD valid session. Graded rung 2: a splice/deserialization primitive,
not observed memory unsafety; the public full chain's native-class
memory bug is undisclosed. Eight observations below, all on the ASan
builds, zero sanitizer output:

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
   no application session code at all; any pre-auth POST carrying a
   session id and a file part reaches it, under the non-default
   session config the harness sets (`session.use_strict_mode=0`,
   `use_cookies=0`, `use_only_cookies=0`,
   `upload_progress.cleanup=0` — with the compile default
   `use_strict_mode=1` the FILE_START write shrinks to 1019 bytes,
   below the carrier, and the splice cannot be calibrated; witness
   observation, tape #98). Geometry: three progress
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
   fpm-error.log: "child NNN exited on signal 9 (SIGKILL)" — the
   SIGKILL is delivered by the committed LD_PRELOAD kill shim at
   the pwrite boundary: the worker, the interrupted write and the
   respawn are real, but the death is simulated, not an OOM kill
   (witness disclosure nit, tape #98); the
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
6. **Branch coverage, 8.2 branch** (wake 11): the last affected head
   of the 8.2 branch, php-8.2.35 (fixed only in 8.2.36, the 2026-11-19
   release), is source- and behavior-verified affected: its
   `ps_files_write` still truncates only when
   `ZSTR_LEN(val) < data->st_size` (mod_files.c:239-241) and both
   committed producer harnesses reproduce the full splice →
   promotion on the 8.2.35 ASan build — app-level producer
   (`aftershell-producer-8.2.35-asan.log`: kill at byte 100 of a real
   session write, `R[0:100]||C[100:]` on disk, `EVIL=object(stdClass)`,
   control clean) and the unauthenticated rfc1867 producer
   (`aftershell-upload-8.2.35-asan.log`: same calibrated geometry as
   the 8.4 lane, K=1019, n=1866, splice on disk, promoted stdClass,
   control clean) — zero ASan/UBSan/ZEND_ASSERT output in both logs.
   Portability note: the app-level harness needs the CLI binary
   (`php -r`); 8.2's CGI SAPI has no `-r`.
7. **Branch coverage, 8.3 branch** (wake 12): the last affected head of
   the 8.3 branch, php-8.3.36 (fixed only in 8.3.37), is behavior-verified
   affected: both producer harnesses reproduce on
   `lab/build/php-8.3.36-asan` — app-level producer
   (`aftershell-producer-8.3.36-asan.log`: kill at byte 100,
   `R[0:100]||C[100:]` on disk, `EVIL=object(stdClass)`, control clean)
   and the unauthenticated rfc1867 producer
   (`aftershell-upload-8.3.36-asan.log`: same geometry as the 8.2 lane,
   K=1019, n=1866, splice verified byte-exact, promoted stdClass,
   control clean) — zero ASan/UBSan/ZEND_ASSERT in both logs.
8. **Branch coverage, 8.5 branch** (wake 13): the last affected head of
   the 8.5 branch, php-8.5.12 (fixed only in 8.5.13), is behavior-verified
   affected: source still truncates only when
   `ZSTR_LEN(val) < data->st_size` (mod_files.c:240-241), and both
   producer harnesses reproduce on `lab/build/php-8.5.12-asan` —
   app-level producer (`aftershell-producer-8.5.12-asan.log`: kill at
   byte 100, `R[0:100]||C[100:]` on disk, 210-byte file,
   `EVIL=object(stdClass)`, control clean) and the unauthenticated
   rfc1867 producer (`aftershell-upload-8.5.12-asan.log`: K=1019,
   FILE_START write n=1892 — 8.5's record layout matches the 8.4
   lane, not 8.2/8.3's 1866; 1589-byte carrier, splice verified
   byte-exact, promoted stdClass, control clean) — zero
   ASan/UBSan/ZEND_ASSERT in both logs. With this, every affected
   branch head (8.2.35, 8.3.36, 8.4.27, 8.5.12) is behavior-verified
   and branch coverage is complete.

**Witness acceptance (2026-11-20, tapes #98, #103, #108):** every
behavioral claim in this reopened lane is independently ESTABLISHED at
rung 2 by the witness's own re-runs of the committed harnesses (never
my logs): the FPM replay on 8.4.26/8.4.27 with its own 8.4.28
patch-sensitivity control and wrong-cut controls (K±16 do not promote
— promotion needs exact calibration, not any partial write; tape #98);
the 8.2.35 and 8.3.36 branch coverage, byte-exact, into
`lab/build/evidence/w6-branch/` (tape #103; its 8.2.35 citation nit is
repaired, commit 851f305); and the 8.5.12 branch coverage with a
K−16 counterexample (`A_EVIL=NULL`, tape #108) — the
branch-coverage-complete claim holds independently. Zero
ASan/UBSan/ZEND_ASSERT output in every independent run; no
contradiction, no repair outstanding.

## Rung 3: splice-decode warning → corrupted native timezone cache (wake 17)

The operator's 2026-11-20 directive (#113) refused a stand-down at rung 2.
Reading the pinned 8.4.27/8.4.28 trees and NEWS found two security fixes in
the same 2026-11-19 release: GHSA-fm2m-fjf5-v3cp (CVE-2026-126714, the
session-splice lane) and GHSA-gr4f-wgx5-jpfv (CVE-2026-129496, a
use-after-free of the Date extension's timezone cache fixed by 8.4.28).
Depthfirst's write-up says its withheld full chain uses a native-class
memory-corruption primitive and mentions date/time objects among the
audited classes; which native bug it used is UNKNOWN. The chain below is a
demonstrated one on published material, not a claim about their decoder.

Harness: `lab/repro/php2shell-rung3-tzcache.py` (PHP CGI, loopback only, no
network). It writes a session file whose bytes are the documented
`splice-MID` shape from `lab/repro/php2shell-aftershell-splice-consumer.sh`
(a long `s:` record whose declared length cuts before the object bytes —
the wrong-cut state that the witness also produced with K±16), sets
`date.timezone=Bogus/Zone` and a file `error_log`, and sends a multipart POST
with `PHP_SESSION_UPLOAD_PROGRESS` and a Cookie SID. The stale-pointer
mechanism is the advisory's: a diagnostic written to a file error log
during module startup allocates the timezone cache in temporary memory;
the native reference survives until the Date RINIT. The corrupted session
is decoded in `php_session_rfc1867_update()` before RINIT; the decoder's
warning is formatted for the file log while that reference is stale.

Observed (evidence logs `lab/build/evidence/aftershell-tzcache-php-8.4.26-asan.log`,
`...-8.4.27-asan.log`, `...-8.4.28-asan.log`):

- 8.4.26-asan and 8.4.27-asan, `splice-mid`: rc −6,
  `ERROR: AddressSanitizer: SEGV on unknown address 0x0008a5c3c279`,
  `SUMMARY: AddressSanitizer: SEGV Zend/zend_hash.c:945:8 in
  zend_hash_str_find_bucket`. Stack: `php_session_cancel_decode
  (ext/session/session.c:271)` → `php_session_decode` →
  `php_session_initialize` → `php_session_rfc1867_update (session.c:3225)`
  → `rfc1867_post_handler` → `php_hash_environment` →
  `php_request_startup (main/main.c:1906)` → `php_log_err_with_severity`
  → `php_format_date` → `get_timezone_info` → `php_date_parse_tzfile
  (ext/date/php_date.c:505)` → `zend_hash_str_find_bucket`. In a variant
  with a shorter session record UBSan reported "applying non-zero offset
  ... to null pointer" at the same `zend_hash.c:945` site — two independent
  sanitizer manifestations of the invalid read.
- 8.4.28-asan, same harness: rc 0, no sanitizer output; the file error log
  records `PHP Request Startup: Failed to decode session object. Session has
  been destroyed` normally. Patch-sensitive control, not a crash-only
  observation.
- Clean controls on all three builds: `valid-record` (session file decodes),
  `no-record`, `valid-timezone` (no startup diagnostic), `no-cookie` (no
  session file opened). The standalone `max-input-vars` advisory recipe also
  fails affected-only on 8.4.26/8.4.27 (`_zend_is_inconsistent` assertion on
  the stale HashTable) and is clean on 8.4.28.

Conditions to reproduce honestly: `date.timezone` invalid (or another
startup diagnostic reaching the file error log), file-based `error_log`,
`session.upload_progress.enabled=1`, a session id the worker accepts, and
splice bytes that make the pre-RINIT decode warn. This is an affected-only
invalid native pointer read, graded rung 3. The bytes at the faulting
address are not chosen by the attacker in this experiment: Stage A
placement and a benign marker are the missing rung-4 evidence.

## Black-box discriminators (affected-only, reproducible)

- OOM fatal text: 8.4.26 `exhausted at file:0` vs 8.4.27
  `Zend/zend_alloc.c:3293` (fix propagates `ZEND_FILE_LINE`).
- Session record `x|O:7:"Missing":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}`:
  8.4.26 re-encodes to `x|O:3:"foo":0:{}`; 8.4.27 refuses.
- Session record `x|C:7:"Missing":0:{}`: 8.4.26 warns and converts to
  `x|O:7:"Missing":0:{}`; 8.4.27 keeps it byte-identical.

These are data-integrity mutations, not memory unsafety.

## Next route from rung 3 (Stage A)

- Stage A placement: reuse the freed startup tzcache allocation with
  attacker-chosen bytes and prove a canary at a chosen offset; only then
  attempt a benign marker execution and a rung-4 claim. Missing evidence:
  control of the stale pointer and the replacement contents.
- A public disclosure of Depthfirst's withheld native decoder could supply
  the exact gadget instead of this independently found Date-cache route.
- A vendor advisory naming a concrete serialize-handler payload class not
  covered here (coverage: vendor phpt recipes verbatim, unresolved-class
  reserved-prop collisions, C: slot, NUL-mangled, compound with OOM).
- A admissible SAPI not built here (FrankenPHP / LSAPI) or corrected
  upstream release checksums requiring re-provisioning.

Negative results and failed hypotheses are preserved in
`reports/php2shell-status.md`; no closed lane has been retried into
existence.
