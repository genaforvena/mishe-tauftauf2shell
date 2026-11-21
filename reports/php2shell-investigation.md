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
reads a wild pointer; ASan reports `SEGV` in `zend_hash_str_find_bucket` at
`Zend/zend_hash.c:790:8` on 8.4.26 and `Zend/zend_hash.c:945:8` on 8.4.27
(same statement, different tree line). The faulting address is
non-deterministic: my logs show `0x0008a5c3be58` (8.4.26) and
`0x0008a5c3c279` (8.4.27); the witness's independent runs show
`0x0008a5c3c26c` / `0x0008a5c3be4c` (`lab/build/evidence/w8-tzcache/`).
The fixed 8.4.28 build logs the same warning and exits 0. Full chain,
conditions, controls and the per-build evidence are in the dedicated
section below. Rung 4 (chosen bytes at a chosen offset, pointer control or
benign marker execution) was still NOT claimed there.

**Amended 2026-11-20 (wake 18): Stage A reached a CONSTRAINED rung-4 form.**
With `USE_ZEND_ALLOC=0`, the stale timezone cache is a textbook ASan
heap-use-after-free (56-byte region allocated in `php_date_parse_tzfile()` at
`php_date.c:501` from the startup `date.timezone` diagnostic, freed by
`tracked_free_all()` → `shutdown_memory_manager()` at the end of
`php_module_startup()`, read again from the PRE-RINIT decode warning).
On the plain 8.4.27 build a query-string value makes a request-lifetime
allocation reuse that freed chunk: GDB dumps prove the attacker's value
length and bytes land at HashTable offsets 16, 24, 28 and 32 — the exact
fields `zend_hash_str_find_bucket()` reads. Query values of length 9–24 turn
the affected build's silent UAF into SIGSEGV (lengths 25 and above exit 0 with
this groomscript; the cause of that upper boundary is UNKNOWN); identical input on the fixed
8.4.28 build exits 0. Grade: rung 4 in the limited sense of chosen bytes at
chosen offsets plus control of the consumed pointer field's low bits; NOT
arbitrary-address control, no marker executed. Full evidence below.

Witness verdict (message #138, 2026-11-20): ESTABLISHED at rung 4 CONSTRAINED
from an independent clean-HEAD re-run of every proof.sh leg into
`lab/build/evidence/w10-stageA/`. Its sweep found the upper boundary at 24
(0–8 and 25/26/27/31/32 all rc 0), corrected the ASan frame to
`_zend_is_inconsistent` (see item 1 below) and confirmed the key-independence
controls. No repair was owed; grade unchanged. The witness did not
independently re-run the `malloc56` backtrace (item 2): its controls are
consistent with it, not proof of that specific backtrace.

## Evidence ladder, honestly graded

| Stage | Grade | Evidence |
|---|---|---|
| Suspected vulnerability (source/advisory) | yes | Fix commit `php/php-src@3584a98bd` ("Avoid state corruption via bailout") read as spec; patch sha256-pinned at `lab/src/php-fix-3584a98bda0f2c0d367255b046798b0d3a221a19.patch` |
| Reproducible crash / deterministic fatal | yes | `lab/repro/php2shell-rung2-oom-cgi.sh`: memory_limit=8M, three vendor POST shapes, `Allowed memory size ... exhausted` in `php_request_startup()`, exit 255 on 8.4.26-ASan |
| Confirmed memory corruption (reopened lane + native Date cache, wakes 17–18) | **yes (rung 3)** | `lab/repro/php2shell-rung3-tzcache.py`: affected 8.4.26/8.4.27 ASan CGI, splice-decode warning → `AddressSanitizer: SEGV` in `zend_hash_str_find_bucket` (`zend_hash.c:790:8` on 8.4.26, `:945:8` on 8.4.27 — same statement, different tree line); faulting address non-deterministic, e.g. `0x0008a5c3be58` / `0x0008a5c3c279` in my runs and `0x0008a5c3c26c` / `0x0008a5c3be4c` in the witness's; with `USE_ZEND_ALLOC=0` ASan instead reports a 56-byte `heap-use-after-free` with allocation/free stacks (`lab/build/evidence/stageA/uaf-8.4.27-asan-USE_ZEND_ALLOC0.log`); fixed 8.4.28 clean; controls clean on every build |
| Demonstrated security impact (chosen bytes/pointer/marker) | **yes, CONSTRAINED rung 4 (wake 18; witness #138)** — plus version-neutral rung-2 data mutation | `lab/repro/php2shell-stageA-groom.py`: on plain 8.4.27 with `USE_ZEND_ALLOC=0`, a query-string value reuses the freed startup tzcache chunk; GDB shows the value length at HashTable `arData` (offset 16) and the value bytes at offsets 24–32 — precisely the fields `zend_hash_str_find_bucket()` consumes. rc −11 for value lengths 9–24 on 8.4.27, rc 0 on 8.4.28 and for all three controls. Limit: `arData` is a small chosen integer (length), not an arbitrary address; no marker executed. |

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
  `ERROR: AddressSanitizer: SEGV on unknown address <wild>` — the address
  varies between runs (my logs: `0x0008a5c3be58` on 8.4.26,
  `0x0008a5c3c279` on 8.4.27; the witness's independent runs:
  `0x0008a5c3c26c` / `0x0008a5c3be4c`), with `SUMMARY: AddressSanitizer:
  SEGV Zend/zend_hash.c:790:8` on 8.4.26 and `Zend/zend_hash.c:945:8` on
  8.4.27 in `zend_hash_str_find_bucket` (the same statement
  `idx=HT_HASH_EX(arData,nIndex)`, different tree line). Stack:
  `php_session_cancel_decode (ext/session/session.c:271)` →
  `php_session_decode` → `php_session_initialize` →
  `php_session_rfc1867_update (session.c:3225)` → `rfc1867_post_handler` →
  `php_hash_environment` → `php_request_startup (main/main.c:1906)` →
  `php_log_err_with_severity` → `php_format_date` → `get_timezone_info` →
  `php_date_parse_tzfile (ext/date/php_date.c:505)` →
  `zend_hash_str_find_bucket`. A UBSan manifestation of the same invalid
  read was reproduced with the IDENTICAL `splice-MID` record
  (`lab/tmp/tz_matrix.py`, whose record matches line 51 of the committed
  harness): "applying non-zero offset 773979844 to null pointer" at the
  same site — two independent sanitizers agree the pointer is invalid.
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
invalid native pointer read, graded rung 3 as run here. Wake 18's Stage A
below adds attacker-chosen bytes at chosen offsets to the same chain.

## Black-box discriminators (affected-only, reproducible)

- OOM fatal text: 8.4.26 `exhausted at file:0` vs 8.4.27
  `Zend/zend_alloc.c:3293` (fix propagates `ZEND_FILE_LINE`).
- Session record `x|O:7:"Missing":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}`:
  8.4.26 re-encodes to `x|O:3:"foo":0:{}`; 8.4.27 refuses.
- Session record `x|C:7:"Missing":0:{}`: 8.4.26 warns and converts to
  `x|O:7:"Missing":0:{}`; 8.4.27 keeps it byte-identical.

These are data-integrity mutations, not memory unsafety.

## Stage A: attacker bytes in the freed startup HashTable (wake 18)

Replay: `bash lab/repro/php2shell-stageA-proof.sh` (loopback only; logs in
`lab/build/evidence/stageA/`). It drives the same splice-MID warning as the
rung-3 harness with an added `QUERY_STRING` and
`USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1` so `emalloc` is libc `malloc` and the
freed startup chunk can actually be reused.

1. **Exact UAF identity (ASan).** With the same env, 8.4.27-asan no longer
   reports a wild-address SEGV but a `heap-use-after-free`: READ of size 4 at
   offset 8 of a 56-byte region; allocated at `php_date_parse_tzfile()`
   (`ext/date/php_date.c:501`) from `OnUpdate_date_timezone()` during
   `zm_startup_date()`; freed by `tracked_free_all()` →
   `shutdown_memory_manager()` at the end of `php_module_startup()`; read
   from `php_session_cancel_decode()` → `php_format_date()` →
   `get_timezone_info()` → `zend_hash_str_find()`. Evidence:
   `lab/build/evidence/stageA/uaf-8.4.27-asan-USE_ZEND_ALLOC0.log`. 8.4.28
   is clean. ASan aborts in `_zend_is_inconsistent` (`zend_hash.c:57`),
   reading offset 8 of the chunk — a distinct read from the `:945`
   `HT_HASH_EX` deref that faults the plain build (witness nit, #138). This
   removes any ambiguity about which object and which free the rung-3 read
   concerns.
2. **Reuse path.** A GDB watchpoint on the stale pointer's `arData` field and
   a conditional `malloc(56)` backtrace show the first post-startup 56-byte
   allocation is `zend_new_array_singleton()` from `php_default_treat_data()`
   for `$_GET` (`lab/build/evidence/stageA/malloc56-backtrace-8.4.27-plain.log`);
   at the request-time warning the same address holds a request-lifetime
   object carrying the query-string value. The witness's controls are
   consistent with this backtrace but did not independently re-run it
   (#138): treat the exact occupant type as author-observed, not
   witness-established.
3. **Chosen bytes at chosen offsets.** With `QUERY_STRING=XXX=ABCDEFGHIJ`
   (value length 10), `lab/repro/php2shell-stageA-fieldprobe.gdb` captures
   `DATEG(tzcache)` at its startup use and dumps the 56 bytes at every
   `zend_hash.c:945` hit on that same pointer. First hit: the live startup
   table (`flags=8`, `nTableMask=-2`, valid `arData`, zero elements). Second
   hit, during the PRE-RINIT decode warning: `flags=0`, `nTableMask=0`,
   `arData=0x0a` (the value LENGTH), `nNumUsed=0x44434241` (`"ABCD"`),
   `nNumOfElements=0x48474645` (`"EFGH"`), next word `0x4847464544434241`
   (`"ABCDEFGH"`), then `"IJ\0…"`. With `XXX=AAAAAAAAA` (length 9) the same
   fields read `arData=0x9`, `0x41414141`, `0x41414141`, `0x4141414141414141`.
   These are the exact fields `zend_hash_str_find_bucket()` consumes
   (`arData` as the pointer for `HT_HASH_EX`, and the counters). Evidence:
   `stageA-php-8.4.27-plain-splice-mid-gdb-qs{14,13}.log`.
4. **Black-box, patch-sensitive.** On plain 8.4.27, no query string or a
   value of length ≤ 8 gives rc 0 (the UAF is silent: the stale chunk aliases
   a benign, valid-looking HashTable); lengths 9–24 give rc −11 SIGSEGV
   (witness sweep: 25/26/27/31/32 give rc 0; upper boundary UNKNOWN). The
   key name is irrelevant (`XXX` behaves like `UTC`), so the control is the
   value's length/content, not a special key. Fixed 8.4.28 exits 0 for every
   length. Controls on 8.4.27 with the long query string — `valid-record`,
   `valid-timezone`, `no-cookie` — all exit 0, so both the startup diagnostic
   and the PRE-RINIT warning are still required.

Grade: **rung 4, constrained**. The attacker chooses bytes at chosen offsets
inside the live struct the consumer dereferences and controls the low bits of
the consumed pointer field (`arData` equals the chosen value length). NOT
claimed: an arbitrary 64-bit address, `nTableMask` control, a benign marker
execution, or a gadget chain — the consumed read address is
`chosen_length + hash("UTC")*4`, so this is a constrained pointer primitive,
not an arbitrary write. Pointer placement is an observed negative for query
and multipart grooming (Stage B) and session data (Stage B extension);
other SAPIs remain UNKNOWN.

No benign marker is available through THIS consumer: the stale access is a
data dereference (`HT_HASH_EX(arData,nIndex)`), not an indirect call, so a
marker would need a different consumer of the same freed object — UNKNOWN,
not claimed.

## Stage B: pointer-placement attempt on the same freed chunk (wake 19)

Replay: `python3 lab/repro/php2shell-stageB-occupants.py` (loopback only;
logs in `lab/build/evidence/stageB/`). It reuses the committed Stage A
fieldprobe and varies the query shape (10 cases) and the multipart field
shape (7 cases, one extra field parsed before the upload-progress warning),
then prints the last dump of the stale table at the PRE-RINIT warning.
The consumer computes
`nIndex = h | ht->nTableMask` and `((uint32_t*)arData)[(int32_t)nIndex]`;
a chosen-address read therefore needs a real pointer at offset 16 **and**
a zero or chosen mask at offset 12. All 17 shapes give only two occupants,
never that combination:

- long query values (9–24 bytes, e.g. `XXX=ABCDEFGHIJ`): a zend_string —
  `flags=0`, `mask=0`, `arData=0x0a` (the chosen length), value bytes at
  offsets 24–32; the GDB log shows `SIGSEGV` at `zend_hash.c:945`;
- short/nested query values, and ALL POST-field shapes (long values,
  arrays, nested keys, long names, no field): a genuine HashTable —
  `flags=0x10` or `0x00`, `mask=fffffffe`/`fffffffc`, `arData=0x5555…`
  (a real bucket pointer), `nNumUsed` 1–4; no fault, rc 0.

So neither query nor multipart-field grooming can put a chosen 64-bit
address into the consumed pointer field: the pointer-bearing occupant
always carries the table's valid small negative mask, which maps the huge
`h` of `"UTC"` back into the table's own hash slots, while the mask-zero
occupant always carries a small integer at `arData`. A chosen-address read
or a write would need a different freed object or a second consumer;
neither is established. This is a preserved negative for the two tested
input channels, not proof about every possible 56-byte allocation.

## Stage B extension: session-data channel (wake 20)

Replay: `python3 lab/repro/php2shell-stageB-session-channel.py` (loopback only;
logs in `lab/build/evidence/stageB/sessgroom-*.log`). It reuses the committed
Stage A fieldprobe but sends no query string, removing the Stage A
query-value groomer. Seven malformed
php-serialize session records try a `stdClass` object and long strings before
and after the failing `s:64:"AA"` declaration. Every leg emits "Failed to
decode session object" (so the warning path really runs), yet the stale chunk
at the warning is always a genuine one-element HashTable —
`flags=0x10`, `mask=fffffffe`, real `arData=0x5555…`, `nNumUsed=1` — with
rc 0 and no fault. No session-derived object or string claims the chunk at
the warning: it always holds a genuine HashTable (allocator UNKNOWN).

Together with Stage B this establishes a **structural either-or** at this
consumer: the occupant with `mask=0` always carries a small integer (a value
length) at `arData`, and the occupant with a real pointer at `arData` always
carries the table's valid negative mask, which folds `h` back into the
table's own hash slots. Full arbitrary-address control through this freed
object is therefore blocked by the observed consumer/allocator pairing on
this CGI path, not merely by an ungroomed heap — the same class of
structural block recorded for the sibling nginx2root plant. Grade remains
rung 4 CONSTRAINED: chosen bytes at chosen offsets and low-bit control of
the consumed pointer. Other SAPIs (FPM, Apache) remain UNKNOWN; no marker
or arbitrary address is claimed. This is a preserved negative, not a
retried hypothesis.

## Second consumer: indirect-call route closed (wake 21)

that is an indirect call. Beyond the observed read, `ext/date/php_date.c`
has two other operation sites on `DATEG(tzcache)`: `zend_hash_str_add_ptr`
(php_date.c:511, a write of a valid `timelib_tzinfo*` into the found table), and
`ZEND_MODULE_POST_ZEND_DEACTIVATE_D(date)` (php_date.c:428-433), which calls
`zend_hash_destroy()` — walking buckets and invoking the stored
`pDestructor` (`_php_date_tzinfo_dtor`) — then `FREE_HASHTABLE()`. That
destructor slot is at HashTable offset 24, where the Stage A groomscript
places attacker bytes, so it looked like a route to a chosen indirect call.

It is unreachable on this path. `PHP_RINIT_FUNCTION(date)`
(php_date.c:404-412) sets `DATEG(tzcache) = NULL` on every request. The
observed UAF read happens in `php_hash_environment()` at
`main/main.c:1906`, BEFORE `zend_activate_modules()` at `main.c:1907` runs
RINIT; request shutdown then calls `zend_post_deactivate_modules()` at
`main.c:2000`, which sees the NULL pointer and never enters
`zend_hash_destroy()`. The only other consumer, the add at php_date.c:511,
writes a fixed native pointer, not a chosen address.

Controls (plain 8.4.27 query groomer and the committed ASan/UAF harness):
8.4.27-asan splice-MID with ZERO query string still aborts rc −6 with the
SAME `heap-use-after-free` (`_zend_is_inconsistent`, zend_hash.c:57, 8 bytes
into the 56-byte region) — under ASan the freed block is quarantined, so the
groomer is needed for the plain build's chosen-byte placement, not for
sanitizer detection. 8.4.28-asan splice-MID rc 0; 8.4.27-asan valid-record
rc 0 with no ASan report, consistent with RINIT nulling the pointer before
shutdown. Logs: `lab/build/evidence/stageB/shutdown-uaf/stageA-php-8.4.{27,28}-asan-{splice-mid,valid-record}-plain-qs0.log`.
Grade unchanged; the "second consumer is an indirect call" upgrade
condition is now a source-backed negative for this CGI path.

## Stage A on FPM: corruption confirmed, byte placement not transferred (wake 22)

The wake-21 "other SAPIs UNKNOWN" narrowed for FPM. New harnesses:
`lab/repro/php2shell-stageA-fpm.sh` (single FastCGI request) and
`lab/repro/php2shell-stageA-fpm-sweep.py` (query-length sweep); both are
loopback-only and reuse `php2shell-fpm-client.py`.

**Trigger-setting lesson.** FPM applies `php_admin_value[date.timezone]` and
`php_admin_value[error_log]` too late to emit the startup diagnostic that
allocates the 56-B tzcache: the first attempt produced only the decode
warning and no fault. Passing `date.timezone=Bogus/Zone`, `error_log=<file>`
and `log_errors=1` as php-fpm `-d` flags (as the CGI groomer does) makes the
"PHP Startup: Invalid date.timezone value" warning appear and the UAF fire.
`php_admin_value` is not inert once `-d` supplied the invalid zone: the
single-shot config re-applies it at child init (`fpm_child_init` →
`fpm_php_init_child` → `fpm_php_apply_defines_ex` →
`OnUpdate_date_timezone` → `php_date_parse_tzfile:505`) and re-reads the
stale tzcache there (witness #208).

**Observed, 8.4.27, affected build.** With the startup diagnostic, a
splice-MID session record, an upload-progress multipart POST and a query
string:
- `php-8.4.27-fpm-asan`: the single-shot config aborts at CHILD INIT, before
  a request is served (`baseline_rc=2`, line 47 of
  `lab/build/evidence/stageA-fpm/stageA-fpm-8.4.27-fpm-asan.log`); the stack is
  `fpm_child_init` → `fpm_php_init_child` → `fpm_php_apply_defines_ex` →
  `OnUpdate_date_timezone` → `php_date_parse_tzfile:505` →
  `_zend_is_inconsistent` (`zend_hash.c:57:7`). In the sweep config (no
  `php_admin_value[date.timezone]`) the same UAF fires at REQUEST time from
  `php_session_cancel_decode (session.c:271)` → `php_log_err` →
  `php_format_date` → `get_timezone_info` → `php_date_parse_tzfile:505`.
  Witness re-run: `lab/build/evidence/w13-fpm-asan-sweep/sweep-qs0.log`,
  `sweep-qs10.log`; full child-init stack in
  `lab/build/evidence/w13-fpm-asan/fpm-error-8.4.27-fpm-asan.log`.
- `php-8.4.27-fpm-plain` (ZEND_DEBUG): SIGABRT, worker stderr
  `zend_hash.c(2920): ht=… is already destroyed` and
  `_zend_is_inconsistent: Assertion '0' failed`.
- `php-8.4.27-fpm-nodebug` (no ZEND_DEBUG): SIGSEGV, worker dies.
  Sweeps cover query-value lengths 0, 4, 8, 9, 10, 14, 24, 25, 32; every
  one faults on the plain builds. Evidence:
  `lab/build/evidence/stageA-fpm/sweep-*.log` and
  `lab/build/evidence/stageA-fpm-nodebug/sweep-*.log`.

**Controls.** In the sweep config (no `php_admin_value[date.timezone]`),
`date.timezone=UTC` (valid) and no session cookie serve normally with zero
sanitizer output (`lab/build/evidence/w13-fpm-asan-sweep/sweep-validtz.log`,
`sweep-nocookie.log`; witness re-run). That control does NOT hold for the
single-shot config: affected ASan and debug baseline no-cookie requests time
out (`rc 2`). `php-8.4.28-fpm-asan` with the identical config emits the
startup and decode warnings, serves every request, and reports zero
sanitizer output
(`lab/build/evidence/stageA-fpm-fixed/stageA-fpm-8.4.28-fpm-asan.log`).
Patch sensitivity holds on FPM.

**Interpretation / grade.** The first consumer (the stale-tzcache read) is
now confirmed memory corruption on FPM across three build flavors, not just
suspected. But the CGI-specific Stage A property — attacker-chosen bytes at
chosen offsets via query-string grooming — does NOT transfer: the fault is
query-length-independent (including length zero), and the debug build shows
the stale table read in an "already destroyed" state, not a benign reused
HashTable. No chosen-byte placement, pointer control or marker is claimed on
FPM; whether a 56-B occupant with pointer at offset 16 and mask=0 exists
there remains UNKNOWN (no GDB field inspection on an FPM worker), and the
indirect-call route is closed on every SAPI by core RINIT ordering (wake 21).
Grade unchanged: rung 4 CONSTRAINED (CGI, witness #138); FPM adds a
deterministic crash at rung 3, not a rung-4 upgrade. Apache remains UNKNOWN.
Witness #208 independently replayed both committed harnesses from clean HEAD
and ESTABLISHED the FPM rung-3 corruption with grade unchanged (evidence in
`lab/build/evidence/w13-fpm*/`); its three precision nits above are folded.

## Wake 24: FPM occupant fieldprobe — structural bits present, no attacker control

The wake-22 report left "does an FPM occupant have a pointer at +16 and
mask=0" as UNKNOWN. New loopback harness
`lab/repro/php2shell-stageA-fpm-fieldprobe.py` runs the plain 8.4.27 FPM
worker under GDB with `set follow-fork-mode child`, breaks at
`php_date.c:505` and dumps `date_globals.tzcache` on every hit while the
committed FastCGI client sends the Stage A splice request. Logs:
`lab/build/evidence/w24-fpm-fieldprobe3/fieldprobe-{long10,nested,none}.log`.

Two hits are observed. Hit 1 (child init) is the live startup table:
`tc=0x5555560e6770 flags=00000008 mask=fffffffe arData=0x555555d01550
nNumUsed=0`. Hit 2 (the request-time PRE-RINIT decode warning, on the same
pointer) is the freed chunk's occupant:

```
STALE n=2 tc=0x5555560e6770 flags=00000002 mask=00000000
         arData=0x5555561801f0 nNumUsed=00000140 nNumOfEl=00005555
0x5555560e6770: 0x0000555556191cd0 0x0000000000000002
0x5555560e6780: 0x00005555561801f0 0x0000555500000140
0x5555560e6790: 0x0000000000000000 0x00007fff00000000
0x5555560e67a0: 0x0000780071657266
```

So the literal Stage B precondition — a real pointer at offset 16 and
mask=0 at offset 12 — **does** exist on FPM, unlike the CGI occupant types.
But it is not a rung-4 upgrade: the hit-2 bytes are identical for query
`XXX=ABCDEFGHIJ`, `XXX=0__ABCDEFGHIJ` and no query at all, so the occupant is
a fixed request-lifetime object, not attacker-groomed. The final word
contains ASCII `freq\0x\0x`, consistent with an ini/bucket key. Moreover
flags=0x02 at +8 (refcount 0) makes `zend_hash_str_find()` report
`ht=0x5555560e6770 is already destroyed` at `zend_hash.c:2920` and abort at
the `zend_hash.c:74` `_zend_is_inconsistent` assertion before the consumer
can use `arData`; no chosen-address read occurs. The worker stderr in the
same log carries both messages. Grade unchanged: rung 4 CONSTRAINED on CGI
only, FPM confirmed corruption at rung 3, Apache UNKNOWN.

Two failed harness approaches are preserved, not retried: attaching GDB from
a sibling process is denied by Yama `ptrace_scope` (the attach log shows
`ptrace: Inappropriate ioctl for device`, while the un-debugged worker still
aborts at `zend_hash.c:74`); and the first fork-follow script auto-quit on
four startup `zend_hash.c:945` hits before the client connected, so its
dump was the child-init table, not the stale request-time occupant.


## Wake 25: Stage A on mod_php — Apache UNKNOWN closed, rung 4 CONSTRAINED

Wake 24 left Apache as the only SAPI with neither the rung-3 corruption nor
the occupant question tested. New loopback-only harness
`lab/repro/php2shell-stageA-apache.py` starts one prefork child with a
per-case `httpd.conf`/`php.ini`, pre-stages the spliced session file, and
sends the multipart upload-progress POST with the session cookie; the plain
module is built by `lab/php2shell/build-apache-plain.sh` (no sanitizer,
`-g -O0`, `apxs2`). All cases use `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1`
and bind 127.0.0.1 only.

1. **Rung 3, ASan 8.4.26 mod_php.** `lab/build/evidence/w25-apache-asan/apache-splice.log`
   is a textbook 56-byte `heap-use-after-free` read in
   `zend_hash_str_find_bucket` (`zend_hash.c:788`) via
   `php_date_parse_tzfile:505 ← get_timezone_info ← php_format_date ←
   php_log_err_with_severity ← php_session_cancel_decode:271` during
   `php_request_startup → rfc1867_post_handler`. Allocation is
   `php_date_parse_tzfile:501` from `OnUpdate_date_timezone` in
   `zm_startup_date`; the free is
   `tracked_free_all → zend_mm_shutdown → php_module_startup:2401` from
   `php_apache_server_startup` (parent post_config, inherited by the
   prefork child). No-cookie and valid-timezone controls are clean
   (274/210 response bytes, zero sanitizer markers).
2. **Black-box, plain 8.4.27 mod_php.** With a query value of length 9, 10,
   16 or 24 the child dies with `exit signal Segmentation fault (11)`
   (`lab/build/evidence/w25-apache-{len9,len10,len16,len24}/`), matching
   CGI's 9–24 window; length 8, 25 and 32 answer normally, and the
   no-cookie/valid-timezone controls answer normally. The fixed 8.4.28
   plain module built the same way answers the identical splice with a
   274-byte response and no signal (`lab/build/evidence/w25-apache-fixed/`).
3. **Chosen bytes, plain 8.4.27 mod_php under GDB.** Fork-follow GDB with a
   pending `php_date.c:505` breakpoint gives two hits: the parent startup
   table (`flags=00000008 mask=fffffffe`, real `arData`) and the child's
   request-time stale read. The child hit is
   `flags=00000000 mask=00000000 arData=0x000000000000000a` with raw bytes
   `0x4847464544434241 0x0000000000004a49` at offsets 24/32 for query
   `XXX=ABCDEFGHIJ`, and `0x5a5a5a5a` at both offsets for
   `XXX=ZZZZZZZZZZ` (`lab/build/evidence/w25-apache-gdb{,-z}/apache-splice.log`).
   `arData` is the value length, not an address; the process faults at
   `zend_hash.c:945` in `zend_hash_str_find_bucket`.

Grade: **mod_php reaches the same rung 4 CONSTRAINED form as CGI** — chosen
bytes at chosen offsets of the consumed stale HashTable, no pointer control
and no marker executed. Witness #258 independently replayed the harness into
its own `lab/build/evidence/w18-apache-modphp/` (plain 8.4.27 module sha256
`5f6e7ba9...` matched) and **ESTABLISHED** rung 3 CONFIRMED plus rung 4
CONSTRAINED with no correction: the ASan 56-B UAF at `zend_hash.c:788`, the
plain 8.4.27 SIGSEGV window at query lengths 9/10/16/24 (clean at 8/25/32,
fixed 8.4.28 clean), and the fork-follow GDB child hit
(`flags=0 mask=0 arData=0xa`, chosen bytes at +24/+32, fault at
`zend_hash.c:945`) all reproduced. FPM remains rung 3 only (wake 24).
Preserved failed approach: the first length sweep was invalid because GDB
detached the prefork parent at `quit`, leaving it bound to port 18160; the
harness now kills that parent by its unique per-case config path. The
earlier `ready=False` logs were overwritten by the valid rerun.

## Open routes after Stage A

- Extending the groom to set `arData` to a chosen address is an observed
  negative for query and multipart grooming (Stage B) and for session data
  (Stage B extension). On FPM the corruption path is confirmed but byte
  placement is not established and the fault is query-length-independent
  (wake 22); on mod_php (wake 25) chosen bytes transfer but `arData` is a
  length, so this route still cannot yield arbitrary-address control.
  The consumer is structurally either-or on the CGI path. Stage A is
  witness-ESTABLISHED on both CGI (#138) and mod_php (#258); no re-run is
  owed on either leg.
- A public disclosure of Depthfirst's withheld native decoder could supply
  the exact gadget instead of this independently found Date-cache route.
- A vendor advisory naming a concrete serialize-handler payload class not
  covered here (coverage: vendor phpt recipes verbatim, unresolved-class
  reserved-prop collisions, C: slot, NUL-mangled, compound with OOM).
- An admissible SAPI not built here (FrankenPHP / LSAPI) or corrected
  upstream release checksums requiring re-provisioning.

Negative results and failed hypotheses are preserved in
`reports/php2shell-status.md`; no closed lane has been retried into
existence.

## New descendant lane: CVE-2026-129481 (wake 27, 2026-11-20)

The 2026-11-19 release carried seven critical 9.2 CVEs; four were not
covered anywhere in this plant. CVE-2026-129481 (GHSA-g3vh-838c-65v7) is an
incomplete fix for CVE-2026-109619, this target's original bug: when a fatal
error interrupts session shutdown before the recorded script filename is
released, the stale pointer survives into the next request on the same
worker. This is a separate vulnerability from the closed rung-2 619 lane —
the earlier consumer matrix never exercised a failing session-cleanup
callback — so it is recorded as a new lane, not a reopening of 619.

`lab/repro/php2shell-cve129481-fpm.py` drives one static FPM child over
loopback FastCGI. Request 1 starts a session, stores a stream whose user
wrapper's `stream_close()` raises an uncaught Error, and unsets `$_SESSION`
so the session globals hold the last array reference. The fatal must fire
in the FINAL RSHUTDOWN's `zval_ptr_dtor` — not in `session_destroy()` — so
the bailout skips `php_session_cleanup_filename()` with no second pass.

On affected 8.4.27-fpm-asan (`lab/build/evidence/w27-cve129481-final/`)
ASan reports a 4-byte READ of a freed 64-byte region:
`zend_string_release (zend_string.h:426)` ← `php_session_cleanup_filename
(session.c:128)` ← `php_rshutdown_session_globals (session.c:163)` ←
`zm_deactivate_session (session.c:2979)`. The region was freed at the end
of the prior request by `tracked_free_all → shutdown_memory_manager`. An
ordinary next-request script (no session calls) reaches it via session
module shutdown, aborting that worker. Fixed 8.4.28 shows no ASan and
terminates the worker on the bailout; a benign `stream_close()` control on
8.4.27 shows no ASan and keeps the worker alive. Two earlier trigger
variants are preserved as negatives in the status ledger. Grade: **rung 3
CONFIRMED** for this lane on 8.4.27 FPM — confirmed memory corruption,
patch-sensitive, no rung-4 control claimed. Pre-auth reachability is
application-dependent and not claimed. CVE-2026-129474 was later tested at
rung 3 in wakes 29–30 (section below). CVE-2026-129182 has a committed
loopback FPM harness (`lab/repro/php2shell-cve129182-fpm.py`) replaying its
vendor regression case; both the debug and the finished 8.5.12 release ASan
FPM builds preserve a negative (vendor diagnostics reproduced, zero ASan
markers in malloc-backed, ZendMM and control modes — see the status ledger),
so its grade is **UNKNOWN** and no rung 3/4 or pre-auth claim is made. Wake 46
root-caused that negative under gdb: the worker does receive
`ZEND_ASAN_FORCE_FAST_SHUTDOWN=1` and takes the fast shutdown path
(`fast_shutdown=1`), but request N+1's `zend_activate()` UNDEFs
`EG(last_fatal_error_backtrace)` at `zend_execute_API.c:440` before the
`PHP Request Shutdown` warning reaches the unconditional dtor at
`zend.c:1509` (`active=0`, `type=IS_UNDEF`); `zval_ptr_dtor` on IS_UNDEF is a
no-op, so no stale pointer is dereferenced. Removing the admin timezone
directive changes nothing. An RSHUTDOWN fatal does produce ASan on this
build, but its stack is the separate 129481 session-filename UAF, not the
backtrace-repopulation path. The 8.5.13 fixed release build remains unbuilt;
patch sensitivity is untested and is not worth a build while both verdicts
are clean. A future attempt needs an exception-free fatal while
`EG(active)==0` that reaches the repopulation branch before startup resets
the global; full bytes are in `reports/php2shell-status.md` wake 46.
129289 remains untested (smuggling, not memory corruption).

ASan attributes the report to the FPM **worker** PID, which is shared across
requests: the worker that logged it (3153888; witness replay 3168299) served
the baseline probe, req1 and the mid probe, while req2 was served by a fresh
worker (3153916 / 3168323). The mid probe is the "ordinary next request"
above — its FastCGI connection is reset because the worker aborts during that
request's module-deactivation pass. A committed marker harness
(`lab/repro/php2shell-cve129481-mechanism.py`, output
`lab/build/evidence/w28-mechanism/`) makes this decisive: the mid request
writes a file from its PHP body before responding, and the marker exists
carrying the req1 worker's PID (3333600) while the mid response is empty and
req2 goes to a fresh PID (3333850). The worker therefore completed
req1's own shutdown, entered the mid request, and aborted in the mid request's
`php_request_shutdown` — it did not die inside req1. Source confirms the
ordering: `php_request_shutdown()` calls `zend_deactivate_modules()` at
`main.c:1968` (step 5) and `shutdown_memory_manager()` at step 15, so a free
followed by that read cannot occur in one shutdown call;
`zend_deactivate_modules()` wraps each module's RSHUTDOWN in `zend_try`
(`zend_API.c:3440-3448`), so req1's fatal bailout is caught there and its
shutdown completes through step 15. Witness #287 proposed rewriting this as a
same-request bailout free followed by the module-deactivation pass; that
rewrite is REJECTED on the marker evidence and the source ordering. The
rung-3 grade itself was ESTABLISHED by the witness's own replay and is unchanged.

## New descendant lane: CVE-2026-129474 (wake 29, 2026-11-20)

The 2026-11-19 release also carried CVE-2026-129474 /
GHSA-8mjj-2r7p-4hg2 (magic-method backtrace UAF, 8.5 only, vendor RCE
claim). Advisory read as provisioning, not accepted fact: the attack needs
`fatal_error_backtraces=1` (default on 8.5) and
`zend.exception_ignore_args=0` (the production ini sets 1, which blocks the
path), with a fatal error reported while a `__call`/`__callStatic` trampoline
frame is current. Affected `>=8.5.0 <8.5.13`.

The fixed tarball `php-8.5.13.tar.xz` (sha256
`607602acaf0c3061818e9916ec44a058e8b3d43959a83862b9cd3ec7bf5b785f`,
cross-checked against php.net's version JSON) contains the vendor's own
regression case, `Zend/tests/GHSA-8mjj-2r7p-4hg2.phpt`. Diffing the pristine
8.5.12 and 8.5.13 `Zend/` trees isolates the fix at
`zend_builtin_functions.c:1737`, in `debug_backtrace_get_args()`:

```diff
- if (call->func->type == ZEND_USER_FUNCTION) {
+ /* Extra args are moved after CVs and TMPs in user functions, except
+  * for trampoline frames (see i_init_func_execute_data()).
+  */
+ if (call->func->type == ZEND_USER_FUNCTION
+  && !(call->func->op_array.fn_flags & ZEND_ACC_CALL_VIA_TRAMPOLINE)) {
```

The vulnerable path applies the ordinary user-function extra-argument offset
to a magic-method trampoline frame, whose args are laid out differently, and
therefore reads stale zvals from the wrong slots.

`lab/repro/php2shell-cve129474.py` runs the vendor case verbatim on two CLIs.
On affected `php-8.5.12-asan` with `fatal_error_backtraces=1`,
`zend.exception_ignore_args=0`, `memory_limit=4M`, the soft OOM in the
`$a.$a` CONCAT is handled at DO_FCALL and the fatal backtrace (evidence
`lab/build/evidence/w29-cve129474/vulnerable.log`) prints:

```
Fatal error: Allowed memory size of 4194304 bytes exhausted at .../zend_string.h:169 (tried to allocate 2101248 bytes) in .../ghsa-8mjj-2r7p-4hg2.php on line 8
Stack trace:
#0 .../ghsa-8mjj-2r7p-4hg2.php(8): C::test(3, 4, 'aaaaaaaaaaaaaaa...', NULL, NULL)
#1 {main}
```

The call was `C::test(1, 2, 3, 4, $a.$a)`; the backtrace reports five
*different* zvals — a deterministic stale-argument read, not an ordinary
resource-limit message. With `USE_ZEND_ALLOC=0` no fatal occurs at all (the
soft OOM needs ZendMM), so ASan cannot see this read: ZendMM pools request
memory. No ASan report is claimed. This is a CLI demonstration; the vendor's
network-facing path (framework magic method plus a crafted request) is not
reproduced here, and no pre-auth, pointer-control or marker-execution claim
is made.
The fixed-control build `lab/build/php-8.5.13-asan` (same configure flags,
sha256-pinned source) produces
`#0 ...: C::test(1, 2, 3, 4, 'aaaaaaaaaaaaaaa...')` on the identical input.
Both runs and the verdict are in `lab/build/evidence/w29-cve129474/`
(`verdict.txt: CONFIRMED`); the harness prints the two frames and exits 0.
Wake 30 adds instrument-observed memory state (witness #327 nit 2).
`lab/repro/php2shell-cve129474-gdb.gdb` breaks in the 8.5.12 vulnerable CLI
at `zend_builtin_functions.c:1822` — the pointer reset applied to every
`ZEND_USER_FUNCTION` frame — and at the consuming loop head at `:1825`.
The first stop shows the 5-argument `C::test` frame has `fn_flags=0x44011`
with `ZEND_ACC_CALL_VIA_TRAMPOLINE` (`1<<18`) set, `first_extra_arg=0`,
`last_var=0`, `T=2`, and the unreset `p` slots holding type 4 (long) `1`
and `2`. After the reset `p` has advanced by two zvals (0x20 bytes) and the
slots actually consumed are `3`, `4`, type 6 (string), type 0 (undef),
type 0 (undef) — exactly the five zvals the fatal backtrace prints.
Evidence: `lab/build/evidence/w30-cve129474-gdb/committed-harness-vuln.log`.
The wrong-slot read is therefore observed in memory under a debugger, not
only inferred from output and the patch diff; it is a wrong frame-slot
argument read on a magic trampoline, not a claimed freed-memory UAF.
Grade: **rung 3 CONFIRMED** — a deterministic stale-argument read observed
both in the fatal backtrace and as wrong frame slots under gdb, and
patch-sensitive; still no ASan report (ZendMM pools the memory and the soft
OOM requires ZendMM). **Not rung 4**: no attacker-chosen occupant at a
controlled offset, no pointer control, no marker execution, and no
reproduced network-facing framework path.

### Wake 47 — 129182: exact fix diff and error ordering (negative, unchanged grade)

Comparing the pinned 8.5.12 and 8.5.13 trees shows the 129182 fix is two
`if (EG(active))` guards in `Zend/zend.c`: one around the `last_fatal_error_backtrace`
destructor at `:1509`, one around the backtrace repopulation at `:1534`. The
fix comment states the global is "useless when the executor is inactive, and
setting it at this point would leak." A focused loopback FPM GDB replay
(`lab/build/evidence/w47-cve129182-ordering/`) observes the exact order at the
vendor regression: the req1 fatal repopulates the array (`type` on entry to
`REPOP1534` is 0, `active=1`); req1's own `zend_shutdown_executor_values()`
then clears `EG(active)` at `zend_execute_API.c:280` and UNDEFs the global at
`:440` while its type is still `IS_ARRAY` (775), leaving only a stale
`value.arr`; the req2 PHP_VALUE diagnostic runs with `active=0, flags=7` but
`type=IS_UNDEF`, so the destructor is a no-op and the E_WARNING never reaches
the repop branch. This corrects wake 46's source label — line 440 is in
`zend_shutdown_executor_values()`, not `zend_activate()` — without changing
its conclusion. The source ordering agrees: `zend_activate()` at `main.c:1938`
precedes `sapi_activate()` at `:1940`, which applies `PHP_VALUE` at
`sapi/fpm/fpm/fpm_main.c:1365`. Both vendor diagnostics reproduce and ASan
stays silent. A fatal error with `EG(active)==0` and a still-`IS_ARRAY` global
is required; none was found in the post-deactivate release paths. Grade
remains UNKNOWN, with no rung 3/4 or pre-auth claim, and no fixed-release
build was started while both verdicts are clean.

### Wake 48 — new adjacent lane: CVE-2026-129538, CGI PATH_INFO underflow (rung 3 CONFIRMED)

8.5.13's NEWS (`lab/build/php-8.5.13-asan/NEWS:49-51`) lists
GHSA-5j3f-64r7-f564 / CVE-2026-129538, "PHP-CGI out-of-bounds read and write
during PATH_INFO correction" — an adjacent memory-corruption claim in the
same tree and the CGI SAPI already used by the Stage A lane. The deterministic
8.5.12→8.5.13 `sapi/cgi/cgi_main.c` diff is two guards:

```diff
- char *path_info = env_path_info ? env_path_info + pilen - slen : NULL;
+ char *path_info = (env_path_info && pilen > slen) ? env_path_info + pilen - slen : NULL;
- if (orig_path_info != path_info) {
+ if (path_info && orig_path_info != path_info) {
```

`slen` is the length stripped off `SCRIPT_FILENAME` while walking back to a
regular file (`cgi_main.c:1262-1286`); when `slen > pilen = strlen(PATH_INFO)`,
`path_info` points BEFORE the PATH_INFO environment string. The following
`path_info[0] = 0` (`:1294`) and `CGI_PUTENV("PATH_INFO", path_info)` (`:1306`)
therefore write and read out of bounds. The vendor regression
`sapi/cgi/tests/ghsa-5j3f-64r7-f564.phpt` supplied the three shapes.

Committed harness `lab/repro/php2shell-cve129538.py` invokes php-cgi directly
with those shapes (no web server; loopback-only) on the pinned 8.5.12-asan
(affected) and 8.5.13-asan (fixed) builds, plus a suffix-length sweep and an
optional GDB observation. Evidence `lab/build/evidence/w48-cve129538/`
(gitignored throwaway); `committed/verdict.txt` reads `VERDICT: CONFIRMED`,
all seven checks PASS.

- Vendor shapes, affected 8.5.12: short suffix `PATH_INFO="/b"` (correct),
  long suffix `PATH_INFO="xxxx"`, `PATH_TRANSLATED` shape `PATH_INFO="cted"` —
  both corrupted values are adjacent bytes read from before the real
  PATH_INFO; fixed 8.5.13 returns `"/x"` with `ORIG_PATH_INFO=NULL` for both.
- Sweep with `SECRET=TOPSECRET0123456789` and suffix length `n=1..20`: on
  8.5.12, `PATH_INFO` is the last `n+1` bytes of the preceding
  `PATH_INFO=` name for n=2..11, empty at n=12, then the last `n-11` bytes of
  the SECRET value for n=13..20 (`n=20` → `"23456789"`). The suffix length
  chooses the out-of-bounds offset. 8.5.13 returns `"/x"` for all 20 lengths.
  The same long-suffix shape on 8.4.27-asan also yields `"xxxx"`; 8.4.28's
  source carries the identical `pilen > slen` guard, so the fix covers both
  affected branch heads tested here.
- GDB (`php2shell-cve129538.py` GDB leg) stops at `cgi_main.c:1294`:
  `PTR 0x7fffffffef08 ENV 0x7fffffffef17` — the store address is 15 bytes
  before `getenv("PATH_INFO")`; the byte is `47` (`'/'`) before the store and
  `0` after. The out-of-bounds NUL write is observed in memory, not inferred.

ASan stays silent because the overwritten/read bytes belong to the initial
environment block, which the sanitizer does not redzone; the evidence is the
byte-level GDB observation and the affected/fixed output difference, not a
sanitizer report. Conditions needed: `cgi.fix_pathinfo=1`, a SCRIPT_FILENAME
whose last component is not a regular file, a PATH_INFO shorter than the
stripped suffix, and a preceding environment string to read from. The first
harness supplies those variables directly, as a CGI web server would. Grade:
**rung 3 CONFIRMED** for the new lane — observed OOB write and attacker-offset
OOB read with a server-visible leak of neighbouring bytes. No arbitrary-address
or chosen-byte write, pointer control, marker execution, pre-auth reachability
or RCE is claimed; no prior lane's grade changes.

The remote-input question was then advanced: committed harness
`lab/repro/php2shell-cve129538-fcgi.py` starts each pinned php-cgi as a
FastCGI responder on 127.0.0.1 and sends the same shape as FCGI_PARAMS through
the existing minimal client (`has_env=1`, `FCGI_GETENV`/`FCGI_PUTENV`), so
PATH_INFO and SCRIPT_FILENAME arrive with the request rather than in the
process environment. Evidence `lab/build/evidence/w48-cve129538/fcgi-committed/verdict.txt`:
`VERDICT: CONFIRMED` (three/three checks). Short suffix yields `"/x"` on all
three builds; long suffix yields `PATH_INFO=".0.1"`, `ORIG_PATH_INFO="/x"` on
both 8.4.27-asan and 8.5.12-asan, but `"/x"`/`NULL` on 8.5.13-asan. The
corrupted value is again a slice of an adjacent FastCGI-side string. This
establishes the input channel at the FastCGI protocol level; whether a given
web server lets an HTTP request set both params (and therefore whether the
primitive is remotely reachable on a real deployment) stays UNKNOWN — no web
server was used. ASan remains silent because the neighbouring strings are
inside the request's allocations; no sanitizer report is claimed. Rung 3
CONFIRMED unchanged. A follow-up steering leg was added to the same harness
(suffix length 20, `SECRET=TOPSECRET0123456789` before or after PATH_INFO in
FCGI_PARAMS). On 8.5.12 the leaked value follows the parameter order:
`"23456789"` when SECRET precedes PATH_INFO, `"27.0.0.1"` when it follows;
8.5.13 returns `"/x"` in both orders. Evidence
`lab/build/evidence/w48-cve129538/fcgi-steered/verdict.txt`: `CONFIRMED`,
five/five checks. So the attacker chooses the offset (suffix length) and the
adjacent value (param order); the leaked bytes are server-side memory, and
the destination is `$_SERVER['PATH_INFO']`. That is the natural stop for this
lane: no chosen-byte write, pointer control or marker execution is reachable,
and the HTTP-to-FastCGI input mapping stays UNKNOWN without a web server.

### Wake 50 — real-web-server HTTP reachability for 129538 (rung 3, reachability demonstrated)

This closes the UNKNOWN left at the end of wake 48 and overturns wake 49's
Apache-only negative. A real loopback nginx 1.24 forwards HTTP requests over
FastCGI to the pinned php-cgi responder; an ordinary HTTP request path is now
the only attacker input. nginx is provisioned as a locally extracted `.deb`
under the gitignored `lab/nginx-local/` (no system install); the committed
harness `lab/repro/php2shell-cve129538-nginx.py` re-extracts it on a clean
checkout. It listens on 127.0.0.1:18081 and forwards to php-cgi on
127.0.0.1:18952, testing 8.5.12-asan against 8.5.13-asan under identical
configs. Evidence: gitignored
`lab/build/evidence/w50-nginx/verdict.txt`, with per-config nginx/php-cgi logs.

Three mappings were exercised. The standard `fastcgi_split_path_info
^(.+\.php)(/.+)$` + `$fastcgi_script_name` mapping puts the suffix only in
PATH_INFO and leaves SCRIPT_FILENAME clean (`pilen >= slen`): both builds are
identical, no underflow — this confirms wake 49's class of negative also holds
on nginx for the standard config. A naive mapping with `SCRIPT_FILENAME
$document_root$uri` and a one-byte `PATH_INFO=/` plus `ORIG_PATH_INFO=/`
produces `slen > pilen`: on 8.5.12 the corrected `PATH_INFO` is `xxxxx` at
suffix length 16 and `xxxxxxxxx` at 20, while 8.5.13 leaves `PATH_INFO=/`
unchanged at both lengths. A third mapping adds `SECRET=TOPSECRET0123456789`
immediately before PATH_INFO: 8.5.12 leaks `6789` (n=16) and `23456789`
(n=20) into the script's `$_SERVER['PATH_INFO']`, matching wake 48's
direct-FastCGI steering observation exactly; 8.5.13 returns `/x` in both
cases. The harness verdict reads `HTTP-REACHABLE OOB READ CONFIRMED`.

The 8.5.12→8.5.13 `sapi/cgi/cgi_main.c` diff is exactly the 129538 fix
(verified wake 48: the `pilen > slen` guard at `:1286`), so the output
difference is attributable to that patch, not to an unrelated build change.
Because `ORIG_PATH_INFO` is set in the naive configs, the OOB NUL write at
`:1294` also fires on this HTTP path (the store is transient, restored at
`:1304`); wake 48's GDB observation at `:1294` establishes that byte-level
store, and ASan remains silent because the adjacent strings are inside the
request's allocations — no sanitizer report is claimed.

Honest limits: the naive mapping requires a specific server configuration
(full URI in SCRIPT_FILENAME and a short fixed PATH_INFO); it is a real nginx
config driven by a real HTTP request, not a synthetic FCGI_PARAMS injection,
but it is not the nginx default and no claim is made that stock configs are
affected. The primitive remains an attacker-offset OOB read of adjacent
FastCGI param bytes plus a fixed-value (zero) NUL write at a chosen offset:
there is still no chosen-byte write, pointer control, marker execution,
pre-auth claim or RCE. Grade stays **rung 3 CONFIRMED** for this lane, now
with demonstrated HTTP reachability on a real web server; no other lane's
grade changes.


### Wake 51 — new adjacent lane: CVE-2026-129501 DOM XML serialization double-free (rung 3 CONFIRMED)

8.5.13's NEWS (lines 82 and 85) named an unexamined adjacent lane:
GHSA-x8r7-mg3g-74hg / CVE-2026-129501, "Double free during DOM XML
serialization", next to "Fix error paths in
`dom_xml_serializing_a_document_node()`". The exact 8.5.12 → 8.5.13
`ext/dom/xml_serializer.c` diff is two hunks:

1. `dom_xml_ns_prefix_map_add()`: when a candidates list has
   `GC_REFCOUNT(list) > 1` it is duplicated with `zend_array_dup()`. The fix
   adds `DOM_Z_UNOWNED(val, Z_PTR_P(val))` to every value in the duplicate,
   because a descendant does not own the prefix. Without it, both the
   original list and the duplicate carry the `DOM_Z_OWNED` flag and each
   `efree()`s the same prefix at map destruction.
2. `dom_xml_serializing_a_document_node()`: the old code set
   `node->children = NULL` around `xmlSaveDoc()` and restored it afterwards.
   A `TRY` bailout mid-save (a stream wrapper can reach the real document)
   returned before the restore, leaving the real document mutated. The fix
   serializes a shallow `xmlDoc declaration_doc` copy with NULL children.

Build and fixed-side method (honest limits). No prior build had ext/dom.
`lab/php2shell/build-dom.sh` produced ONE dom-enabled 8.5.12 ASan/UBSan CLI
(`lab/build/php-8.5.12-asan-dom`, `--disable-all --enable-debug
--enable-cli --enable-dom --with-libxml`, clang, libxml 2.9.14 with the
`LIBXML_VERSION < 21300` compat path, bundled lexbor). The first `make`
reached the tool's 1500-second deadline at 524 objects; a 28-second resume
completed it. A full 8.5.13 dom build was not started. Instead the fixed
variant is this same binary relinked after replacing `ext/dom/xml_serializer.c`
with the byte-identical 8.5.13 file (verified with `diff -q`); the claim is
therefore patch-sensitivity to the real 8.5.13 fix, not a version-pair
build comparison. Both binaries are preserved as `sapi/cli/php-vuln` and
`php-fixed` in that gitignored build directory.

Replay from a clean checkout (no network, loopback/local only):
```
bash lab/php2shell/build-dom.sh 8.5.12
bash lab/php2shell/build-dom-fixed-variant.sh
python3 lab/repro/php2shell-cve129501-dom.py \
  lab/build/php-8.5.12-asan-dom/sapi/cli/php-vuln \
  lab/build/php-8.5.12-asan-dom/sapi/cli/php-fixed
```
The first `make` may exceed a 25-minute tool deadline on this 2-core host;
resuming `make` in the build directory reuses the completed objects.

Harness `lab/repro/php2shell-cve129501-dom.py` runs three local CLI cases
with `USE_ZEND_ALLOC=0` and `ASAN_OPTIONS=detect_leaks=0`: the vendor
regression body from `ext/dom/tests/modern/xml/GHSA-x8r7-mg3g-74hg.phpt`,
an XMLDocument-only shape (the second vendor case, no HTML5/lexbor parser),
and a clean single-namespace control. Raw logs and
`verdict.txt` are in gitignored `lab/build/evidence/w51-129501-dom/`.

- vendor case: affected rc=1 `ASAN_DOUBLE_FREE`, fixed rc=0 `CLEAN`; the
  fixed output matches the vendor `--EXPECT--` byte for byte.
- XMLDocument-only case: affected rc=1 `ASAN_DOUBLE_FREE`, fixed rc=0 `CLEAN`.
- control: `CLEAN` on both builds.
- ASan stack (affected): `dom_xml_ns_prefix_map_destroy`
  (`xml_serializer.c:126`) ← `dom_xml_ns_prefix_map_dtor` (`:143`) ←
  `dom_xml_serialize_element_node` (`:1181`) inside
  `Dom\XMLDocument::saveXml()`. A 4-byte prefix region is freed twice by
  the same function — fix hunk 1.
- Allocator condition measured: with the default ZendMM (no
  `USE_ZEND_ALLOC=0`) the same input exits 0 with correct output and ASan
  is silent (`xml_only.zendmm.log`) — the pooled allocator hides the second
  free. No ASan claim is made for the default allocator, and no claim that
  the underlying double free is absent there.

This repro exercises fix hunk 1 only; the stream-wrapper bailout path of
hunk 2 was not tested. Grade **rung 3 CONFIRMED** for this lane: an observed
double free in the affected serializer source, patch-sensitive to the real
fixed source. No chosen-byte write, pointer control, benign marker,
pre-auth reachability or web-server path was demonstrated, so rung 4 is
not claimed and no other lane's grade changes.

