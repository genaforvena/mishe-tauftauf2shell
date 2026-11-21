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
  **Witness verification (2026-11-20, 11:42Z–12:01Z) — the reopened
  lane is independently ESTABLISHED at rung 2.** Three witness verdicts,
  each from the witness's own runs of the committed harnesses (never my
  logs), zero sanitizer output, controls clean: tape #98 — FPM replay
  (a21e4dd): 8.4.26/8.4.27 splice+promotion, 8.4.28
  patch-sensitivity control, and wrong-cut controls (K±16, both
  respawn but A_EVIL=NULL — promotion needs exact calibration); one
  disclosure nit (name the unauth route's non-default session config;
  label the FPM SIGKILL shim-delivered) folded into the report this
  wake. Tape #103 — 8.2.35 (4ccc180) and 8.3.36 (9792456): both
  harness re-runs byte-exact into lab/build/evidence/w6-branch/;
  citation nit fixed earlier (851f305). Tape #108 — 8.5.12 (666796e):
  both harness re-runs into lab/build/evidence/w7-8.5/, K=1019/n=1892
  confirmed, plus a K−16 counterexample (A_EVIL=NULL) — the
  branch-coverage-complete claim holds independently. No contradiction,
  no repair outstanding.
  **Wake 17 (2026-11-20, 12:11Z–) — rung 3 reached on the combined chain,
  patch-sensitive.** Operator directive #113 refused further rung-2
  stand-down. Tree/NEWS diff of the pinned 8.4.27 and 8.4.28 builds found
  GHSA-gr4f-wgx5-jpfv / CVE-2026-129496 (Date timezone-cache UAF, fixed in
  the same 8.4.28 release as the splice fix), plausibly the class of
  native-class bug Depthfirst withheld, though which bug they used stays
  UNKNOWN. Committed harness
  `lab/repro/php2shell-rung3-tzcache.py` writes the splice-MID session bytes
  from the committed consumer harness (wrong cut → decode failure), starts
  affected php-cgi with an invalid `date.timezone` and a file `error_log`,
  and sends an unauth multipart POST with a Cookie SID and upload-progress
  key. The PRE-RINIT decode warning formats its log timestamp from a stale
  native tzcache pointer. Observed in
  `lab/build/evidence/aftershell-tzcache-php-{8.4.26,8.4.27,8.4.28}-asan.log`:
  8.4.26 and 8.4.27 rc −6 with `ERROR: AddressSanitizer: SEGV on unknown
  address <wild>` — the address varies per run (my logs `0x0008a5c3be58`
  on 8.4.26 and `0x0008a5c3c279` on 8.4.27; the witness's independent
  runs `0x0008a5c3c26c` / `0x0008a5c3be4c`) — with `SUMMARY:
  AddressSanitizer: SEGV Zend/zend_hash.c:790:8` on 8.4.26 and
  `Zend/zend_hash.c:945:8` on 8.4.27 in `zend_hash_str_find_bucket`: the
  same statement `idx=HT_HASH_EX(arData,nIndex)`, different tree line;
  stack through `php_session_cancel_decode (session.c:271)` →
  `php_session_rfc1867_update (session.c:3225)` →
  `php_request_startup (main.c:1906)` → `php_log_err_with_severity` →
  `php_format_date` → `php_date_parse_tzfile (php_date.c:505)`. 8.4.28:
  rc 0, no sanitizer, warning logged normally. UBSan reproduced the same
  invalid read with the IDENTICAL `splice-MID` record (`lab/tmp/tz_matrix.py`,
  its record matches the committed harness): "applying non-zero offset
  773979844 to null pointer" at the same site — both sanitizers agree the
  pointer is invalid. All five controls (valid record, no record, valid
  timezone, no cookie, standalone advisory max-input-vars recipe) are
  clean on 8.4.28; the standalone recipe is affected-only too (stale
  HashTable assertion). Grade: rung 3 for the combined chain — confirmed
  invalid native pointer read with observed bytes, not only a crash.
  Witness verdict (tape #126, 2026-11-20): ESTABLISHED at rung 3 from a
  clean-HEAD re-run into `lab/build/evidence/w8-tzcache/`, including the
  affected-only `max-input-vars` assertion; the three precision nits
  (per-build line, non-deterministic address, identical UBSan record) are
  folded here and in the investigation report (commit d500a9d).
  **Wake 18 (2026-11-20, 12:27Z–) — Stage A: constrained rung 4 on the
  combined chain.** Witness #126's three precision nits folded (commit
  d500a9d). Replay: `bash lab/repro/php2shell-stageA-proof.sh`.
  (a) With `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1`, 8.4.27-asan reports a
  textbook 56-byte `heap-use-after-free` instead of a wild-address SEGV:
  allocated `php_date_parse_tzfile:501` via `OnUpdate_date_timezone` in
  `zm_startup_date`, freed by `tracked_free_all` → `shutdown_memory_manager`
  at end of `php_module_startup`, read from `php_session_cancel_decode` →
  `php_format_date` → `get_timezone_info` → `zend_hash_str_find`; 8.4.28
  clean. Evidence `lab/build/evidence/stageA/uaf-8.4.27-asan-USE_ZEND_ALLOC0.log`.
  ASan's top frame is `_zend_is_inconsistent` (`zend_hash.c:57`), reading
  offset 8 of the chunk — a different read from the plain build's `:945`
  `HT_HASH_EX` deref (witness #138 nit).
  (b) On plain 8.4.27 with the same env, a query-string value reuses that
  freed chunk; GDB (`lab/repro/php2shell-stageA-fieldprobe.gdb`) captures
  the stale pointer at startup and dumps the 56 bytes at the second
  `zend_hash.c:945` access: with `XXX=ABCDEFGHIJ`, HashTable `arData`
  (offset 16) = 0x0a = value length, `nNumUsed` (offset 24) = 0x44434241
  ("ABCD"), `nNumOfElements` (offset 28) = 0x48474645 ("EFGH"), next word
  0x4847464544434241 ("ABCDEFGH"), then "IJ\0…"; with `XXX=AAAAAAAAA`
  (9) the same fields are 0x9 / 0x41414141 / 0x41414141 /
  0x4141414141414141. Those are the exact fields consumed by
  `zend_hash_str_find_bucket`. Evidence
  `lab/build/evidence/stageA/stageA-php-8.4.27-plain-splice-mid-gdb-qs{13,14}.log`.
  (c) Black-box: value length 0–8 → rc 0 (silent UAF); 9–24 → rc −11
  SIGSEGV on 8.4.27 (25/26/27/31/32 → rc 0; upper boundary UNKNOWN);
  key name irrelevant; 8.4.28 rc 0 for all lengths;
  `valid-record`, `valid-timezone`, `no-cookie` controls rc 0 on 8.4.27
  with the long query. First post-startup 56-B malloc traced to
  `zend_new_array_singleton()` for `$_GET`
  (`stageA/malloc56-backtrace-8.4.27-plain.log`). Harness, fieldprobe and
  proof scripts committed as e737acc. **Grade: rung 4, constrained** —
  chosen bytes at chosen offsets plus low-bit control of the consumed
  pointer field; NOT arbitrary-address control, no marker execution.
  Witness controls are consistent with that backtrace but #138 did not
  independently re-run it; the occupant's exact C type stays author-observed.
  Witness #138 (2026-11-20) re-ran every proof.sh leg from clean HEAD into
  `lab/build/evidence/w10-stageA/`: **ESTABLISHED at rung 4 CONSTRAINED**,
  no repair owed, grade unchanged; its sweep fixed the 9–24 boundary and
  the ASan frame. Next experiment: place a genuine pointer at offset 16
  and attempt a benign marker (outcome below).
  **Wake 19 (2026-11-20, 13:00Z) — Stage B pointer-placement NEGATIVE.**
  Committed `lab/repro/php2shell-stageB-occupants.py` varies the query
  shape (10 cases) and multipart field shape (7 cases) under the Stage A
  GDB fieldprobe; logs in `lab/build/evidence/stageB/{occupant,post}-*.log`.
  The stale chunk at the PRE-RINIT warning is either a zend_string
  (`flags=0`, `mask=0`, `arData=0xa` = chosen value length, value bytes at
  offsets 24–32, SIGSEGV at `zend_hash.c:945`) for long query values, or
  a genuine HashTable (`flags=0x10` or `0x00`,
  `mask=fffffffe`/`fffffffc`, real `arData=0x5555…`, `nNumUsed` 1–4,
  no fault) for short/nested query values, every POST-field shape and
  no input. Because the consumer reads
  `((uint32_t*)arData)[(int32_t)(h|mask)]`, a chosen-address read needs
  a real pointer at offset 16 AND mask=0; no tested shape gives both
  (the pointer-bearing occupant always has the table's valid small
  negative mask). Grade unchanged: rung 4 CONSTRAINED; pointer control
  and marker remain unclaimed; other SAPIs UNKNOWN (session data: wake 20).
  **Wake 20 (2026-11-20, 15:05Z) — Stage B session-data channel NEGATIVE.**
  Committed `lab/repro/php2shell-stageB-session-channel.py` replays seven
  malformed php-serialize session records (bare failing string, stdClass
  object before/after it, 10- and 24-byte string properties) under the Stage A
  GDB fieldprobe with no query string, so session decode is the only
  request-time allocator before the PRE-RINIT warning. Logs
  `lab/build/evidence/stageB/sessgroom-*.log`: every leg emits "Failed to
  decode session object" (warning path runs), stale chunk is always a real
  one-element HashTable (`flags=0x10`, `mask=fffffffe`, real `arData`,
  `nNumUsed=1`), rc 0, no fault. No session-derived object/string claims the
  chunk. Together with Stage B this is a structural either-or at the
  consumer: mask=0 ⇒ small integer at arData; real pointer ⇒ valid negative
  mask. Grade unchanged (rung 4 CONSTRAINED, witness #138); other SAPIs
  UNKNOWN; no arbitrary address or marker claimed.
  **Wake 21 (2026-11-20, 16:05Z) — second-consumer route NEGATIVE.** The
  only other tzcache consumers in `ext/date/php_date.c` are the add at
  :511 (writes a fixed native pointer) and
  `ZEND_MODULE_POST_ZEND_DEACTIVATE_D(date)` (:428-433) →
  `zend_hash_destroy()` → stored `pDestructor` (attacker-byte slot at
  offset 24). Unreachable: `PHP_RINIT_FUNCTION(date)` (:404-412) NULLs
  `DATEG(tzcache)`; the UAF read is in `php_hash_environment()` at
  `main.c:1906`, before `zend_activate_modules()` at :1907 runs RINIT,
  and shutdown's `zend_post_deactivate_modules()` (`main.c:2000`) sees
  NULL. ASan controls in
  `lab/build/evidence/stageB/shutdown-uaf/`: 8.4.27-asan splice-MID with
  zero query string rc −6 (same `_zend_is_inconsistent` UAF — quarantine
  makes the groomer unnecessary for ASan detection); 8.4.28-asan and
  8.4.27-asan valid-record rc 0, no report. Grade unchanged; no route to
  an indirect call through this freed object on this CGI path.
  **Wake 22 (2026-11-20, 16:18Z) — FPM Stage A: corruption confirmed, byte
  placement NOT transferred.** New loopback harnesses
  `lab/repro/php2shell-stageA-fpm.sh` and
  `lab/repro/php2shell-stageA-fpm-sweep.py`. Trigger-setting lesson: FPM's
  `php_admin_value[date.timezone]` is applied too late to emit the
  tzcache-allocating startup diagnostic; `-d date.timezone=Bogus/Zone`,
  `-d error_log=<file>` and `-d log_errors=1` are required. Once `-d` supplies
  the invalid zone, `php_admin_value` is not inert: at child init FPM re-reads
  the stale tzcache via `fpm_php_apply_defines_ex` →
  `OnUpdate_date_timezone` → `php_date_parse_tzfile:505` (witness #208).
  The cited single-shot ASan log therefore faults at CHILD INIT with
  `baseline_rc=2`, not during a served request; the request-time chain
  (`php_session_cancel_decode:271` → `php_format_date` →
  `php_date_parse_tzfile:505`) is established in the sweep config, e.g.
  `lab/build/evidence/w13-fpm-asan-sweep/{sweep-qs0,sweep-qs10}.log`.
  Both configs give `AddressSanitizer: heap-use-after-free` at
  `zend_hash.c:57:7 in _zend_is_inconsistent`.
  Plain 8.4.27 FPM builds fault on all query-value lengths 0/4/8/9/10/14/
  24/25/32: the ZEND_DEBUG build aborts with `ht=… is already destroyed`
  and `_zend_is_inconsistent: Assertion '0' failed`, the non-debug build
  SIGSEGVs (`lab/build/evidence/stageA-fpm/sweep-*.log`,
  `lab/build/evidence/stageA-fpm-nodebug/sweep-*.log`). Valid timezone and
  no-cookie controls are clean in the sweep config only
  (`lab/build/evidence/w13-fpm-asan-sweep/{sweep-validtz,sweep-nocookie}.log`);
  the single-shot config's affected ASan/debug baseline no-cookie times out
  (`rc 2`). `php-8.4.28-fpm-asan` with the identical
  config fires both warnings, serves every request and reports zero
  sanitizer output (`lab/build/evidence/stageA-fpm-fixed/…`), so the fix
  holds on FPM. The first consumer is therefore confirmed corruption on
  FPM, but the query-length-independent fault means CGI's chosen-byte
  placement does NOT transfer; no occupant GDB inspection was done on an
  FPM worker, so pointer-at-+16/mask=0 remains UNKNOWN there, and the
  indirect-call route is closed everywhere (wake 21). Grade unchanged:
  rung 4 CONSTRAINED (witness #138); FPM adds a rung-3 deterministic crash.
  Apache was still UNKNOWN at that point (superseded by wake 25 below).
  Witness #208 independently re-ran both harnesses
  from clean HEAD and ESTABLISHED the FPM rung-3 corruption, grade unchanged
  (`lab/build/evidence/w13-fpm*/`); the three precision nits above are folded.

  **Wake 24 (2026-11-20, 17:10Z) — FPM occupant fieldprobe: the wake-22
  UNKNOWN is resolved.** New harness
  `lab/repro/php2shell-stageA-fpm-fieldprobe.py` (fork-follow GDB on plain
  8.4.27 FPM, `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1`, loopback FastCGI
  client); logs in `lab/build/evidence/w24-fpm-fieldprobe3/`. At the
  request-time `php_date.c:505` hit the stale pointer `0x5555560e6770`
  holds `flags=00000002 mask=00000000 arData=0x5555561801f0` with raw bytes
  identical across long10/nested/no-query shapes (last word contains ASCII
  `freq\0x\0x`). So the structural pointer-at-+16/mask=0 bits exist on FPM,
  but the occupant is a fixed, not attacker-groomed object and flags=0x02
  makes the worker abort at `zend_hash.c:74` "already destroyed" before the
  consumer dereference. No chosen-address read, no rung-4 upgrade; grade
  unchanged (rung 4 CGI-only CONSTRAINED, FPM rung 3, Apache UNKNOWN).
  Failed approaches preserved: sibling GDB attach denied by Yama
  `ptrace_scope`; first fork-follow script auto-quit on startup
  `zend_hash.c:945` hits before the request.

  **Wake 25 (2026-11-20, 17:47Z) — Apache UNKNOWN closed; mod_php reaches
  rung 4 CONSTRAINED (witness-ESTABLISHED #258).** New
  loopback harness `lab/repro/php2shell-stageA-apache.py` (one prefork
  child, per-case `httpd.conf`/`php.ini`, pre-staged splice session file,
  multipart upload-progress POST with session cookie) and plain-module
  builder `lab/php2shell/build-apache-plain.sh`. (1) ASan 8.4.26 mod_php:
  `lab/build/evidence/w25-apache-asan/apache-splice.log` reports a 56-B
  `heap-use-after-free` read at `zend_hash.c:788` from
  `php_session_cancel_decode:271 → php_format_date → php_date_parse_tzfile:505`;
  alloc at `php_date.c:501` in `zm_startup_date`, free by
  `tracked_free_all → zend_mm_shutdown → php_module_startup:2401` in
  `php_apache_server_startup`. nocookie/validtz controls clean. (2) Plain
  8.4.27 mod_php: query value lengths 9, 10, 16 and 24 give
  `exit signal Segmentation fault (11)`; 8, 25, 32 and both controls are
  clean; plain 8.4.28 answers the same splice clean
  (`lab/build/evidence/w25-apache-fixed/`). (3) Fork-follow GDB on plain
  8.4.27 at `php_date.c:505`: parent startup hit has real table
  (`mask=fffffffe`); child request-time hit has `flags=0 mask=0 arData=0xa`
  and raw bytes `0x4847464544434241 0x0000000000004a49` for query
  `XXX=ABCDEFGHIJ`, `0x5a5a5a5a` at both offsets for `XXX=ZZZZZZZZZZ`;
  SIGSEGV at `zend_hash.c:945` (`lab/build/evidence/w25-apache-gdb/`,
  `lab/build/evidence/w25-apache-gdb-z/`).
  `arData` is the value length, not an address — chosen bytes at chosen
  offsets, no pointer control, no marker. Grade: rung 3 CONFIRMED and rung 4
  CONSTRAINED on mod_php, same limit as the witness-ESTABLISHED CGI leg;
  FPM stays rung 3 only. Negative preserved: the first length sweep was
  invalid because GDB's `quit` detached the prefork parent, which kept port
  18160 bound; harness cleanup now kills it by the unique config path.
  Witness #258 independently replayed the harness into its own
  lab/build/evidence/w18-apache-modphp/ (plain 8.4.27 libphp.so sha256
  5f6e7ba9... matched) and ESTABLISHED rung 3 CONFIRMED + rung 4 CONSTRAINED
  with no correction — the ASan 56-B UAF, the plain 8.4.27 SIGSEGV window at
  query lengths 9/10/16/24 (clean 8/25/32, fixed 8.4.28 clean), and the
  fork-follow GDB child hit (flags=0 mask=0 arData=0xa, chosen bytes at
  +24/+32, SIGSEGV at zend_hash.c:945) all reproduced.

- **Rung (original 618/619 lane, closed):** 2. Trigger deterministic (rung 1); the consumer hunt now covers
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

## Wake 27 (2026-11-20) — new descendant lane: CVE-2026-129481, rung 3

An advisory-fetch provisioning check found that the 2026-11-19 release
carried SEVEN critical 9.2 CVEs, not only 115560/126714. Four were
uncovered anywhere in this plant: **CVE-2026-129481** (session-filename
UAF), CVE-2026-129182 (backtrace-global repopulation UAF, 8.5 only),
CVE-2026-129474 (magic-method backtrace UAF, 8.5 only, vendor-demonstrated
RCE), CVE-2026-129289 (FPM request smuggling via unread php://input — RCE
but NOT memory corruption, outside this ladder). 129481 and 129182 are
incomplete fixes for CVE-2026-109619, this target's original bug;
CVE-2026-129496 (Date cache) was already in both reports as the native bug.
Only 129481 was tested this wake (one bounded experiment).


Replay: `python3 lab/repro/php2shell-cve129481-fpm.py
lab/build/php-8.4.27-fpm-asan/sapi/fpm/php-fpm <outdir> <port>`
(`--control` for the benign-close control). Loopback only, one static FPM
child, `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1`, OPcache not compiled in.
Request 1 starts a session, stores a stream whose user wrapper's
`stream_close()` raises a fatal, and calls `unset($_SESSION)` so the
session globals hold the last array reference; the fatal must fire in the
FINAL RSHUTDOWN `zval_ptr_dtor` so the bailout skips
`php_session_cleanup_filename()` (session.c:163).

Observed (`lab/build/evidence/w27-cve129481-final/cve129481.log`, also
`w27-cve129481-rshutdown/`): ASan `heap-use-after-free`, READ of size 4 at
`0x506000019044`, 4 bytes into a 64-byte region. Read stack:
`zend_string_release (zend_string.h:426)` ←
`php_session_cleanup_filename (session.c:128)` ←
`php_rshutdown_session_globals (session.c:163)` ←
`zm_deactivate_session (session.c:2979)` ← `zend_deactivate_modules` ←
`php_request_shutdown (main.c:1968)`. Free stack: `free` ← `tracked_free_all
(zend_alloc.c:3367)` ← `zend_mm_shutdown` ← `shutdown_memory_manager
(zend_alloc.c:3231)` at the end of the previous request. The stale
`PS(session_started_filename)` is released by the NEXT request's ordinary
session-module shutdown even when that script calls no session functions
(the intervening probe's FastCGI connection resets as the worker aborts).

PID attribution note (witness #287 dispute, resolved wake 28): ASan labels the
FPM **worker** PID, not a request ID. The worker that logged the UAF
(3153888; witness 3168299) served baseline, req1 and the mid probe; req2 went
to a fresh worker (3153916 / 3168323). The mid probe IS the "NEXT request"
above — its connection resets because the worker aborts in that request's
session-module shutdown. A committed marker harness
(`lab/repro/php2shell-cve129481-mechanism.py`, evidence
`lab/build/evidence/w28-mechanism/`, reproduced three times): the mid
request's PHP body writes `mid-entered-pid=<req1 worker PID>` before
responding; the marker exists (3333600) while the mid response is empty and
req2 is served by a fresh PID (3333850) — the worker completed req1, entered
mid, and aborted in mid shutdown. Source: `php_request_shutdown` calls
`zend_deactivate_modules` (main.c:1968, step 5) before
`shutdown_memory_manager` (step 15), and `zend_deactivate_modules` wraps each
RSHUTDOWN in `zend_try` (zend_API.c:3440-3448), so a free-then-read inside one
shutdown call is structurally impossible. Witness #287's proposed
"same-request" rewrite is REJECTED on this evidence; the rung-3 grade it
independently ESTABLISHED is unchanged.

Controls: fixed 8.4.28-fpm-asan, identical trigger → no ASan, and FPM
terminates the worker on the shutdown bailout (the fix's second component);
benign `stream_close()` on 8.4.27 (`--control`) → no ASan, one worker PID.
Preserved negatives: closing the stream during general symbol-table teardown
gives a clean run (`w27-cve129481/`) because `cleanup_filename()` runs first;
calling `session_destroy()` in user code also gives a clean run
(`w27-cve129481-destroy/`) because RSHUTDOWN runs a second pass that clears
the field. These are timing constraints, not guessed-away failures.

Grade: **rung 3 CONFIRMED** (observed stale-pointer release with allocation
and free stacks, patch-sensitive) for CVE-2026-129481 on affected 8.4.27
FPM. NOT rung 4: no attacker-controlled occupant at a chosen offset, no
pointer control, no marker. Unauth reachability depends on an application
path reaching a failing session cleanup (vendor call it application-
dependent); not claimed. Witness replay ESTABLISHED (#287, grade only — its
proposed mechanism rewrite was disputed and rejected on marker evidence, wake
28; see PID attribution note above).

## Wake 29 (2026-11-20) — new descendant lane: CVE-2026-129474

Claim sources, read as provisioning: the advisory
GHSA-8mjj-2r7p-4hg2 and the official php.net 8.5.13 release record.
Affected `>=8.5.0 <8.5.13`; CVSS 9.2; vendor reports RCE but the advisory
states exploitation is application-dependent and needs
`fatal_error_backtraces=1` plus `zend.exception_ignore_args=0` (production
ini sets the latter to 1, blocking the path). This is PHP core, hence a lane
inside the admitted PHP2Shell target, not a new target/mind.

Provisioning: `php-8.5.13.tar.xz` sha256
`607602acaf0c3061818e9916ec44a058e8b3d43959a83862b9cd3ec7bf5b785f`,
matched against `https://www.php.net/releases/index.php?json&version=8.5.13`
and pinned in `lab/php2shell/provision.sh`. The fixed tarball ships
`Zend/tests/GHSA-8mjj-2r7p-4hg2.phpt`, the vendor's own regression case.
Diff of the pristine 8.5.12/8.5.13 `Zend/` trees gives the relevant fix in
`zend_builtin_functions.c::debug_backtrace_get_args()`: the
`ZEND_USER_FUNCTION` branch now excludes
`ZEND_ACC_CALL_VIA_TRAMPOLINE`. The vulnerable code applies the ordinary
CV/TMP extra-argument offset (`p = ZEND_CALL_VAR_NUM(call, last_var + T)`)
to a magic-method trampoline frame built by
`zend_get_call_trampoline_func()` (`num_args=0, last_var=0`), so it reads
wrong slots. The delete/refill path is the 8.5 delayed-OOM fatal: CONCAT
sets `ZEND_OOM_STATE_PENDING` + `vm_interrupt`; `zend_fcall_interrupt()`
calls `zend_handle_delayed_oom()`; `zend_error_cb()` at `zend.c:1534`
captures the fatal backtrace while the trampoline frame is current.

Reproduction: `python3 lab/repro/php2shell-cve129474.py VULN_BIN FIXED_BIN
[OUTDIR]` writes `vulnerable.log` / `fixed.log` / `verdict.txt`.
On `php-8.5.12-asan` (`lab/build/evidence/w29-cve129474/vulnerable.log`)
the vendor case's call `C::test(1, 2, 3, 4, $a.$a)` produces
`#0 ...: C::test(3, 4, 'aaaaaaaaaaaaaaa...', NULL, NULL)` — five wrong
zvals, a deterministic stale-argument read. `USE_ZEND_ALLOC=0` suppresses
the fatal entirely (no soft OOM under libc malloc), so ASan cannot observe
this read: ZendMM pools request memory. **No ASan report is claimed.**
Fixed control: `lab/build/php-8.5.13-asan` (sha256-pinned source, same
configure flags) prints
`#0 ...: C::test(1, 2, 3, 4, 'aaaaaaaaaaaaaaa...')` on the identical script.
`lab/build/evidence/w29-cve129474/verdict.txt` records `CONFIRMED` and the
harness exits 0. Wake 30 adds debugger memory-state observation (witness
#327 nit 2): `lab/repro/php2shell-cve129474-gdb.gdb` run on the 8.5.12 CLI
stops at `zend_builtin_functions.c:1822` on the 5-arg frame, which is a
magic trampoline (`fn_flags=0x44011`, bit 18 set, `first_extra_arg=0`,
`last_var=0`, `T=2`); the unreset slots hold `1,2`, and at the consuming
loop head (`:1825`, `i==0`) `p` is +0x20 bytes and the slots are `3,4`,
string, undef, undef — the five zvals printed in the fatal backtrace.
Evidence `lab/build/evidence/w30-cve129474-gdb/committed-harness-vuln.log`.
Grade: **rung 3 CONFIRMED** — wrong-slot argument read observed in memory
under gdb and patch-sensitive; no ASan report (ZendMM required for the soft
OOM). This is a trampoline frame-slot misread, not a claimed UAF. NOT rung
4: no chosen occupant at a controlled offset, no pointer control, no
marker, and no reproduced framework/network path; pre-auth and vendor RCE
claims stay UNVERIFIED.

Preserved negatives from this wake: OOM while evaluating a large argument
(`str_repeat`) reports the fatal at the argument expression with correct
args (`#0 ...: str_repeat(...)`), not in the trampoline; a huge
`__callStatic` frame declared in source OOMs at compile time; the
`array_fill` + spread-args variant (`t5`) reaches a fatal inside
`__callStatic` but with correct args; seeding stale temporaries from an
earlier `sink()` call (`t6`) still produced correct args. Only the vendor's
exact `$a.$a` CONCAT case produced the wrong-argument read. These are timing
and layout constraints, not erased failures.

**Wake 31 (2026-11-20, IN PROGRESS at this checkpoint) — CVE-2026-129182
bounded harness, debug-build NEGATIVE preserved, release-build replay owed.**
Claim source: NEWS of the pinned 8.5.13 tree names GHSA-2fjv-p558-g82m
(CVE-2026-129182) "Use-after-free via repopulation of last_fatal_error_backtrace
global after shutdown"; its vendor regression
`sapi/fpm/tests/fatal-error-backtrace-request-reset.phpt` fires a fatal in
req1 (`eval("class RequestReset {}; class RequestReset {}")`,
`fatal_error_backtraces=1`) and sends req2 with FastCGI
`PHP_VALUE=date.timezone=invalid`, applied before request startup while
shutdown is still flagged. Fix diff: 8.5.13 `Zend/zend.c:1511` gates the dtor
and `:1540` gates `zend_fetch_debug_backtrace` on `EG(active)`; 8.5.12
`:1509`/`:1534` are unconditional.
Harness `lab/repro/php2shell-cve129182-fpm.py` (loopback static FPM,
`--control`, `--use-malloc`), build support in `lab/php2shell/build-fpm.sh`
and `lab/php2shell/build-fpm-release.sh`; commit `c5eb6a8`.
On the **debug** ASan FPM build
(`lab/build/php-8.5.12-fpm-asan`, `--enable-debug`),
`lab/build/evidence/w31-cve129182/vulnerable-shape.log` reproduces the
vendor case exactly — `Cannot redeclare class RequestReset` with a Stack
trace, then `PHP Warning: PHP Request Shutdown: Invalid date.timezone value
'invalid', using 'UTC' instead`, body `UTC` — with **zero ASan output**.
Causal limitation, not a grade: `Zend/zend_execute_API.c:455` only honours
`ZEND_ASAN_FORCE_FAST_SHUTDOWN` when `ZEND_DEBUG` is OFF; the debug build
takes the graceful path that dtors and UNDEFs the global at
`zend_execute_API.c:309-310`. CLI destructor-fatal probes on both 8.5.12 and
8.5.13 debug ASan builds (`lab/build/evidence/w31-cli-probe/`) are likewise
clean and preserved as negatives. Wake 45 completed the release replay: the
8.5.12 release ASan FPM binary (`lab/build/php-8.5.12-fpm-release-asan/sapi/fpm/php-fpm`,
`Debug Build => no`) was finished by compiling the one remaining TU
`ext/opcache/jit/zend_jit.lo` with `-g0 -O0` in the build-dir Makefile; every
other TU kept `-g -O1`, ASan/UBSan instrumentation was unchanged and the
harness disables opcache. `python3 lab/repro/php2shell-cve129182-fpm.py <bin>
lab/build/evidence/w31-cve129182 18190 --use-malloc` reproduces both vendor
diagnostics exactly — req1 fatal `Cannot redeclare class RequestReset` with a
Stack trace, req2 `PHP Warning: PHP Request Shutdown: Invalid date.timezone
value 'invalid', using 'UTC' instead`, body `UTC` — but `VERDICT=CLEAN_NO_UAF`
with zero ASan markers. The same clean verdict holds with
`ZEND_ASAN_FORCE_FAST_SHUTDOWN=1` exported in the parent environment, in
ZendMM mode (no `--use-malloc`), and with `--control`. Evidence
`lab/build/evidence/w31-cve129182/{vulnerable-malloc,vulnerable-shape,control.log,build-8.5.12-resume6.log}`;
the earlier debug-build `vulnerable-shape.log` is intact. Grade stays
**UNKNOWN**: the advisory claim is not reproduced under fast shutdown on
this host. No rung 3, rung 4 or pre-auth claim. The 8.5.13 fixed release
build is still unbuilt (324 objects), so patch sensitivity is untested.

## Wake 46 (2026-11-21 01:31–01:52Z) — 129182 negative root-caused
The 8.5.12 release-ASan FPM replay reproduces both vendor diagnostics but
zero ASan; the reason is now instrument-observed, not inferred. All bytes in
`lab/build/evidence/w46-cve129182/` (gitignored); committed harness unchanged.
- Env probe (`envprobe.py`, reusing the committed harness) prints
  `ENV='1'` for `ZEND_ASAN_FORCE_FAST_SHUTDOWN` inside the worker, so the pool
  `env[...]` directive does reach `getenv()` — the earlier H1 (env lost) is
  rejected. `shutdown_executor()` also measures `fast_shutdown=1`,
  `full_tables_cleanup=0`, so the graceful dtor at `zend_execute_API.c:309-310`
  is skipped as expected.
- gdb breakpoints (`gdb-trace.log`) on every `ZVAL_UNDEF` site and on
  `zend.c:1509` give the exact sequence: worker `init_executor():139` UNDEF;
  req1 fatal hits `zend.c:1509` with `active=1, type=0, arr=nil`, then
  `zend.c:1510` UNDEF and `zend.c:1534` populates the backtrace array;
  **req2 startup `zend_activate()` (`zend_execute_API.c:440`) UNDEFs the global
  (no dtor)**; req2's `PHP Request Shutdown: Invalid date.timezone value
  'invalid'` warning then hits `zend.c:1509` with `active=0, type=0 (IS_UNDEF)`,
  stale `value.arr=0x50600001c760`. `zval_ptr_dtor` on IS_UNDEF is a no-op —
  there is no stale pointer to dereference, hence no UAF. The warning fires
  after request startup (at shutdown), not before it.
- Removing `php_admin_value[date.timezone] = UTC` (`fpm-noadmin.conf` +
  `run-noadmin.sh`) gives identical diagnostics and zero ASan, so the timing
  is not an artefact of the admin directive.
- Reusing the committed 129481 RSHUTDOWN-fatal harness against the same
  8.5.12 release FPM does produce an ASan UAF (`cve129481.log`), but the read
  stack is `zend_string_release ← php_session_cleanup_filename ←
  php_rshutdown_session_globals ← zm_deactivate_session`, i.e. 129481's
  session-filename UAF — a new observation (129481 also reproduces on 8.5.12
  release FPM), not 129182. Its fatal carried an exception, so `zend_error`
  took the exception branch rather than the backtrace-repopulation branch;
  an `E_USER_ERROR` variant (`inactivefatal.py`) ended at the same 129481
  stack. Preserved as a negative for 129182.
Grade stays **UNKNOWN with a measured cause**: the vendor trigger does not
place a live stale backtrace pointer in front of the inactive `zend_error`
on this host. NEWS calls it a UAF; the fix's own source comment says setting
the global while inactive "would leak", so the leak reading is preserved
alongside the advisory claim. No rung 3, rung 4 or pre-auth claim. Do not
build the 8.5.13 fixed release merely to compare two clean verdicts; a
future attempt needs a fatal, exception-free error while `EG(active)==0`
that reaches the repopulation branch before request startup UNDEFs the global.

## Wake 47 (2026-11-21 02:00–02:20Z) — 129182 fix diff and exact error ordering
New deterministic source fact: the 8.5.12 → 8.5.13 `Zend/zend.c` diff IS the
129182 fix and consists of exactly two `if (EG(active))` guards — around
`zval_ptr_dtor(&EG(last_fatal_error_backtrace))` at `zend.c:1509` and around
`zend_fetch_debug_backtrace(&EG(last_fatal_error_backtrace), ...)` at `:1534`,
whose in-tree fix comment reads "EG(last_fatal_error_backtrace) is useless when
the executor is inactive, and setting it at this point would leak." Two other
8.5.13 hunks are unrelated: `global_map_ptr_last = 0` at `:1232` and a
`zval garbage` copy-before-overwrite dtor-order fix in
`zend_execute_API.c:1971/2013`. That turns the open question into a precise
condition: an `E_FATAL_ERRORS` error while `EG(active)==0` with no exception
and `fatal_error_backtrace_on=1`, reaching `:1509`/`:1534` before the global
is UNDEFed.

Focused loopback GDB replay, evidence `lab/build/evidence/w47-cve129182-ordering/`
(gitignored, throwaway; committed harness unchanged), breakpoints at
`php_date.c:531`, `zend_execute_API.c:440`, `zend.c:1509` and `:1534`:

```
DTOR1509 active=1 type=0 arr=(nil)
REPOP1534 active=1 type=0 arr=(nil)
ZEND_ACTIVATE440 active=0 type=775      # 775 & 0xff = 7 = IS_ARRAY
TZWARN active=0 flags=7 type=0 arr=0x50600001c6a0
DTOR1509 active=0 type=0 arr=0x50600001c6a0
ZEND_ACTIVATE440 active=0 type=0
```

Both vendor diagnostics still reproduce (req1 `Cannot redeclare class
RequestReset` with a Stack trace; req2 `PHP Warning: PHP Request Shutdown:
Invalid date.timezone value 'invalid', using 'UTC' instead`), still zero ASan.
The decisive new observation is the `type=775` (IS_ARRAY) at the line-440
UNDEF: the req1 fatal's live backtrace array is present when that UNDEF runs,
and the UNDEF leaves only the stale `value.arr`. Every later inactive
`zend_error` in the replay therefore sees `type=IS_UNDEF`, so `zval_ptr_dtor`
is a no-op and the E_WARNING cannot take the `:1534` repop branch.

Correction to wake 46's wording: `zend_execute_API.c:440` is the tail of
`zend_shutdown_executor_values()` (the function spans roughly lines 269–441;
`shutdown_executor()` begins at 443), **not** `zend_activate()`. The UNDEF at
that line is req1's shutdown, not req2's startup. Wake 46's causal conclusion
is unchanged, but the mechanism is now stated correctly: req1's own shutdown
UNDEFs the global before req2's PHP_VALUE diagnostic. Source ordering agrees:
`zend_activate()` runs at `main/main.c:1938`, then `sapi_activate()` at
`:1940`, whose FPM `read_request` applies `PHP_VALUE` at
`sapi/fpm/fpm/fpm_main.c:1365` via `zend_parse_ini_string` →
`OnUpdate_date_timezone` (`ext/date/php_date.c:526/531`). A fatal error is
still required; no natural PHP-controllable fatal was found in the
post-`zend_deactivate` release path (`php_free_request_globals`,
`zend_post_deactivate_modules`, `sapi_deactivate_module`) or between
`main.c:280` (active cleared) and `:440` (UNDEF) with `fast_shutdown=1`.

Grade unchanged: **UNKNOWN with a fully ordered measured cause**; no rung 3,
rung 4 or pre-auth claim. NEWS' "UAF" and the fix comment's "leak" are both
preserved. No 8.5.13 fixed release build was started — both verdicts remain
clean and patch sensitivity is not worth ~324 objects. A revisit needs a
fatal, exception-free error while `EG(active)==0` reaching `:1509`/`:1534`
with the zval still IS_ARRAY, which the FPM ordering above does not provide.

## Wake 48 (2026-11-21 02:27–) — new lane CVE-2026-129538, rung 3 CONFIRMED

From 8.5.13 NEWS (`lab/build/php-8.5.13-asan/NEWS:49-51`): GHSA-5j3f-64r7-f564
/ CVE-2026-129538, "PHP-CGI out-of-bounds read and write during PATH_INFO
correction." The 8.5.12→8.5.13 `sapi/cgi/cgi_main.c` diff is exactly the
`pilen > slen` guard on the `env_path_info + pilen - slen` computation and a
`path_info &&` guard on its use; 8.4.28 carries the same fix, 8.4.27/8.5.12
do not. Vendor regression `ghsa-5j3f-64r7-f564.phpt` supplied three shapes.
Committed harness `lab/repro/php2shell-cve129538.py` (direct php-cgi calls,
loopback only) replays them on 8.5.12-asan vs 8.5.13-asan, a suffix-length
sweep with a `SECRET` neighbour, and a GDB write observation. Evidence
`lab/build/evidence/w48-cve129538/committed/verdict.txt`: `VERDICT: CONFIRMED`,
seven/seven checks PASS. Affected 8.5.12: long-suffix `PATH_INFO="xxxx"`,
PATH_TRANSLATED shape `"cted"` (fixed: `"/x"`, ORIG NULL); sweep n=2..11 leaks
the `PATH_INFO=` name tail, n=12 empty, n=13..20 leaks the SECRET value tail
(`n=20` → `"23456789"`), fixed clean for all 20; GDB at `cgi_main.c:1294`
shows the store 15 bytes before `getenv("PATH_INFO")`, byte `47`→`0`.
8.4.27-asan also yields `"xxxx"` on the long-suffix shape. ASan silent
(environment block is not redzoned); the proof is the GDB byte observation
plus the patch-sensitive output difference. Grade **rung 3 CONFIRMED** for
this new lane: observed OOB write and attacker-offset OOB read with a
server-visible leak. No arbitrary write, pointer control, marker execution,
pre-auth reachability or RCE claim; no other lane's grade changes.
FastCGI follow-through (same wake): committed harness
`lab/repro/php2shell-cve129538-fcgi.py` starts php-cgi as a 127.0.0.1 FastCGI
responder and sends the shape as FCGI_PARAMS (`has_env=1`). Evidence
`lab/build/evidence/w48-cve129538/fcgi-committed/verdict.txt`: CONFIRMED,
3/3; long suffix yields `PATH_INFO=".0.1"` on 8.4.27-asan and 8.5.12-asan
but `"/x"` on fixed 8.5.13, short suffix clean on all three. So both inputs
can arrive as request params, not only process env; real-web-server HTTP
reachability stays UNKNOWN (no web server used), ASan still silent. Rung 3
CONFIRMED unchanged. Steering leg added to the same harness (suffix 20,
SECRET param before/after PATH_INFO): 8.5.12 leaks `"23456789"` /
`"27.0.0.1"` respectively, fixed 8.5.13 `"/x"` both. Evidence
`lab/build/evidence/w48-cve129538/fcgi-steered/verdict.txt`: CONFIRMED, 5/5.
Attacker chooses offset (suffix length) and adjacent value (param order);
leak destination `$_SERVER['PATH_INFO']`. Lane at natural stop: no chosen-byte
write, pointer control or marker execution; HTTP-to-FastCGI mapping UNKNOWN.

## Wake 50 (2026-11-21 03:33–) — 129538 real-nginx HTTP reachability: POSITIVE
Named next experiment, reopening 129538 after wake 49's Apache-only negative:
can a real web server's HTTP→FastCGI mapping produce `slen > pilen`?
Provisioned nginx 1.24 by extracting the Ubuntu `.deb` locally into
gitignored `lab/nginx-local/` (sudo not needed, no system install); added
`lab/nginx-local/` to `.gitignore`. Committed harness
`lab/repro/php2shell-cve129538-nginx.py` (self-provisioning; commit `3009924`)
starts nginx on 127.0.0.1:18081 → php-cgi on 127.0.0.1:18952 and tests three
mappings on 8.5.12-asan vs 8.5.13-asan. Evidence gitignored
`lab/build/evidence/w50-nginx/verdict.txt`.
- standard `fastcgi_split_path_info`: clean and identical on both builds
  (suffix only in PATH_INFO, `pilen >= slen`) — confirms wake 49's negative
  class on nginx too.
- naive `SCRIPT_FILENAME $document_root$uri`, `PATH_INFO=/`, `ORIG_PATH_INFO=/`:
  8.5.12 corrected PATH_INFO=`xxxxx` (n=16) / `xxxxxxxxx` (n=20); 8.5.13
  leaves `/` unchanged.
- naive + `SECRET=TOPSECRET0123456789` before PATH_INFO: 8.5.12 leaks
  `6789` (n=16) / `23456789` (n=20) into `$_SERVER['PATH_INFO']`, matching
  wake 48's direct-FastCGI steering; 8.5.13 clean (`/x`) both lengths.
Verdict: `HTTP-REACHABLE OOB READ CONFIRMED`. The 8.5.12→8.5.13 cgi_main.c diff
is exactly the 129538 guard (wake 48), so patch-sensitive. ORIG_PATH_INFO is
set, so the OOB NUL write at `:1294` fires on this path too (GDB byte proof in
wake 48; ASan silent, no sanitizer claim). Honest limits: the naive mapping
is a specific (non-default) nginx config; the primitive is still an
attacker-offset OOB read + fixed-zero NUL write, no chosen-byte write,
pointer control, marker, pre-auth or RCE. Grade **rung 3 CONFIRMED** with
demonstrated HTTP reachability; no other lane's grade changes. Wake 48's
"HTTP mapping UNKNOWN" is now CLOSED; wake 49's Apache negative stands but
is no longer the last word on real-server reachability.


## Wake 51 (2026-11-21 04:08–) — new lane CVE-2026-129501, rung 3 CONFIRMED
Named next experiment from wake 50. 8.5.13 NEWS:82/85 names GHSA-x8r7-mg3g-74hg
/ CVE-2026-129501 "Double free during DOM XML serialization" and
"Fix error paths in dom_xml_serializing_a_document_node()". Exact 8.5.12→8.5.13
`ext/dom/xml_serializer.c` diff = two hunks: (1) `dom_xml_ns_prefix_map_add`
marks values in a `zend_array_dup`'d candidates list `DOM_Z_UNOWNED` so the two
list copies do not both `efree()` the same prefix; (2) document serialization
uses a shallow `xmlDoc declaration_doc` copy instead of NULLing the real
document's children around `xmlSaveDoc()` (a TRY bailout mid-save left it NULL).
ONE full build, `lab/build/php-8.5.12-asan-dom` (dom-enabled 8.5.12 ASan/UBSan
CLI, clang, libxml 2.9.14 compat path, bundled lexbor) via the committed
`lab/php2shell/build-dom.sh`; first make hit a 1500s tool deadline at 524
objects, a 28s resume finished. The "fixed" binary is that same binary relinked
after swapping in the byte-identical 8.5.13 `xml_serializer.c` (`diff -q`
clean) — a real-fix patch-sensitivity comparison, NOT a full 8.5.13 build.
Binaries kept as `sapi/cli/php-vuln` / `php-fixed`.
Committed harness `lab/repro/php2shell-cve129501-dom.py`; evidence in gitignored
`lab/build/evidence/w51-129501-dom/verdict.txt` = CONFIRMED:
- vendor phpt body: affected rc=1 ASAN_DOUBLE_FREE; fixed rc=0 CLEAN, output
  matches the vendor `--EXPECT--` byte for byte.
- XMLDocument-only shape (no lexbor): affected rc=1 ASAN_DOUBLE_FREE; fixed
  rc=0 CLEAN. Clean control: CLEAN on both.
- ASan: 4-byte prefix chunk freed twice at `dom_xml_ns_prefix_map_destroy`
  (`xml_serializer.c:126`) ← `:143` ← `dom_xml_serialize_element_node:1181`,
  under `Dom\XMLDocument::saveXml()` — fix hunk 1.
- Needs `USE_ZEND_ALLOC=0`; default ZendMM exit 0, correct output, ASan silent
  (`xml_only.zendmm.log`) — pooled allocator hides the second free. No ASan
  claim under ZendMM. Fix hunk 2's stream-wrapper path NOT tested.
Honest limits: no chosen-byte write, pointer control, marker, pre-auth or web
reachability. Grade **rung 3 CONFIRMED** for this lane only; no other lane changed.


## Wake 52 (2026-11-21 04:52–) — 129501 hunk #2 stream-wrapper mutation CONFIRMED (DOM-state, no grade change)
Bounded experiment chosen over the costly plain-DOM tcache build: the 8.5.13
tree has two regression tests absent from 8.5.12 for the untested second hunk
of the exact fix — `ext/dom/tests/modern/xml/serialize_document_write_failure.phpt`
and `serialize_document_write_mutation.phpt`. Committed harness
`lab/repro/php2shell-cve129501-dom-hunk2.py` embeds both --FILE--/--EXPECT--
bodies and runs them against wake 51's preserved `php-vuln` / `php-fixed`
pair (no new build, default ZendMM). Gitignored evidence
`lab/build/evidence/w52-129501-hunk2/verdict.txt` = CONFIRMED:
- `failure`: affected `bool(false)`, documentElement `NULL`, `int(0)` children,
  declaration-only output (TRY bailout never restores children); fixed matches
  vendor EXPECT (`string(4) "root"`, `int(1)`, full document).
- `mutation`: affected `int(1)` children, both injected and after comments
  orphaned; fixed `int(3)` with both comments, matching vendor EXPECT.
- No ASan/UBSan report, rc=0 both binaries: hunk 2 corrupts DOM tree state,
  not allocator memory, on these inputs.
Negative probes (throwaway, gitignored): keeping a reference to the orphaned
comment, `removeChild()` and `gc_collect_cycles()` under `USE_ZEND_ALLOC=0`
gave no ASan report; libxml tolerates the inconsistent list. A retained
original child also kept a valid `parentNode` after dropping the document.
Fixed keeps 2 children where affected keeps 1. No UAF/invalid deref reached.
Grade unchanged: rung 3 CONFIRMED for 129501 comes from wake 51's hunk-1
double free; hunk 2 is a confirmed DOM-state fault patch-sensitive to the
exact 8.5.13 source and adds no rung-3/4 claim. tcache escalation CLOSED
NEGATIVE: the only owned prefix is `dom_xml_generate_a_prefix` (`"ns"+%u`,
max 13-byte request = glibc 0x20 bin); a PHP `zend_string` is >=32 bytes
(0x30/ZendMM 32-class) and all other `dom_xml_ns_prefix_map_add` callers pass
`prefix_owned=false`. No controlled-size PHP string can be interposed in that
bin; no plain DOM build needed. Revisit only with a different owned-prefix
source.


## Wake 52 (continued) — new lane CVE-2026-129291 FPM epoll UAF: rung-2 fix-sensitive fault
8.5.13 NEWS names unexamined `GHSA-jm4m-qfqx-967m` / CVE-2026-129291 "PHP-FPM
epoll use-after-free can lead to local privilege escalation". The exact
8.4.27→8.4.28 `sapi/fpm/fpm/fpm_children.c` diff: `fpm_event_del()` on the
child's stdout/stderr events and set fds to -1 before closing them. Committed
harness `lab/repro/php2shell-cve129291-fpm.py` embeds the new 8.5.13 vendor
test `sapi/fpm/tests/ghsa-g3vh-838c-65v7.phpt` and runs it against two FPM
ASan build dirs; gitignored evidence `lab/build/evidence/w52-129291-fpm/`.
Same-branch pair: 8.4.27 FAIL (`bool(false)`, no child-exit warning or
replacement), 8.4.28 PASS (`bool(true)`) -> verdict CONFIRMED. 8.5.12 FPM
ASan also fails. No ASan/UBSan report on either failing run: functional
fault only, so grade rung 2 reproducible/fix-sensitive, NOT rung 3.
Limits preserved: swapping only 8.5.13 `fpm_children.c` into 8.5.12 left the
test FAILing; adding 8.5.13 `zend_builtin_functions.c` (129182 fix) too also
left it FAILing — the test is not isolated to the epoll hunk. No pointer
control, chosen byte, marker, LPE demo or web path. No other lane's grade
changes. Next experiment if reopened: full 8.5.13 FPM ASan build for a true
version pair, or GDB at `fpm_child_free`/`fpm_event_del` on the affected
master; do NOT repeat the single- or dual-TU swaps (both negatives).


## Wake 53 (2026-11-21, 05:23–05:36Z) — standalone CVE-2026-129496, rung 3 CONFIRMED
GHSA-gr4f-wgx5-jpfv was already used in wake 17's combined splice chain;
wake 53 isolates it as its own lane using the advisory's simpler
startup-diagnostic recipe (invalid `date.timezone` + `max_input_vars=1` + file
`error_log`, no session corruption and no third-party extension).
Exact fix: `main/main.c` error-log timestamp uses
`php_format_date(..., PG(modules_activated) && EG(active))`;
`ext/date/php_date.c` also moves `php_date_global_timezone_db` init before
`REGISTER_INI_ENTRIES`. New committed harness
`lab/repro/php2shell-cve129496-tzcache.py`; evidence
`lab/build/evidence/w53-129496/verdict.txt` = CONFIRMED.
Affected `php-8.5.12-fpm-release-asan/sapi/cgi/php-cgi-vuln`: rc=1, ASan SEGV
read in `__strlen_avx2`, stack `php_default_treat_data` (php_variables.c:583)
→ `php_error_docref` → `php_log_err_with_severity` (main.c:991) →
`php_format_date` (php_date.c:894) → `timelib_unixtime2local` →
`timelib_get_time_zone_info` (parse_tz.c:908) → `_estrdup` → strlen on stale
tzcache. Fixed `php-cgi-fixed` = same build with ONLY the upstream one-line
main.c guard rebuilt: rc=0, correct output, no ASan. Controls without the
invalid timezone clean on both. Cross-branch: plain 8.4.27 rc=139 vs plain
8.4.28 rc=0; 8.4.28 carries the same guard.
Conditions/negatives: default ZendMM required — `USE_ZEND_ALLOC=0` leaves both
clean; debug ASan CLI builds clean; release-ASan needed. Local zend_test
`warn_on_startup` phpt reproduced vendor output but stayed clean on debug
ASan. Grade rung 3 CONFIRMED for this lane only: observed invalid read of
freed tzcache with symbolized consumer path and fix-sensitive comparison.
No chosen bytes/pointer control/marker/pre-auth HTTP/FPM/Apache LPE demo;
rung 4 closed. Next: stale-reference inheritance on loopback FPM/mod_php,
then a chosen-byte occupant; or full 8.5.13 release-ASan CGI version pair.
Do NOT repeat the debug-ASan runs.

## Wake 54 (2026-11-21, 05:44–06:12Z) — 129496 standalone: FPM stale-reference inheritance CONFIRMED, grade unchanged
Closed wake 53's named "next experiment". FPM calls `php_module_startup()`
once in the master, so the invalid-`date.timezone` startup diagnostic
allocates tzcache in startup memory and leaves `DATEG(tzcache)` stale; forked
workers inherit the pointer. New committed harness
`lab/repro/php2shell-cve129496-fpm.py` (loopback FastCGI client reusing
`php2shell-fpm-client.py`) starts the release-ASan
`php-8.5.12-fpm-release-asan/sapi/fpm/php-fpm` with
`-d date.timezone=Not/AZone -d max_input_vars=1 -d log_errors=1 -d error_log=<file>`
and sends a GET with `QUERY_STRING=a=1&b=2` as the FIRST request.
Observed (gitignored `lab/build/evidence/w54-129496-fpm/`): startup warning
logged; first request kills the worker with ASan SEGV
`0x7048c5795241`, stack `__strlen_avx2 <- timelib_get_time_zone_info
(parse_tz.c:908) <- timelib_unixtime2local <- php_format_date (php_date.c:894)`
— the identical CGI lane read, now via inheritance. Client gets
`Connection reset by peer`; respawned worker serves request 2 clean.
Three CLEAN controls: (1) valid timezone `UTC` (no startup diagnostic) —
warning still fires, no crash, causality proven; (2) `php-fpm-fixed` =
same release-ASan tree relinked with ONLY the one-line `main.c` guard
(verified sole `.c` changed after the 05:13Z vuln build) — rc 0, no ASan;
(3) warm-up request before attack consumes the stale pointer via date RINIT
(first run of this wake) — attack then clean. `USE_ZEND_ALLOC=0` stays a
negative. Grade rung 3 CONFIRMED, SAPI widened CGI->FPM; no chosen bytes,
pointer control, marker, or real nginx front end, so rung 4 CLOSED.
Pre-auth HTTP reachability at default config remains UNPROVEN (FastCGI to a
loopback listener only). Do NOT re-run debug-ASan CGI runs.

## Wake 55 (2026-11-21, 06:19–) — new adjacent DOM lane: reflected-attribute setter UAF CONFIRMED, rung 3
Named experiment: 8.5.13 NEWS's un-CVE'd DOM fix "use-after-free when reflected
attribute setters replace an attribute whose child still has a live wrapper",
with vendor test `ext/dom/tests/reflected_attribute_write_live_child.phpt`.
One existing dom-enabled 8.5.12 ASan CLI build reused (no new full build).
Committed harness `lab/repro/php2shell-dom-reflected-attr.py`; committed
minimal fix patch `lab/php2shell/dom-reflected-attribute-fix.patch`.
A/B: vulnerable = wake-51 `php-fixed` (8.5.13 xml_serializer only); fixed =
`php-fixed-domattr` = same tree + upstream `dom_set_attribute_value()` helper
(`node_list_unlink(existing->children)` before `xmlSetNsProp`, element.c:160,
token_list.c:197/:437, php_dom.c:2348, php_dom.h:118). Evidence
`lab/build/evidence/w55-domattr/harness/verdict.txt` = CONFIRMED: all five
vendor cases ASAN_UAF on vulnerable / CLEAN on fixed, control CLEAN/CLEAN,
fixed output matches vendor EXPECT byte for byte. ASan: heap-use-after-free
READ of 8 at `dom_node_parent_get node.c:247`, freed by `xmlFreeNodeList <-
xmlSetNsProp <- dom_element_reflected_attribute_write element.c:160`.
Grade rung 3 CONFIRMED for this lane only; overall rung 4 unchanged — no
SAPI, HTTP reachability, chosen bytes, pointer control or marker.
NEXT if reopened: chosen-byte occupant of the freed xmlNode child with a live
accessor, or a DOM-consuming HTTP app reaching a reflected setter. Do NOT
repeat the same A/B (closed).

## Wake 56 (2026-11-21, 06:44–) — DOM reflected-attr UAF: rung 4 POINTER CONTROL on a plain build
Named wake-55 NEXT (chosen-byte occupant) achieved. Built the first non-ASan
dom-enabled 8.5.12 CLI (`lab/php2shell/build-dom-plain.sh`, committed) because
ASan quarantines the free; libxml 2.9.14 / glibc malloc. Saved vuln and fix
binaries in gitignored `lab/build/evidence/w56-domattr-groom/`. Committed
harness `lab/repro/php2shell-dom-reflected-attr-groom.py`; final
`.../w56-domattr-groom/harness/verdict.txt` = RUNG4_POINTER_CONTROL (seven
checks all True).
Fix-sensitive A/B: stale wrapper reads new value (p1), reads back 119 fully
chosen bytes (p2), writes through it corrupt the new node/attribute (p3),
reparenting steers its parentNode to a chosen element (p4), empty replacement +
normalizeDocument() -> destructor double-frees the chunk ->
`free(): double free detected in tcache 2` SIGABRT (rc -6) / fixed rc 0 (p5).
POINTER CONTROL (p6): first attempt with 89-byte str_repeat failed; GDB logging
of `__zend_malloc` measured the cause — `zend_string_safe_falloc(N,1,0)`
allocates N+32, so N=89 -> 121 B (0x88 bin, not the freed 0x80 chunk). N=88
gives exactly 120 B. With `USE_ZEND_ALLOC=0`, N=88 occupies the freed chunk;
val[] starts at +24 so string indices 16..23 are node->parent at +40. Chosen
0x4242424242424242 -> SIGSEGV with GDB `php_dom_object_get_data
(obj=0x4242424242424242)` at php_dom.c:324 via dom_node_parent_get node.c:253;
0x41 and 0x5a variants track the input (`p8-verification.txt`); fixed survives
rc 0. p7 preserves the 121-B negative as a size-class calibration control.
libxml2 source lesson: `xmlSetNsProp` frees old child then always allocates a
new 120-B text node (immediate 0x80 reuse); removeAttribute only unlinks.
Grade rung 4 DEMONSTRATED for this lane, honestly conditioned: local CLI+dom,
non-ASan, USE_ZEND_ALLOC=0, empty replacement + normalizeDocument(), exact
120-B occupant. Read-side pointer control to a chosen-address fault; no
arbitrary write, no marker, no SAPI/HTTP/pre-auth. Do NOT repeat p1-p7 unchanged.
