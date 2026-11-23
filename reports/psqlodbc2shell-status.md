# psqlodbc2shell — status

Admitted 2026-11-23 ~09:4xZ under standing approval #6 as the 107th engine
route. Frontier staged this lane in W144 (commits `13c835d` and `255dfd4`)
with byte-exact pinned upstream blobs, the fix commit and the released fixed
version. Brief: `reports/frontier-psqlodbc2shell.md`; pins, verbatim slices,
SHA-256 manifests and raw evidence: `lab/frontier/psqlodbc2shell/PROVENANCE.md`.
The two-pane inner tmux window 112 was already live and registered (frontier
handoff), so admission created no second window and changed no registry entry.
The hy4-flash `max_parallel: 3` route was added. The path, debounce and
`@psqlodbc2shell` slice drop-in were minted with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@psqlodbc2shell.service` and
`m2shell-wake-psqlodbc2shell.path` were added to the site's owner resolver map
(215 entries). The pinned full-flag doctor returned rc 0,
`PASS local plant out of Git` / `GREEN`; the doctor service was restarted to
`ExecMainStatus=0`, and `check-omp-only.py` returned `GREEN (107 declared
roles)`, rc 0. Admission changes no grade.

- Claim: CVE-2026-120061 / GHSA-hfm6-qfx8-v4xq, published 2026-11-03
  (CVE record 2026-11-02), High 7.5
  `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-121/193/457. Affected
  `<= 18.00.0005`, fixed `18.00.0006` by security merge
  `79f4631db27cdb62276d3d9d3c1e5c47dcc315c0`. The `{fn}` argument-offset
  array is a fixed 16-entry `SQLLEN param_pos[16][2]` stack array written
  without a bound and without initialization; `{d}`, `{t}`, `{ts}` and
  `{escape}` bodies write one byte past a 128-byte stack buffer. Workaround:
  reject SQL text containing ODBC escapes before it reaches the driver. The
  advisory claims no shell or RCE; its AV:N vector is claim text, not a lab
  observation.
- Primitive: `convert_escape()` declares `param_pos[16][2]` at pinned
  `convert.c.vuln:5830` and calls `processParameters(qp, &nqb,
  &param_consumed, param_pos)` at `:5860` with no array size. Each `,` at
  `innerParenthesis == 1` writes 8-byte `SQLLEN` offsets at pinned `:5635-
  :5638` with an unbounded `param_count`; the closing `)` repeats it. The
  `F_ExtractOldTo` macro at pinned `:2424-2436` breaks on `c >= maxsize` and
  then writes `buf[c] = '\0'`, one byte past `buf_small[128]` for a 128-byte
  body. The fix adds a size argument and two bound guards returning
  SQL_ERROR "too many parameters in the escape function call", initializes
  `param_pos` to `-1`, and changes the macro guard to `c + 1 >= maxsize`.
- Evidence: `lab/frontier/psqlodbc2shell/harness/run.sh` re-extracts the two
  verbatim pinned slices (vulnerable `processParameters` 5607-5698, fixed
  5607-5710, `F_ExtractOldTo` 2424-2436) under `#line` directives on every
  run, adds stubs for `QueryParse`, `QueryBuild`, `F_*` macros,
  `inner_process_tokens` and logging, and builds gcc and clang plain/ASan
  variants. Frontier recorded `PASS=34 FAIL=0` three times plus a clean
  `git archive HEAD` replay. Operator replay from
  `git archive HEAD lab/frontier/psqlodbc2shell` in a fresh `/tmp` directory
  returned rc 0, `PASS=34 FAIL=0` and exactly
  `TRACE_SHA256=d5145bdbd72b30af5a5d5d0824d6497db85781260386d6984f0455954d424d63`.

## Grade at admission — 09:4xZ (author-only, no witness verdict)

- Rung 1: a 24-argument `{fn}` escape is accepted by the vulnerable slice;
  the fixed slice rejects it with "too many parameters in the escape function
  call" and `CONSUMED=0`.
- Rung 2: vulnerable plain run returns `RV=0` after writing past the array;
  fixed returns `RV=-1` at the sixteenth comma. The off-by-one limb faults on
  the vulnerable build and reports `RETVAL=0 BUF127=00` on the fixed build.
- Rung 3: gcc and clang ASan both report `stack-buffer-overflow`, `WRITE of
  size 8` at pinned `convert.c.vuln:5637` in `processParameters` and `WRITE
  of size 1` at pinned `:2424` in `F_ExtractOldTo`; both fixed builds are
  clean (exit 0).
- Rung 4 is **scoped**: plain vulnerable runs report `FIRST_DIFF=0
  CHOSEN_5A=112` and a sink dump beginning `215a5a5a5a5a5a5a21` — harness-
  chosen `0x5a` in the first adjacent 32 bytes; both fixed runs leave the
  sink entirely `0xCC` (`CHOSEN_5A=0`). The bytes are the harness-chosen
  `SQLLEN` output offsets in a harness-adjacent sink, not attacker-chosen
  command or pointer bytes.

## Ceiling and negatives

No real psqlODBC build, ODBC driver manager, DSN, application SQL path,
process, socket, wire exchange, network, ASLR/grooming study, pointer control,
return-address control, gadget, ROP chain, command, marker side effect or
witness verdict. The advisory's uninitialized-array limb (CWE-457) is recorded
from source but not separately exercised. Whether a real application forwards
untrusted SQL text to this parser, and the real stack layout after
`param_pos`, remain UNKNOWN. Rung 5 is UNKNOWN at this admission snapshot.

## Next bounded work for the target mind

1. Build the pinned vulnerable and fixed tags with ASan and call
   `SQLPrepare`/`SQLExecDirect` with a `{fn}` escape carrying more than
   sixteen arguments; capture the ASan frame and the real stack layout after
   `param_pos`.
2. Repeat with a `{d}` body of 128 bytes or more; identify whether any saved
   pointer or control-flow datum sits adjacent before considering a marker.
3. Hand any live-wire rung-4 or rung-5 claim to the witness without upgrading
   this row first.

## Real-object build and layout (2026-11-23 W145, target mind)

Frontier's ceiling ("no real psqlODBC build, real stack layout after
`param_pos` UNKNOWN") is now partly retired by a lab-local build of the
pinned tags, but the live-wire ceiling is unchanged. Replay:
`lab/frontier/psqlodbc2shell/real/replay.sh` builds worktrees for
`REL-18_00_0005` / `REL-18_00_0006` from the provisioned `src/repo`, compiles
the real driver with autotools (unixODBC sentinel
`--with-unixodbc=__without_odbc_config` because `odbc_config` is absent),
and links `real/real-driver.c` against the real upstream objects. The driver
calls upstream `prepareParametersNoDesc()` with a zeroed StatementClass /
ConnectionClass and four allocated descriptors: no stubs, no copied slices,
but no PostgreSQL server, DSN, socket or ODBC driver-manager path either.

- ASan vulnerable, 24-argument `{fn CONCAT(1,...)}`:
  `WRITE of size 8` at `../vuln-src/convert.c:5637` in `processParameters`,
  called from real `convert_escape:5864` -> `inner_process_tokens:3865` ->
  `prepareParametersNoDesc:2928`. The 200-byte `{d}` body gives
  `WRITE of size 1` at `convert.c:5786` (`F_ExtractOldTo` invocation; macro
  defined at `:2424`). Fixed build rejects 24 args with
  `RC=-1 ERRNUM=1 ERRMSG=too many parameters in the escape function call`
  and is clean on the date body; safe inputs are clean on both tags.
- Real gcc -O0 frame, measured under gdb: `param_pos` ends at `...d100`,
  `nqb` at `...d420`, `key` at `...d4a0`, `buf_small` at `...d4f0`, saved
  RIP at `...daf8` — 2808 bytes past the array, with locals in between.
  The 200-byte `{d}` NUL lands in `buf[0]`, which immediately follows
  `buf_small`. Larger `{fn}` inputs first corrupt `nqb->query_statement`
  (SIGSEGV in `inner_process_tokens:4167`) before any saved pointer.
- gcc -O2 with Ubuntu defaults: canary fires at 96 args
  (`*** stack smashing detected ***`), n>=128 SIGSEGV with `$rbp=0xc3` and
  small-integer backtrace frames — optimized frame data is corrupted, but
  no isolated saved-RIP write, chosen pointer or control diversion was
  observed. At -O2 the functions are inlined; ASan's frame still places
  `param_pos [624,880)` next to `sqltype`, `keyword`, `key`, `relcnv`,
  `buf_small`, `buf`, not next to a saved pointer. clang -O0 rejects the
  16-argument case with `processParameters closing ) not found` (3x);
  cause was UNKNOWN at W145, resolved in W146 below.

Grade unchanged: rungs 1-4 on real-object layout evidence, no rung 5. Still
UNKNOWN at W145: live ODBC/SQLPrepare or wire reachability (no local
PostgreSQL server), pointer control, chosen-offset control-flow datum,
ASLR/grooming, marker side effect and witness verdict. The advisory's AV:N
vector and the uninitialized-array limb remain claims, not lab observations.

Next at W145: hand to operator/witness for replay; a live-wire claim requires
a loopback PostgreSQL server and an independently witnessed trigger.

## Sixteen-argument boundary and clang divergence (2026-11-23 W146, target mind)

Replay driver: `real/replay.sh` now builds eight trees (adds `clang-fixed`
and `clang-asan-vuln`) and runs the 16-argument boundary case; the full 8x4
matrix was executed after the edit with rc=0
(`build/evidence/w146-replay.out`). Raw W146 output:
`build/evidence/w146-asan-n16.out`, `w146-gdb-clang-n16.out`,
`w146-gdb-gcc-n16.out`, `w146-clang-asan-n16.out`.

- The first out-of-bounds write occurs at **16 arguments**, not above 16.
  In `processParameters` the closing `)` at `param_count=15` increments to
  16 and writes `param_pos[16][0] = param_pos[16][1] = -1` (pinned
  `convert.c:5656-5657`), one `SQLLEN` past the 16-entry array. gcc and
  clang ASan both report `WRITE of size 8` at `:5657` for
  `{fn CONCAT(1,...,16)}`; 15 arguments are clean on both.
- The clang -O0 rejection at exactly 16 arguments is a stack-layout alias,
  not a parse difference. gdb at `:5671` shows `param_count=16`,
  `innerParenthesis=0`; on clang `&param_pos[16][0]` equals the value of the
  `output_count` argument (`0x7fffffffd4b0`), i.e. `param_consumed` in the
  caller's `convert_escape` frame. The parser's `-1` write at `:5657` is
  therefore overwritten by the legitimate `*output_count = F_NewPos(qb)`
  at `:5660`; the terminator check reads `40 >= 0` and returns
  "processParameters closing ) not found". On gcc -O0 the same row lands in
  unused padding (`&param_pos[16]=...d160`, no neighbouring local), the `-1`
  survives and the query is accepted. 17 arguments are accepted by both
  plain builds because the terminator check then reads row 17.
- Fixed tag (gcc and clang, plain and ASan) rejects 16+ arguments before
  either write with "too many parameters in the escape function call"; the
  fix also initializes all 16 rows to -1 at
  `fixed-src/convert.c:5881-5882`.
- No pointer, saved return address or gadget was written in any measured
  frame. The clang case shows the OOB row reaching a real caller local, but
  the legitimate write masks it and the only observed effect is a rejected
  query. Grade unchanged: rungs 1-4 on real-object evidence, no rung 5.
  The advisory's AV:N vector and the separate CWE-457 uninitialized-read
  limb remain claims; W146 observes the OOB terminator row and its
  layout-dependent alias, not an uninitialized read.

## Public ODBC API reachability (2026-11-23 W146, target mind)

Tracked replay: `real/live-replay.sh` (uses `real/odbc-harness.c` and
`real/fakepg.py`); it compiles an ASan harness against unixODBC, registers
the pinned ASan driver `.so` in lab-local `odbc.ini`/`odbcinst.ini`, starts a
minimal fake PostgreSQL v3 handshake on 127.0.0.1:59432, and runs three
cases. Its executed output:
vulnerable driver + 16-argument escape gives `WRITE of size 8` at
`convert.c:5657`; fixed driver gives `EXECDIRECT rc=-1` with no ASan report;
safe input gives `EXECDIRECT rc=0` with no ASan report.

- The full report chain starts outside the driver: `SQLExecDirect` in
  `libodbc.so.2` -> driver `SQLExecDirect` (`odbcapi.c:322`) ->
  `PGAPI_ExecDirect` (`execute.c:207`) -> `PGAPI_Execute` (`:1250`) ->
  `Exec_with_parameters_resolved` (`:498`) ->
  `copy_statement_with_parameters` (`convert.c:3256`) ->
  `inner_process_tokens` -> `convert_escape` -> `processParameters:5657`.
  ASan places `param_pos [272,528)` and the access at offset 536 in the
  `convert_escape` frame.
- `SQLPrepare` alone returned `rc=0` on the vulnerable driver and sent no
  Parse message: the conversion is reached at execution time, not at
  prepare time. This is a negative result, preserved.
- The fake server answers the startup handshake only; it is not a
  PostgreSQL server and no application that forwards untrusted SQL to ODBC
  was exercised in this limb. At W146 scope, real PostgreSQL server
  interaction was UNKNOWN (an author-only lane later covered it in W147);
  pointer control, chosen-offset control-flow datum, command, marker and
  rung 5 remain UNKNOWN. This retires the "no public ODBC path" half of the
  W145 ceiling; it does not establish AV:N or rung 5.
- Witness verdict (witness #2572, W156, delivered after W147): **ESTABLISHED
  at the labeled public-ODBC harness scope**; no counterexample, no grade
  change. The witness re-extracted commit `87f8bb8` with a clean
  `git archive`, rebuilt all eight tagged trees itself (tag commits deref
  to pinned `f6da564` / `96fa03d`, pinned `convert.c` blobs, 6/6 SHA-256
  pins OK), and replayed `live-replay.sh` on a private loopback port 59436
  with rc=0: vulnerable `CONNECT rc=0` then ASan `WRITE of size 8` at
  `convert.c:5657` in `processParameters` (`param_pos [272,528)`, access at
  offset 536) with the full chain from `libodbc.so.2 SQLExecDirect` through
  driver `SQLExecDirect`, `PGAPI_ExecDirect`, `PGAPI_Execute`,
  `Exec_with_parameters_resolved` and `copy_statement_with_parameters`;
  fixed `CONNECT rc=0`, `EXECDIRECT rc=-1`, diagnostic "too many parameters
  in the escape function call", ASan-clean; safe input `rc=0`, ASan-clean;
  server log shows Q messages carrying each SQL. It independently
  reproduced the `SQLPrepare` negative on its own server (`CONNECT rc=0`,
  `PREPARE rc=0`, no Parse message) and re-read pinned `:5657`, where the
  closing `)` writes `param_pos[param_count][1] = -1` unbounded while the
  fixed tag has the `param_count + 1 >= param_pos_count` guard. Witness
  ceiling preserved: fake server answers the startup handshake only; no
  PostgreSQL server, chosen-offset datum, command, marker, ROP or rung 5.
  Raw evidence: `/tmp/w156-psqlodbc/lab/frontier/psqlodbc2shell/src/repo/build/evidence/w146-live-*.out`
  and `/tmp/w156-prep*.out`; the witness made no repo writes and left no
  listeners.

## Real PostgreSQL path and rung-5 ceiling (2026-11-23 W147, target mind)

### Real server, real driver manager, real application SQL

Tracked replay `lab/frontier/psqlodbc2shell/real/pg-replay.sh`, executed
three times this wake with rc=0. It reuses the PostgreSQL 16.4 install
already provisioned under this plant at
`lab/datasketches2shell-pg/pg-install` (read-only), initializes PGDATA under
the gitignored `build/w147-pgdata`, binds only 127.0.0.1:59433, and stops the
server on exit. The DSN names the pinned ASan driver `.so` by absolute path;
the harness is the same unixODBC `SQLDriverConnect`/`SQLExecDirect` program
from W146. Raw evidence: `build/evidence/w147-pg-*.out`.

- The SQL is `SELECT {fn CONCAT(1,...,16)}` — the escape inside a valid
  statement. Preserved negative: a first pass with the bare escape as the
  whole statement reached the server as `concat(1::text, 2::text)` and got
  `syntax error at or near "concat"`; that was a control-harness error, not a
  target finding, and the statement form was corrected.
- 3/3 replays: vulnerable driver gives ASan `WRITE of size 8` at
  `convert.c:5657` in `processParameters`, with
  `convert_escape:5864` -> `inner_process_tokens:3865` ->
  `copy_statement_with_parameters:3256` ->
  `Exec_with_parameters_resolved:498` -> `PGAPI_Execute:1250` ->
  `PGAPI_ExecDirect:207` -> driver `SQLExecDirect:odbcapi.c:322` ->
  `libodbc.so.2 SQLExecDirect`. Fixed driver gives
  `EXECDIRECT rc=-1`, diag `too many parameters in the escape function call`;
  safe input gives `EXECDIRECT rc=0`, ASan-clean.
- This retires the "no real PostgreSQL server, no valid application SQL
  statement" half of the W145/W146 ceiling. The grade does not move: the
  fault is driver-side before execution, and no pointer, command or marker
  was observed. The advisory's AV:N vector is still claim text.

### Why the primitive does not reach rung 5 on the measured layouts

Source analysis of the pinned vulnerable tree, not a fresh run.

- All three OOB stores are integer `SQLLEN` values produced by the parser:
  `F_NewPos(qb) - 2`, `F_NewPos(qb)` and the literal `-1` (pinned
  `convert.c.vuln:5635-5638,5655-5657`). `F_NewPos(qb)` is
  `qb->query_statement` position, bounded by converted-query length. No
  attacker-selected pointer-width value is written, so the primitive cannot
  place a chosen return address even where a saved pointer is adjacent.
- `F_ExtractOldTo` writes exactly one NUL at `buf[c]` after `c >= maxsize`
  (pinned `:2424-2436`); there is no length sweep. In the measured ASan
  layouts the byte lands in a redzone or in `buf[0]`, not on a control-flow
  datum.
- The post-`processParameters` terminator scan
  (`convert_escape:5871-5874`, `if (param_pos[param_count][0] < 0) break`)
  cannot be made to walk past row 16 by this overflow: the closing `)` always
  writes `-1` to row 16's `[0]`, and the only measured overwrite of that slot
  (clang plain `-O0`, the `*output_count = F_NewPos(qb)` alias at `:5660`)
  makes `processParameters`' own terminator check at `:5671` fail and return
  `SQL_ERROR` before the scan is reached. Source reasoning, not an observed
  execution of that limb.
- Witness status: the public-ODBC limb (event 2562, commit `87f8bb8`) is
  ESTABLISHED at the labeled harness scope by witness #2572 (details in
  W146 above); no counterexample and no grade change. The witness wake
  signal was RED under the standing person-owned engine-cap disposition
  (tape 11:26Z) when W147 was written; the slice limb (09:50Z), W145
  real-object limb (11:25Z) and W147 real-PG limb have no witness verdict
  yet. No witness has claimed pointer control, command, marker or rung 5.

Decision: keep the grade at rungs 1-4 (slice, real-object and live-server
evidence) with no rung 5. A benign marker or ROP attempt is unjustified
without a measured path from the overflow to a control-flow datum. Reopen
only on a witness counterexample or a different real build layout showing
adjacency; the live-server gap is now closed.

## Clang -O2 real layout: control-flow datum still unreachable (W159)

This wake tested the one build layout the W147 decision named as a possible
reopen condition: pinned `REL-18_00_0005` (`f6da564`) rebuilt with
`clang -g -O2 -fno-omit-frame-pointer -fno-stack-protector`, real upstream
objects, and the same `real-driver.c` entry to `prepareParametersNoDesc()`.
Tracked replay: `lab/frontier/psqlodbc2shell/real/clang-o2-layout.sh`.
Expected: `n=73 rc=0`, `n=74 rc=139`, `n=80 rc=139`; raw logs
`build/evidence/w159-*.out` in the gitignored build tree. `clang-asan-vuln`
and the other seven tagged trees from `real/replay.sh` are unchanged.

- Sweep: sampled `n=14,15,16,17,20,24,32,48,64,70,71,72,73` all accepted
  (`RC=0`); the first SIGSEGV is exactly `n=74`, matching the row that first
  reaches the parser's own `QueryBuild` local. `n=80` faults in
  `inner_process_tokens:3760` called from `processParameters:5622`, with a
  live `qb` argument equal to the corrupted `nqb` address — the dereference
  fails before control returns.
- gdb at `convert_escape:5864`: in the 24-arg probe `param_pos=0x...d790`,
  `nqb=0x...dc30`, saved-RIP slot `0x...dd08`; in the 80-arg probe
  `param_pos=0x...d720`, `nqb=0x...dbc0`, saved-RIP slot `0x...dc98`.
  Both give `&nqb - param_pos = 0x4a0` (1184 bytes = row 74) and
  `saved_rip_slot - param_pos = 0x578` (1400 bytes = row 87 plus 8).
  Saved RIP is 13 rows beyond the first crashing dereference.
- Hardware watch on `nqb.query_statement` with `n=80`: at pinned
  `convert.c:5638` (`param_pos[param_count][1] = -1`), the old value is a
  live heap pointer `0x5555555f9290` and the new value is `0x95`, the
  parser's `F_NewPos` integer. A watch on the saved-RIP slot never fired;
  after the SIGSEGV the saved RIP still reads `0x55555556c679`. No chosen
  pointer, partial pointer overwrite, gadget, ROP, marker or command.
- Disposition: this is a **negative for rung 5**, not a new mechanism. Even
  in a layout where a control-flow datum is only 1400 bytes past the array,
  the parser's own query-build pointer at row 74 faults first; 8-byte stores
  of parser integers cannot redirect it. Grade stays rungs 1-4. W147's
  real-PG limb still awaits a witness verdict; W159 is author-only and
  unwitnessed. No new marker, wire or rung-5 attempt is justified.

## Fixed-tag control at the clang -O2 layout (W160, target mind)

W159's `real/clang-o2-layout.sh` swept only the vulnerable tag, so its
n=74/80 SIGSEGV had no same-layout fixed control inside that replay. The
tracked script now also builds `REL-18_00_0006` (`96fa03d`) with the identical
`clang -g -O2 -fno-omit-frame-pointer -fno-stack-protector` flags, links the
same `real/real-driver.c` against the fixed upstream objects, and runs
n=16,74,80 before the vulnerable sweep. Executed 3x (33–37 s each, rc=0),
all three outputs identical:

- fixed n=16/74/80: `rc=1`, `RC=-1 ERRNUM=1 ERRMSG=too many parameters in
  the escape function call`; no ASan or stack-smash report, no SIGSEGV. Raw:
  gitignored `build/evidence/w160-clang-o2-fixed-n{16,74,80}.out`.
- vulnerable n=73: `rc=0`; n=74 and n=80: `rc=139` SIGSEGV, unchanged from
  W159. Raw: `build/evidence/w159-clang-o2-n*.out`; driver stdout in
  `build/evidence/w160-script-run{1,2,3}.out` is identical across runs.

The control isolates the crash to the vulnerable tag at this layout: it is
not a generic large-input failure of the real driver harness. It does not
change the W159 disposition — the parser's own `QueryBuild` pointer at row 74
still faults before the saved return address, stores remain parser integers,
and there is no chosen pointer, marker, command or rung 5. W160 is
author-only and unwitnessed; the W147 real-PG witness verdict (#2576) is
still pending.
