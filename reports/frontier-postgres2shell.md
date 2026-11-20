# Frontier brief — PostgreSQL FDW batch-insert "BatchOvercount"

- **Advisory**: CVE-2026-120149 / GHSA-gqm6-3wfg-52x5, "PostgreSQL FDW
  batch-insert mismatch executes arbitrary code" (PostgreSQL Security,
  published 2026-11-12; GitHub Advisory Database 2026-11-12). CWE-122.
  CVSS 3.0/3.1 8.8 High, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`.
- **Affected / fixed**: core server, all supported branches before the
  2026-11-12 security release — affected < 18.7, < 17.12, < 16.16, < 15.20,
  < 14.25; fixed in 18.7 / 17.12 / 16.16 / 15.20 / 14.25 (and 19 RC 2).
- **Precondition**: the victim is the *local* PostgreSQL backend. The attacker
  must make a foreign data wrapper report more inserted rows than the backend
  supplied — e.g. control a foreign server's responses, or get a remote INSERT
  rule that expands rows, and hold the local privilege to use/create the
  foreign server (`PR:L`). Both ends are loopback-able: the reproduction uses
  `postgres_fdw` with `SERVER loopback` on one local instance.
- **Claim sources (read-only provisioning, treated as claims)**: PostgreSQL
  security page `postgresql.org/support/security/CVE-2026-120149/`; PostgreSQL
  18.7 release notes, item "Avoid out-of-bounds accesses in FDW batch inserts";
  fix commit `1e0a55a0fb26e13a6f0b1da87dea06957780b9e4` (full patch fetched
  from `github.com/postgres/postgres/commit/1e0a55a0f.patch`).

## Verified ground truth (this lab, 2026-11-20)

Documents read: the primary advisory, the 18.7 release-note entry and the full
fix patch (all claim sources above). Stock images were pulled by digest and
run loopback-only; no instrumented build was made.

Advisory text (claim): "Heap-based buffer overflow in PostgreSQL foreign
batch inserts allows a foreign server to execute arbitrary code, via
reporting that it inserted more rows than the server supplied. postgres_fdw
can legitimately encounter this when a rule on the remote table expands an
INSERT into additional rows."

Stock images pulled and pinned:

- `postgres:17.11` (affected) →
  `sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f`
- `postgres:17.12` (fixed) →
  `sha256:b60e90042aa6b8dbecd58e224b3e36114dbf8ad754465264c2476ad58a86e45c`

Harness `lab/frontier/postgres2shell/{run.sh,trigger.sql}` replays the fix's
own regression snippet on one container: a remote table whose INSERT rule
expands each row into three, a foreign table with `batch_size '10'`, and
`INSERT INTO ftable VALUES (1),(2)` (two rows sent, FDW reports six). Host
ports 55431/55432 published on 127.0.0.1 only; the foreign connection is
in-container loopback; no external probe.

| build | `INSERT` result | rule-table count | server log | psql rc |
|---|---|---|---|---|
| 17.11 | connection lost mid-statement | not reached | `server process (PID 91) was terminated by signal 11: Segmentation fault`, then "terminating any other active server processes" | 2 |
| 17.12 | `INSERT 0 2` | 6 | no termination/ERROR/FATAL lines | 0 |

Logs: `lab/frontier/postgres2shell/logs/{trigger-17.11.out,server-17.11.log,
differential-17.11.meta}` and the matching `17.12` files. Reproduce with
`./run.sh 17.11` and `./run.sh 17.12`.

## Valgrind observation on the stock affected binary (rung 3)

A second 17.11 instance in the same container was started under Valgrind
(`--track-origins=yes --error-limit=no`) on in-container loopback port 55435;
`lab/frontier/postgres2shell/trigger-vg.sql` points the FDW at it. Before the
trigger, no backend reported an uninitialised-pointer or invalid-write error
(clean startup produced only `Syscall param write(buf)` padding noise in one
backend). The trigger's backend then produced (log
`logs/valgrind-17.11.log`, stdout `logs/valgrind-17.11-stdout.log`):

- `Use of uninitialised value of size 8` at `0x4628C8`, where the uninitialised
  value "was created by a heap allocation … `pstrdup` …
  `postgres_fdw.so` … `ExecInitModifyTable`" — i.e. an 8-byte pointer from a
  foreign-server allocation is being consumed as data.
- `Invalid write of size 4` at the **same** `0x4628C8`, `Address 0x38 is not
  stack'd, malloc'd or (recently) free'd`, then `Process terminating with
  default action of signal 11 (SIGSEGV): Access not within mapped region at
  address 0x38`. Stack: `0x4628C8 -> 0x462A4A -> 0x4661E5 ->
  standard_ExecutorRun -> PortalRun -> PostgresMain -> BackendMain`.
- `ERROR SUMMARY: 48 errors from 4 contexts` for that backend; the other two
  contexts are `Syscall param write/pwrite64(buf) points to uninitialised
  byte(s)` (ordinary PostgreSQL buffer-padding noise, not claimed as this bug).

This is a Valgrind memory report, not just a crash: an uninitialised 8-byte
heap value from the FDW is used as a pointer and a 4-byte write faults at
`0x38`, consistent with the over-reported count walking `rslots[]` past its
`numSlots` entries and dereferencing a garbage slot pointer. **Limits:** the
stock binary is stripped, so the report shows `???` for `0x4628C8` and never
names `ExecBatchInsert` or `rslots[]`; the source-line attribution comes from
the fix diff plus the origin/stack correlation, not from a symbolised report.
The uninitialised value in this run was *not attacker-chosen*; no pointer or
marker control was exercised.

## Symbolised fault and the OOB slot bytes (gdb, 2026-11-20)

Installed the exact-build debug symbols in the lab container
(`postgresql-17-dbgsym=17.11-1.pgdg13+2`) and replayed the same trigger under
gdb on a second 17.11 instance (in-container loopback only, no host port).
This upgrades rung 3 from a correlation to a named instruction and source
line, and answers the read-vs-write question directly.

- `info address ExecBatchInsert` = `0x35a840`; line 1274 starts at
  `0x35a8b8`; the faulting instruction is `0x35a8c8 <ExecBatchInsert+136>:
  mov %ecx,0x38(%rbx)`. The Valgrind IP `0x4628C8` is that same file offset
  plus the Valgrind client load base `0x108000` — exact match.
- Line 1268 (`slot = rslots[i]`) compiles to `mov (%r14,%r12,8),%rbx` at
  `0x35a8b4`; line 1274 (`slot->tts_tableOid = ...`) compiles to the 4-byte
  store above. `tts_tableOid` is at offset `0x38` in `TupleTableSlot`
  (checked against the 17.11 `tuptable.h` layout), so the reported
  `Invalid write of size 4 ... Address 0x38` is a NULL slot base plus the
  field offset, not a write at absolute address 0x38 of an array.
- Live break at the loop head showed `numInserted=6`, `numSlots=2`,
  `rslots=0x61a0495da580`. `slots[0]=0x...a7a0`, `slots[1]=0x...aae0` are
  valid; **indices 2..9 are all zero**. `postgres_fdw` returns the very same
  `slots` array (`execute_foreign_modify()` returns `slots` and overwrites
  `*numSlots = n_rows`), so the overrun walks uninitialised entries *inside*
  the 10-pointer `ri_Slots` allocation. At `i=2` gdb read `slot=(nil)` and
  stopped at SIGSEGV on line 1274. Backtrace:
  `ExecBatchInsert -> ExecPendingInserts -> ExecModifyTable ->
  standard_ExecutorRun`. Logs:
  `lab/frontier/postgres2shell/logs/gdb-17.11-symbolised.log` (sha256
  `feb388a194deeaef31391cc69f925aae9736d94e1f6957790a1337abe114d670`) and
  `gdb-17.11-psql.out` (`fe3af636ac2875411c1c48d813a4a849932c389d6892560ffead1ed11b2d8fbf`).

Both claim directions are therefore correct about different statements: the
fix commit's "read past the end of the array" is the `rslots[i]` load at line
1268; the advisory's 4-byte heap write is the `tts_tableOid` store at line
1274 through the garbage pointer. In the observed run the garbage pointer is
**NULL**, so no chosen address, chosen bytes or marker execution occurred.

Sanitizer scope note: `ri_Slots` is a `palloc` array inside PostgreSQL's
ExecutorState arena, not a standalone malloc block. An ASan build would not
poison reads into the tail of that same arena chunk, so a plain ASan replay
is not a reliable detector for the line-1268 overrun; Valgrind's V bits did
flag the uninitialised pointer. No ASan build was needed for the
symbolisation above.

## Source-bound mechanism (read from the fix patch, not inferred)

`ExecForeignBatchInsert()` is an FDW callback that returns the count of
successfully inserted tuples through an out-parameter. The core treated that
count as the length of the returned slot array:

- `src/backend/executor/nodeModifyTable.c`, `ExecBatchInsert()`:
  `numInserted` comes back from the FDW; the loop
  `for (i = 0; i < numInserted; i++) { slot = rslots[i]; … }` walks
  `rslots[]`, which only has `numSlots` entries (the rows actually sent).
  If a malicious/over-reporting FDW returns `numInserted > numSlots`, the loop
  reads past the end of `rslots[]` and uses an out-of-bounds `TupleTableSlot *`.
- `src/backend/commands/copyfrom.c`, `CopyMultiInsertBufferFlush()`: the
  analogous FDW `inserted` count is used as a size; same over-report hazard.
- The fix is two clamps: `numInserted = Min(numInserted, numSlots);` and
  `inserted = Min(inserted, size);`, with the comment "An FDW may report more
  rows than we gave it, which would lead to buffer overruns in the loop below…
  a proper fix means reworking the batch insert API" (a stopgap, per author).
- Upstream regression test (in the same patch): a remote table with
  `CREATE RULE … DO INSTEAD INSERT … SELECT i FROM generate_series(1,3)`,
  foreign table with `batch_size '10'`, `INSERT INTO ftable VALUES (1),(2)`.
  Two rows sent, the rule reports six; fixed build clamps to two and stores
  six rows in the rule table (`SELECT count(*)=6`). Our fixed-build run
  reproduces exactly this: `INSERT 0 2`, count 6.

**Claim direction, refined by the Valgrind run:** the advisory assigns CWE-122
("writes past the end of a buffer") while the fix commit says the backend
"proceeds to read past the end of the array". The Valgrind report shows both an
uninitialised 8-byte *read* consumed as a pointer and an *invalid write* at
`0x38` through it. The precise source statement that reads `rslots[i]` is still
attributed from the fix diff, not a symbolised report — keep this distinction.
Do not collapse the advisory's RCE claim into a demonstrated primitive.

## Rung ladder — honest grading

- **Rung 1 (reproducible trigger): PASS.** Deterministic stock-image
  differential on loopback, clean affected/fixed pinning.
- **Rung 2 (observed state failure): PASS.** The FDW's over-reported count
  (six for two rows) reaches the backend; affected build loses the connection
  with a backend SIGSEGV, fixed build clamps to `INSERT 0 2` with the rule
  table at six. The version-sensitive 2-vs-6 boundary holds.
- **Rung 3 (memory report): PASS, now symbolised.** The Valgrind report shows
  the uninitialised 8-byte FDW-heap value used as a pointer and the invalid
  4-byte write at `0x38` followed by SIGSEGV, triggered by the INSERT and
  absent before it. Exact-build symbols and a live gdb replay name the fault
  `ExecBatchInsert+136`, `nodeModifyTable.c:1274`, with the OOB read at line
  1268; see the symbolised section above. The stock binary itself stays
  stripped — the names come from the matching Debian debug package, not from
  the Valgrind log.
- **Rung 4 (demonstrated security impact): NOT DEMONSTRATED.** The OOB slots
  read in the observed allocation are all zero; the consumed `TupleTableSlot
  *` is NULL, not attacker-chosen. The primitive would be a 4-byte store of
  the foreign relation's OID through a controlled slot pointer, but no such
  pointer was observed or placed. No GOT/pointer control, no marker
  execution. The advisory's "arbitrary code execution" remains a CLAIM.

## Feasibility and cheapest next step

Tractability **HIGH for rungs 1–3**, **MEDIUM for rung 4**: pure C core-server
code, open source with the exact fix commit and a deterministic regression
test, stock images pullable, both endpoints loopback-able. It needs no
hardware feature (unlike the AVX-512-blocked Java4Shell). Reachability is
narrower than a default-on listener: the attacker must influence a foreign
server's row-count response and hold `PR:L`. The primitive is an OOB slot
pointer read followed by a 4-byte store through it. The observed slot tail is
all zeros, so the practical question is whether that tail can be groomed
with chosen pointer bytes — unproven and not achieved by the stock trigger.

Next rung: the remaining question is purely a grooming question — can bytes
of a chosen pointer value be placed into the tail of the 10-entry `ri_Slots`
allocation before `ExecBatchInsert` reads it? The stock trigger leaves all
eight OOB entries zero. Even with a chosen pointer, the written value is a
relation OID, so a demonstration needs an observed controlled write at a
chosen address, not just an OOB pointer read. Preserve the fixed-build
differential and the zero-tail negative.

## Reproduce

```
cd lab/frontier/postgres2shell
./run.sh 17.11          # logs/trigger-17.11.out, server-17.11.log
./run.sh 17.12          # logs/trigger-17.12.out, server-17.12.log
# Valgrind: install valgrind in the 17.11 container, initdb a second PGDATA,
# start it under valgrind on in-container 127.0.0.1:55435, then connect psql
# to THAT wrapped instance (port 55435, not the normal 5432) and replay
# trigger-vg.sql there: the script seeds batch_table/batch_rule_table and the
# expanding batch_rule on the wrapped instance itself and points the FDW back
# at the same port, so the SIGSEGV happens in a Valgrind-wrapped backend and
# logs/valgrind-17.11.log captures the memory report. Replaying against 5432
# also crashes but yields NO Valgrind report — do not read that as rung 3.
```

Symbolised replay (needs the matching `postgresql-17-dbgsym` and gdb with
PTRACE capability; loopback only, no host port published):

```
# new 17.11 container with --cap-add=SYS_PTRACE, listen_addresses=127.0.0.1,
# gdb + postgresql-17-dbgsym=17.11-1.pgdg13+2 installed; copy /usr/lib/debug
# from the original lab container if the PGDG repo is unavailable.
# Hold a psql session open on a FIFO, note SELECT pg_backend_pid();
# attach: gdb -q -batch -p <backend-pid> -x pg2shell-gdb.cmd
# (breakpoint *ExecBatchInsert+120 dumps rslots[] and each slot pointer)
# then send trigger.sql's FDW setup and INSERT through the FIFO.
# Evidence: logs/gdb-17.11-symbolised.log, logs/gdb-17.11-psql.out
```

The gdb command file is committed at `lab/frontier/postgres2shell/gdb.cmd`;
the captured log above is its actual output.

All listeners bind/publish on 127.0.0.1 only (host ports 55431/55432;
in-container 55435 for the Valgrind instance). Stock image digests are pinned
above; no host package changes.
