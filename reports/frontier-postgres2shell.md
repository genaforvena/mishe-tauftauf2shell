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
  foreign server (`PR:L`). Both ends are loopback-able: the upstream regression
  test uses `SERVER loopback`.
- **Claim sources (read-only provisioning, treated as claims)**: PostgreSQL
  security page `postgresql.org/support/security/CVE-2026-120149/`; PostgreSQL
  18.7 release notes, item "Avoid out-of-bounds accesses in FDW batch inserts";
  fix commit `1e0a55a0fb26e13a6f0b1da87dea06957780b9e4` (full patch fetched
  from `github.com/postgres/postgres/commit/1e0a55a0f.patch`).

## Verified ground truth (documents read 2026-11-20, NO local lab run yet)

The primary advisory, the release-note entry and the full fix patch were read
this wake. No PostgreSQL source was built, no instance started, no bytes
observed locally. Every rung below is therefore **NOT DEMONSTRATED in this
lab**; the observations in this section are about *documents*, not about a
running victim.

Advisory text (claim): "Heap-based buffer overflow in PostgreSQL foreign
batch inserts allows a foreign server to execute arbitrary code, via
reporting that it inserted more rows than the server supplied. postgres_fdw
can legitimately encounter this when a rule on the remote table expands an
INSERT into additional rows."

Release note (claim): "Avoid out-of-bounds accesses in FDW batch inserts
(Nathan Bossart)… The PostgreSQL Project thanks Sumedh Pathak and Sven Klemm
for reporting this problem. (CVE-2026-120149)" — links commit `1e0a55a0f`.

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
  six rows in the rule table (`SELECT count(*)=6`). This is the patch-sensitive
  differential to reproduce locally.

**Claim discrepancy preserved, not resolved:** the advisory assigns CWE-122
("writes past the end of a buffer") and says "buffer overflow", but the fix
commit message says the backend "proceeds to read past the end of the array"
and the clamp prevents "buffer overruns in the loop below" whose body reads
`rslots[i]`. Read vs write direction, and the exact downstream dereference of
the out-of-bounds slot pointer, are **UNKNOWN** until the vulnerable source
loop body and a sanitizer run are examined locally. Do not collapse the
advisory's RCE claim into a demonstrated primitive.

## Rung ladder — honest grading (no local evidence yet)

- **Rung 1 (reproducible trigger): NOT DEMONSTRATED.** Planned: two loopback
  PostgreSQL instances (foreign + local), `postgres_fdw` with the upstream
  rule/batch_size test, INSERT of two rows on an affected build; differential
  against a fixed build. The upstream regression test is a claim, not a local
  observation.
- **Rung 2 (observed state failure): NOT DEMONSTRATED.** Planned observation:
  over-reported count (6 > 2) reaching the backend loop.
- **Rung 3 (ASan/UBSan-confirmed corruption): NOT DEMONSTRATED.** Needs an
  ASan-instrumented build of the affected branch; the expected report is an
  OOB access on `rslots[]` in `ExecBatchInsert`, but no report has been seen.
- **Rung 4 (demonstrated security impact): NOT DEMONSTRATED.** No controlled
  slot pointer, no pointer/GOT control, no marker execution. The advisory's
  "arbitrary code execution" is a CLAIM.

## Feasibility and cheapest next step

Tractability **HIGH for rungs 1–3**, **MEDIUM for rung 4**: pure C core-server
code, open source with the exact fix commit and a deterministic regression
test, stock packages pullable, both endpoints loopback-able. It needs no
hardware feature (unlike the AVX-512-blocked Java4Shell). Reachability is
narrower than a default-on listener: the attacker must influence a foreign
server's row-count response and hold `PR:L`, so a dedicated mind should weigh
that against other lanes. The primitive is an OOB *read* of slot pointers with
a subsequent dereference — attractive for rung 4 if adjacent heap memory can
be groomed with chosen `TupleTableSlot *` values, but unproven.

Cheapest next rung: build an affected branch (e.g. 17.11) with
`-fsanitize=address -O0 -g`, start two loopback clusters, load
`contrib/postgres_fdw`, replay the upstream rule test, and capture the ASan
report naming `ExecBatchInsert` and `rslots[]`. Preserve the differential
against 17.12. If the read direction holds, attempt to place a chosen slot
pointer immediately after `rslots[]` before any code-execution claim.

## Reproduce (planned, not yet executed)

```
# affected vs fixed: PostgreSQL 17.11 vs 17.12, both built with ASan
# loopback clusters on distinct ports; postgres_fdw SERVER loopback
# replay patch's contrib/postgres_fdw/sql/postgres_fdw.sql regression snippet
#   CREATE RULE expanding one INSERT into 3 rows; batch_size '10'
#   INSERT INTO ftable VALUES (1),(2);
# capture backend ASan report; diff fixed build (clamps 6 -> 2)
```

All listeners must bind 127.0.0.1 only. No host package changes, no external
probe. No lab work has been done for this candidate yet.
