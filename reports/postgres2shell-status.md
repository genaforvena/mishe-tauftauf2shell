# Postgres2Shell status

Admitted 2026-11-20 by the operator under standing approval #6 (handoff #188).
Dedicated two-pane window and two-pane restorer registry entry are live;
hy4-flash route is set. Trigger unit is still owed from the person's full-flag
sync per `docs/runtime-pin.md`.

## Inherited, not yet re-run by this mind

- **Target.** PostgreSQL FDW batch-insert overcount, CVE-2026-120149 /
  GHSA-gqm6-3wfg-52x5, core server, CVSS 8.8. Affected < 18.7 / < 17.12 /
  < 16.16 / < 15.20 / < 14.25; fix `1e0a55a0f`.
- **Precondition (not pre-auth).** `PR:L` plus control of a foreign server's
  row-count response; the loopback reproduction uses `postgres_fdw` with a
  remote INSERT rule expanding two rows into six.
- **Stock differential.** Pinned 17.11: backend SIGSEGV, connection lost,
  psql rc 2. Pinned 17.12: `INSERT 0 2`, rule-table count 6, rc 0.
- **Rungs 1/2 PASS.** Rung 3 PASS on stock 17.11 under Valgrind: uninitialised
  8-byte FDW-heap value used as a pointer, `Invalid write of size 4` at `0x38`,
  then SIGSEGV; absent before the trigger.

## Open

- Rung 4 is **NOT demonstrated**: the consumed pointer was uninitialised heap
  data, not attacker-chosen; no controlled slot pointer, marker execution or
  code control. The advisory's RCE claim stays a CLAIM.
- Stock binary is stripped, so `ExecBatchInsert` / `rslots[]` are attributed
  from the fix diff plus origin/stack correlation, not a symbolised report.
  Advisory CWE-122 write vs fix-commit read remains UNKNOWN. Next bounded step:
  symbolise the faulting access, resolve read vs write, check MemoryContext
  behavior before assuming ASan poisons palloc'd intra-arena reads.
- Loopback ports 55431/55432 only. Evidence:
  `reports/frontier-postgres2shell.md` (commits `4e2f974`, `929ac1f`, `9393def`).
