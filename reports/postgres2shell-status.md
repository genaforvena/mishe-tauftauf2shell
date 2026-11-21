# Postgres2Shell status

Admitted 2026-11-20 by the operator under standing approval #6 (handoff #188).
Dedicated two-pane window and two-pane restorer registry entry are live;
hy4-flash route is set. Trigger unit is still owed from the person's full-flag
sync per `docs/runtime-pin.md`.

## Verified in this plant

- **Rungs 1/2 PASS.** Pinned stock 17.11 differential: backend SIGSEGV,
  connection lost, psql rc 2. Pinned 17.12: `INSERT 0 2`, rule-table count 6,
  rc 0. Both endpoints on loopback only.
- **Rung 3 PASS, symbolised.** Exact-build `postgresql-17-dbgsym` plus a live
  gdb replay names the fault `ExecBatchInsert+136`,
  `nodeModifyTable.c:1274` (`mov %ecx,0x38(%rbx)`, the 4-byte
  `tts_tableOid` store); the OOB pointer read is line 1268. Valgrind's
  `Invalid write of size 4` at `0x38` is the NULL slot base plus the field
  offset. Both the fix-commit "read past the array" and the advisory CWE-122
  "write" are correct about different statements; the claim discrepancy is
  resolved, not collapsed. `ri_Slots` is a palloc array inside the
  ExecutorState arena, so plain ASan would not poison the intra-arena OOB
  read — Valgrind's V bits were the useful detector.
- **Groom probe (2026-11-20).** The walk is attacker-extendable to 240
  reported rows and can consume stale valid slot pointers from a prior batch,
  but the first out-of-array pointer is NULL or a packed palloc chunk header.
- **Chunk-placement probe (2026-11-21).** The last named alternative — SQL
  placing a chosen 8-byte value after `ri_Slots` — is tested and NEGATIVE:
  distinctive 64-bit markers never appear in the 48-word OOB dump; the only
  marker occurrence is the INSERT `sourceText` in the backtrace. Source
  closure: `nodeModifyTable.c:913` writes `ri_Slots[i]` only for
  `i < ri_BatchSize`; no SQL path reaches the tail.

## Open

- Rung 4 is **NOT demonstrated** and the lane is closed on this host: no
  attacker-chosen address, chosen bytes or marker execution was observed.
  The advisory's RCE claim stays a CLAIM. A future attempt needs a
  fundamentally different primitive, not another replay of this trigger.
- Loopback ports 55431/55432 only. Full evidence and hashes:
  `reports/frontier-postgres2shell.md`; harness
  `lab/frontier/postgres2shell/`.
