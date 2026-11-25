# Catalog-derived parser route in a ready two-node group — NEGATIVE (2026-11-25 21:53Z)

Scope: loopback-only PG16.15, full pinned vulnerable pgactive 2.1.9 library
(`3177a37cd16c0010e5973190b4bbe31287144849823752865a5c8fb9ee162998`).
No external system was contacted. No rung change: the parser was **not**
reached, so this is a bounded negative, not a trigger.

## Question

The single-node probe in `../originpath/FINDINGS.md` could not drive
`pgactive_get_global_locks_info()` -> `pgactive_fetch_sysid_via_node_id_ifexists()`
because its group never left state `b`. The two-node lane now joins a ready
group (`NODE1_READY=r`, `NODE2_READY=r`), so the prerequisite is met. With a
99-byte replication origin installed as `replorigin_session_origin`, an
explicit `pgactive_acquire_global_lock('ddl_lock')` should put that origin OID
in `state.lock_holder`; the SQL diagnostic would then parse the crafted name
via the unbounded `%s` in `pgactive_catalogs.c:351`.

## Experiment

`run-two.sh` gained `CATALOG_PROBE` (default 0, so all existing arms are
unchanged). With `CATALOG_PROBE=1 NO_HANDLER=1 NO_CONFLICT=1 sh run-two.sh`,
after the group reaches `r` on both nodes, one backend runs:

```sql
SELECT pg_replication_origin_create('pgactive_123_1_2_3_' || repeat('AZ', 80));
SELECT pg_replication_origin_session_setup('<that name>');
SELECT pgactive.pgactive_acquire_global_lock('ddl_lock');
SELECT * FROM pgactive.pgactive_get_global_locks_info();
```

The generated name is 99 bytes and is saved in `evidence/catalog-name.txt`.

## Observed

- `CREATE_GROUP=0`, `NODE1_READY=r`, `JOIN_GROUP=0`, `NODE2_READY=r`,
  `CATALOG_SESSION=0`, `PGSTOP1=0`, `PGSTOP2=0`, `TERMINATIONS1=0`,
  `TERMINATIONS2=0`. Used library hash matches the vulnerable pin; the
  script restores it on exit.
- The origin was created (OID 2) and its session setup succeeded. The lock
  call returned without ERROR. The diagnostic returned one row with
  `owner_replorigin` NULL and `lock_mode=nolock`: `state.lock_holder` was not
  the crafted origin, so `pgactive_fetch_sysid_via_node_id_ifexists()` was
  called with a different OID or not called at all.
- No `could not parse slot name` error, no ASan report, no backend
  termination. The parser's overflow was **not** exercised from this route.

Two runs are preserved. The first used four separate `psql -c` invocations,
which lose the session-level origin between backends; its individual outputs
are in `evidence/first-run/`. The second used one backend, ruling out session
scope as the explanation; its outputs and server logs are in `evidence/`.
Both gave the same result. No cluster is left running; ports 58431/58432 are
free.

## Disposition

A ready group plus an explicit SQL lock acquisition is not sufficient to put
a hand-crafted origin into `state.lock_holder`. The cause of that state is
not established here; do not claim the route is impossible. The catalog
route stays UNKNOWN, now bounded by this negative. No chosen bytes reach a
saved control-flow word and no command side effect exists, so the rung
ceiling is unchanged. A further attempt needs a concrete hypothesis for how
an apply-worker lock holder gets a crafted origin OID — not another blind
repetition of this call sequence.
