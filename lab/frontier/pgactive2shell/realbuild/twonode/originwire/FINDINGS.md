# Catalog-derived replication-origin name reaches the parser in a live apply worker (2026-11-25 22:23Z)

This closes the "catalog route UNKNOWN" in the report. The crafted name is
not a direct SQL argument and not bytes carried in the replication stream: it
is a row in the receiving node's `pg_replication_origin` catalog, resolved by
origin id when a remote change is logged as a conflict. The remote change is
the wire trigger. Creation of replication origins is owner-only on this build
(`originpath/FINDINGS.md`), so the `PR:L` plus specific-privileges precondition
of the advisory is part of this result, not hidden.

## Source route

- `pgactive_apply.c:3065`: apply worker sets `replorigin_session_origin` from
  its own origin id at startup.
- `pgactive_apply.c:782`: `get_local_tuple_origin()` reads the origin id
  recorded for the conflicting local tuple's xmin via
  `TransactionIdGetCommitTsData()` (`:1450`).
- `pgactive_apply.c:798`: `process_remote_insert()` calls
  `pgactive_make_apply_conflict()` under `log_update`.
- `pgactive_conflict_logging.c:688` and `:716`:
  `pgactive_fetch_sysid_via_node_id()` for `replorigin_session_origin` and for
  `local_tuple_origin_id`.
- `pgactive_catalogs.c:304-333`: `replorigin_by_oid()` returns the catalog
  name; `:321` calls `pgactive_parse_replident_name()`.
- `pgactive_catalogs.c:347-358`: unbounded `%s` into a 64-byte `NameData`.

`No handler` is required so the separate `fcinfo` defect in
`pgactive_conflict_handlers_resolve()` cannot fire first. `log_update` is
forced by `pgactive.debug_apply_delay=5000` on the receiving node: node 1's
insert commits at T1, the crafted-origin row commits locally at T2 > T1, and
the delayed apply worker only replays node 1's insert afterwards. Last-update-
wins then keeps local and sets `log_update=true` (`pgactive_apply.c:1466-1535`).

`run-two.sh` gained two default-off knobs: `ORIGIN_TUPLE=1` (this arm) and
`ORIGIN_REWRITE=1` (the failed first attempt, below). No existing arm changes.

## Negative: renaming the worker's own origin

`ORIGIN_REWRITE=1` appended 260 crafted bytes to every `pgactive_%` row in
`pg_replication_origin` on both nodes. The worker had already captured its
origin id, but slot-name generation derives a slot name from the origin name;
after the rename every apply-worker restart failed with
`replication slot "pgactive_5_...__" already exists` and exited with code 1.
The run was stopped by its 300s wrapper timeout before table creation
(`origin-rewrite-negative.log` here); both clusters were stopped immediately
afterwards. That attempt never reached the parser. Keep it as a negative:
do not rename the worker's own origin row.

## Observed: vulnerable 2.1.9, plain and ASan

Commands, from `realbuild/twonode/` with loopback ports 58431/58432:

```sh
VERSION=2.1.9 NO_HANDLER=1 ORIGIN_TUPLE=1 sh run-two.sh
VERSION=2.1.9 ASAN=1 NO_HANDLER=1 ORIGIN_TUPLE=1 sh run-two.sh
VERSION=2.1.10 NO_HANDLER=1 ORIGIN_TUPLE=1 sh run-two.sh
```

- Both 2.1.9 runs: `CREATE_GROUP=0`, `NODE1_READY=r`, `NODE2_READY=r`,
  `TABLE_ON_NODE2=t`, `INSERT1=0`, `TUPLE_ORIGIN_INSERT=0`, `PGSTOP1=0`,
  `PGSTOP2=0`. Used normal library sha256
  `3177a37c...162998`, restored after each run; used ASan library sha256
  `56550571...d29e`. No postmaster left running.
- Plain backend: `evidence/server2.log` reports
  `ERROR: could not parse slot name: pgactive_1_1_1_1_AZ...` (275-byte name).
  The parser was reached in the live apply worker; `elog(ERROR)` longjmps, so
  `TERMINATIONS1=0`, `TERMINATIONS2=0` and no canary abort. Evidence in
  `v219-plain/`.
- ASan-preloaded postmaster: two reports from node 2's apply worker,
  `stack-buffer-overflow`, `WRITE of size 261`, frame
  `pgactive_parse_replident_name src/pgactive_catalogs.c:351`, called via
  `pgactive_fetch_sysid_via_node_id_ifexists` (`:321`),
  `pgactive_fetch_sysid_via_node_id` (`:338`),
  `pgactive_make_apply_conflict src/pgactive_conflict_logging.c:716`,
  `process_remote_insert src/pgactive_apply.c:798`,
  `pgactive_apply_main src/pgactive_apply.c:3071`. The report puts the access
  at offset 96 of the frame's `[32, 96) 'replication_name' (line 349)`.
  Full stack in `v219-asan/server2.log`. Evidence in `v219-asan/`.
- Fixed 2.1.10 control (sha256 `986917a8...2885a`): same setup and remote
  insert, no ASan, no termination, and node 2 reports
  `ERROR: could not parse replication origin name: pgactive_1_1_1_1_AZ...`.
  Evidence in `v2210-fixed/`.

## Rung assessment

Rung 3 is confirmed by ASan in a **live apply worker** with a remotely
triggered change and a crafted catalog-derived name, with a vulnerable/fixed
differential. Rung 4 for chosen bytes at chosen offsets remains the earlier
harness and live-SQL-marker evidence; this run supplies the live consumer and
the remote trigger that were previously missing from the catalog route. It
does **not** establish rung 5: the overflowing input still fails the pinned
`!= 4` check and leaves through the `elog(ERROR)` longjmp, so the saved RA at
+120 and canary at +72 are abandoned rather than consumed. No chosen pointer,
no saved IP, no command side effect. The crafted row is created by a
privileged local session; a lower-privilege origin-creation route was not
demonstrated.

Author observation, not an independent witness verdict. All runs were
loopback-only; no cluster is left running, the normal 2.1.9 library was
restored, and the used/restored hashes are copied into `../` here.
