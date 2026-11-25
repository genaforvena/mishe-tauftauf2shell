# Catalog-derived replication-origin name reachability (2026-11-25 03:34Z)

Scope: loopback-only PostgreSQL 16.15 with the full pinned pgactive 2.1.9
library loaded via `shared_preload_libraries`. `sh run.sh` rebuilds a fresh
cluster under `/tmp/pgactive-originpath-pgdata`, port 58429, socket `/tmp`,
and stops it on exit. Evidence is in `evidence/`.

## Source question

`pgactive_parse_replident_name()` is not only called by the owner-only SQL
wrapper (`pgactive.c:1531`). Pinned `pgactive_catalogs.c:321` calls it from
`pgactive_fetch_sysid_via_node_id_ifexists()` with a name obtained from
`replorigin_by_oid(node_id, missing_ok, &riname)` — i.e. the name is read
from the `pg_replication_origin` catalog, not supplied as a direct SQL
argument. The patch format is
`pgactive_REPORIGIN_ID_FORMAT = "pgactive_" UINT64_FORMAT "_%u_%u_%u_%s"`
(`internal-v2.1.9.h:31`); the trailing `%s` writes into a 64-byte
`NameData replication_name`. A name whose trailing part exceeds 63 bytes
overflows that object. This matches the advisory's "crafted replication
origin name" wording.

## Observed (owner/superuser session)

`pg_replication_origin_create()` does **not** enforce a 63-byte bound here.
Names of 66, 67, 99 and 275 bytes were created and persisted in
`pg_replication_origin.roname` (`evidence/origin-catalog.out`,
`evidence/origin-272.out`, `evidence/origin-long.out`; all `RC=0`). So a
catalog-derived origin name can be long enough to overflow the parser's
64-byte buffer. This is a precondition only: no wire trigger was exercised.

By contrast, `pg_create_logical_replication_slot()` with a 96-byte requested
name stored a **63-byte** name (`evidence/slot-catalog.out`, `n=63`), so the
output-plugin slot-name caller at `pgactive_output.c:382`
(`pgactive_parse_slot_name`) cannot receive an overlong name through this
route on this build. First attempt failed with
`library "pgactive" may not be used as an output plugin`; adding
`-c output_plugin_libraries=pgactive` allowed slot creation and exposed the
63-byte truncation. Both are preserved.

## Privilege result (lower-privilege route not demonstrated)

A plain `CREATE ROLE lowpriv LOGIN` cannot create a replication origin
(`ERROR: permission denied for function pg_replication_origin_create`) and
cannot call the parser
(`ERROR: permission denied for function pgactive_parse_replident_name`).
`pg_proc.proacl` is owner-only for both, with `prosecdef = f`
(`evidence/lowpriv-origin.out`, `evidence/lowpriv-parser.out`,
`evidence/acl.out`). `pgactive_acquire_global_lock(text)` and
`pgactive_get_global_locks_info()` are also `REVOKE ... FROM public` in the
pinned install script. No lower-privilege path to the parser was found.

## Negative: catalog-derived trigger not driven

The candidate internal SQL route is
`pgactive_get_global_locks_info()` -> `pgactive_fetch_sysid_via_node_id_ifexists()`
(`pgactive_locks.c:2550`) with `state.lock_holder` assigned from
`replorigin_session_origin` at `pgactive_locks.c:1560`. With a 99-byte origin
created, `pg_replication_origin_session_setup(...)` succeeded
(`evidence/acquire.out`, first statement), but `pgactive_acquire_global_lock`
failed with `ERROR: database with oid=5 is not configured for pgactive or
pgactive is still starting up`, and `pgactive_get_global_locks_info()` failed
with the same error (`evidence/locks-after.out`). `pgactive_create_group`
returned success but `pgactive_wait_for_node_ready(5)` reported current
state `b` (`evidence/ready.out`). A ready multi-node pgactive group is a
prerequisite not met in this single-node cluster. On 2026-11-25 21:53Z the
same call sequence was retried in the ready two-node group
(`../twonode/catalogprobe/FINDINGS.md`): both nodes reached `r`, the 99-byte
origin and session setup succeeded, but the diagnostic returned a NULL
`owner_replorigin` and `lock_mode=nolock`, with no parse error and no
termination. The parser was not reached there either. This route remains
UNKNOWN, not demonstrated and not ruled out.

## Provisioning negatives

- `pgactive.skip_ddl_replication = off` cannot be set in a backend session
  (`unsafe pgactive configuration options can not be disabled locally`) and
  setting it via `-c` at postmaster start prevented the library from loading
  (`CREATE EXTENSION: pgactive must be loaded via shared_preload_libraries`).
  Working form: `ALTER SYSTEM SET pgactive.skip_ddl_replication = off` in its
  own statement after `CREATE EXTENSION`, then `SELECT pg_reload_conf()`.
- `pg_replication_origin_session_origin()` does not exist in this build;
  that first probe was removed.

No cluster is left running; `PGSTOP=0` on every run. No external system was
contacted.
