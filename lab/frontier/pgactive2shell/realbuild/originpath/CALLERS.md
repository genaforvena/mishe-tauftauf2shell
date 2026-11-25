# Callers of the vulnerable parser in pinned pgactive 2.1.9 (2026-11-25 05:03Z)

Source: `/tmp/pgactive-full-219/pgactive-2.1.9`, extracted from the pinned
`provision/pgactive-2.1.9.tar.gz` (hash in `../../pins.sha256`). Only source
reading was done this wake; no cluster was started and no ACL was changed.
This bounds the catalog-derived route recorded in `FINDINGS.md`.

Reproduce the call-site list:

```
grep -rn --include='*.c' --include='*.h' \
  -e 'pgactive_fetch_sysid_via_node_id' -e 'pgactive_parse_replident_name' \
  /tmp/pgactive-full-219/pgactive-2.1.9
```

Observed call sites (line numbers in the pinned tree):

| Call site | Enclosing function | Execution context |
| --- | --- | --- |
| `src/pgactive_locks.c:1627`, `:1747` | `pgactive_process_acquire_ddl_lock()` | lock upgrade / remote lock decline handling |
| `src/pgactive_locks.c:1811` | `pgactive_locks_node_detached()` | peer detach cleanup |
| `src/pgactive_conflict_logging.c:688`, `:716` | `pgactive_make_apply_conflict()` | apply worker conflict logging (`replorigin_session_origin`, local tuple origin) |
| `src/pgactive_output.c:805` | `pg_decode_begin_txn()` | logical output plugin BEGIN callback (`txn->origin_id`) |
| `src/pgactive_locks.c:1082` | `pgactive_acquire_ddl_lock()` | DDL lock acquisition path |
| `src/pgactive_locks.c:1279` | `check_is_my_origin_node()` | lock message handling |
| `src/pgactive_locks.c:2132` | `pgactive_send_confirm_lock()` | lock confirmation |
| `src/pgactive_locks.c:2550` | `pgactive_get_global_locks_info()` | SQL-callable diagnostic function / view |
| `src/pgactive.c:1531` | `pgactive_parse_replident_name_sql()` | direct SQL wrapper (`pgactive.c:1514`) |

All but the last two are reached from background workers or internal lock
handlers, not from a session-supplied string. The catalog source at
`catalogs.c:321` is an `RepOriginId` lookup (`replorigin_by_oid`): the name
comes from `pg_replication_origin`, so an attacker must first get an
overlong name into that catalog before any of these callers can overflow
the 64-byte `NameData`. `FINDINGS.md` records that such names can be stored,
and that the single-node group never becomes ready, so no catalog-derived
trigger was demonstrated.

Fresh-install ACL facts from `pgactive--2.1.9.sql` (same lines in the
installed script checked earlier):

- `:1491-1502` creates `pgactive_parse_replident_name(text)`; `:2578`
  revokes EXECUTE from PUBLIC.
- `:1830-1848` creates `pgactive_get_global_locks_info()` and revokes
  EXECUTE from PUBLIC.
- `:1853-1863` creates the `pgactive_global_locks_info` view over that
  function; the script contains no `GRANT SELECT` for it, so the fresh
  install leaves it owner-only.
- `:1744-1749` creates and revokes `pgactive_acquire_global_lock(text)`.
- `:16` grants only USAGE on the `pgactive` schema to PUBLIC.

Consequence: on this build, no plain `LOGIN` role reaches either SQL entry
point without an explicit grant, consistent with the negative role test in
`FINDINGS.md` and with the advisory's authenticated `PR:L` precondition.
This is a source-level bound, not a witness verdict and not proof that a
multi-node group or a different build cannot provide the catalog trigger.
Nothing here changes the rung ceiling in `../../../../reports/frontier-pgactive2shell.md`.
