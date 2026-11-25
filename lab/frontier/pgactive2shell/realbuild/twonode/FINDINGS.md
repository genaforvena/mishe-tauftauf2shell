# Live two-node apply-worker conflict (2026-11-25 13:47Z)

This is the first observation of the second stack object from
`../conflictpath/FINDINGS.md` in a **live process on the real replication
path**, not a standalone probe. Two loopback PostgreSQL 16.15 clusters run
the pinned vulnerable pgactive 2.1.9 extension; a raced insert on the same
primary key makes each node's apply worker resolve an `insert_insert`
conflict through `pgactive_conflict_handlers_resolve()`. Both apply workers
then die with signal 11. No external address is contacted; both clusters bind
only 127.0.0.1 and are stopped by `run-two.sh`.

## Recipe and host-specific prerequisites

`run-two.sh` creates both clusters from scratch (`n1`, `n2`, ports 58431 and
58432, private sockets `s1`, `s2`) and stops them at the end. Four setup
faults were diagnosed and repaired while building it; they are part of the
result, not incidental:

1. The 2.1.9 source `pgactive.control` declares `default_version=2.1.8`, so
   the per-db worker's `pgactive_maintain_schema()` `ALTER EXTENSION` with no
   target tries a 2.1.9 -> 2.1.8 downgrade and the worker exits. The script
   writes a lab-only control file with the requested version.
2. PG16.15 requires `pgactive` in `output_plugin_libraries`; without it
   `CREATE_REPLICATION_SLOT ... LOGICAL pgactive` fails and node 2 stays in
   state `i` ("previous init failed, manual cleanup is required").
3. `ALTER SYSTEM` and `pg_reload_conf()` must be separate statements —
   `psql -c 'a; b'` sends one implicit transaction and `ALTER SYSTEM`
   rejects it.
4. `pgactive_create_conflict_handler()` is a hard `ereport(ERROR, "feature
   is not implemented yet")` stub in 2.1.9. A configured handler is a direct
   row in `pgactive.pgactive_conflict_handlers`; the handler function itself
   is created with `CREATE OR REPLACE FUNCTION` because DDL replication
   already creates it on the peer.

`pgactive.skip_ddl_replication=off` is set with `ALTER SYSTEM` after
`CREATE EXTENSION`, and the script waits for `node_status='r'` on both nodes
before creating `public.t (id int PRIMARY KEY, val text)`. The handler is
`public.resolve_conflict(public.t, public.t, text, regclass,
pgactive.pgactive_conflict_type)` returning `(c public.t, action
pgactive.pgactive_conflict_handler_action)` with `action := 'ROW'`, and the
catalog row is type `insert_insert` on both nodes.

## Observed runs (2026-11-25 13:47Z - 13:57Z)

| Run | Extension | Library sha256 prefix | Handler | Inserts | Apply-worker terminations |
| --- | --- | --- | --- | --- | --- |
| `runs/v219-conflict` | 2.1.9 | `3177a37c` (vulnerable) | `insert_insert`, ROW | raced on both nodes | 1 each, signal 11 |
| `runs/v219-noconflict` | 2.1.9 | `3177a37c` | configured | node 1 only | 0 |
| `runs/v219-nohandler` | 2.1.9 | `3177a37c` | none | raced | 0 |
| `runs/v2210-nohandler` | 2.1.10 | `3177a37c` (see caveat) | none | raced | 0 |
| `runs/v2210-real-fixed` | 2.1.10 | `986917a8` (fixed) | configured | raced | 0 |

In the crashing run the server logs say
`background worker "pgactive apply worker" (PID ...) was terminated by
signal 11: Segmentation fault`, followed by `all server processes
terminated; reinitializing`. The worker restarts and crashes again on the
same conflict, six times over eight seconds before shutdown — the fault is
deterministic, not a one-off. Final table state diverged: node 1 holds
`1 | node1`, node 2 holds `1 | node2`, so neither remote insert was applied.
The no-conflict and no-handler controls show zero terminations, and the
no-handler conflicts converged to a single row, so the crash needs both a
configured handler and a conflict reaching it.

The genuine fixed control matters. An earlier "2.1.10" run crashed, but
investigation found a script bug: a lost variable block meant the library
swap never happened, so that run used the 2.1.9 shared object. The script
now records the installed library hash at startup (`/tmp/twonode-used-sha.txt`)
and after restore (`/tmp/twonode-restored-sha.txt`). `runs/v2210-real-fixed`
used `986917a8656c...2885a` (the 2.1.10 build) and produced **zero**
terminations on both nodes; the vulnerable 2.1.9 library `3177a37c...162998`
is restored after every run. Caveat: `runs/v2210-nohandler` predates the fix
and also used the 2.1.9 library, so it is a no-handler control only.

## Causal reading

The 2.1.9 source calls the resolver with `local_tuple` non-NULL for an
`insert_insert` conflict (`src/pgactive_apply.c` around :1605). With
`local != NULL`, pinned `pgactive_conflict_handlers.c:761` writes
`fcinfo.args[0].isnull = false` (zero) into what the shipped binary places
at the canary slot `rbp-0x38`; this host's canary low byte is `00`, so the
canary survives. `:777` writes the `insert_insert` enum OID through
`fcinfo.args[4].value` onto saved RBP at `rbp+0x00`; the saved return address
at `rbp+0x08` is not written. Returning through a corrupted frame pointer is
consistent with the observed SIGSEGV, and the fixed build's
`LOCAL_FCINFO(fcinfo, 5)` removes exactly those out-of-object writes.

The handler's return value is not the trigger: a run with the handler
returning `SKIP` instead of `ROW` still crashed on the vulnerable library
(`runs/v219-skip`, 1 termination each). The `local == NULL` variants
(`update_delete`, `delete_delete`) would instead write `01` into the canary
low byte and abort, but no such conflict has been triggered here.

Attribution gaps: no core dump was produced (`core_pattern` pipes to
apport, which did not retain one), so there is no live backtrace naming the
faulting frame; the overwritten words are fixed enum and pointer values,
not attacker-chosen bytes. The differential (vulnerable crashes, fixed
clean, no-handler clean, no-conflict clean) is the causal evidence; an ASan
live run is recorded separately if it succeeded.

## Rung status

A remote-triggered, deterministic crash of both real apply workers is now
observed, with the vulnerable/fixed differential isolating it to the 2.1.9
stack object. That is demonstrated denial of service in the lab build. It
is **not** rung 5: no command side effect, no saved instruction pointer, no
replication-wire byte control and only fixed-value writes. The CVE's parser
primitive remains separately established at rung 4 as labeled in the main
report. Change the conclusion if a fixed-library run ever crashes under the
same conflict, or if a live backtrace points elsewhere.

## Live ASan confirmation (2026-11-25 13:58Z)

`ASAN=1 sh run-two.sh` rebuilds the pinned 2.1.9 library with
`-fsanitize=address -fno-omit-frame-pointer`, starts both loopback clusters
with `LD_PRELOAD=libasan.so`, and races the inserts as before. Both apply
workers report, in `runs/v219-asan2/server{1,2}.log`:

```
ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 8 at ... thread T0
    #0 pgactive_conflict_handlers_resolve src/pgactive_conflict_handlers.c:759
    #1 check_apply_update src/pgactive_apply.c:1605
    #2 process_remote_insert src/pgactive_apply.c:788
    #3 pgactive_process_remote_action src/pgactive_apply.c:2420
    #4 pgactive_apply_work src/pgactive_apply.c:2815
    #5 pgactive_apply_main src/pgactive_apply.c:3071
SUMMARY: AddressSanitizer: stack-buffer-overflow src/pgactive_conflict_handlers.c:759
```

This is the out-of-object `fcinfo.args[0].value` store in a **live apply
worker on the real remote-change path**, not a standalone probe. It upgrades
the conflict-handler primitive from rung 3 in a probe to rung 3 confirmed in
a live process, and together with the vulnerable/fixed crash differential
it makes the remote-triggered denial of service causal. The library hash was
recorded before the run (`3177a37c...162998`) and restored afterwards.
No command execution or instruction-pointer control is demonstrated.

## Author clean-archive replay (2026-11-25 14:03Z)

`git archive HEAD lab/frontier/pgactive2shell/realbuild/twonode` extracted
to `/tmp/pgactive-two-clean` and `sh run-two.sh` there reproduced the
result from committed bytes only: both nodes ready, handler registered,
both inserts committed, `TERMINATIONS1=1 TERMINATIONS2=1` with signal 11
in each server log. The first attempt hit a stale cluster left on port
58432 by a harness-bug run; after stopping it the unchanged script
replayed cleanly. Exact statuses, hashes and log lines are in
`clean-archive-replay.txt`. This is an author replay, not an independent
witness verdict.

## local == NULL canary abort, live (2026-11-25 17:53Z)

`run-two.sh` gained `CONFLICT_TYPE` (default `insert_insert`). The
`delete_delete` arm seeds one row on node 1, waits for `SEED_ON_NODE2=1`,
then races DELETEs on both nodes. The handler is registered as
`delete_delete` and returns `SKIP` (the caller rejects a returned row for
this conflict type).

This exercises the second caller family, `pgactive_apply.c:1185`
(`UpdateDelete`) / `:1405` (`DeleteDelete`), which passes `local = NULL`.
The pinned disassembly says `fcinfo.args[0].isnull = true` becomes `01` in
the canary low byte at `rbp-0x38`; this host's canary low byte is `00`, so
the check fails at return.

| Run | Library sha256 prefix | Conflict | Handler | Terminations |
| --- | --- | --- | --- | --- |
| `runs/v219-deletedel` | `3177a37c` (vulnerable) | seed + raced DELETE | `delete_delete`, SKIP | 1 each, signal 6 |
| `runs/v2210-deletedel` | `986917a8` (fixed) | seed + raced DELETE | `delete_delete`, SKIP | 0 |

The vulnerable logs contain `*** stack smashing detected ***: terminated`
and `background worker "pgactive apply worker" ... was terminated by
signal 6: Aborted`; the fixed logs have no such line. Contrast with the
`insert_insert` arm above: `local != NULL` writes `00` into the canary so
it survives, and the corrupted saved RBP produces signal 11 instead. Both
outcomes come from the same out-of-object `fcinfo.args[0].isnull` store;
the observed signal is a function of the canary byte, as predicted.

This closes the "no `local == NULL` conflict has run" gap in the earlier
causal reading. It does not add attacker byte control: the stored value is
the fixed boolean `true`. The vulnerable library is restored after both
runs (verified `3177a37c...162998`), both clusters are stopped by the
script and no process remains on ports 58431/58432. Rung ceiling unchanged.
