# Frontier brief — pgactive2shell (CVE-2026-134068)

Status 2026-11-25 02:21Z: witness #3896 ESTABLISHED AS LABELED the original
pinned-function harness; all SQL-path and full-extension evidence below is
author-run and unreplayed by an independent witness. This is a research
artifact, not independent acceptance.
Screened against `reports/frontier-*.md`, the wall's do-not-duplicate list
and the site's target charters before provisioning: `postgres2shell` owns
core PostgreSQL FDW batch-overcount (CVE-2026-120149), not this separate AWS
extension; `pgactive` had no prior report, chart or lab lane.

## Ground truth (claim, not verified remotely)

- CVE-2026-134068, CWE-787 (stack-based buffer overflow), CNA Amazon,
  published 2026-11-24. AWS bulletin 2026-198-AWS and GHSA-5369-r3fj-cggr.
- Claim: an authenticated database user with specific privileges might
  execute arbitrary OS commands as the database OS user via a crafted
  replication origin name. CVSS 4.0 7.7, `AV:N/AC:H/PR:L`.
- Affected: pgactive >= 2.1.0 and < 2.1.10. Fixed: 2.1.10.
- Fix: `aws/pgactive` tags `v2.1.9`
  (`f34c8aa6f9f5c4ad5ee4bfdf93fef4b000be8f9e`) and `v2.1.10`
  (`c3829ddb81c8c8e927b6e5a0baba3b1a016fcb52`); the security hunk is in
  `src/pgactive_catalogs.c`. Both fresh-install SQL scripts already contain
  `REVOKE ALL ON FUNCTION pgactive_parse_replident_name(text) FROM public`
  (observed locally in both pinned tarballs), so that revoke is not itself
  the 2.1.10 difference.
  Workarounds in the bulletin include keeping
  `pgactive.pgactive_conflict_handlers` empty and using only pgactive-generated
  replication slot/origin names. All sources read-only; no external system probed.

## Source-bound mechanism

`pgactive_parse_replident_name()` (pinned vulnerable
`src/pgactive_catalogs.c:347-358`) declares a stack `NameData replication_name`
(`char data[64]`, NAMEDATALEN 64) and calls:

```c
sscanf(riname, pgactive_REPORIGIN_ID_FORMAT,
       &node->sysid, &node->timeline, &node->dboid, local_dboid,
       NameStr(replication_name))
```

The pinned format (`include/pgactive_internal.h:31`) ends in an **unbounded
`%s`**. A replication origin name longer than 63 bytes writes attacker-chosen
bytes past the 64-byte stack object before the return-value check runs. The
check is `!= 4`, i.e. it expects the trailing `%s` *not* to match; the write
has already happened by then.

The v2.1.10 fix (pinned `catalogs-v2.1.10.c:347-357`,
`internal-v2.1.10.h:38`) replaces `%s` with `%n` into `parsed_len`, then
rejects when `parsed_len < 0 || riname[parsed_len] != '\0'`. The same pattern
is fixed in `pgactive_parse_slot_name()` in the same diff.

## Local experiment and observed bytes

`lab/frontier/pgactive2shell/` pins both full release archives, both
`pgactive_catalogs.c` copies and both `pgactive_internal.h` headers with
SHA-256 (`pins.sha256`). `generated/functions_vuln.c` and
`generated/functions_fixed.c` extract the whole function verbatim from the
pinned sources; only the surrounding types and the `elog` counter are
stand-ins reproducing pinned layouts. The harness supplies a wire-shaped
name `pgactive_1_1_1_1_` followed by 96 chosen bytes `48 5a 4d 49` repeating;
a safe input has no trailing name.

- Vulnerable ASan build: `stack-buffer-overflow`, `WRITE of size 97`, address
  at offset 96 in frame, `[32, 96) 'replication_name' ... overflows this
  variable`, frame `pgactive_parse_replident_name
  generated/functions_vuln.c:20`; rc 1. `harness/evidence/asan-vuln-attack.out`.
- Vulnerable plain build: stand-in `elog` captures bytes inside the live
  function before return: `CAPTURE-IN`, `CAPTURE-CANARY64` (offset 64, 0
  bytes past the 64-byte object) and `CAPTURE-MARKTAIL` (offset 92) all
  `485a4d49`; the process then aborts with `*** stack smashing detected ***`.
  `harness/evidence/plain-vuln-attack.out`.
- Fixed ASan and plain builds are clean on the same attack; fixed plain
  reports `RET=-1` and `CAPTURE=NONE`. Safe input is accepted (`RET=0`).
- `sh harness/run.sh`: 19 PASS / 0 FAIL, rc 0.

## Real PostgreSQL SQL path (2026-11-24 23:03Z)

`lab/frontier/pgactive2shell/sqlpath/` compiles the verbatim pinned parser
bodies and the pinned SQL wrapper into two small C extensions against real
PostgreSQL 16.15 server headers, registers the pinned SQL signature in a
loopback-only cluster (`initdb` from public Ubuntu packages extracted into
`/tmp`, no system-wide install, sockets and ports inside the lab), and calls
`pgactive_parse_replident_name(text)` with
`pgactive_123_1_2_3_` + 80 `AZ` bytes:

- Plain backend: safe name returns a row; vulnerable attack reaches the
  parser and reports `ERROR: could not parse slot name: ...` without a
  crash. `elog(ERROR)` longjmps before the stack canary is checked, so the
  plain call is not a crash detector. Fixed library rejects the same name
  with `ERROR: could not parse replication origin name: ...`.
  `sqlpath/evidence/vuln-*.out`, `fixed-*.out`.
- ASan-preloaded backend: vulnerable attack faults the live backend;
  `sqlpath/evidence/asan-server.log` reports `ERROR: AddressSanitizer:
  stack-buffer-overflow`, `WRITE of size 161`, frame
  `pgactive_parse_replident_name ... parser.c:62`, called from
  `pgactive_parse_replident_name_sql ... parser.c:91`, and
  `[32, 96) 'replication_name' ... Memory access at offset 96 overflows this
  variable`. Postmaster log names the exact SQL statement. Fixed control
  runs in a restarted cluster, returns `ASAN_FIXED_SETUP=0`,
  `ASAN_FIXED_SAFE=0`, SQL rejection with rc 1, and `FIXED_SERVER_CLEAN`.
  `sqlpath/evidence/asan-*.out`, `asan-fixed-server.log`.
- Live-backend chosen-byte capture (2026-11-25 00:26Z): `run-gdb.sh` tried
  attaching gdb to the live backend at the `elog(ERROR)` line, but
  `/proc/sys/kernel/yama/ptrace_scope = 1` denies attach; that negative result
  is preserved in `sqlpath/evidence/gdb-live-capture.out` and the host guard
  was not changed. `sh run-live-capture.sh` instead builds a separate
  `LIVE_CAPTURE` extension whose only addition to the verbatim v2.1.9 body
  is a `memcpy` of 128 bytes from `&replication_name` inside the existing
  error branch, before the longjmp. In one backend session (reset, attack,
  read) `sqlpath/evidence/live-attack.out` returns 256 hex chars = 128 bytes,
  all alternating `41 5a` (`AZ` repeating, chosen by the SQL input). Offsets
  0, 64, 92 and 96 decode to `41`, `41`, `41`, `41`; offsets 65, 93, 97 to
  `5a`. The safe-name control produces no capture (empty bytea), and the
  attack still reports `ERROR: could not parse slot name: ...`. This is an
  in-function marker observed in a live process, not a control of a saved
  pointer/return address and not rung 5.
- Scaffolding lane: the above `sqlpath/` lane is not a full pgactive build or
  wire path; the extension contains only the parser and its pinned SQL
  wrapper. Provisioning steps and false negatives are recorded in
  `sqlpath/PROVISION.md`.

## Full pinned extension, real SQL path (2026-11-25 02:21Z)

`lab/frontier/pgactive2shell/realbuild/` builds the complete pinned 2.1.9
release against the extracted PostgreSQL 16.15 tree, loads it into a
loopback-only cluster with `shared_preload_libraries=pgactive` (plus
`track_commit_timestamp=on` and `wal_level=logical`, required by `_PG_init`),
and calls the real `pgactive.pgactive_parse_replident_name(text)` function.
The pinned 2.1.10 library is the control; build flags, extra public packages
and a known 2.1.10 `pg_dump` header incompatibility are recorded in
`realbuild/PROVISION.md`.

- 2.1.9: safe name returns the parsed row; the 80-`AZ` attack reaches the real
  function and reports `ERROR: could not parse slot name: ...` with no backend
  termination (the `elog(ERROR)` longjmp skips the stack-canary check).
  `realbuild/evidence/vuln-*.out`.
- 2.1.10: same safe row, attack rejected with
  `ERROR: could not parse replication origin name: ...`.
  `realbuild/evidence/fixed-*.out`.
- Function ACL is `{"\"mesh-home\"=X/\"mesh-home\""}` in both fresh installs:
  no PUBLIC EXECUTE in either version. The advisory's authenticated `PR:L`
  precondition remains part of the claim; this lane has not demonstrated a
  lower-privilege caller reaching the parser.
- With the ASan-instrumented full 2.1.9 library and libasan preloaded into the
  postmaster, the real SQL call reports `AddressSanitizer: stack-buffer-overflow`,
  `WRITE of size 161` at offset 96 of `[32, 96) 'replication_name' (line 349)`,
  frames `pgactive_parse_replident_name src/pgactive_catalogs.c:351` and
  `pgactive_parse_replident_name_sql src/pgactive.c:1531`. The postmaster log
  names the exact statement; the normal library was restored after the run.
  `realbuild/evidence/real-asan-server.log`, `real-asan-attack.out`.
- Clean-archive receipt: `git archive 20123ce2 lab/frontier/pgactive2shell/realbuild
  | tar x -C /tmp/pgactive-real-clean` followed by `sh run-real.sh`,
  `VERSION=2.1.10 LABEL=fixed sh run-real.sh` and `sh run-real-asan.sh`
  reproduced all three lanes: `vuln_SAFE=0`, `vuln_ATTACK_RC=1`,
  `fixed_SAFE=0`, `fixed_ATTACK_RC=1`, `ASAN_ATTACK_RC=2`, `PGSTOP=0`,
  `ASAN_STOP=0`, and the same `WRITE of size 161` frames. Author replay,
  not an independent witness verdict.


## Saved-return-address layout (negative, 2026-11-25 03:09Z)

`realbuild/layout/` instruments the complete pinned 2.1.9 library without
ASan to emit the parser's stack window after the overflow, at payload lengths
0..256. PGXS-default build measurements put the first matching copy of the
caller return-address value below the buffer (offset -32); a later
machine-code check corrected that identification: `replication_name` is at
`rbp-0x70`, the stack canary at `rbp-0x28` (offset +72) and the function's
saved return address at `rbp+8` (offset +120). Long payloads overwrite
the +120 slot and the canary, but every overflowing input exits via
`elog(ERROR)` longjmp, so neither word is consumed. No backend terminated
at any length. Exact offsets, commands, logs and the 2026-11-25 06:15Z
disassembly correction are in `realbuild/layout/FINDINGS.md` and
`realbuild/layout/evidence/disassembly-correction.txt`. This closes the
saved-pointer/return-address route toward a stronger rung 4 on this host;
it does not alter the earlier marker-based rung-4 evidence.

A 2026-11-25 08:06Z binary-only check extends this to the shipped,
non-instrumented 2.1.9 library: the parser is inlined into
`pgactive_parse_replident_name_sql` at 0x16290 with the same frame
(buffer `rbp-0x70`, canary +72, saved RA +120), and the error path passes
`riname` in a register rather than from an overwritten spill slot. A
glibc 2.39 probe with the pinned five-conversion format returns 4 with the
`%s` destination untouched and 5 for any non-empty tail, so the pinned
`!= 4` check cannot be passed with an overflowing store. Full addresses
and probe output:
`realbuild/layout/evidence/production-frame-check.txt`. The rung ceiling
is unchanged; this closes the saved-pointer route in the production build
as well as the instrumented one.

## Catalog-derived origin-name reachability (2026-11-25 03:34Z)

`pgactive_parse_replident_name()` also has an internal caller: pinned
`pgactive_catalogs.c:321` passes a name obtained from
`replorigin_by_oid()` in `pgactive_fetch_sysid_via_node_id_ifexists()`.
`realbuild/originpath/` tests the name-length preconditions on a loopback
PostgreSQL 16.15 cluster with the full pinned 2.1.9 library loaded:

- `pg_replication_origin_create()` accepted names of 66, 67, 99 and 275
  bytes; the catalog stored all of them. A catalog-derived origin name can
  therefore be long enough to overflow the parser's 64-byte `NameData`.
  No wire trigger was exercised.
- `pg_create_logical_replication_slot()` truncated a 96-byte requested
  name to 63 bytes in `pg_replication_slots`, so the output-plugin slot-name
  caller at `pgactive_output.c:382` cannot receive an overlong name through
  this route on this build.
- A plain `LOGIN` role can neither create replication origins nor call the
  parser: both are owner-only (`proacl`) and non-`SECURITY DEFINER`. The
  global-lock functions that reach the parser internally are also revoked
  from PUBLIC in the pinned install script. No lower-privilege route was
  demonstrated, consistent with the advisory's `PR:L` plus specific
  privileges.
- Driving the catalog-derived route through
  `pgactive_get_global_locks_info()` was attempted and failed: a single-node
  group stayed in state `b`, and lock acquisition reported "database ... is
  not configured for pgactive or pgactive is still starting up". On
  2026-11-25 21:53Z the same call sequence was retried in the ready two-node
  group at 21:53Z: both nodes reached `r`, a 99-byte origin and session setup
  succeeded, but the diagnostic returned `owner_replorigin` NULL with
  `lock_mode=nolock`, no parse error and no termination, so the crafted name
  never reached the parser. That global-lock route stays UNKNOWN. A *different*
  catalog-derived route was established later that evening through conflict
  logging in a live apply worker; see the 2026-11-25 22:23Z section below.

Exact commands, rc values and preserved negatives are in
`realbuild/originpath/FINDINGS.md` and `realbuild/originpath/evidence/`.

### Parser caller map (2026-11-25 04:53Z)

A source-only sweep of the pinned 2.1.9 tree enumerated every caller of
`pgactive_fetch_sysid_via_node_id*` and
`pgactive_parse_replident_name()` (`realbuild/originpath/CALLERS.md`).
All call sites except the two SQL entry points run in background workers or
internal lock handlers: apply-worker conflict logging
(`pgactive_conflict_logging.c:688,716`), the logical output plugin's BEGIN
callback (`pgactive_output.c:805`), and six lock paths in
`pgactive_locks.c`. The two SQL entry points are
`pgactive_parse_replident_name(text)` and
`pgactive_get_global_locks_info()`; the fresh-install script revokes
EXECUTE on both from PUBLIC (`pgactive--2.1.9.sql:2578,1848`), and the
`pgactive_global_locks_info` view over the latter has no `GRANT SELECT`
(`pgactive--2.1.9.sql:1853-1863`). No plain role reaches either without an
explicit grant. This bounds, but does not close, the catalog-derived route:
an overlong name still has to enter `pg_replication_origin`, and the
single-node group never became ready (`FINDINGS.md`). No new trigger, no
change to the rung ceiling.

## Rung-4 feasibility and ceiling

Rungs 1 (deterministic trigger), 2 (unbounded `%s` into a fixed stack object)
and 3 (ASan-confirmed corruption) are established on the verbatim pinned
function, in the standalone harness and inside a live PostgreSQL backend
reached by SQL. Rung 4 is now MET AS LABELED in two places:
chosen offsets 0, 64 and 92 in the standalone harness, and 128 consecutive
chosen `41/5a` bytes read from the live backend stack at offsets 0..127 via
the `LIVE_CAPTURE` marker before the error longjmp. From 2026-11-26 there is a
third, stronger observation in a live apply worker: a 616-byte crafted origin
name puts chosen `41 5a` bytes into the `callback`, `arg` and `previous` words
of the live `ErrorContextCallback`, and the error path dereferences the
corrupted callback (signal 11). It is still a chosen *invalid* address, not a
chosen command. The two marker sites remain instrumentation; the ASan build
confirms the same write independently, now also in the complete pinned 2.1.9
extension via the real SQL function and, from 22:23Z on 2026-11-25, in a live
apply worker driven by a remote insert (see below). Not established: arbitrary
bytes carried on the replication wire, control of a saved pointer/return
address (the saved RA at 120 is overwritten but the pinned `!= 4` check sends
every overflowing input through the error longjmp), a chosen IP or command, a
command side effect, or rung 5. The advisory's command-execution claim remains
a claim. The authenticated `PR:L` precondition and the need for a writable
replication-origin name are part of it, not hidden. The original pinned
harness was independently replayed by witness #3896; the SQL-path,
live-capture, full-extension and catalog-arm evidence has not been
independently replayed.


## Cheapest next experiment

The saved-pointer route in the real extension is measured and closed: the
return-address slot at +120 is overwritten, but the pinned five-conversion
format makes every matching `%s` input fail the `!= 4` check, so the error
longjmp abandons it and the canary at +72 is never checked. The live apply-worker
route below supplies the missing consumer and a remote trigger, but its
crafted name still comes from local catalog state and still leaves through
the same longjmp. Witness replay of the commit containing
`realbuild/` should run
`sh run-real.sh`, `VERSION=2.1.10 LABEL=fixed sh run-real.sh` and
`sh run-real-asan.sh` with the provisioning in `realbuild/PROVISION.md`;
SQL-path, live-capture, full-extension and layout evidence stays unreplayed
until that happens.

## Clean-archive replay and generated-name bound (2026-11-25 08:59Z)

The saved-pointer negative was replayed from committed bytes:
`git archive b620fc1a lab/frontier/pgactive2shell/realbuild/layout |
tar x -C /tmp/pgactive-layout-clean`, then `LABEL=opt sh run-layout.sh`
against the normal 2.1.9 library (sha256 `3177a37c...162998` checked before
the run). All 15 payload lengths returned RC=1 with `LIVENESS_RC=0`,
`BACKEND_TERMINATIONS=0` and both source and library restored. At N=256 the
canary slot (+72) and saved RA slot (+120) again hold chosen `41 5a` bytes,
and the backend stays alive. The closure is not a working-tree artifact;
details in `realbuild/layout/evidence/clean-archive-replay.txt`. Author
replay, not an independent witness verdict.

Source-only bound on the wire path: the pinned builders
`pgactive_replident_name()` (`src/pgactive_catalogs.c:386-398`) and
`pgactive_slot_name()` (`src/pgactive_common.c:40-45`) both pass
`EMPTY_REPLICATION_NAME` as the trailing `%s` argument, so names generated
by the extension have an empty tail and cannot overflow. The vulnerable
caller `pgactive_fetch_sysid_via_node_id_ifexists()`
(`src/pgactive_catalogs.c:303-333`) reads its name from
`replorigin_by_oid()`; a hand-crafted name must already be in the catalog,
matching the advisory's "use only pgactive-generated names" workaround.
This narrows the trigger without supplying one. Rung ceiling unchanged.

## Separate conflict-handler stack object (2026-11-25 09:05Z)

Checking the advisory's second workaround ("keep
`pgactive.pgactive_conflict_handlers` empty") against the pinned diff found
a **separate** stack-object defect in the same releases, not the `%s`
parser bug. Pinned 2.1.9 `src/pgactive_conflict_handlers.c:716` declares
`FunctionCallInfoBaseData fcinfo;` with no `args[]` storage and `:751-791`
writes five 16-byte `NullableDatum` slots through it; 2.1.10 uses
`LOCAL_FCINFO(fcinfo, 5)`. A standalone probe built with real PostgreSQL
16.15 server headers (`realbuild/conflictpath/fcinfo-probe.c`) measures
`sizeof(FunctionCallInfoBaseData)=32`, `offsetof(args)=32` and ASan reports
`WRITE of size 8` one byte past the 32-byte object
(`realbuild/conflictpath/evidence/asan-fcinfo-probe.out`).

Disassembly of the shipped 2.1.9 library (sha256 `3177a37c...162998`)
places `fcinfo` at `rbp-0x60`: `args[0].isnull` lands on the stack canary
at `rbp-0x38` and `args[4].value` on saved RBP at `rbp+0x00`; the saved
return address at `rbp+0x08` is not written. This host's canary low byte is
`00`, so a `local == NULL` conflict writes `01` there and the canary check
fails, while a `local != NULL` conflict preserves the canary but returns
with a corrupted frame pointer. Both outcomes are inferred from the binary
and the canary probe, not observed in a live conflict.

All three callers are in the apply worker (`src/pgactive_apply.c:1185`,
`:1405`, `:1605`), which needs a configured conflict handler and a remote
conflict; no live trigger was exercised. This is rung 3 in a standalone
probe only: no chosen bytes in a live process, no pointer/IP control, no
command side effect and no change to the rung ceiling. Details and limits
in `realbuild/conflictpath/FINDINGS.md`.

## Live two-node conflict: apply-worker crash and ASan write (2026-11-25 13:58Z)

The preceding paragraph is superseded by a real replication experiment.
`realbuild/twonode/run-two.sh` builds two loopback PostgreSQL 16.15
clusters (ports 58431/58432) with the full pinned 2.1.9 extension, joins
them into a pgactive group, configures an `insert_insert` conflict handler
and races the same primary key on both nodes. Each node's apply worker
then dies with `signal 11: Segmentation fault`, repeatedly, and the two
tables diverge. With no handler, or with a handler but no conflicting
second insert, neither worker dies. A genuine 2.1.10 shared-library run
(sha256 `986917a8...2885a`, control SQL at 2.1.10, same handler, same race)
has **zero** terminations. An earlier apparent 2.1.10 crash was a harness
bug: a lost variable block left the 2.1.9 library installed; the script now
records the used and restored library hashes on every run.

An ASan build of the same pinned 2.1.9 library, preloaded into both live
postmasters, reports `stack-buffer-overflow` and `WRITE of size 8` in
`pgactive_conflict_handlers_resolve src/pgactive_conflict_handlers.c:759`,
called from `check_apply_update src/pgactive_apply.c:1605` and
`process_remote_insert src/pgactive_apply.c:788` — the real remote-change
path, not a probe. This is confirmed memory corruption (rung 3) in a live
process plus a deterministic remote-triggered denial of service with a
vulnerable/fixed differential. It is not rung 5: the overwritten words are
the fixed enum OID and pointer values, no command side effect and no
saved instruction pointer. The CVE's `%s` parser primitive retains its
separate rung-4-as-labeled status. Recipe, controls, binaries, hashes and
limits are in `realbuild/twonode/FINDINGS.md` and `runs/`. An author
clean-archive replay of commit `52473a73` reproduced both signal-11
terminations (`realbuild/twonode/clean-archive-replay.txt`); an independent
witness verdict is still owed.

## local == NULL conflict: canary abort confirmed live (2026-11-25 17:53Z)

The disassembly model in `realbuild/conflictpath/FINDINGS.md` predicted a
second, distinct live outcome for the two resolver callers that pass
`local == NULL` (`pgactive_apply.c:1185` `UpdateDelete` and `:1405`
`DeleteDelete`): `fcinfo.args[0].isnull = true` writes `01` into the canary
low byte on this host, so the return-time check aborts, whereas the
`insert_insert` caller writes `00` there and dies later with a corrupted
saved RBP. `run-two.sh` now takes `CONFLICT_TYPE` (default
`insert_insert`) and a `delete_delete` arm that seeds one row on node 1,
waits for it on node 2, then races DELETEs on both.

With the pinned 2.1.9 library (sha256 `3177a37c...162998`) and a
`delete_delete` handler returning `SKIP`, both apply workers log
`*** stack smashing detected ***: terminated` and
`was terminated by signal 6: Aborted`; `TERMINATIONS1=1`,
`TERMINATIONS2=1`. The genuine 2.1.10 library (sha256 `986917a8...2885a`,
same handler and conflict) has `TERMINATIONS1=0`, `TERMINATIONS2=0`.
The vulnerable library is restored after each run. This is a live
confirmation of the source/disassembly reading and a second remote-triggered
DoS differential, not a new primitive: the overwritten word is still the
fixed canary byte, no chosen bytes, no saved IP and no command side effect.
Rung ceiling unchanged. Evidence: `realbuild/twonode/runs/v219-deletedel/`
and `runs/v2210-deletedel/`.

## Catalog-derived parser in a live apply worker (2026-11-25 22:23Z)

The catalog route is no longer just a precondition. `run-two.sh` gained a
default-off `ORIGIN_TUPLE=1` arm: node 2 delays apply by 5 s, a privileged
session there creates a 275-byte origin named
`pgactive_1_1_1_1_` + 130 `AZ` pairs and inserts the conflicting row under it,
then node 1's earlier insert is replayed. Last-update-wins sets `log_update`,
so `pgactive_make_apply_conflict()` asks the parser about the local tuple's
origin id (`pgactive_apply.c:782,798` →
`pgactive_conflict_logging.c:716` → `pgactive_catalogs.c:321,351`). No conflict
handler is configured, so the separate `fcinfo` defect cannot fire first.

- Vulnerable 2.1.9, plain: `evidence/server2.log` reports
  `could not parse slot name: pgactive_1_1_1_1_AZ...`; no termination, because
  `elog(ERROR)` longjmps. Library sha256 `3177a37c...162998`.
- Vulnerable 2.1.9, ASan-preloaded postmasters: two node-2 reports,
  `stack-buffer-overflow`, `WRITE of size 261` at offset 96 of
  `[32, 96) 'replication_name' (line 349)`, frame
  `pgactive_parse_replident_name src/pgactive_catalogs.c:351`, called from
  `pgactive_fetch_sysid_via_node_id_ifexists` (`:321`),
  `pgactive_fetch_sysid_via_node_id` (`:338`),
  `pgactive_make_apply_conflict src/pgactive_conflict_logging.c:716`,
  `process_remote_insert src/pgactive_apply.c:798` and
  `pgactive_apply_main src/pgactive_apply.c:3071`. ASan library sha256
  `56550571...d29e`.
- Fixed 2.1.10 control (sha256 `986917a8...2885a`): same setup and remote
  insert, no ASan, no termination, and node 2 reports
  `could not parse replication origin name: ...`.

This is rung 3 confirmed in a live apply worker with a remotely triggered
change and a vulnerable/fixed differential, and it supplies the live consumer
missing from the earlier catalog work. It is not rung 5: the crafted name is
local catalog state, not bytes carried on the wire; creation of that row is
owner-only here; and the pinned `!= 4` check still sends every overflowing
input through the error longjmp, so the saved RA and canary are never
consumed. A first attempt that renamed the worker's own origin row poisoned
slot-name generation and caused a restart loop; it is preserved as a negative
in the same findings. Full commands, hashes, logs and limits:
`realbuild/twonode/originwire/FINDINGS.md`. Author observation, not an
independent witness verdict.

### Wire-name bound and replay receipt (2026-11-26 00:55Z)

Source check on pinned 2.1.9: both connection setup
(`pgactive.c:798` → `pgactive_create_slot()` at `:536`) and catchup mode
(`pgactive_apply.c:370`) derive the replication-origin name from numeric
`sysid`, `timeline` and `dboid` through `pgactive_replident_name()`
(`pgactive_catalogs.c:386-395`), which appends the empty
`EMPTY_REPLICATION_NAME`. The SQL formatter rejects a non-empty
`replication_name` (`pgactive.c:1581`). Generated names therefore cannot
carry the 275-byte payload: the long name in this arm is privileged local
catalog state. This bounds the generated-name route; other consumers of
catalog-derived names remain open.

The catalog arm now has a one-command clean-archive replay:
`sh lab/frontier/pgactive2shell/realbuild/twonode/witness-replay-originwire.sh`
(commit `99adbb67`). It restores the normal 2.1.9 library on exit and prints
`VERDICT=PASS` only if all three arms produce their expected library hash,
markers, parser message/report and termination counts. Author smoke at
00:59Z: `VERDICT=PASS FAILURES=0 LEFTOVER_POSTMASTERS=0`, all arms `RC=0`
and `LIB_OK=1`. The first smoke at 00:54Z failed two wrapper assertions
(ASan used-hash timing and an ASan-arm node-2 recovery-mode stop); both the
failure and its fix are preserved in `originwire/FINDINGS.md`. This is an
author smoke, not an independent witness verdict; replay offered as #4657.

## Consumed chosen callback pointer in the live apply worker (2026-11-26 03:15Z)

The saved return address is not the only consumed word on the error path.
`process_remote_insert()` pushes a live `ErrorContextCallback` on
`error_context_stack` before conflict logging (`pgactive_apply.c:631-643`), so
`errstart()` dereferences its `callback` word on the way to the longjmp. A
lab-only noinline probe in `pgactive_parse_replident_name()` measured that
struct at `&replication_name + 464` (with `callback`, `arg`, `previous` at
+464/+472/+480). The original 275-byte catalog name writes 261 bytes and
stops short: a negative. But `pg_replication_origin.roname` is `text` on
PG16.15, and `pg_replication_origin_create()` accepted a 616-byte name; the
new `ORIGIN_PAYLOAD_LEN` knob in `run-two.sh` drives that arm. With 600 `AZ`
pairs, the probe printed
`CBREACH buf=0x7ffc183fbee0 cb=0x7ffc183fc0b0 delta=464
fn=0x5a415a415a415a41 arg=0x5a415a415a415a41 prev=0x5a415a415a415a41`
and node 2's apply worker was then `terminated by signal 11`
(`TERMINATIONS1=0 TERMINATIONS2=1`); the normal library was restored to
`3177a37c...162998`. This is chosen bytes at chosen offsets in a pointer that
the live error path actually consumes — stronger than the earlier
in-function marker, but still not rung 5: the target is an invalid chosen
address, there is no chosen command or command side effect, and ASLR moved
`action_error_callback` between runs. A marker-placement attempt is preserved
as a negative in `callbackreach/FINDINGS.md`. Author observation, not an
independent witness verdict. One-command replay:
`sh lab/frontier/pgactive2shell/realbuild/twonode/witness-replay-callbackreach.sh`.
