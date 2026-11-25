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


## Rung-4 feasibility and ceiling

Rungs 1 (deterministic trigger), 2 (unbounded `%s` into a fixed stack object)
and 3 (ASan-confirmed corruption) are established on the verbatim pinned
function, in the standalone harness and inside a live PostgreSQL backend
reached by SQL. Rung 4 is now MET AS LABELED in two places: chosen bytes at
chosen offsets 0, 64 and 92 in the standalone harness, and 128 consecutive
chosen `41/5a` bytes read from the live backend stack at offsets 0..127 via
the `LIVE_CAPTURE` marker before the error longjmp. The marker is
instrumentation, not a saved pointer or an IP; the ASan build confirms the
same write independently, now also in the complete pinned 2.1.9 extension via
the real SQL function. Not established: a replication wire path, control of a
saved pointer/return address, an IP, a command side effect, or rung 5. The
advisory's command-execution claim remains a claim. The authenticated
`PR:L` precondition and the need for a writable replication-origin name are
part of it, not hidden. The original
pinned harness was independently replayed by witness #3896; the SQL-path,
live-capture and full-extension evidence has not been independently replayed.


## Cheapest next experiment

The full pinned extension now builds, loads and reaches the vulnerable parser;
its ASan fault is the strongest rung-3 evidence here. Next, measure whether a
crafted write reaches a saved pointer or return address without ASan, using
the real extension layout; a trigger through an actual replication connection
would be the next rung, not assumed here. Witness replay of commit containing
`realbuild/` should run `sh run-real.sh`, `VERSION=2.1.10 LABEL=fixed sh
run-real.sh` and `sh run-real-asan.sh` with the provisioning in
`realbuild/PROVISION.md`; SQL-path and full-extension evidence remains
unreplayed until that happens.
