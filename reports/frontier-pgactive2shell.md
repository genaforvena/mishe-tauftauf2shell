# Frontier brief — pgactive2shell (CVE-2026-134068)

Status 2026-11-24 21:4xZ: STAGED and handed off, witness UNKNOWN, operator
admission pending. This is a research artifact, not independent acceptance.
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
  `src/pgactive_catalogs.c`, with `REVOKE ALL ON FUNCTION
  pgactive_parse_replident_name(text) FROM PUBLIC` in the SQL migration.
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
rejects when `parsed_len < 0 || riname[parsed_len] != '\0'`. Companion SQL
revokes PUBLIC EXECUTE on the parser. The same pattern is fixed in
`pgactive_parse_slot_name()` in the same diff.

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

## Rung-4 feasibility and ceiling

Rungs 1 (deterministic trigger), 2 (unbounded `%s` into a fixed stack object)
and 3 (ASan-confirmed corruption) are established on the verbatim pinned
function. Rung 4 is PARTIAL: chosen bytes observed at chosen offsets 0, 64
and 92 inside the live stack object, plus a stack-smashing abort in the lab
build. Not established: a built PostgreSQL + pgactive instance, a SQL or
replication wire path, control of a saved pointer/return address, an IP, a
command side effect, or rung 5. The advisory's command-execution claim
remains a claim. The authenticated `PR:L` precondition and the need for a
writable replication-origin name are part of the claim, not hidden. No real
database process was started; witness replay UNKNOWN.

## Cheapest next experiment

Build pinned pgactive 2.1.9 against the host's PostgreSQL 16 development
headers, load it into a loopback-only cluster, and call the exposed
`pgactive_parse_replident_name(text)` SQL function with an overlong name.
Observe whether the real build corrupts the stack and whether a crafted name
can reach a return address or adjacent pointer under ASan; keep 2.1.10 and
safe-name controls. A successful wire-level trigger through an actual
replication connection would be the next rung, not assumed here.
