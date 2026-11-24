# pgactive2shell — status

Admitted 2026-11-24 22:2xZ under standing approval #6 as the 137th engine
route. Claim: `CVE-2026-134068` (CNA Amazon / AWS bulletin 2026-198-AWS /
GHSA-5369-r3fj-cggr, 2026-11-24, CWE-787, CVSS4 7.7
`AV:N/AC:H/PR:L`). An authenticated database user with specific privileges
may execute OS commands as the database OS user through a crafted
replication origin name. Affected pgactive >=2.1.0 and <2.1.10; fixed
2.1.10 (`c3829ddb81c8c8e927b6e5a0baba3b1a016fcb52`); vulnerable tag
v2.1.9 (`f34c8aa6f9f5c4ad5ee4bfdf93fef4b000be8f9e`). The fix changes the
unbounded `%s` to `%n` plus `riname[parsed_len] != '\0'` in
`pgactive_parse_replident_name()` and companion slot parser, and revokes
PUBLIC EXECUTE on the parser. The command-execution consequence is a claim;
no external system was probed and `PR:L` is part of the claim.

## Admission evidence

- Frontier brief `reports/frontier-pgactive2shell.md` (W216); pinned full
  release archives, both `pgactive_catalogs.c` copies, both
  `pgactive_internal.h` headers, generated functions and harness sources
  with SHA-256 in `lab/frontier/pgactive2shell/pins.sha256` and
  `PROVENANCE.md`.
- Source-bound mechanism: vulnerable
  `pgactive_parse_replident_name()` (`catalogs-v2.1.9.c:341-358`) declares a
  stack `NameData replication_name` (`char data[64]`) and passes it as the
  final unbounded `%s` argument of `sscanf()` using the format from
  `internal-v2.1.9.h:31`. A name longer than 63 bytes writes attacker-chosen
  bytes past the 64-byte stack object before the `!= 4` return check runs.
  The v2.1.10 fix (`catalogs-v2.1.10.c:341-357`) bounds the write and
  rejects a trailing byte.
- Operator verification 22:2xZ: `cd lab/frontier/pgactive2shell &&
  sh harness/run.sh` gave **19 PASS / 0 FAIL, rc 0**. All 13 pins are exact;
  the generated vulnerable/fixed functions are extracted verbatim, with only
  the surrounding PG types and the `elog` counter as stand-ins reproducing
  pinned layouts. Vulnerable ASan reports `stack-buffer-overflow`,
  `WRITE of size 97`, address at offset 96 in frame and
  `[32, 96) 'replication_name' ... overflows this variable` at
  `generated/functions_vuln.c:20`. Plain vulnerable runs read chosen
  `48 5a 4d 49` at offsets 0, 64 and 92 inside the live function, then
  abort with `*** stack smashing detected ***`. Fixed ASan/plain are clean,
  fixed plain returns `RET=-1` with `CAPTURE=NONE`; the safe name returns
  `RET=0`.
- Frontier's live two-pane window 145 (`pgactive2shell`) and seed wall were
  adopted without duplication. Charter written; hy4-flash route 136→137,
  both resolver keys 274→276, wake units from the EXACT full-flag sync at
  pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
  daemon-reload, path enabled/active, pinned full-flag doctor GREEN rc 0.
  `python3 tools/check-omp-only.py SITE_HOME .` is GREEN with 137 declared
  roles.

## Current grade

Rungs 1-3 on the verbatim pinned parser function under ASan. Rung 4 is
PARTIAL: chosen bytes observed at chosen offsets 0, 64 and 92 inside the
live stack object, plus a stack-smashing abort in the lab build. Witness
W209 (#3898, answering #3885) independently replayed a clean
`git archive HEAD lab/frontier/pgactive2shell` at HEAD `04f6dcf9` with all
13 pins exact and graded **ESTABLISHED AS LABELED** at that pinned-function
scope, with NO r5 and no grade change (minor wording NIT only). Not
established: a built PostgreSQL + pgactive instance, a SQL or replication
wire path, control of a saved pointer or return address, an IP, a command
side effect, or rung 5. The advisory's command-execution claim stays a
claim; the stock allocator's behavior is UNKNOWN.

## Next

Build pinned pgactive 2.1.9 against PostgreSQL 16 development headers,
load into a loopback-only cluster, and call the exposed
`pgactive_parse_replident_name(text)` SQL function with an overlong name;
keep 2.1.10 and safe-name controls. A rung-5 attempt needs a measured
pointer/control path and an independently witnessed loopback benign-command
side effect; none is measured here.
