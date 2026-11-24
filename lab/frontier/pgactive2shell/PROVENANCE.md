# pgactive2shell provenance

All provisioning was read-only public fetching; no external target was
probed. SHA-256 values of every pinned and generated artifact are in
`pins.sha256` and rechecked by `harness/run.sh` PASS-19.

- Vulnerable tag `v2.1.9`, commit
  `f34c8aa6f9f5c4ad5ee4bfdf93fef4b000be8f9e`:
  - `provision/catalogs-v2.1.9.c` — `src/pgactive_catalogs.c` at that tag.
  - `provision/internal-v2.1.9.h` — `include/pgactive_internal.h` at that tag.
  - `provision/pgactive-2.1.9.tar.gz` — full codeload archive of the tag.
- Fixed tag `v2.1.10`, commit
  `c3829ddb81c8c8e927b6e5a0baba3b1a016fcb52`:
  - `provision/catalogs-v2.1.10.c`, `provision/internal-v2.1.10.h`,
    `provision/pgactive-2.1.10.tar.gz`.
  - Fix diff read at
    `https://github.com/aws/pgactive/compare/v2.1.9...v2.1.10.diff`; the
    security hunk is in `src/pgactive_catalogs.c`, with companion
    `REVOKE ALL ON FUNCTION pgactive_parse_replident_name(text) FROM PUBLIC`
    in the SQL migration.
- Verbatim extraction:
  - `generated/functions_vuln.c` — `catalogs-v2.1.9.c` lines 341-358, plus
    the format macro from `internal-v2.1.9.h:31`.
  - `generated/functions_fixed.c` — `catalogs-v2.1.10.c` lines 341-357,
    plus the scan format macro from `internal-v2.1.10.h:38`.
  - Only added text: one-line comments, the include, and the macros. No
    decoder logic is reimplemented. Line numbers are claims about the pinned
    bytes; hashes are authoritative.
- Stand-ins in `harness/types.h`: `NameData` with `char data[64]` and
  `NameStr(name)` from host PostgreSQL headers
  (`pg_config_manual.h:29` NAMEDATALEN 64, `internal/c.h:747`); `Oid`,
  `TimeLineID`, `uint64`, `UINT64_FORMAT` from `pg_config.h:591`
  (INT64_MODIFIER "l") and `internal/c.h:550`; `pgactiveNodeId` layout from
  pinned `internal-v2.1.10.h:67-72`. `SCNu64` comes from `<inttypes.h>`.
  `g_dest` records the destination address through the stand-in `NameStr`
  macro; `elog` is a counter. Under `CAPTURE_MODE` the stand-in `elog` calls
  `dump_chosen()` inside the pinned function, before it returns.
- Claim sources: CVE-2026-134068 record
  (`https://www.cve.org/CVERecord?id=CVE-2026-134068`), AWS bulletin
  2026-198-AWS (`https://aws.amazon.com/security/security-bulletins/2026-198-aws/`)
  and the v2.1.10 release notes. All read-only provisioning.

## Harness evidence

`sh harness/run.sh`: 19 PASS / 0 FAIL, rc 0.

- `harness/evidence/asan-vuln-attack.out`: ASan stack-buffer-overflow,
  `WRITE of size 97`, address at offset 96 in frame, `[32, 96)
  'replication_name'` overflowed, frame
  `pgactive_parse_replident_name generated/functions_vuln.c:20`, rc 1.
- `harness/evidence/asan-vuln-safe.out`, `asan-fixed-attack.out`: clean.
- `harness/evidence/plain-vuln-attack.out`: in-function capture
  `CAPTURE-IN`, `CAPTURE-CANARY64` and `CAPTURE-MARKTAIL` all
  `485a4d49` (chosen `H Z M I` bytes at offsets 0, 64 and 92 of the
  64-byte stack object); the plain vulnerable process then aborts with
  `*** stack smashing detected ***` after the write.
- `harness/evidence/plain-vuln-safe.out`: `RET=0`, accepted.
- `harness/evidence/plain-fixed-attack.out`: `RET=-1`, `CAPTURE=NONE`.

## Clean-archive replay (2026-11-24 21:45Z)

`git archive 6b17910b lab/frontier/pgactive2shell
reports/frontier-pgactive2shell.md` extracted to `/tmp/pgactive-replay`;
`sh harness/run.sh` from that clean directory reported `RESULT 19 PASS /
0 FAIL`, rc 0. Pins and verbatim extraction were checked there as well.
