# Frontier brief: sqlitesession2shell — CVE-2026-119379 (SQLite Session same-name nCol heap OOB write)

**Status: ADMITTED 03:2xZ under standing #6 as the 199th declared target mind;
independent witness replay is still owed, not accepted. This author report is
not acceptance.** Target slug `sqlitesession2shell`; at staging there was no
prior charter, lab directory or window, and it is not in the frontier
do-not-duplicate list (the distinct admitted target is `sqlitefts5shell`). The
two-pane window 207 and the seed wall were adopted as-is.
Grade at handoff is recorded in `reports/sqlitesession2shell-status.md` after
the local observation, not inferred from advisory prose.

## Verified ground truth (sources read 2026-11-27)

- **Claim sources:** OSV
  `https://api.osv.dev/v1/vulns/CVE-2026-119379`, NVD
  `https://nvd.nist.gov/vuln/detail/CVE-2026-119379`, researcher advisory and
  PoC `https://abraxaslabs.tech/research/sqlite-session-ncol` and
  `https://github.com/abraxas/sqlite-session-ncol`, vendor bug
  `https://sqlite.org/bugs/info/2026-08-16T10:15:25Z`, upstream fix
  `https://github.com/sqlite/sqlite/commit/64459c87cc702d600704fb77ee40ca1782398a52`
  (Fossil `3f57024aecea0f3b565ed823cf94b085031c481fd6323c1f2e4319a53500864f`)
  and release log `https://sqlite.org/releaselog/3_54_0.html`.
- **CVE / severity:** CVE-2026-119379, CWE-787, NVD CVSS 3.1 7.8 HIGH
  (`AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`). The researcher's own page predates
  CVE assignment and still says "no CVE"; the CVE records are authoritative
  for the ID, not the researcher's score (8.1, `AV:N`) or reach label.
- **Versions and pins:** affected SQLite before 3.54.0 **when built with
  `-DSQLITE_ENABLE_SESSION`**; vulnerable tag `version-3.53.4` is git
  `b09c88c14082339b66c7b7158d609a771e64ca69` with SOURCE_ID
  `2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc`.
  Fixed tag `version-3.54.0`; the fix commit above touches four files
  (`ext/session/sqlite3session.c`, new `ext/session/sessioncorrupt.test`,
  `manifest`, `manifest.uuid`). Exact pin hashes live in
  `lab/frontier/sqlitesession2shell/pins/SHA256SUMS` and `pins/tags.json`.
- **Claimed primitive:** a changeset with two table blocks that reuse the same
  table name, first `nCol=2`, then `nCol=64`, makes apply reuse the first
  block's `aUpdateMask` (4 bytes) while `sessionUpdateFind()` memsets
  `((64+33)/32)*4 = 12` bytes. Published oracle: ASan `WRITE of size 12`,
  0 bytes past the 4-byte region, at amalgamation `sqlite3.c:238155` /
  raw `ext/session/sqlite3session.c:4381-4412`; the single-block 2-column
  control applies with rc=0. The published 242-byte changeset is in the
  upstream fix's `sessioncorrupt.test` (`unhex` literal) and the researcher's
  `lab/poc.c`; no RCE or write-what-where is claimed by either.

## Source-bound mechanism (pinned bytes)

Vulnerable `ext/session/sqlite3session.c:5619` keys the apply-context reset on
the table name alone:

```
if( zTab==0 || sqlite3_strnicmp(zNew, zTab, nTab+1) ){
  /* sessionUpdateFree(), sessionTableInfo(), schema/nCol checks, rebuild */
}
```

A repeated name skips that arm. `sessionUpdateFind()` at `:4381-4412` allocates
`aUpdateMask` only when the pointer is NULL, sizes it from the first block's
`nCol` (`nU32*sizeof(u32)`), then memsets from the *current* `pIter->nCol`.
The fix replaces the name comparison with a `bNew` flag produced by
`sessionChangesetNext(pIter, 0, 0, &bNew)` so a new table block always resets
the context; the C delta is 4 additions and 5 deletions plus a 56-line
regression test with the exact 242-byte changeset.

## Local observation (2026-11-27 W309, GCC ASan and plain controls)

`lab/frontier/sqlitesession2shell/` builds both release pins verbatim: it
generates the amalgamation with each pin's own `./configure && make sqlite3.c`
and compiles `harness.c` with `-DSQLITE_ENABLE_SESSION
-DSQLITE_ENABLE_PREUPDATE_HOOK` in ASan and plain modes. The 242-byte fixture
is decoded verbatim from the hex literal in upstream `sessioncorrupt.test`
inside `pins/fix.patch` and was checked byte-for-byte against the public PoC
encoder; the 28-byte control is its first block. `sh build-all.sh` returned rc
0 `BUILD_OK`; `sh run-all.sh` rc 0 **PASS=44 FAIL=0**; runner SHA-256
`f16b47cd967319c2cf12b67bb27984aac56c6ae055ee14b074a88cb9dfc361e8`.

- **Vulnerable 3.53.4 ASan trigger:** rc 134, `heap-buffer-overflow`,
  `WRITE of size 12`, `0 bytes after 16-byte region`, sink frame
  `sessionUpdateFind src-vuln/sqlite-src-3530400/sqlite3.c:238155` from
  raw `ext/session/sqlite3session.c:4401`; allocation at amalgamation `:238148`
  via `sqlite3MemMalloc` (`:28035`). The call chain reaches
  `sqlite3changeset_apply` (`:239703`). The logical request is 4 bytes;
  pinned `sqlite3MemMalloc` adds an 8-byte header, so ASan reports a 16-byte
  usable region — **the published "4-byte region" geometry was not observed**.
- **Fixed 3.54.0 trigger and both 28-byte controls:** rc 0, `apply-rc=0`,
  ASan-clean. The fixed pin still contains the same `memset()` text; upstream's
  `bNew` flag forces the apply-context rebuild on a repeated table block.
- **Plain vulnerable trigger:** rc 139 deterministically in 5/5 repeats — the
  hypothesis that a 12-byte overrun stays inside allocator slack was
  disproved. Both plain controls and both fixed plain runs exit 0 with
  `apply-rc=0`. No chosen-byte readback. Full hashes, raw excerpt and negatives:
  `lab/frontier/sqlitesession2shell/PROVENANCE.md`.
Clean `git archive ca9a5d35 lab/frontier/sqlitesession2shell` replay (20
committed lab files; `runs/`, source trees, build dirs and binaries absent)
rebuilt both amalgamations, returned rc 0 `BUILD_OK`, then unmodified
`sh run-all.sh` rc 0 `PASS=44 FAIL=0` with the same runner hash and the raw
`sqlite3.c:238155` WRITE-12. Frontier and operator clean-archive replays both
landed; independent witness replay is owed.


## Rung-4 feasibility and cheapest next experiment

The sink is a 12-byte heap overwrite of a 4-byte logical request (ASan reports
a 16-byte usable region) in a library that must be compiled with a non-default
Session extra. The cheapest step toward
rung 4 is a real local consumer: an ASan replica/sync daemon on loopback that
accepts a changeset from a local peer, applies it through
`sqlite3changeset_apply*` on the vulnerable pin, and exposes a chosen-byte
readback in an adjacent live object; fixed-pin and well-formed single-block
controls are mandatory. Neither CLI reach, heap grooming, pointer control,
marker execution nor remote command execution is claimed by this brief.

## Screened alternatives this wake

Four scouts returned 32 candidates. SQLite Session won on a 9-line source-bound
C fix, a public 242-byte changeset with a published ASan oracle, and a
sub-minute amalgamation build. PHP bcmath CVE-2026-17544 (one-line fix, public
PoC, ~5-10 min PHP CLI build) and CPython bz2 CVE-2026-9669 (small C change,
in-commit hex PoC) were the strongest backups. libevent CVE-2026-63388 has a
full network PoC but a larger CMake build; Vim helpfile CVE-2026-25749 needs a
full editor build; PyMongo, Apache Arrow, MariaDB and Hyperscan are heavier or
lack PoCs; LuaJIT and unzip lack a shipped CVE/fixed tag. Ruby, 7-Zip, PHP-CGI,
SQLite FTS5, zlib, msgpack and libarchive are excluded or staged elsewhere.
