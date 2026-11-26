# frontier-sqlitefts5shell — SQLite FTS5 secure-delete footer OOB WRITE (CVE-2026-119374)

## Claim source and scope

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-119374 — "SQLite before
  3.54.0 built with FTS5 contains a heap buffer overflow in
  `fts5DoSecureDelete()` that allows attackers to write past the leaf page
  buffer via crafted footer key offsets"; CWE-787, high, `AV:L` (local).
  Credit: YEONBA (finder), Abraxas Labs (reporter), Dan Kennedy (remediation).
- Fix: SQLite git `d9de6eedbe918c074c7556400fa21df5960704d9`
  (Fossil `9cd4f9e9205c5a5096388397a39349db9ff5377d19095c6b20388ff799969c31`,
  2026-08-11, branch-3.53 backport `34171bee08`), parent `4267bbf920cc`. The
  fix is in `ext/fts5/fts5_index.c` and adds a 202-byte regression test
  (`fts5corruptB.test` 4.0) carrying a 5120-byte hexdb corrupt database.
- Public research with an explicit local reproduction recipe:
  https://abraxaslabs.tech/research/sqlite-fts5-securedel and its proof of
  concept https://github.com/abraxas/sqlite-fts5-securedel . It claims an ASan
  WRITE of size 1 in `fts5PutVarint64` ← `sqlite3Fts5PutVarint` ←
  `fts5DoSecureDelete` on the 5120-byte hexdb, triggered by
  `DELETE FROM t WHERE rowid = 1` against vulnerable GA 3.53.4. The same page
  states the limit plainly: local crash, no write-what-where, no RCE, and
  explicitly not CVE-2026-11824 (`szLeaf<4`, fixed in 3.53.2). Treat all of it
  as a claim reproduced only by the local lab below.
- Vulnerable pin: SQLite 3.53.4, git tag `version-3.53.4` =
  `b09c88c14082339b66c7b7158d609a771e64ca69` (2026-07-24), official
  `https://www.sqlite.org/2026/sqlite-src-3530400.zip`, SOURCE_ID suffix
  `bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc`.
- Checked before staging: no report, charter, manifest row or lab lane for
  SQLite/FTS5 anywhere in this plant. SQLite is a widely embedded runtime
  library; the bug needs `SQLITE_ENABLE_FTS5` and an attacker-supplied `.db`
  with `secure-delete` already enabled. No network listener exists in the
  library, so the reach is local, not a wire path.

## Source-bound mechanism

`fts5DoSecureDelete()` in the pinned `ext/fts5/fts5_index.c` (around
`:5514-5544`) rewrites a segment leaf's footer when FTS5 `secure-delete`
flushes a DELETE. On 3.53.4:

```c
const int nMove = nPg - iNextOff;     /* Number of bytes to move */
int nShift = iNextOff - iOff;
int iPrevKeyOut = 0;
int iKeyIn = 0;
if( nMove>0 ) memmove(&aPg[iOff], &aPg[iNextOff], nMove);
iPgIdx -= nShift;
nPg = iPgIdx;                         /* nPg is now the NEW footer start */
fts5PutU16(&aPg[2], iPgIdx);
for(iIdx=0; iIdx<nIdx; /* no-op */){
  u32 iVal = 0;
  iIdx += fts5GetVarint32(&aIdx[iIdx], iVal);
  iKeyIn += iVal;                     /* iKeyIn is a signed int, uncapped */
  if( iKeyIn!=iDelKeyOff ){
    int iKeyOut = (iKeyIn - (iKeyIn>iOff ? nShift : 0));
    nPg += sqlite3Fts5PutVarint(&aPg[nPg], iKeyOut - iPrevKeyOut);
    iPrevKeyOut = iKeyOut;
  }
}
```

`aPg` is `pSeg->pLeaf->p`, allocated by `fts5DataRead()` as the blob plus
`FTS5_DATA_PADDING` (20 bytes). After `nPg = iPgIdx` the old allocation length
is gone: hostile footer varints can drive `iKeyIn` past it, and each
`sqlite3Fts5PutVarint()` (1–9 bytes; a negative signed difference encodes as a
9-byte varint) writes through `&aPg[nPg]`. The 20 padding bytes are an
over-read allowance, not a bound on footer rewrites. The fix keeps the
original `nPg` as `nNewPg`, widens `iKeyIn` to `i64`, and calls
`FTS5_CORRUPT_IDX(p)` when `iKeyIn>nPg`, before the write.

## Local evidence (W266, 2026-11-26)

Harness `lab/frontier/sqlitefts5shell/` uses the unmodified official 3.53.4
tarball with `-DSQLITE_ENABLE_FTS5`; the fixed build applies only the
`fts5_index.c` code hunk from `d9de6eed`, at hunk offset -1 because the GA
differs from the commit parent by one line. Canonical runner `run-all.sh`
sha256 `71b234d43ebd56187ce679e680b124ecb498dbb40894509785864090e6d10a32`:
**RESULT PASS=26 FAIL=0**, rc 0, executed 12:12:03Z–12:16:47Z, console
`evidence/run-all-console.log` sha256
`3c0e8cc6d8f0ae17601eeac2d952173de0ffc77ad46b7bf2a7076535e4f7165c`.
The runner is offline, verifies every pinned artifact by sha256, and keeps
the 14.5-MB source zip and generated trees out of Git (hashes and refetch
URL in `PROVENANCE.md`).

- Pins: tarball
  `d18fa15aec74d8c17e1463f861095adc01b5ad190256acb4f91d22f0368d232b`,
  code-only fix patch `5e648094ba1d8b9f84e036b5a4547efafc8ab28f962101a2d1c3077547d55f5f`,
  hexdb `4d84273f893d5a359e6316ac511b247b6ca9f8a2640a79b1522a45f1b6033713`,
  decoded DB `6403bc6c08deee687c69e6d05c680a443f7d994bda19071131db0bd196538fa3`.
  Sanity: `sqlite_version()` = 3.53.4, `count(t)` = 1.
- Vulnerable GCC 13.3 ASan: `heap-buffer-overflow`, **WRITE of size 1**,
  `0 bytes after a 640-byte region`, rc 134. Frames `fts5PutVarint64`
  (`sqlite3.c:268441`) → `sqlite3Fts5PutVarint` (`:268456`) →
  `fts5DoSecureDelete` (`:256373`) → `fts5FlushSecureDelete` (`:256436`) →
  `fts5FlushOneHash` (`:256537`), through the ordinary SQL DELETE commit.
  Clang 18.1.3 (`-gline-tables-only -O0`) reproduces WRITE-1 at `:256373`,
  rc 134. Full debug info stalled >10 min in Clang on this host; the failed
  hypothesis is preserved in `PROVENANCE.md`.
- Plain vulnerable build: `count` 1 → DELETE rc 0 → `count` 0; the absence
  of a crash there is not evidence of absence of the write.
- Fixed controls (GCC and Clang ASan): no report; rc 1 with
  `fts5: corruption in table "t"` — the `iKeyIn>nPg` guard stops the write.
  Safe controls on the vulnerable build: crafted-DB read/`MATCH 'alpha'` and
  a clean FTS5 `secure-delete` table DELETE are both ASan-clean.
- Source markers: vulnerable `ext/fts5/fts5_index.c:5525` (`nPg = iPgIdx;`)
  and `:5533` (unbounded `PutVarint`); fixed `:5525` (`nNewPg = iPgIdx;`),
  `:5532` (guard), `:5538` (bounded write).

## Honest rung-4 feasibility assessment

Grade: **rung 3 real-source ASan-confirmed OOB WRITE; rung 4 PARTIAL**. The
write happens in upstream's own
`fts5DoSecureDelete()` on an unmodified vulnerable GA, through the ordinary
SQL `DELETE` path, and the corrupt footer controls where the write cursor
lands. Not claimed: a named adjacent object or pointer field under control,
a write-what-where primitive, a wire or request path, a command, or r5.
The public research calls this a local crash and explicitly disclaims RCE.
The cheapest rung-moving experiment after reproduction is to measure the
encoded bytes actually written past `nn+20` under a named heap neighbour and
check whether the varint content is attacker-chosen, not merely the cursor.

## Cheapest next rung-moving experiment

Groom the ASan-recover build so a named object with a pointer field follows
the `Fts5Data` blob, then vary footer varints and read back the bytes past
`nn+20`; a controlled value at a named field would support a rung-4 upgrade.
Independently, find a loopback consumer that opens attacker-supplied `.db`
files with FTS5 enabled (for example a lab-only backup-restore or document
ingest path) and confirm the DELETE path is reachable from its input. No
claim is made here that either exists in this plant's targets.
