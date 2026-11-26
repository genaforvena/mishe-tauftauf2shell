# sqlitefts5shell — staged by frontier; admission and witness replay owed

CVE-2026-119374: SQLite before 3.54.0 built with `SQLITE_ENABLE_FTS5` rewrites
an FTS5 leaf footer in `fts5DoSecureDelete()` with an uncapped write cursor,
so a crafted database with `secure-delete` enabled writes past the leaf
allocation on a DELETE. Brief: `reports/frontier-sqlitefts5shell.md`.

## Evidence (author, W266 2026-11-26)

- Pins: vulnerable GA 3.53.4 (`b09c88c14082339b66c7b7158d609a771e64ca69`,
  official `sqlite-src-3530400.zip` sha256
  `d18fa15aec74d8c17e1463f861095adc01b5ad190256acb4f91d22f0368d232b`);
  fix `d9de6eedbe918c074c7556400fa21df5960704d9` (code-only hunk sha256
  `5e648094ba1d8b9f84e036b5a4547efafc8ab28f962101a2d1c3077547d55f5f`);
  public YEONBA hexdb sha256
  `4d84273f893d5a359e6316ac511b247b6ca9f8a2640a79b1522a45f1b6033713`.
- Runner `lab/frontier/sqlitefts5shell/run-all.sh` sha256
  `71b234d43ebd56187ce679e680b124ecb498dbb40894509785864090e6d10a32`
  — **RESULT PASS=26 FAIL=0**, rc 0, executed 12:12:03Z–12:16:47Z, console
  sha256 `3c0e8cc6d8f0ae17601eeac2d952173de0ffc77ad46b7bf2a7076535e4f7165c`.
  Offline, all artifacts sha256-pinned; the 14.5-MB zip and generated trees
  are intentionally uncommitted with refetch URL in `PROVENANCE.md`.
- Vulnerable GCC and Clang ASan: heap-buffer-overflow **WRITE of size 1**,
  `0 bytes after a 640-byte region`, rc 134, through `fts5PutVarint64` →
  `sqlite3Fts5PutVarint` → `fts5DoSecureDelete` → `fts5FlushSecureDelete` →
  `fts5FlushOneHash` at generated `sqlite3.c:256373` (write site) and
  `:268441` (varint encoder). Pinned source markers:
  `ext/fts5/fts5_index.c:5525` `nPg = iPgIdx;`, `:5533` unbounded write;
  fixed `:5532` `iKeyIn>nPg` guard, `:5538` bounded write.
- Controls: plain vulnerable DELETE silently succeeds (count 1 → 0); fixed
  GCC and Clang ASan are clean with rc 1 `fts5: corruption in table "t"`;
  crafted-DB read/MATCH and a clean FTS5 secure-delete DELETE are ASan-clean.
  Clang full `-g` stalled >10 min on this host; `-gline-tables-only -O0`
  preserved the ASan line numbers. Details in `PROVENANCE.md`.
- Grade: rung 3 real-source ASan OOB WRITE; rung 4 PARTIAL. No named adjacent
  object, pointer, wire/request path, command or r5. Local corrupt-DB input.

## Next

Staged 2026-11-26 with registered two-pane window 180. Operator admission and
independent witness replay are owed; witness must re-fetch the pinned zip from
the exact URL and verify its hash before the offline runner. Do not duplicate
this lane or its window. The sibling CVE-2026-119373 (`detail=none` negative
rowids) belongs to this mind if admitted, not a separate window.
