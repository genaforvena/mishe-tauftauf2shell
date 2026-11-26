# sqlitefts5shell — provenance

CVE-2026-119374: SQLite < 3.54.0 FTS5 `fts5DoSecureDelete()` one-byte heap
OOB WRITE. This lab is a local, offline replay only: every input is a file
under this directory. No socket, listener, request, or external system is
used by `run-all.sh`. All fetches below were one-time provisioning.

## Public ground truth and exact URLs

- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-119374>
  (affected `< 3.54.0`, CWE-787).
- Vulnerable GA pin: SQLite 3.53.4, git tag `version-3.53.4`, commit
  `b09c88c14082339b66c7b7158d609a771e64ca69`; official source tarball
  <https://www.sqlite.org/2026/sqlite-src-3530400.zip>, SOURCE_ID
  `bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc`,
  published 2026-07-24. CLI self-report: `3.53.4 2026-07-24 19:02:57
  bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc (64-bit)`.
- Fix commit: `d9de6eedbe918c074c7556400fa21df5960704d9` (Fossil
  `9cd4f9e9205c5a5096388397a39349db9ff5377d19095c6b20388ff799969c31`,
  2026-08-11, YEONBA). Patch fetched from
  <https://github.com/sqlite/sqlite/commit/d9de6eedbe918c074c7556400fa21df5960704d9.patch>.
- Public reproduction recipe: <https://abraxaslabs.tech/research/sqlite-fts5-securedel>.
  Trigger is `DELETE FROM t WHERE rowid = 1`; a MATCH/count-only query does
  not reach the write. Reported ASan stack:
  `fts5PutVarint64 <- sqlite3Fts5PutVarint <- fts5DoSecureDelete <-
  fts5FlushSecureDelete <- fts5FlushOneHash`.
- Crafted DB transcript:
  <https://raw.githubusercontent.com/abraxas/sqlite-fts5-securedel/main/lab/yeonba-fts5corruptB-4.hexdb>
  (also present in the fix commit's `ext/fts5/test/fts5corruptB.test`,
  regression test 4.0). Header: `size 5120 pagesize 512`, filename `poc.db`.

Fetch times are filesystem mtimes (UTC) at provisioning on 2026-11-26:
`src/yeonba-fts5corruptB-4.hexdb` and `src/fix-d9de6eed.patch` at
11:41:22Z; `src/sqlite-src-3530400.zip` at 11:42:00Z.

## Pin table (SHA-256)

| artifact | bytes | SHA-256 |
| --- | ---: | --- |
| `src/sqlite-src-3530400.zip` | 14,557,315 | `d18fa15aec74d8c17e1463f861095adc01b5ad190256acb4f91d22f0368d232b` |
| `src/fix-d9de6eed.patch` | 20,546 | `abc7c5fe0d639fbaf3270b67297c653c726cf0efeb4fb6cee56fc44915965ae0` |
| `src/fix-fts5-index-only.patch` | 1,651 | `5e648094ba1d8b9f84e036b5a4547efafc8ab28f962101a2d1c3077547d55f5f` |
| `src/yeonba-fts5corruptB-4.hexdb` | 14,058 | `4d84273f893d5a359e6316ac511b247b6ca9f8a2640a79b1522a45f1b6033713` |
| `src/decode_hexdb.py` | 2,640 | `e172e9151aa6c8bf0eacb5f06983e0fe720313105093f972a6223b9622b7c770` |
| `evidence/poc.db` (decoded) | 5,120 | `6403bc6c08deee687c69e6d05c680a443f7d994bda19071131db0bd196538fa3` |
| `ext/fts5/fts5_index.c` vulnerable | — | `f344bce47dd5c8ef72f8f3b8354edf7ab0bfb2109364481e8f5e580c919c0842` |
| `ext/fts5/fts5_index.c` fixed | — | `189f31d3ab50c44f427d49a86bc2d537be5a621f00f9b7889eff556d936b24f2` |
| generated `sqlite3.c` vulnerable | — | `b1dd5d74ec7f29055a6684fa06fb3c2f6821c87dd38f9a458dfd2e8a1db28189` |
| generated `sqlite3.c` fixed | — | `1492a66c2059c836c35d3bbe74ca799d2610fd3c5542a7fe16f2d81b10dbfcc5` |
| `run-all.sh` | — | `71b234d43ebd56187ce679e680b124ecb498dbb40894509785864090e6d10a32` |
| `src/run-all.sha256` | 65 | `349689eb1f7da36aed8fd2e35d60a498244d489078a27e5a9525ed04e23de899` |

`run-all.sh` verifies every pinned artifact at run time with `pin()`;
`src/run-all.sha256` holds the runner's own expected hash. No network call
exists in the runner.

## Source markers (pinned line numbers)

- Vulnerable `ext/fts5/fts5_index.c:5525` — `nPg = iPgIdx;`
  (the write cursor is reassigned to the shortened index size).
- Vulnerable `ext/fts5/fts5_index.c:5533` —
  `nPg += sqlite3Fts5PutVarint(&aPg[nPg], ...)`.
- Fixed `ext/fts5/fts5_index.c:5525` — `nNewPg = iPgIdx;`
  → `5532` — `if( iKeyIn>nPg ){ FTS5_CORRUPT_IDX(p); break; }`
  → `5538` — `nNewPg += sqlite3Fts5PutVarint(&aPg[nNewPg], ...)`;
  final write gated on `p->rc==SQLITE_OK`.
- Generated amalgamation (ASan report coordinates): vulnerable
  `sqlite3.c:256373` — OOB varint write; `fts5PutVarint64` at
  `sqlite3.c:268441`. Fixed `sqlite3.c:256372` — guard;
  `sqlite3.c:256378` — bounded write.

The code-only patch is the first `diff --git` section of the upstream patch
(extracted verbatim); it contains no test changes. It applies to the 3.53.4
tarball at hunk offset `-1` because the git commit and GA tarball differ by
one line in this file. The runner applies only this patch for fixed builds.
The code-only hunk applies cleanly, so the offered fallback fixed GA tarball
`https://www.sqlite.org/2026/sqlite-src-3540000.zip` was not fetched or used.

## Build configuration

Per variant/compiler/sanitizer, from a fresh extraction of the pinned zip:

```
# GCC (ASan and plain)
CC=gcc CFLAGS='-fsanitize=address -g -O1 -DSQLITE_ENABLE_FTS5' \
  ./configure --disable-tcl
# Clang: full -g on the generated amalgamation stalls in the compiler/linker
# for >10 min on this host; line tables keep ASan line numbers and finish in
# ~15 s. -O0 does not change the source coordinates of the write.
CC=clang CFLAGS='-fsanitize=address -gline-tables-only -O0 -DSQLITE_ENABLE_FTS5' \
  ./configure --disable-tcl
make -j2 sqlite3
```

Plain builds omit `-fsanitize=address`. Compilers: GCC 13.3.0, Clang
18.1.3. ASan runs use
`ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:detect_leaks=0`.
The hexdb decoder is pure Python local file I/O: decimal `| offset:` lines
are written into a 5,120-byte zero-filled buffer at page base + offset;
gaps stay zero.

## Control matrix

| control | build | result |
| --- | --- | --- |
| crafted DB sanity | vulnerable plain GCC | `sqlite_version()` = 3.53.4, `count(t)` = 1 |
| trigger | vulnerable GCC ASan | rc 134; ASan heap-buffer-overflow WRITE of size 1, 0 bytes after a 640-byte region; frames `fts5PutVarint64` → `sqlite3Fts5PutVarint` → `fts5DoSecureDelete` → `fts5FlushSecureDelete` → `fts5FlushOneHash`; report line `sqlite3.c:256373` |
| trigger | vulnerable Clang ASan (`-gline-tables-only -O0`) | rc 134; same WRITE of size 1, 0 bytes after 640-byte region, frames through `fts5DoSecureDelete` and `sqlite3.c:256373` (with column `:16`) |
| plain observable | vulnerable GCC, no ASan | `SELECT count(*)` = 1, `DELETE` rc 0, `SELECT count(*)` = 0 (silent corruption in non-ASan build) |
| fixed control | fixed GCC ASan | no ASan report; rc 1, `Error ... fts5: corruption in table "t"` — guard stops the write |
| fixed control | fixed Clang ASan | no ASan report; rc 1, same corruption error |
| safe A | vulnerable GCC ASan, crafted DB read only | `count(t)` = 1; `MATCH 'alpha'` returns the nine terms; rc 0, no ASan report |
| safe B | vulnerable GCC ASan, clean FTS5 table with `secure-delete=1` | create/insert/DELETE: count 2 → 1, rc 0, no ASan report |

Evidence files: `evidence/gcc/vuln-asan-delete.log`,
`evidence/clang/vuln-asan-delete.log`, `evidence/gcc/vuln-plain-delete.log`,
`evidence/gcc/fixed-asan-delete.log`, `evidence/clang/fixed-asan-delete.log`,
`evidence/gcc/safe-read-asan.log`, `evidence/gcc/safe-clean-asan.log`,
`evidence/run-all-console.log`.

## Artifact-size / Git policy

Intentionally NOT committed (registered here with hashes instead):
`src/sqlite-src-3530400.zip` (14.5 MB, hash above), all of `build/` (generated
source trees, amalgamations, CLI binaries, run DBs), the exploratory
`src/sqlite-src-3530400/` extraction, and generated `evidence/poc.db`.
The runner requires the pinned zip to be present locally and verifies its
sha256; a witness must re-fetch it from the exact URL above and verify the
same hash before running offline. Small pinned sources (upstream patch,
code-only patch, hexdb transcript, decoder) and text evidence logs are kept
in the directory. No git commit, brief, window, wall, or registry change was
made by this work.

## Limits and caveats

- The input is a locally crafted/corrupt database file; no wire, pointer,
  address, or command-control path was observed or claimed. This is a
  one-byte heap-boundary violation, not a demonstrated exploit primitive.
- ASan detects the boundary at `0 bytes after 640-byte region`; heap padding
  is not a bound and does not make the write safe. The plain build returning
  rc 0 is not evidence of absence of the bug.
- The fix control returns a corruption error rather than completing the
  DELETE; that is the intended `FTS5_CORRUPT_IDX(p)` stop, and the absence
  of an ASan report proves the write was not attempted.
- `delete-all` is only valid for contentless/external-content FTS5 tables;
  safe control B deliberately uses an ordinary DELETE on a clean secure-delete
  table instead.

## Final verification

`./run-all.sh` was executed at 12:12:03Z–12:16:47Z from the lab directory
after all pins were finalised. It exited 0 with `RESULT PASS=26 FAIL=0`.
The complete console is `evidence/run-all-console.log`, SHA-256
`3c0e8cc6d8f0ae17601eeac2d952173de0ffc77ad46b7bf2a7076535e4f7165c`.
An earlier draft swapped the generated binary tag order (`vuln-gcc-asan`
instead of `vuln-asan-gcc`) and produced rc 127 for the drivers; the tag order
was corrected before the final run, which rebuilt all five binaries from the
extracted tarball and re-executed every check. The console contains only the
final successful run.
