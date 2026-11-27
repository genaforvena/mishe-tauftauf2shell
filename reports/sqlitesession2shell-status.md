# sqlitesession2shell — admitted status (2026-11-27)

Staged by frontier W309 from CVE-2026-119379 (SQLite Session extension, CWE-787,
NVD CVSS 3.1 7.8 HIGH). Vulnerable release `3.53.4` git tag
`b09c88c14082339b66c7b7158d609a771e64ca69`, archive SHA-256
`d18fa15aec74d8c17e1463f861095adc01b5ad190256acb4f91d22f0368d232b`; fixed
release `3.54.0` git tag `6932c59ee5c280599dfae9e7b431698a7cab9687`, archive
SHA-256 `8847659821e0c5116bd14a94644c82ba932b2d9a05ac81af2e34af814aad7c58`.
The source-bound fix is upstream commit
`64459c87cc702d600704fb77ee40ca1782398a52` (Fossil `3f57024aecea0f3b`), a
9-line `ext/session/sqlite3session.c` delta plus a 56-line regression test with
the exact 242-byte changeset. Build requires `-DSQLITE_ENABLE_SESSION` and
`-DSQLITE_ENABLE_PREUPDATE_HOOK`; a default amalgamation is out of scope.

Admitted 03:2xZ under standing #6 as the 199th declared target mind; the staged
two-pane window 207 was adopted as-is (panes %420/%421 dead=0, one registry
entry, 208/208 unique names, no duplicate CVE/GHSA or sink lane). The operator
replay used a clean `git archive ca9a5d35 lab/frontier/sqlitesession2shell`
(20 committed files; no `runs/`, source trees, build dirs or binaries) and
observed the raw ASan `WRITE of size 12`, 0 bytes past a 16-byte region at
amalgamation `sqlite3.c:238155` from raw `ext/session/sqlite3session.c:4401`;
the fixed pin and both single-block controls were clean.

`harness.c` calls the pinned public `sqlite3changeset_apply()` API with two
fixtures: the upstream 242-byte two-block changeset (table `t`, first block
`nCol=2`, second block same name `nCol=64`) and its 28-byte first block alone
as the safe control. It builds both release pins verbatim: each pin's own
`./configure && make sqlite3.c` generates the amalgamation, which is compiled
with GCC 13.3.0 in ASan and plain modes. No upstream file is edited.

Measured grade at handoff: **R1 — / R2 ✓ / R3 ✓ / R4 — / R5 —**. R2 is the
observed stale apply-state reuse: the vulnerable pin's `aUpdateMask` is
allocated from the first block and overwritten from the second. R3 is GCC ASan
corruption in the verbatim pinned sink with a published upstream fixture, not
a full-program exploit. The representative observation:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 12 at 0x502000000400 thread T0
0x502000000400 is located 0 bytes after 16-byte region [0x5020000003f0,0x502000000400)
#2 sessionUpdateFind src-vuln/sqlite-src-3530400/sqlite3.c:238155
#7 sqlite3changeset_apply src-vuln/sqlite-src-3530400/sqlite3.c:239703
```

Raw source line: `ext/session/sqlite3session.c:4401`
(`memset(p->aUpdateMask, 0, nU32*sizeof(u32));`); allocation at amalgamation
:238148. The logical request is 4 bytes; pinned `sqlite3MemMalloc` adds an
8-byte header, so ASan reports a 16-byte usable region. **The published
"4-byte region" geometry was not observed and is not claimed.** The fixed pin
retains the `memset()` text but rebuilds the apply context via upstream's
`bNew` flag from `sessionChangesetNext()`, so its trigger run is ASan-clean.

`sh build-all.sh`: rc 0 `BUILD_OK`. `sh run-all.sh`: rc 0 **PASS=44 FAIL=0**,
runner SHA-256
`f16b47cd967319c2cf12b67bb27984aac56c6ae055ee14b074a88cb9dfc361e8`.

Observed differentials, all captured in ignored `runs/` files:

| Run | Observed |
|---|---|
| vulnerable ASan trigger (242 B) | rc 134, heap-buffer-overflow WRITE 12, 0 bytes after 16-byte region, raw pinned sink frame; no `apply-rc` |
| vulnerable ASan control (28 B) | rc 0, `apply-rc=0`, ASan-clean |
| fixed ASan trigger / control | rc 0, `apply-rc=0`, ASan-clean |
| vulnerable plain trigger | rc 139 deterministically in 5/5 repeats; no sanitizer report |
| vulnerable plain control, both fixed plain runs | rc 0, `apply-rc=0` |

Negatives preserved: the 4-byte-region claim, the hypothesis that a 12-byte
overrun stays inside allocator slack (disproved by the plain rc 139), the
researcher's Docker/loopback service (not run), and any chosen-byte readback,
pointer corruption, marker, wire exploit or RCE (none attempted). The oracle is
the ASan WRITE and the vulnerable/fixed/safe differentials only. No rung 4 or
rung 5 is claimed.

Brief: `reports/frontier-sqlitesession2shell.md`. Hashes, full raw ASan excerpt,
build commands and negatives: `lab/frontier/sqlitesession2shell/PROVENANCE.md`.
Clean `git archive ca9a5d35 lab/frontier/sqlitesession2shell` replays from both
frontier and operator (20 lab files, no `runs/`, source trees, build dirs or
binaries): rc 0 `BUILD_OK`, rc 0 `PASS=44 FAIL=0`, runner SHA-256 unchanged,
raw `sqlite3.c:238155` WRITE-12. Window 207 was adopted as-is on the inner
socket and in the registry. Handoff DMs to operator, witness and the target
mind were sent; independent witness replay is owed and this author report is
not acceptance.

## Named depth experiment

Build a real local consumer: an ASan replica/sync process on loopback that
accepts a changeset from a local peer and applies it through
`sqlite3changeset_apply*` on the vulnerable pin. Measure whether the 12-byte
overwrite can be placed at a chosen offset in a live adjacent object (chosen-
byte readback), with a fixed-pin control and a well-formed single-block
control. Preserve the negatives: the published 4-byte-region geometry was not
observed, the plain vulnerable trigger faults before any readback, the
researcher's Docker service was not run, and no pointer, wire path, marker or
command has been demonstrated. R4/R5 remain NOT CLAIMED.
