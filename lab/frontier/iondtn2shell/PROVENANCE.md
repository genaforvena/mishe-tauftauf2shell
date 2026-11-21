# Provenance — iondtn2shell frontier harness

All bytes below were fetched read-only from public upstream sources on
2026-11-21 ~05:18Z (blobless `git clone --filter=blob:none` of
`https://github.com/nasa-jpl/ION-DTN.git`, then `git show <ref>:<path>`).
Nothing outside the lab was probed; no AMP/CLA socket or daemon was started.

## Claim sources

- Maintainer advisory GHSA-gmhw-vmwr-wrxh,
  <https://github.com/nasa-jpl/ION-DTN/security/advisories/GHSA-gmhw-vmwr-wrxh>
  (published 2026-11-07, High 7.5,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, availability only,
  "No known CVE" in its metadata). Affected `3.6.2 <= 4.2.0`, patched
  `4.2.1-a.2`.
- VulnCheck advisory
  <https://www.vulncheck.com/advisories/ion-dtn-heap-buffer-overflow-via-nm-mgr-amp-rendering>
  and CVE-2026-123999
  <https://www.cve.org/CVERecord?id=CVE-2026-123999> describe a matching
  mechanism (unbounded `strcat` in `nm_mgr` AMP rendering, heap OOB write)
  with CVSS v4 8.7, also availability-only (`VA:H`, `VC:N/VI:N`). The GHSA's
  "No known CVE" and VulnCheck's CVE assignment are recorded as conflicting
  claim metadata; neither is treated as observation.
- Upstream release notes `release-notes.txt` at 4.2.1-a.2 list "a heap
  out-of-bounds write in the NM manager's report, table, and macro formatting
  path, where unbounded string concatenation could overflow a fixed-size
  rendering buffer". Added by commit `798cb2c99c1780419eaa0f0a1c72a60f9de32829`.

## Upstream fix

Commit `4b158b64211ad399a00be4215dd81de2f4767d1e`, "Fix (NM): Enhance bounds
checking in AMP string formatters" (2026-09-16), parent
`ccde6a38ea95517ff2d5af3ca63daaf1db03f340`. It changes one file,
`nm/mgr/nm_mgr_print.c` (+199/-39): `ui_str_from_ac()`, `ui_str_from_mac()`
and `ui_str_from_tbl()` switch from unbounded `strcat()` to capacity-tracked
`istrlen()`/`istrcat()` with bail-out on exhaustion. Only `ui_str_from_ac()`
is exercised by this harness.

## Pinned source bytes

| ref | meaning | sha256 of `nm/mgr/nm_mgr_print.c` |
| --- | --- | --- |
| `568df887cb9f18aa8ec013b1a566d83215e499ae` | tag `ion-open-source-4.2.0` dereferenced | `31b9673ccc2573da71156cca7139bdf962d718044acb0cbe9bbac7077dd12127` |
| `54d4b1f0b647e0cb7dfc558651777a042acf5e38` | tag `ion-open-source-4.2.1-a.2` dereferenced | `c2abf2d0ff0031bb191706bc1cebb35aa680379d779b301f7a25aef1ab06084d` |

The affected-tag file is byte-identical to the fix parent's file
(`git diff 568df88 4b158b64^ -- nm/mgr/nm_mgr_print.c` is empty), so no
intervening change contaminates the A/B comparison. Affected
`ui_str_from_ac()` is lines 548–563; the vulnerable concatenations are at
lines 557 and 558, the `STAKE(1024)` at line 550. Fixed function is lines
543–588; the capacity check is at line 564 and the safe append at line 570.
`run.sh` verifies both sha256 values and all six line positions before it
compiles anything.

## Harness boundary

`driver.c` includes verbatim pinned lines 548–563 (affected) and 543–588
(fixed) under `#line 548` / `#line 543 "nm_mgr_print.c"`. Collaborators are
stubs: `STAKE`/`SRELEASE` are a harness allocator, `vecit_*` is a minimal
vector iterator, `ui_str_from_ari()` returns an attacker-controlled rendered
value, and in the fixed build `istrlen`/`istrcat`/`putErrmsg`/`CHKNULL` are
safe local implementations. No production statement is reimplemented.

Two build modes:

- **capture** — `STAKE(1024)` returns a 1024-byte region followed by a
  512-byte harness-owned victim region; the chosen-byte observations read
  that adjacent region. This is instrumented scaffolding: a real heap's
  adjacency and allocator metadata are not asserted.
- **asan** — `STAKE` is plain `malloc(1024)` and ASan detects the cross-boundary
  `strcat` at real pinned line 557.

The 18 rendered values are 80 bytes each, so the upstream loop writes
`18 × 81 = 1458` bytes into the 1024-byte buffer (434-byte overflow). Five
8-byte tokens are placed at write offsets 1024/1088/1152/1280/1408. No daemon,
socket, AMP payload, interactive UI, network input or attacker execution is
involved. Severity and remote reachability remain advisory claims.
