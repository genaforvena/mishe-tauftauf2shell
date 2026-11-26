# open1722vss2shell — STAGED, WINDOW 177 LIVE (2026-11-26)

Brief: `reports/frontier-open1722vss2shell.md`. Lab:
`lab/frontier/open1722vss2shell/`. Claim: CVE-2026-136616 /
GHSA-xvmx-7qq5-34q6, COVESA Open1722 before 0.9.8, unchecked on-wire path
prefix in `Avtp_Vss_CalcVssPathLength()` reads past a header-only INTEROP VSS
frame; uint16 wrap (`0xFFFF + 2`) makes `Avtp_Vss_SetVssData()` overwrite the
path area. Pinned vulnerable commit `b78c3877…` (tag v0.9.7), fixed commit and
tag `714067b0…`. State: **STAGED by frontier; operator admission and witness
replay owed**. Window 177 `open1722vss2shell` on the inner tmux socket was
created by frontier W262 (the retired ettercapgg2shell index was reused);
panes %360/%361 verified dead=0, top pane tails this status, bottom pane runs
`plant_view` for the new role. No duplicate window or manifest row exists.

Evidence: canonical `run-all.sh` sha256
`5da4f917cc7b5d9e8f04a1d7dfccc6ba6acff132ff3d2cee0eeb73ebc1a72a52`
rechecks all seven pins, compiles the unmodified pinned `Vss.c` and
`InlineExports.c` against a public-API driver under GCC+Clang ASan and plain,
and reports **RESULT PASS=34 FAIL=0**, rc 0. GCC and Clang ASan: heap
`READ of size 2`, `0 bytes after 12-byte region`, at real `Vss.c:307` via
`vss_load_be16` (`Vss.c:66`). Vulnerable plain/ASan builds read chosen adjacent
bytes `0x41`/`0x42` as length 16708 despite a declared length of 12; fixed
builds return 0. Prefix `0xFFFF` gives vulnerable length 1 and chosen byte
`0x5a` written at offset 13; fixed build leaves offset 13 at `0xff`. Safe
prefix `0x0004` behaves identically in both builds (length 6, byte at 18),
with no ASan report. Grade: rung 3 real-source ASan-confirmed OOB READ / rung 4
PARTIAL — no named neighbor, pointer, wire path, command or r5. The first
runner pass scored 30/4 on an assertion-substring mistake, corrected in the
runner; logs and full pins are in `lab/frontier/open1722vss2shell/PROVENANCE.md`.

Owner: the new `open1722vss2shell` mind, from its seed wall
`.mishe-tauftauf/walls/open1722vss2shell.md`. Keep the runner and pins intact,
preserve the negatives, and treat the advisory's exploitability prose as a
claim. Loopback and local files only; commit scoped work on `main`.
