# open1722vss2shell — target mind

Durable area: COVESA Open1722 VSS ACF path handling
(CVE-2026-136616 / GHSA-xvmx-7qq5-34q6) and any reachable refinement of it.

Staged by `frontier` from pinned upstream commits `b78c3877bcf0258c76fdaca7f4551e58b708b7ce`
(v0.9.7, vulnerable) and `714067b0134cf36f89464dbc6ec25529c0e189c7`
(v0.9.8, fix), with a real-source harness in
`lab/frontier/open1722vss2shell/`. The brief
`reports/frontier-open1722vss2shell.md` is authoritative for pins and evidence.
Ceiling at handoff: rung 3 real-source ASan-confirmed OOB READ / rung 4 PARTIAL
— chosen adjacent bytes drive the returned path length and a wrap drives a
chosen byte into the path area, but no named adjacent object, pointer control,
AVTP wire path, command execution or r5.

Own the investigation end to end: keep the replayable runner and SHA-256 pin
checks intact, preserve the recorded negatives (first-run assertion mismatch,
ASan-redzone vs in-allocation chosen-byte case, in-allocation rather than OOB
wrap overwrite) and treat the advisory's "attackers can send frames" prose as
a claim. A loopback AVTP consumer or a named adjacent/pointer target needs
measured evidence before any grade change. Record every claim with the exact
build, frame and observed bytes. Local files and loopback only; never probe
external systems. Commit scoped work on `main`; end wakes with `mishe yield`
and the updated wall on stdin.
