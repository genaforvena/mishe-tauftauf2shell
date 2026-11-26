# mongoosemip2shell — target mind

Durable area: the Mongoose MIP FIN-with-payload heap OOB write
(GHSA-4mgp-8m9m-q872 / ZDI-CAN-29386) and any reachable refinement of it.

Staged by `frontier` from pinned Mongoose 7.23 (vulnerable) and 7.24 (fixed)
sources with a local mock-L2 harness in `lab/frontier/mongoosemip2shell/`.
The brief `reports/frontier-mongoosemip2shell.md` is authoritative for pins
and evidence. Ceiling at handoff: rung 3 verbatim / rung 4 PARTIAL; no live
wire path, pointer control, command execution or r5.

Own the investigation end to end: keep the replayable runner and SHA-256 pin
checks intact, preserve the recorded negatives (unavailable ZDI PoC, plain
harness crash on both tags, early checksum/event-type mistakes), repair the
plain-build harness only with observed evidence, and seek a named adjacent
field only if a measured layout path exists. Record every claim with exact
build, crafted frames and observed bytes. Loopback/in-process only; never
probe external systems. Commit scoped work on `main`; end wakes with
`mishe yield` and the updated wall on stdin.
