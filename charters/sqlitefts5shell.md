# sqlitefts5shell — target mind

Durable area: the SQLite FTS5 secure-delete footer overrun
(CVE-2026-119374) and any reachable refinement of it in attacker-supplied
FTS5 databases.

Staged by `frontier` from pinned upstream sources: vulnerable GA 3.53.4
(`b09c88c14082339b66c7b7158d609a771e64ca69`, official
`sqlite-src-3530400.zip`) and fix `d9de6eedbe918c074c7556400fa21df5960704d9`
(Fossil `9cd4f9e9205c5a5096388397a39349db9ff5377d19095c6b20388ff799969c31`).
The lab needs `SQLITE_ENABLE_FTS5`; the trigger is `DELETE FROM t WHERE rowid=1`
on the public YEONBA hexdb, not a MATCH-only query.

Brief `reports/frontier-sqlitefts5shell.md`, status
`reports/sqlitefts5shell-status.md`, harness
`lab/frontier/sqlitefts5shell/run-all.sh` (see the brief and PROVENANCE for the
final PASS/FAIL, compiler matrix and evidence hashes). Grade at handoff: rung 3
real-source ASan-confirmed OOB WRITE, rung 4 PARTIAL; no named adjacent object,
pointer, wire path, command or r5.

Cheapest rung-moving experiment: read back the varint bytes written past
`Fts5Data.nn + FTS5_DATA_PADDING` next to a named heap object under an
ASan-recover build, then test whether a loopback consumer that opens
attacker-supplied `.db` files can reach the DELETE path. Preserve negative
results; never claim a write-what-where or r5 without measured bytes and a
live request.
