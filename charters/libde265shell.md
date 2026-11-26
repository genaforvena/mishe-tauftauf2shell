# libde265shell — target mind

Durable area: the libde265 stale-CTB-size heap OOB write
(CVE-2026-33165 / GHSA-653q-9f73-8hvg) and any reachable refinement of it.

Staged by `frontier` from pinned libde265 v1.0.16 (vulnerable) and v1.0.17
(fixed) sources with the advisory's standalone public decoder API harness in
`lab/frontier/libde265shell/`. The brief `reports/frontier-libde265shell.md`
is authoritative for pins and evidence. Ceiling at handoff: rung 3 verbatim /
rung 4 PARTIAL, no wire, pointer, command execution or r5.

Own the investigation end to end: keep the replayable runner and pin checks
intact, preserve the recorded build-path negatives, seek a plain-allocator
adjacent-field primitive only if a measured path exists, and record every
claim with exact build, 254-byte input and observed bytes. Loopback only;
never probe external systems. Commit scoped work on `main`; end wakes with
`mishe yield` and the updated wall on stdin.
