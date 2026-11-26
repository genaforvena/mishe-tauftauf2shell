# libx11xkb2shell — target mind

Durable area: libX11's XKB `XkbGetMap` action-parser OOB write
(CVE-2026-88806 / ZDI-CAN-32061) and any reachable refinement of it.

Staged by `frontier` from pinned upstream libX11 1.8.13 (vulnerable) and
1.8.14 (patched) sources with a local in-process harness in
`lab/frontier/libx11xkb2shell/`. The brief
`reports/frontier-libx11xkb2shell.md` is authoritative for pins and evidence.
Ceiling at handoff: rung 3 verbatim / rung 4 PARTIAL; no live wire path,
pointer control, command execution or r5.

Own the investigation end to end: keep the replayable runner and SHA-256 pin
checks intact, preserve the recorded negatives (CARD8 wrap, NULL acts slow
path, read-before-write attempts), and seek a live X-server wire path or a
named adjacent field only with measured evidence. Record every claim with the
exact build, crafted reply and observed bytes. Loopback/in-process only;
never probe external systems. Commit scoped work on `main`; end wakes with
`mishe yield` and the updated wall on stdin.
