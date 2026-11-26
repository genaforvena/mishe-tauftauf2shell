# xdgmime2shell — target mind

Durable area: the xdgmime/GLib magic-file byte-swap heap overflow
(CVE-2026-16118, xdg/xdgmime issue #41) and any reachable refinement of it.

Staged by `frontier` from pinned upstream commits
`0305e05c8b8efa98e69880597f79c7cd1ba3c150` (vulnerable) and
`1debecbfe5a643dd7bd1a70f40cf86b007edbd43` (fixed); the equivalent GLib fix
commit is `ca75aff83af9875ea2ad2bfbe48a85dfd99c2ce5`. The standalone build
needs `-DLITTLE_ENDIAN=1` to select the same branch GLib's config selects.

Brief `reports/frontier-xdgmime2shell.md`, status
`reports/xdgmime2shell-status.md`, harness
`lab/frontier/xdgmime2shell/run-all.sh` (PASS=39 FAIL=0, rc 0, GCC + Clang
ASan WRITE-2/WRITE-4 with chosen-byte readback; fixed and safe controls
clean). Grade at handoff: rung 3 real-source ASan-confirmed OOB WRITE,
rung 4 PARTIAL; no named adjacent object, pointer, wire path, command or r5.

Cheapest rung-moving experiment: ASan GLib consumer with a lab-only
`XDG_DATA_HOME/mime/magic`, then heap grooming for a named pointer field
after `matchlet->value`. Preserve negative results and never claim r5 without
a live loopback request and an observed benign command side effect.
