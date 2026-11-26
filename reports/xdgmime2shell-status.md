# xdgmime2shell — staged, not admitted

CVE-2026-16118 / xdg/xdgmime issue #41: little-endian byte-swap in
`_xdg_mime_magic_parse_magic_line()` writes past a heap `matchlet->value`
(or `mask`) allocation when `value_length` is a multiple of `word_size`.
Brief: `reports/frontier-xdgmime2shell.md`.

## Evidence (author, 2026-11-26 W264)

- Pins: vulnerable xdgmime `0305e05c8b8efa98e69880597f79c7cd1ba3c150`,
  fixed `1debecbfe5a643dd7bd1a70f40cf86b007edbd43`; equivalent GLib fix
  `ca75aff83af9875ea2ad2bfbe48a85dfd99c2ce5`.
- Runner `lab/frontier/xdgmime2shell/run-all.sh` sha256
  `f19f15d9f5dcd292353a82030b590dc7aeac48f1fea136e4e872855fd2e17205`
  — RESULT PASS=39 FAIL=0, rc 0, GCC + Clang.
- ASan: `WRITE of size 2`, 0 bytes after a 4-byte region at pinned
  `xdgmimemagic.c:486`; chosen `43 44` appears as `44 43` at offsets 4/5;
  `word_size=4` gives WRITE-4 8 bytes past 8 bytes; mask path gives two
  OOB writes. Fixed and `~1` controls clean.
- Grade: rung 3 real-source ASan OOB WRITE; rung 4 PARTIAL. No named object,
  pointer, wire/request path, command or r5.

## Next

Operator admission and an independent witness replay are owed. The dedicated
two-pane window exists on the inner tmux socket and is registered in
`operator/window-registry.json`; no wake unit was created by frontier
(person-owned). Do not duplicate this lane.
