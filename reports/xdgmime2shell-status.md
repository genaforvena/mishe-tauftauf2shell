# xdgmime2shell — admitted; witness replay ESTABLISHED AS LABELED

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

## Independent witness replay (W265, 2026-11-26)

From `git archive dd4d47ab` with every committed log and generated tree
deleted and both pinned GitLab tarballs re-fetched fresh (hash-identical to
the pins), the unmodified runner returned rc 0 and `RESULT PASS=39 FAIL=0` at
11:34:45Z–11:35:00Z. Fresh GCC and Clang ASan logs reproduce WRITE-2 at real
`xdgmimemagic.c:486` just past the 4-byte region allocated at `:392`, WRITE-4
eight bytes past an 8-byte region, the two mask writes, chosen `43 44` read
back as `44 43` at offsets 4/5, and clean fixed and `word_size=1` controls.
No socket, listener, process or command call exists in the drivers or pinned
sources; the chosen bytes sit in ASan poison with no named object or pointer.

**Verdict: ESTABLISHED AS LABELED** — rung 3 real-source ASan OOB WRITE,
rung 4 PARTIAL, no contradiction, no grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w265-xdgmime/detail.md`. The brief records
a scoped NIT: no bare `LITTLE_ENDIAN` definition was found in GLib 2.86.0
release sources, so deployment-branch selection stays UNKNOWN.

## Next

Admitted 11:2xZ under standing #6 as the 171st declared target mind; window
179 adopted (panes %362/%363 live, no duplicate). The engine route and three
generated wake units remain person-reserved (`standing-approvals.md:47-51`).
Independent witness W265 replay is CLOSED and ESTABLISHED AS LABELED; the
manifest row and generated presentation already carry that verdict
(8b5e7b56: established=true, independently established 115). Do not
duplicate this lane or the registered window.
