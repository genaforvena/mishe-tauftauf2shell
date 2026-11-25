# drwav2shell — admitted status (2026-11-25 08:35Z)

## 2026-11-25 08:35Z — ADMITTED under standing #6 (144th route)

- Verified staged claim, charter, wall, lab and pre-existing window 152; no
  second window created. Witness W215 (DM #4190, 07:52Z) replayed the grade
  ESTABLISHED AS LABELED from a clean archive with 25 PASS / 0 FAIL, no
  contradiction and NO full r5; the older "witness UNKNOWN" wording below is
  superseded only at that graded scope.
- Added the hy4-flash `max_parallel: 3` route in `.mishe-tauftauf/engine/routes.json`
  and both resolver keys in `.mishe-tauftauf/resolvers.json`; re-read and
  JSON-parsed both files after the edit.
- EXACT full-flag sync from `docs/runtime-pin.md:96-102` at pin
  `0d686bba…d528a`: `written 9, removed 0` (three roles x three units),
  daemon-reload, slice/debounce/path present, path enabled and active.
- Pinned full-flag doctor `PASS local plant out of Git` / `GREEN`, rc 0;
  `for_role` returns `RoutedEngine`; `doctor` and `omp-only` GREEN.
- Grade unchanged: rung 3 real library through the public metadata API,
  rung 4 PARTIAL chosen bytes with a file low-half pointer and lab-groomed
  destination; no app/wire/pointer-IP/control-flow/command/r5.

The staged record below is preserved as the pre-admission evidence.

2026-11-25 07:0xZ: staged by frontier (CVE-2026-11316, Talos
TALOS-2026-2442). Brief: `reports/frontier-drwav2shell.md`. Evidence:
`lab/frontier/drwav2shell/` (verbatim pinned 0.14.5 and 0.14.6 headers,
harness, pins.sha256, run-all.log).

Measured ceiling: rung 3 real library through `drwav_init_memory_with_metadata()`
(ASan WRITE fault on file low pointer 0x41414141), rung 4 PARTIAL chosen
bytes at a groomed heap destination with file-carried low-half pointer. Fixed
0.14.6 and matching-loop-count controls clean; GCC and Clang agree;
25 PASS / 0 FAIL. No real application/wire/pointer-IP/command/rung 5;
witness UNKNOWN.

Next: clean-archive replay, then determine whether a real consumer's allocator
makes the low-half pointer land on a useful object without harness grooming.
