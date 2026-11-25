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

## W1 — real library consumer through the file API (2026-11-25 09:04Z)

- Clean `git archive HEAD lab/frontier/drwav2shell` replay at 08:59Z: pins
  3/3 OK, unmodified `sh harness/run-all.sh` → 25 PASS / 0 FAIL. Witness W215
  verdict from 07:52Z remains the independent replay of that harness grade.
- New durable lane `lab/frontier/drwav2shell/consumer/`: verbatim upstream
  dr_libs 0.14.5 `tests/wav/wav_decoding.c`, `wav_common.c` and
  `dr_common.c` (hashes in `consumer/consumer.sha256`), built unmodified
  against pinned 0.14.5 and 0.14.6 headers. `make_wav.py` crafts the on-disk
  RIFF from file-supplied fields. `sh consumer/run-consumer.sh` →
  18 PASS / 0 FAIL.
- Vulnerable consumer with file low pointer `0x41414141`: ASan WRITE SEGV at
  `0x50f041414155` in `drwav__read_cue_to_metadata_obj()` (`dr_wav.h:2306`),
  through public `drwav_init_file_with_metadata()` (`:5390`) from
  `decode_test_file()` (`wav_decoding.c:319`), rc 1. Fixed 0.14.6 and
  matching-`smpl` controls clean. Rung 3 now includes a real consumer and an
  on-disk input; no harness source patch.
- Chosen word at `wav.pMetadata+24` with file low half `0x40`, measured under
  `setarch -R gdb`; `metadataCount=1` for two chunks. Negative preserved: the
  consumer's `libsndfile.pFileData` buffer is at `0x50e000000040`, a different
  ASan region from the metadata array `0x50f000000040`, and only the pointer's
  low half is file-controlled, so that app-owned buffer is unreachable in that
  ASan build. W2 below measures a plain build.
- Ceiling unchanged: rung 3 real consumer/public file API, rung 4 PARTIAL
  instrumented and leak-dependent; no wire, pointer-IP, control-flow
  diversion, command, shell or rung 5. New lane is author replay, not an
  independent witness verdict.
- Post-commit clean-archive replay (09:08Z, HEAD `95fd53bc`): pins 3/3 OK,
  unmodified harness `run-all.sh` 25 PASS / 0 FAIL and unmodified consumer
  `run-consumer.sh` 18 PASS / 0 FAIL from the same extracted tree. Author
  replay only; the new consumer lane has no independent verdict yet.

## W2 — application-owned destination in a plain consumer (2026-11-25 11:13Z)

- New durable lane `lab/frontier/drwav2shell/consumer/run-appdest.sh` builds
  the unmodified upstream consumer without ASan against the pinned 0.14.5 and
  0.14.6 headers. Under `setarch -R gdb` it measures the live
  `libsndfile.pFileData` address (`0x555555581a40` in this run) and crafts the
  150-byte RIFF so its pointer low half is `pFileData - 24` (`0x555581a28`);
  no consumer or library source is patched and no address is written by a
  harness hook. `sh consumer/run-appdest.sh` → 11 PASS / 0 FAIL.
- At `wav_decoding.c:326` the file words `0x4841434b`/`0x42424242` are read
  back at `libsndfile.pFileData`, the consumer's own whole-file buffer.
  `metadataCount=1` for two parsed chunks. The uninstrumented consumer passes
  with rc 0. Same-file 0.14.6 and matching-`smpl` controls leave that buffer
  untouched. Raw output is in `consumer/evidence/appdest-*.out`.
- Rung 4 now has a measured application-owned destination in a real consumer,
  still PARTIAL: the low pointer was measured in a fixed-ASLR lab process and
  is not attacker-known without a leak. No wire, pointer-IP, control-flow
  diversion, command, shell or rung 5. W2 is author replay with no witness
  verdict; the earlier ASan-region negative is preserved and scoped to that
  build.
