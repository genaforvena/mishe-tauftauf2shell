# drwav2shell — status (updated 2026-11-25 19:48Z)

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

## W3 — leak-free fixed-address write in a non-PIE consumer (2026-11-25 12:16Z)

- New durable lane `lab/frontier/drwav2shell/consumer/run-nopie.sh` builds the
  SAME unmodified upstream consumer with `-no-pie` against the pinned 0.14.5
  and 0.14.6 headers. In a non-PIE build the brk heap and the binary's
  `.data`/`.bss` share the below-4-GiB window: measured `wav.pMetadata=0x42d850`,
  `libsndfile.pFileData=0x42da40`, globals `0x41e108`/`0x41e118`. The
  allocator-derived high half of the hijacked cue pointer is therefore zero,
  so the file's low-32 field is the full write address. `sh consumer/run-nopie.sh`
  → 11 PASS / 0 FAIL; pins 3/3 OK.
- File low pointer `0x41e0f0` puts the chosen words `0x4841434b`/`0x42424242`
  in `g_libsndfile` at fixed `0x41e108`; `0x41e100` retargets them to the
  function-pointer global `libsndfile__sf_close` at `0x41e118`. No address
  leak, no `setarch -R`, no gdb write, no source patch. Fixed 0.14.6 and
  matching-`smpl` controls leave both globals untouched. Uninstrumented
  replay of the attack file faults later (rc 139) when the corrupted global
  is used. Raw output in `consumer/evidence/nopie-*.out`.
- Grade: rung 4 strengthens to 8 chosen bytes at an attacker-chosen FIXED
  application address in a non-PIE build, without W2's fixed-ASLR-leak
  dependency. Still no wire/request input, pointer-to-IP overwrite, marker
  execution, command, shell, live service or rung 5; the function-pointer
  write is observed at a breakpoint only. W3 is author replay, no witness
  verdict; the earlier ASan-region and size-class negatives are preserved
  and scoped to their builds.


## W4 — file-chosen control-flow divergence (2026-11-25 12:53Z)

- New durable lane `lab/frontier/drwav2shell/consumer/run-marker.sh`
  (14 PASS / 0 FAIL) with attacker-side `make_marker_wav.py` and committed
  `marker/marker.c`. The six consecutive cue-desync u32 writes cover
  `libsndfile__sf_close` (0x41e118), `libsndfile__sf_readf_short` (0x41e120)
  and `libsndfile__sf_readf_int` (0x41e128) in the -no-pie consumer.
- The crafted file names a lab-only marker object built at fixed text segment
  0x50000000 and injected with `LD_PRELOAD`. gdb backtraces the chosen call:
  marker ← `libsndfile_uninit` (`wav_common.c:178`) ← `decode_test_file`
  (`wav_decoding.c:329`); the marker writes an observed file. Fixed 0.14.6 and
  safe `smpl` loop count on the same file produce no marker side effect.
- Grade: rung 4 now includes a measured file-chosen control-flow diversion
  with a benign marker in a real consumer call path. Still rung-4 mechanics:
  no wire/request input, command, shell, live service or r5. A self-authored
  loopback file-upload wrapper is a synthetic consumer and NOT an r5 lane;
  no such wrapper was built or claimed. W4 is author replay, no witness
  verdict; W1/W2/W3 verdicts still outstanding at 12:50Z.

## W5 — r5 reachability survey (2026-11-25 13:19Z)

- No real network-facing consumer of `drwav_init_*_with_metadata` was found,
  so no r5 lane exists to exercise. Two real consumers of request/network
  audio were checked at source and both call the non-metadata API: Typesense
  `src/aq_model.cpp` at `319f73eca231dccdd0d840ce984727aeed5dc2f1`
  (`transcribe(audio_base64)` -> `read_wav()` -> `drwav_init_memory(...,
  nullptr)`) and Qt multimedia `src/multimedia/audio/qdrawavaudiodecoder.cpp`
  at `766f60872e63fe45029c6ffaa965b69b18fed2df` (QUrl fetched by
  `QNetworkAccessManager` -> `loadWaveAndDecodeData()` ->
  `drwav_init_memory(..., nullptr)`). Neither enters the affected parser.
- GitHub code search outside `dr_wav.h` and exact-phrase web search returned
  only this plant's lab, dr_libs header/tests and advisory pages. Bounded
  survey, not a proof of absence: a real metadata-API consumer is an UNKNOWN
  prerequisite for r5. No self-authored upload wrapper was built.
- Clean-archive replay at HEAD `70ff8805`: pins 3/3 OK, consumer hashes 3/3
  OK, harness 25/0, consumer 18/0, appdest 11/0, nopie 11/0, marker 14/0.
  Witness verdict on W1-W4 still absent at 13:19Z; no replay repeated.
- Grade unchanged: rung 3 real consumer/public API, rung 4 file-chosen
  control flow to a lab marker in a -no-pie real consumer; no wire/request
  input, command, shell, live service, witness verdict for W1-W4 or r5.


## W6 — real network-facing metadata-API consumer found, but patched (2026-11-25 15:11Z)

- A different code index (Sourcegraph public search across all three exact
  `drwav_init_*_with_metadata` spellings) found OpenRBX
  (`bedc4886548f66e873fb06232d6d778396522844`) as a real network-facing
  caller: `Sound::get()` (`Client/App/util/Sound.cpp:419-429`) fetches bytes
  via `ContentProvider::requestContentString()`; `ContentId::isHttp()`
  (`Client/App/include/util/ContentProvider.h:48`) accepts any `http*` id and
  `ContentProvider.cpp:501-505,575-585,665-679` downloads it with
  `Http(id.toString()).get()`; `decodeWav()`
  (`Client/App/util/AudioSystem.cpp:154-179`) feeds those bytes to
  `drwav_init_memory_with_metadata()`. This closes W5's "no real network-facing
  metadata-API consumer found" observation at the API level.
- Cause of no r5 lane in that consumer: its vendored
  `3rdparty/dr_libs/dr_wav.h` is byte-identical (SHA-256
  `fad60f1e...f308cd`) to the lab's pinned fixed 0.14.6 header; the metadata
  path was introduced on 0.14.6 at commit `3bcb593f9388` (2026-11-21). No
  loopback instance was built: the fixed control is byte identity.
- Moondust (`fe246974754b09bf5716a93458583467037e8c64`) vendors 0.14.1, whose
  pass-1/pass-2 `smpl` cursor desync has the same shape
  (`wav/dr_wav.h:2208,2236,2751-2753`), and `MDAudioWAV::openRead()`
  (`audio_wav.cpp:327-343`) calls `drwav_init_with_metadata()`. Its input is a
  local `SDL_RWFromFile` path (`audio_processor.cpp:171`); no network source
  was found, so it is not an r5 lane. GT3 is also on byte-identical 0.14.6.
- Grade unchanged: rung 3 real consumer/public API, rung 4 file-chosen control
  flow to a lab marker; no wire-driven corruption, command, shell, live
  service or r5. No new replay; W1-W4 witness verdicts still UNKNOWN. A real
  network-facing consumer on vulnerable 0.14.5 remains the UNKNOWN r5
  prerequisite; this bounded index survey is not proof of absence. Source
  fetches only, no external probe.

- Clean-archive replay at working HEAD (2026-11-25 15:13Z): pins 3/3, consumer
  hashes 3/3, harness 25/0, consumer 18/0, appdest 11/0, nopie 11/0, marker
  14/0; `tools/check-reproducibility.py` GREEN (29 files). No W1-W4 replay was
  repeated to the witness.


## W8 — real remote-file consumer on vulnerable 0.14.1; no live r5 execution (2026-11-25 19:10Z)

- Broader public-source survey found sphaira and yup as new real
  metadata-API callers on older vulnerable revisions. Exact dependency headers
  were fetched and replayed with the unchanged harness: sphaira 0.14.1
  (`b962384395249f54168d5f5f175c47bd7b39dc1d`, SHA-256
  `a4bd7d50168b9f65e2106b341d94531d5a2283bc672a4ae184e311188f6674ce`),
  Moondust 0.14.1 (byte-identical upstream tag, SHA-256
  `5e60ebb49b738df317e45f955c5032bc7858540d0f90e426364c5f8dc9d848c4`),
  and yup 0.14.3 (byte-identical upstream tag, SHA-256
  `3d1b2f6152fe443a6d1273d9b0441b1b11ae1d71d07dbd682a0a014b3c329fd9`).
  Each exact header gives chosen word present, `metadataCount=1`, ASan WRITE
  SEGV at `0x50f041414155`, and a clean matching-loop control. Raw output:
  `consumer/evidence/w8-{moondust,sphaira,yup}-{chosen,bad,safe}.out`; exact
  URLs/hashes: `consumer/evidence/w8-consumer-headers.txt`.
- Material positive: sphaira
  `3e7a3a8b5f27987e907da97b037e6d7714d81553` mounts HTTP/WebDAV/FTP/NFS/SMB2
  by default (`app.cpp:2158-2198`), exposes them in the file browser, and a
  user-selected `.wav` passes the network-backed `FsStdio` and path to
  `music::Menu` (`filebrowser.cpp:717-718`) -> `audio::OpenSong()` ->
  `drwav_init_with_metadata()` (`audio.cpp:478-481`). `FsStdio` uses
  `std::fopen` (`fs.cpp:484-502`), so remote file bytes reach the vulnerable
  parser. This is user-driven remote-file playback, not a request listener.
- Live r5 remains unexecuted: sphaira requires the Nintendo Switch/Switch 2
  `DEVKITPRO` toolchain (`CMakeLists.txt:9-27`) and has no native/Linux target.
  No Switch runtime is in scope. A Linux wrapper would be synthetic rung 4.
  Moondust remains local-only (`SDL_RWFromFile`); yup's generic `InputStream`
  has no network caller in-repo. G-Diffuser, OpenRBX and GT3 are fixed 0.14.6.
- No exactly-0.14.5 real consumer was found; Sourcegraph broad queries were
  capped and authenticated GitHub code search was unavailable, so absence is
  not proved. Grade unchanged: rung 3 real consumer/public API; rung 4
  file-chosen control flow to a lab marker; no live wire-triggered corruption,
  command, shell, service, W1-W4 witness verdict or r5. No W1-W4 replay was
  re-queued. Source provisioning only; no external probe.


## W9 — version-banner survey and 0.13.14 header replay (2026-11-25 19:48Z)

- Third code-index angle: 134 Sourcegraph version-banner matches, 105 rows
  with vendored `dr_wav.h` at or below 0.14.5; exact query, rows and
  call-site notes in `consumer/evidence/w9-version-survey.txt`.
- Negative for the last r5 prerequisite: the native network-facing
  vulnerable-version candidates do not call the metadata API. roc-toolkit
  0.13.14 uses `drwav_init_file()` (`wav_source.cpp:166`); typesense 0.13.14
  uses `drwav_init_memory()` (`aq_model.cpp:29`). FreeSWITCH-ASR, LibXtract,
  EasyRPG, SPTK, pedalboard and vcvrack-packone use non-metadata
  initializers. Known metadata callers are Switch-only, local-only, no
  network origin in-repo, or on fixed 0.14.6.

- A regex query for every metadata-init call with the header excluded
  returned 18 hits: real callers are sphaira, OpenRBX, Moondust, G-Diffuser,
  GT3, ossia/score (test-only) and ossia/libossia (write-only); the rest are
  upstream tests, a synthetic harness or library definitions (query C in
  `consumer/evidence/w9-version-survey.txt`). Index coverage is not proof
  of absence.
- Exact roc-toolkit 0.13.14 header
  (SHA-256 `72c483563fccfe60c9f97076116bdeb6a8672c1f8f181faf4bff8f89cfe0f3ff`)
  under the unchanged harness: `chosen` `metadataCount=1` and
  `CHOSEN_WORD_PRESENT=1`; `bad` ASan SEGV at `0x50f041414155`
  (`dr_wav.h:2257`); `safe` `metadataCount=2`, no chosen word, rc 0. Raw:
  `consumer/evidence/w9-roc01314-{chosen,bad,safe}.out`. The desync is not
  unique to 0.14.x.
- Grade unchanged: rung 3 real consumer/public API; rung 4 file-chosen
  control flow to a lab marker; no live wire corruption, command, shell,
  service, W1-W4 witness verdict or r5. W1-W4 offers not re-queued. Source
  fetches only, no external probe.

