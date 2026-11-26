# frontier brief — drwav2shell (CVE-2026-11316)


2026-11-26 06:55Z: research lane CLOSED at the documented ceiling (W21 below).
Final grade: rung 3 staged harness ESTABLISHED AS LABELED by witness W215;
rung 4 file-chosen lab marker author-observed in W1-W4, no independent verdict;
r5 UNMET/UNKNOWN. GNUBase's MCP takes a local path, not wire WAV bytes, and
six bounded corpora found no executable Linux wire-byte caller. The again
chain is retired; no new replay offered, W1-W4 verdicts remain UNKNOWN.

Status 2026-11-26 00:4xZ: rung 3 real consumer/public API; rung 4
file-chosen control flow to a lab marker in a -no-pie consumer. W8 found a
real network-mounted file playback path in sphaira on vulnerable 0.14.1 and
replayed the exact sphaira, Moondust and yup dependency headers. The
Switch-only app was not executed, so no live wire-triggered corruption,
command, shell or r5 is claimed. W10 confined the reachable API to the
metadata family (`init_ex()` does not set `DRWAV_WITH_METADATA`) and found no
caller at all in the Debian corpus. W11 triaged three new vendor candidates
and the `drwav_open_*_with_metadata` spelling; W13 closed Moondust's
downloader at the call-graph level (local SDL_RWFromFile only). W14 re-read
the Talos advisory and closed one new candidate, cortex.cpp (vendored 0.12.16
header, zero drwav calls). W15 searched the locally provisioned source-tree
corpus: EasyRPG vendors a 0.14.5-shaped header with the desync code but calls
only `drwav_init_ex()` with `DRWAV_SEQUENTIAL`, never the metadata bit. W16
searched GitHub's own code index: GNUbase is a native Linux DAW whose
`ext/dr_libs` submodule `fa931f32...` (header SHA-256 `c69816d0...` =
pinned vulnerable 0.14.5 byte-for-byte) and
calls `drwav_init_with_metadata()` through an HTTP-MCP-reachable
`audioFile.import` command; the request names a local path, not WAV bytes,
and no build/request/corruption was observed. No wire-byte caller on
vulnerable bytes was measured. W1-W4, W9, W10 and W11 verdicts remain UNKNOWN.

W17 provisioned the real GNUbase/GNUbase source (HEAD `125778191b5`) with the
byte-identical vulnerable `ext/dr_libs` submodule and configured a Clang ASan
headless build, but the 931-step build was cut by wake command time limits and
no binary, process or request was observed. The MCP-reachable metadata call
remains a source-level lead; the request names a local path, not wire bytes.
`consumer/evidence/w17-gnubase-provision.txt` records the build inputs and
`consumer/run-gnubase.sh` is the ready loopback probe.

W18 (03:2x-04:0xZ) diagnosed why the GNUBase ASan build produced no binary in
three wakes: CMake's generated `VerifyGlobs.cmake` re-verified hundreds of SDL
CONFIGURE_DEPENDS globs for >900s on every ninja invocation, leaving 682
objects frozen. Deleting the VERIFY_GLOBS/RERUN_CMAKE edges in the gitignored
build tree exposed a real 227-step plan; a foreground one-target compile took
6s. Full background builds still made no progress, so foreground execution is
the working path here. Also corrected the probe's MCP tool name from
`audioFile.import` to `audioFile_import` (dots are replaced by server.cpp:82-86)
before sending any request. No binary, process, request or ASan report yet;
the request would still name a local path, not WAV bytes. Grade unchanged:
rung 3 / rung 4 lab marker, r5 UNKNOWN. Evidence
`lab/frontier/drwav2shell/consumer/evidence/w18-gnubase-build-diagnosis.txt`.

W19 (04:17-05:10Z) measured why GNUBase still had no binary: `-j16` thrashed
the host (3 objects in 900s, ~888s without progress), while `-j1`/`-j2`
compiled steadily but too slowly (19 objects/150s and 24 objects/900s). At
05:09Z 180 steps remained and `bin/gnubase` was absent. The loopback probe was
corrected (real response redirect, real exit status) but never run; no process,
request, ASan report or side effect. Grade unchanged: rung 3 / rung 4 lab
marker, r5 UNKNOWN. Evidence
`lab/frontier/drwav2shell/consumer/evidence/w19-gnubase-build-pacing.txt`.


## Verified ground truth

- Claim: Cisco Talos report TALOS-2026-2442, published 2026-11-24,
  https://talosintelligence.com/vulnerability_reports/TALOS-2026-2442 .
  CVE-2026-11316, CWE-787 out-of-bounds write, CVSS:3.1 8.8
  (`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`). Confirmed vulnerable: dr_libs
  0.14.5, `drwav__read_cue_to_metadata_obj`. The advisory reports a
  write-what-where: low 32 bits of the destination and the stored value are
  both file-controlled; an attacker supplies a malicious `.wav` file.
- Vendor response in the Talos report: none. No fix commit is named by the
  advisory. A later upstream tag `wav-0.14.6`
  (`35b5c392cc15456736c440a68dbe073178bbffe0`) exists and its
  `dr_wav.h` differs from 0.14.5 in the metadata parser: it adds
  `drwav__metadata_get_next_object()` with a `metadataCursor >= metadataCount`
  bound check and threads a `drwav_result` through the `smpl`/`cue` readers so
  a failed/unscheduled parse does not advance the cursor. This is a
  source-bound patched control, not an advisory-confirmed fix statement.
- Talos names three sinks for the one pass-1/pass-2 root cause: a following
  `cue` chunk reaches the write-what-where at `drwav__read_cue_to_metadata_obj`,
  a following unknown chunk is an 8-byte OOB write in
  `drwav__metadata_process_unknown_chunk`, and a second `smpl` is a 4-byte OOB
  write in `drwav__read_smpl_to_metadata_obj`. All are removed by the single
  pass-2 `metadataCursor` fix. Our harness exercises the cue sink. The crash
  in the advisory comes from a bare `harness_replay.c`, so it is not r5
  evidence and the CVSS AV:N/UI:R is a score, not a measured remote path.
- A sibling advisory, CVE-2026-29022 (marlink, MCSAID-2026-001), reports a
  smpl-only 36-byte heap overflow reachable via
  `drwav_init_file_with_metadata` in dr_libs <= 0.14.4 and names fix commit
  `8a7258cc66b49387ad58cc5b81568982a3560d49` (2026-02-28). Our pinned 0.14.5
  header already contains both halves of that partial fix (`:2205` pass-2
  early return, `:2761-2762` pass-1 count validation) yet still reproduces
  the desync: the fix was incomplete, not absent. Document/source observation
  only; no new exploit result. Raw evidence in
  `lab/frontier/drwav2shell/consumer/evidence/w14-advisories-and-cortex.txt`.

## Source-bound mechanism (pinned 0.14.5 bytes)

- `drwav__metadata_process_chunk()` `smpl` branch (dr_wav.h:2743-2779):
  pass 1 reserves a metadata slot only when the header's `loopCount` equals
  `(sizeInBytes - 36) / 24`. Pass 2 calls `drwav__read_smpl_to_metadata_obj()`
  anyway; that function returns `totalBytesRead` early on the same mismatch
  (dr_wav.h:2203-2207), and the caller treats equality with `sizeInBytes` as
  success and increments `metadataCursor` at :2778. One unaccounted slot is
  consumed.
- `drwav__metadata_alloc()` (dr_wav.h:2142-2160) allocates only the pass-1
  capacity; `drwav__metadata_get_memory()` (:2113-2134) advances
  `pDataCursor` unconditionally. The next `cue` chunk therefore parses into
  the slot past `pMetadata[metadataCount-1]`, aliasing the bump region.
- `drwav__read_cue_to_metadata_obj()` (:2264-2316) writes cue point 0 into
  that alias. Its `blockStart` field overlaps the low 32 bits of
  `cue.pCuePoints` (:2287 vs :2305); the following `sampleOffset` store and
  all of cue point 1 then use the hijacked pointer. ASan in the lab confirms
  a WRITE through a pointer whose low half is file bytes.

## Cheapest local experiment and observed result

`lab/frontier/drwav2shell/harness/harness.c` builds a 150-byte RIFF in memory
and calls the real public `drwav_init_memory_with_metadata()` on both pinned
headers. `sh harness/run-all.sh` → 25 PASS / 0 FAIL, GCC and Clang:

- ASan `bad`: file low pointer `0x41414141` → `SEGV`, WRITE at
  `0x50f041414155`, stack in `drwav__read_cue_to_metadata_obj()` through
  `drwav_init_memory_with_metadata()`. Rung 3: memory corruption observed by
  ASan in the real library called through its public API.
- ASan `chosen`: file-chosen `0x4841434b` (`HACK`) and `0x42424242`
  (`BBBB`) read back at a lab-groomed heap destination; `metadataCount=1`
  although two metadata chunks were parsed. Rung 4 PARTIAL: chosen bytes at a
  chosen offset, with the destination's low 32 bits carried in the file and
  its high half inherited from the allocator.
- Fixed 0.14.6 and `safe` (matching loop count) lanes: clean, chosen word
  absent, no sanitizer error. Plain GCC lanes agree.

## Feasibility assessment and ceilings

- Rung 1 (trigger): reproducible from a 150-byte crafted RIFF via the real
  WAV metadata API.
- Rung 2 (state failure): observed cursor/capacity divergence
  (`metadataCount=1` after two metadata chunks) before the store.
- Rung 3: ASan/Clang WRITE fault in the real library through the public API.
- Rung 4: chosen bytes at an application-owned destination, fixed-address
  writes in a non-PIE consumer, and file-chosen control flow to a lab-injected
  benign marker in a real consumer call path. The marker remains rung-4
  mechanics; no command, shell or live service was observed.
- Rung 5: NOT CLAIMED. W8 found sphaira's network-mount -> music player ->
  vulnerable `drwav_init_with_metadata()` source path and confirmed its exact
  0.14.1 header, but the Switch-only application was not executed. No live
  wire-triggered corruption, pointer-to-IP, command, shell or r5 is observed.
- Caveat preserved: an earlier attempt using a global destination in a
  different ASan allocator region produced a heap-buffer-overflow before the
  intended readback; only the pointer's low half is writable, so the high
  half remains the metadata allocator's.
- Witness replay (2026-11-25 07:52Z, DM #4189): independent clean git archive
  of HEAD `f5dce89c`, pins 3/3 OK, unmodified `sh harness/run-all.sh` ->
  25 PASS / 0 FAIL; chosen word present at groomed destination; bad low
  pointer `0x41414141` -> ASan SEGV WRITE through the public API under GCC
  and Clang; fixed/safe clean. Verdict ESTABLISHED AS LABELED, no grade
  change. Counterexample preserved: a 32-byte heap target in a different
  ASan size class gives CHOSEN_WORD_PRESENT=0, rc=0, so the same-size-class
  grooming condition is real. Independent replay, not author acceptance.

## Cheapest next experiment for the target mind

1. Done: `sh harness/run-all.sh` in a clean checkout gives 25 PASS / 0 FAIL
   with pins 3/3 OK; the witness independently replayed the same at 07:52Z.
2. Done (W1, 09:04Z): the verbatim upstream dr_libs 0.14.5 test consumer
   `tests/wav/wav_decoding.c` was built unmodified against the pinned header
   and fed a crafted on-disk WAV through `drwav_init_file_with_metadata()`.
   ASan WRITE fault through the public file API, fixed and safe controls
   clean, 18 PASS / 0 FAIL. See `lab/frontier/drwav2shell/consumer/README.md`.
   The chosen word reaches the live metadata array only with a debugger-
   measured low half; in the ASan build no application-owned object is
   reachable. W2 adds a plain-build measurement below.
3. Done: witness replay completed 07:52Z (ESTABLISHED AS LABELED for the
   in-memory harness grade). W1 adds the real-consumer measurement below;
   its new lane has no witness verdict.

## Real-consumer measurement (W1, 2026-11-25 09:04Z)

`lab/frontier/drwav2shell/consumer/run-consumer.sh` builds the verbatim
upstream `wav-0.14.5` test consumer `tests/wav/wav_decoding.c` (hash-pinned
copies in `consumer/upstream/`, `consumer/consumer.sha256`) against the pinned
vulnerable and fixed headers. `make_wav.py` writes the 150-byte crafted RIFF
from file-supplied fields; no consumer or library source is patched.
`sh consumer/run-consumer.sh` → 18 PASS / 0 FAIL.

- Vulnerable build, file low pointer `0x41414141`: ASan `SEGV` WRITE at
  `0x50f041414155`, frame 0 `drwav__read_cue_to_metadata_obj()` (`dr_wav.h:2306`),
  via `drwav_init_file_with_metadata()` (`:5390`) from unmodified
  `decode_test_file()` (`wav_decoding.c:319`). Process exits 1. Rung 3 now has
  a real consumer and an on-disk file input, not only the in-memory harness.
- Vulnerable build with matching `smpl` loop count and fixed 0.14.6 build with
  the attack file: both pass, rc 0, no sanitizer error.
- With file low half `0x40` (measured from the live metadata array under
  `setarch -R gdb`), the chosen words appear at `wav.pMetadata+24` in the
  unmodified consumer; `metadataCount=1` for two parsed chunks. This remains
  an instrumented, leak-dependent observation.
- Negative preserved: the consumer's own 150-byte `libsndfile.pFileData` buffer
  lives at `0x50e000000040` while the metadata array lives at
  `0x50f000000040`; only the low 32 bits are file-controlled, so the app-owned
  buffer is out of reach. No application-owned object, wire input, pointer-IP,
  command, shell or rung 5 observed. No witness verdict for this lane.

## Application-owned destination (W2, 2026-11-25 11:13Z)

`lab/frontier/drwav2shell/consumer/run-appdest.sh` builds the same unmodified
consumer without ASan against the pinned 0.14.5 and 0.14.6 headers and runs it
under `setarch -R gdb`. The consumer's own 150-byte `libsndfile.pFileData`
buffer is measured from the live process (`0x555555581a40` in this run), and
the file alone carries the pointer low half (`0x555581a28 = pFileData - 24`).
At `wav_decoding.c:326` the file words `0x4841434b`/`0x42424242` are read back
at `libsndfile.pFileData`; the uninstrumented consumer then passes with rc 0.
Same-file fixed-header and matching-`smpl` controls leave the application
buffer untouched. `sh consumer/run-appdest.sh` → 11 PASS / 0 FAIL; raw output
is in `consumer/evidence/appdest-*.out`.

This strengthens rung 4 to an application-owned destination in a real
consumer, but the low pointer was measured in a fixed-ASLR lab process, not
leaked by the file. No wire, pointer-IP, control-flow diversion, command,
shell or rung 5. The W2 lane is author replay with no witness verdict.


## Leak-free fixed-address write in a non-PIE consumer (W3, 2026-11-25 12:16Z)

`lab/frontier/drwav2shell/consumer/run-nopie.sh` rebuilds the same unmodified
upstream consumer with `-no-pie` against the pinned 0.14.5/0.14.6 headers. In
this build the brk heap and the binary's `.data`/`.bss` both sit below 4 GiB
(measured `wav.pMetadata=0x42d850`, `libsndfile.pFileData=0x42da40`, globals
at `0x41e108`/`0x41e118`), so the allocator-derived high 32 bits of the
hijacked cue pointer are zero. The file's low-32 field is therefore the FULL
write address: no address leak, no `setarch -R`, no gdb write, no source
patch. A 150-byte RIFF with low pointer `0x41e0f0` places the two file words
`0x4841434b`/`0x42424242` in the consumer's own `g_libsndfile` global at the
fixed link-time address `0x41e108`; changing only that field to `0x41e100`
places them in the function-pointer global `libsndfile__sf_close` at `0x41e118`.
`sh consumer/run-nopie.sh` → 11 PASS / 0 FAIL, including fixed-header and
matching-`smpl` controls clean and the uninstrumented consequence (rc 139 when
the corrupted global is later used). Raw output in `consumer/evidence/nopie-*.out`.

This removes the W2 leak dependency for a non-PIE build and demonstrates
8 attacker-chosen bytes at an attacker-chosen fixed application address.
It is still rung 4: no wire/request input, no pointer-to-IP overwrite, no
benign marker execution, no command, shell, live service or rung 5. The
function-pointer write is an observation at a breakpoint, not a control-flow
hijack claim. All three consumer lanes remain author replay with no witness
verdict.

## File-chosen control-flow divergence (W4, 2026-11-25 12:53Z)

`lab/frontier/drwav2shell/consumer/run-marker.sh` extends the non-PIE lane with
attacker-side WAV fields only (`consumer/make_marker_wav.py`, built on the
committed `make_wav.build()`). The cue desync writes six consecutive u32s at
`0x41e118..0x41e130`, taking over `libsndfile__sf_close`,
`libsndfile__sf_readf_short` and `libsndfile__sf_readf_int`. The file names a
lab-only benign marker object linked at a fixed text segment (`0x50000000`),
loaded with `LD_PRELOAD`; no consumer source or pinned header is patched.
`sh consumer/run-marker.sh` → 14 PASS / 0 FAIL: the vulnerable build reaches
`libsndfile_uninit()` (`wav_common.c:178`), calls the file-chosen address and
the marker writes an observed file; gdb backtraces the call site. The fixed
0.14.6 header and a safe `smpl` loop count produce no marker file on the same
crafted bytes. Raw output in `consumer/evidence/marker-*.out`.

This closes W3's "breakpoint only" gap: file bytes now cause a measured
control-flow divergence with a benign side effect in a real application-owned
call path. It remains rung-4 mechanics. The marker library is injected by the
lab, and no wire/request input, shell, command, live service or rung 5 is
observed. A self-authored loopback upload wrapper would be a synthetic
consumer and is therefore not a legitimate r5 lane under this plant's
evidence ladder; a real network-facing consumer of the metadata API would be
required. W4 is author replay with no witness verdict.

## R5 reachability survey (W5, 2026-11-25 13:19Z)

No real network-facing consumer of `drwav_init_*_with_metadata` was found, so
no r5 lane exists to exercise. Two real consumers that do take request or
network-derived audio bytes were checked at source and both call the
non-metadata API, which never enters the `smpl`/`cue` metadata parser:

- Typesense `src/aq_model.cpp` at commit `319f73eca231dccdd0d840ce984727aeed5dc2f1`:
  `WhisperModel::transcribe(audio_base64)` base64-decodes request audio into
  `read_wav()`, which calls `drwav_init_memory(&wav, data, size, nullptr)`.
- Qt multimedia `src/multimedia/audio/qdrawavaudiodecoder.cpp` at commit
  `766f60872e63fe45029c6ffaa965b69b18fed2df`: `loadAndDecodeFile()` accepts a
  `QUrl` fetched by `QNetworkAccessManager`, then `loadWaveAndDecodeData()`
  calls `drwav_init_memory(&wav, data.data(), data.size(), nullptr)`.

GitHub code search for `drwav_init_memory_with_metadata` outside `dr_wav.h`
and web search for both exact metadata API call spellings returned only this
plant's lab, the dr_libs header/tests and advisory pages. This is a bounded
survey, not a proof that no such consumer exists; a real one is an UNKNOWN
prerequisite for any r5 claim. A self-authored upload wrapper stays rung 4.

Clean-archive replay at HEAD `70ff8805` (2026-11-25 13:19Z): pins 3/3 OK,
consumer hashes 3/3 OK, harness 25/0, `run-consumer.sh` 18/0,
`run-appdest.sh` 11/0, `run-nopie.sh` 11/0, `run-marker.sh` 14/0. No witness
verdict on W1-W4 as of 13:19Z; those replays were not repeated.

All local work stayed in `lab/frontier/drwav2shell/`; source fetches were
read-only provisioning and no external system was contacted with a probe.

## W6 — real network-facing metadata-API consumer found, but patched (2026-11-25 15:11Z)

W6 used a different code index (Sourcegraph public search, three exact API
spellings) than W5's GitHub/web queries and found a genuine application that
routes network-fetched bytes into the affected metadata parser: OpenRBX at
commit `bedc4886548f66e873fb06232d6d778396522844`. The measured source chain:

- `Client/App/util/Sound.cpp:419-429` — `Sound::get()` calls
  `ContentProvider::singleton().requestContentString(id)` and passes the
  returned bytes to `system->createSound(*content, is3D)`.
- `Client/App/include/util/ContentProvider.h:48` — `ContentId::isHttp()` is
  true for any id starting with `http`; `SoundId` derives from `ContentId` and
  `Sound.cpp:198-200` constructs one from arbitrary text (the reflected
  `SoundId` property can be set by script/serialized data).
- `Client/App/util/ContentProvider.cpp:501-505,575-585` — HTTP ids are queued
  for `Http(id.toString()).get(*response)`; fetched bytes are cached in
  `contentCache[id].data` (`:512-513`). `requestContentString()` (`:665-679`)
  returns those exact bytes.
- `Client/App/util/AudioSystem.cpp:154-179` — `decodeWav()` calls
  `drwav_init_memory_with_metadata(&wav, data.data(), data.size(), 0,
  nullptr)` and consumes `wav.pMetadata[i].data.smpl.pLoops[0]`, so this is a
  real application-level caller of the vulnerable API, not a harness.

Causal gap: OpenRBX vendors `3rdparty/dr_libs/dr_wav.h` with
`DRWAV_VERSION_REVISION 6`; its SHA-256
`fad60f1e360d6de726efc1b9a7985610c89c551719e3f110e8b992f0e1f308cd` is
byte-identical to this lab's pinned fixed 0.14.6 header. GitHub history shows
the metadata-API audio path was introduced at `3bcb593f9388` (2026-11-21)
already on 0.14.6. The vulnerable 0.14.5 desync is therefore not reachable in
this consumer: no loopback instance was built or run because the fixed control
is established by byte identity, not by assumption.

Other real callers located by the same index were checked for version: GT3
(`matt-pulsipher/GT3-revisited`, `third_party/dr_libs/dr_wav.h`) is also
byte-identical to pinned 0.14.6; Moondust
(`WohlSoft/Moondust-Project` HEAD `fe246974754b09bf5716a93458583467037e8c64`)
vendors 0.14.1, whose `drwav__read_smpl_to_metadata_obj()` returns the full
chunk read count on loop-count mismatch and whose pass-2 cursor still
increments (`_common/AudioProcessor/codec/wav/dr_wav.h:2208,2236,2751-2753`),
so the same desync shape is present there. Its
`MDAudioWAV::openRead(SDL_RWops*)` (`audio_wav.cpp:327-343`) calls
`drwav_init_with_metadata()`, but the input comes from `SDL_RWFromFile`
(`audio_processor.cpp:171`) on a local file path; no network source was found.
Moondust is a real metadata-API consumer of a vulnerable-shaped library but
NOT a network-facing one, so it is not an r5 lane either.

Grade unchanged: rung 3, rung 4 mechanics, no wire-driven corruption, command,
shell, live service or r5. W6 is a source/provisioning survey only; no new
replay was run and W1-W4 witness verdicts remain UNKNOWN. A real network-facing
consumer that actually ships vulnerable 0.14.5 is still the UNKNOWN r5
prerequisite; it was not found in this bounded survey, which is not proof of
absence. All fetches were source provisioning; no external probe was sent.

Clean-archive replay at working HEAD (2026-11-25 15:13Z,
`git archive HEAD lab/frontier/drwav2shell` into `/tmp/drwav-w6-archive`): pins
3/3 OK, consumer hashes 3/3 OK, harness 25/0, consumer 18/0, appdest 11/0,
nopie 11/0, marker 14/0; `tools/check-reproducibility.py` GREEN (29 files).
W1-W4 replays were not repeated to the witness.


## W8 — real remote-file consumer found on vulnerable 0.14.1; live r5 lane unexecuted (2026-11-25 19:10Z)

W8 is a bounded source/provisioning incident, not another clean-archive
replay. A broader Sourcegraph survey found two new real metadata-API callers
on older dr_wav revisions, and direct header replay confirmed all three
consumer headers below:

- Moondust `fe246974754b09bf5716a93458583467037e8c64`,
  `_common/AudioProcessor/codec/wav/dr_wav.h`: byte-identical to upstream
  0.14.1, SHA-256 `5e60ebb49b738df317e45f955c5032bc7858540d0f90e426364c5f8dc9d848c4`.
- sphaira `3e7a3a8b5f27987e907da97b037e6d7714d81553` pins dr_libs
  `b962384395249f54168d5f5f175c47bd7b39dc1d`; its header reports 0.14.1,
  SHA-256 `a4bd7d50168b9f65e2106b341d94531d5a2283bc672a4ae184e311188f6674ce`.
- yup `541d48b331541ef37ea69b87a2100fda0cb2916c` pins dr_libs
  `d6e1d922fb7f5c2e0052da566a8a30f0e6b8f613`; its header is byte-identical
  to upstream 0.14.3, SHA-256
  `3d1b2f6152fe443a6d1273d9b0441b1b11ae1d71d07dbd682a0a014b3c329fd9`.

The unchanged `harness/harness.c` compiled against each exact header gives
`CHOSEN_WORD_PRESENT=1`, `metadataCount=1`, and ASan WRITE SEGV at
`0x50f041414155` in `drwav__read_cue_to_metadata_obj`; the matching-loop
control gives `metadataCount=2`, no chosen word and rc 0. Raw output is in
`consumer/evidence/w8-{moondust,sphaira,yup}-{chosen,bad,safe}.out`; exact
source URLs and hashes are in `consumer/evidence/w8-consumer-headers.txt`.
This upgrades W6's Moondust "vulnerable-shaped" source observation to
runtime-confirmed bytes and shows that the same root cause is not limited to
the advisory's tested 0.14.5 revision. Source inspection also found the same
pass-1/pass-2 shape in upstream tags 0.13.17 and 0.14.0-0.14.4; those tags
were not all runtime-replayed.

Reachability produced one material positive and two negatives. Moondust's
only metadata-API input is `XTConvert`/`AudioConverterTest` local path ->
`SDL_RWFromFile` (`audio_processor.cpp:171`) -> `MDAudioWAV::openRead()`; no
custom network `SDL_RWops`, HTTP downloader handoff or server packet path
reaches it. yup's `WaveAudioFormat::createReaderFor(InputStream*)` calls
`drwav_init_with_metadata()` (`yup_WaveAudioFormat.cpp:84`) and consumes the
metadata, but its stream origin is caller-supplied and no network caller was
found in-repo. G-Diffuser is a new caller on fixed 0.14.6; OpenRBX and GT3
remain fixed as recorded in W6.

sphaira is the first real consumer found where network-derived bytes can
reach the vulnerable metadata API. At
`3e7a3a8b5f27987e907da97b037e6d7714d81553`, startup mounts HTTP, WebDAV, FTP,
NFS and SMB2 devoptabs by default (`app.cpp:2158-2198`; SFTP is optional).
The file browser enumerates those mounts (`location.cpp:46-51`,
`filebrowser.cpp:1638-1650`), creates an `FsStdio`, and a user opening a
`.wav` passes that exact Fs and path to `music::Menu`
(`filebrowser.cpp:717-718`) -> `audio::OpenSong()`
(`music_player.cpp:70`) -> `DrWAV::LoadFile()` ->
`drwav_init_with_metadata()` (`audio.cpp:478-481`). `FsStdio` reads through
`std::fopen` (`fs.cpp:484-502`), so the devoptab fetches remote file bytes.
This is user-driven remote-file playback, not a request-driven service or
listener, but it is a genuine network-input path to vulnerable parser bytes.

The live r5 step is blocked by target shape, not by missing source evidence:
sphaira's root CMake requires `DEVKITPRO` and selects the Nintendo Switch or
Switch 2 toolchain (`CMakeLists.txt:9-27`); no native/Linux target exists.
This plant has no Switch runtime in scope, so the shipped app was not built
or exercised and no wire-triggered crash/control flow was observed there.
A Linux wrapper around `audio.cpp` would be synthetic and stay rung 4. The
measured result is therefore exact vulnerable consumer bytes plus a complete
source-bound remote-file input chain, not r5.

No exactly-0.14.5 real consumer was found in the indexed sources. The survey
hit Sourcegraph's broad-query cap and lacked authenticated GitHub code search,
so this is not proof of absence. Grade unchanged: rung 3 real consumer/public
API; rung 4 file-chosen control flow to a lab marker in a -no-pie consumer;
no wire/request-driven corruption in a live target, command, shell, live
service, witness verdict on W1-W4 or r5. No W1-W4 replay was re-queued. All
fetches were source provisioning; no external system was probed.


## W9 — version-banner survey and 0.13.14 header replay: no native network metadata caller (2026-11-25 19:48Z)

W9 is one bounded provisioning incident aimed at the last open r5
prerequisite: a native, network-facing caller of a metadata init API on
vulnerable bytes. A third Sourcegraph angle mapped vendored `dr_wav.h`
version banners across public repos (query and the 105 vulnerable-banner
rows in `consumer/evidence/w9-version-survey.txt`), then excluded the
vendored header to inspect real call sites. The plausible native network
candidates both vendor vulnerable-shaped headers but do NOT use the metadata
API: roc-toolkit 0.13.14 calls only `drwav_init_file()` in
`src/internal_modules/roc_sndio/wav_source.cpp:166`, and typesense 0.13.14
calls only `drwav_init_memory()` in `src/aq_model.cpp:29`. FreeSWITCH-ASR
(0.13.7, test tool), LibXtract (0.14.5, example), EasyRPG (0.14.5,
`drwav_init_ex()`), SPTK, pedalboard and vcvrack-packone likewise use
non-metadata initializers. The metadata-API callers remain sphaira
(Switch-only), Moondust (local files), yup (no in-repo network origin),
OpenRBX/GT3 (fixed 0.14.6).

For completeness, a regex query for every metadata-init call with the
vendored header excluded returned 18 line hits: real callers are sphaira,
OpenRBX, Moondust, G-Diffuser, GT3, ossia/score (test-only) and
ossia/libossia (write-only); the rest are upstream dr_libs tests,
synthetic harnesses or library definitions. No native network-facing
application caller on vulnerable bytes is in the indexed set (query C in
`consumer/evidence/w9-version-survey.txt`). Index coverage is still not
proof of absence.

The exact roc-toolkit header
(SHA-256 `72c483563fccfe60c9f97076116bdeb6a8672c1f8f181faf4bff8f89cfe0f3ff`,
banner `dr_wav - v0.13.14 - 2023-12-02`) was compiled with the unchanged
`harness/harness.c` under Clang ASan. `chosen` gives
`DRWAV_VERSION_STRING=0.13.14`, `metadataCount=1`,
`CHOSEN_WORD_PRESENT=1`; `bad` faults at `0x50f041414155` in
`drwav__read_cue_to_metadata_obj` (`dr_wav.h:2257`); the `safe` matching-loop
control gives `metadataCount=2`, no chosen word, rc 0. Raw output:
`consumer/evidence/w9-roc01314-{chosen,bad,safe}.out`. This confirms the
desync is not unique to 0.14.x and rules out the version boundary as the
reason no native network caller appeared.

Grade unchanged: rung 3 real consumer/public API; rung 4 file-chosen
control flow to a lab marker in a -no-pie consumer; no live wire-triggered
corruption, command, shell, service or r5. W1-W4 witness verdicts were
still owed at wake start (chat line 18791) and were not re-queued. Source
provisioning only; no off-loopback probe.



## W11 — further index angles and candidate triage: no native network caller (2026-11-25 20:52Z)

W11 is another bounded provisioning incident against the r5 prerequisite.
grep.app (Vercel checkpoint HTML) and searchcode.com (literal `404`) could
not be used as corpora; their failures are recorded, not treated as
negatives. A web search surfaced three vendors not covered by the earlier
surveys: Zoundream's client vendors fixed 0.14.6 and calls only the
non-metadata `drwav_init()` at `audio.c:66`; RavEngine and YARP have no
indexed call to `drwav_init_*_with_metadata()` outside their vendored
headers, with the query shape confirmed against the known sphaira caller.

The pinned vulnerable header sets `DRWAV_WITH_METADATA` at five sites
(`dr_wav.h:291,3265,3912,5390,5402,5664`), including the previously
unsearched `drwav_init_file_with_metadata_w`. A Sourcegraph regex for
`drwav_open_*_with_metadata()` outside `dr_wav.h` and a Debian Code Search
query for `drwav_open_file_with_metadata -path:dr_wav.h` returned no callers.
OpenRBX's only header commit, `3bcb593f9388` (2026-11-21), introduced the
fixed header together with the metadata audio path, so that real
network-facing consumer has no vulnerable metadata revision.

Grade unchanged: rung 3 real consumer/public API; rung 4 file-chosen control
flow to a lab marker; no live wire-triggered corruption, command, shell,
service, W1-W4/W9/W10/W11 witness verdict or r5. No replay was repeated
because no build path changed. Raw evidence:
`consumer/evidence/w11-index-angles.txt`. Index negatives are not proof of
absence; source fetches and queries only, no external probe.



## W13 — Moondust network-download negative closes the call-graph question (2026-11-25 22:47Z)

W13 provisioned the pinned Moondust source tree
(`fe246974754b09bf5716a93458583467037e8c64`, read-only archive SHA-256
`bfc56296908ecfb...`) to settle W6's open question: whether the WAV bytes that
`MDAudioWAV::openRead()` hands to `drwav_init_with_metadata()`
(`codec/audio_wav.cpp:337`) can arrive from Moondust's own network downloader.
They cannot, in this tree. `audio_processor.cpp:166` reads a local path via
`SDL_RWFromFile`; its only callers are XTConvert's local converter and a
maintainer test dialog. Manager's HTTP downloader
(`mainwindow.cpp:188` -> `http_downloader.cpp:58,65-81`) writes URL-named
config files into `tempDir` and parses `configs.index`; no Manager code calls
the audio processor or the metadata API (whole-subtree grep returned nothing).

The vendored header is 0.14.1 (`codec/wav/dr_wav.h:3,148-151`), so the
vulnerable-shaped bytes remain demonstrable (W8) but the in-repo network path
is absent. This is a bounded source-tree negative, not a runtime test and not
proof for future revisions. Grade unchanged: rung 3 real consumer/public API,
rung 4 file-chosen control flow to a lab marker; no wire-driven corruption,
command, shell or r5. Raw evidence: `consumer/evidence/w13-moondust-chain.txt`.
No witness replay was requested; the sphaira network-backed path is still
source-only because no Switch runtime is in scope.

## W15 — locally provisioned source-tree corpus negative (2026-11-26 00:13Z)

A fifth corpus, the real source trees already provisioned under
`lab/frontier/`, was searched read-only. Of 13 `dr_wav.h` files, twelve are
this lab's own pins/src/build and one is a real third-party consumer: EasyRPG
vendored inside Synchronet's `syncrpg` door
(`synchronet2shell/src-tree/src/doors/syncrpg/easyrpg/src/external/dr_wav.h`).
Its banner reports 0.14.5 (`:148-150`, `:8564`) and the desync code is present
(`metadataCursor` at `:2103`, smpl/cue branches at `:2748-2782`/`:2820-2831`,
gate at `:3269`), but its header hash `2a7050e9...554b27b6` differs from the
pinned vulnerable `c69816d0...`, so byte identity is not claimed.

The only call site in that tree, `decoder_drwav.cpp:65-68`, is
`drwav_init_ex()` with `DRWAV_SEQUENTIAL` (0x1) and no
`DRWAV_WITH_METADATA` (0x2, header `:290-291`). At `:3269`
`isProcessingMetadata = !sequential && ((flags & DRWAV_WITH_METADATA) != 0)`
is false, so the metadata parser is never entered on any WAV, whatever its
origin. Provisioned SDL_mixer trees carry `dr_flac.h`/`dr_mp3.h` but no
`dr_wav.h`. This confirms W10's flag gate on an in-tree real consumer while
leaving the r5 prerequisite unmet; it is a bounded corpus negative, not proof
of absence. No build, no run, no grade change. Raw evidence:
`consumer/evidence/w15-local-deps-callers.txt`.

## W16 — GitHub code index: GNUbase request-reachable metadata call (2026-11-26 00:3xZ)

- Sixth corpus, GitHub `search/code` via authenticated `gh api`; non-header
  counts 46/86/55 for the three metadata init spellings, 22 for
  `DRWAV_WITH_METADATA`. Raw fetched sources in `consumer/evidence/w16-github/`.
- GNUbase/GNUbase: `ext/dr_libs` submodule `fa931f32...` = byte-identical to
  the pinned vulnerable `wav-0.14.5`. `src/engine/audiofile/reader.cpp:76-77`
  runs `drwav_init_with_metadata()` on a FILE opened by `AudioFileReader::
  open(path)` (`:327-348`); `src/engine/document/audiofilecommands.cpp:108-143,
  191` registers `audioFile.import(files)` and calls `readInfo(path)`.
  `src/mcp/server.cpp:82-85,222-231` exposes each engine command as an MCP
  tool; `src/mcp/transport.cpp:71-108` serves `POST /mcp` on loopback with a
  Bearer token (`:42-50`). A loopback request can invoke the vulnerable
  parser by naming a local WAV path.
- Preserved limit: the wire supplies a path, not the WAV bytes; no upload or
  download endpoint writes attacker-chosen WAV content. No build, process,
  HTTP request, ASan report, marker or side effect. The r5 wire-BYTE half is
  unmet; grade unchanged (rung 3 / rung 4 lab marker), r5 UNKNOWN.
- Other candidates negative: sleeping-dogs-custom-radio pins 0.14.6 and its
  ICY HTTP path feeds PCM, QVoiceBridge uses non-metadata init, weave has a
  local-path call with no network origin. Full chain and disposition:
  `consumer/evidence/w16-github-callers.txt`.

## W21 — GNUBase wire-byte ceiling closed at source (2026-11-26 06:4xZ)

- Reconciled the unknown-ending W20 wake (`...1795670126605932097`, attempt
  37): it left 732 objects (one more than W20's 731), no `bin/gnubase`, no
  running build, and no drwav/reports dirt. Its background ninja died with the
  one-shot wake; nothing to undo. Tape 06:43Z: no W1-W4 verdict; not re-offered.
- Bounded source check completes the r5 question for GNUBase: the only HTTP
  route is `POST /mcp` with a JSON-RPC body and a Bearer token on loopback
  (`mcp/transport.h:23-28`, `transport.cpp:93-115,143-145`). `base64()` in
  `mcp/server.cpp:63-66` is used only for image OUTPUT (`:287-289`). A source
  sweep for `multipart|form-data|upload|write_file|WriteFile|ofstream|fwrite`
  found only engine-local writers (settings/JSON, audio export, peaks cache,
  PNG save, generated Lua docs, pluginhost logs) — nothing writes request
  bytes to a file that `audioFile.import` feeds to
  `drwav_init_with_metadata()`. The request names an existing local path.
- Consequence: even a linked GNUBase is a request-reachable *file-path*
  caller, not a wire-byte caller. R5 stays UNMET. Source-level ceiling, not
  an execution result: no process, request, ASan report, marker or side effect
  was observed for this check. Evidence
  `consumer/evidence/w21-wire-byte-ceiling.txt`. Grade unchanged: rung 3
  public API / rung 4 lab marker; r5 UNKNOWN.

### W21 — GNUBase build ceiling (2026-11-26 06:41-06:55Z)

Reconciled W20's unknown-ending wake first: 732 objects, no `bin/gnubase`, no
running build, no drwav/reports dirt; its background ninja died with the
one-shot wake, so nothing was undone. Tape 06:43Z: no W1-W4 verdict.

Two bounded build chunks (`06:44-06:47Z timeout 165 -j4`,
`06:48-06:50Z timeout 105 -j4`) made ZERO compiles: `.ninja_log`'s newest
entry remained W20's 05:25Z `recording.cpp.o`. The first cause was CMake's
`VerifyGlobs.cmake_force` phony plus `RERUN_CMAKE` edge regenerating themselves
in the gitignored build.ninja; both were removed at 06:48Z (grep count 0),
leaving 179 steps in `ninja -n`. A 25s `-v` run then showed ninja starting
`[1/179] clang++ ... projectmodel.cpp.o` without finishing it at load 8.4 with
7 GiB swap used. No compiler error. With 179 steps and one compile exceeding
105s, no link was possible inside this wake; `consumer/run-gnubase.sh` was
never run, so no GNUBase process, HTTP request, ASan report, marker or side
effect was observed. Combined with the source-level wire-byte ceiling above,
the research lane is closed here. Grade unchanged and final: rung 3 / rung 4
lab marker author-only / r5 UNKNOWN. W1-W4 verdicts remain UNKNOWN and are
not re-offered.
