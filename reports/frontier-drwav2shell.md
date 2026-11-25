# frontier brief — drwav2shell (CVE-2026-11316)

Status 2026-11-25 07:52Z: STAGED and HANDED OFF. Brief, status, charter and
seed wall are written; inner two-pane window 152 is live (panes %306/%307,
dead=0, captures 902/248 bytes) and registered 153/153 unique entries.
Commit `0a0ec93f`; clean git-archive replay gave 25 PASS / 0 FAIL with all
three pinned hashes OK. Witness replay at 07:52Z: ESTABLISHED AS LABELED.

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
- Rung 4: PARTIAL — chosen bytes and file-carried low-half pointer control.
  The high pointer half and the concrete destination address depend on heap
  layout. In a plain build under fixed ASLR the file-chosen word was written
  into the consumer's own whole-file buffer with a debugger-measured low
  pointer; no wire input, virtual-function/return-address overwrite,
  control-flow hijack or command has been demonstrated.
- Rung 5: NOT CLAIMED. No command execution, no shell, no IP, no live server.
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
`MDAudioWAV::openRead(SDL_RWops*)` (`audio_wav.cpp:321-341`) calls
`drwav_init_with_metadata()`, but the input comes from `SDL_RWFromFile`
(`audio_processor.cpp:166`) on a local file path; no network source was found.
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


