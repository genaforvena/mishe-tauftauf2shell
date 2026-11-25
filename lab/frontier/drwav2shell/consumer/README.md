# drwav2shell — real-consumer lane (W1, 2026-11-25)

## What is exercised

`wav_decoding.c` is a verbatim copy of upstream dr_libs `wav-0.14.5`
`tests/wav/wav_decoding.c` (tag `fa931f3285ced10ace628f7f1ac951e1951e7ea6`).
Together with `wav_common.c` and `tests/common/dr_common.c`, whose hashes are
in `consumer.sha256`, it is an unmodified test consumer shipped by the library.
Its `decode_test_file()` calls the public
`drwav_init_file_with_metadata(&wav, path, 0, NULL)` on files found in
`tests/testvectors/wav/tests/`. The vulnerable and fixed builds use the
verbatim pinned headers in `pins/`; no consumer or library source is patched.

`make_wav.py` writes the 150-byte RIFF from attacker-supplied fields only:
pointer low half, stored word and `smpl` loop count. It never reads process
memory. `run-consumer.sh` builds both headers, writes the file, runs the
consumer from the crafted-file directory and records raw output in
`consumer/evidence/`.

## Measured result (GCC, ASan, 2026-11-25 09:04Z)

`sh consumer/run-consumer.sh` → 18 PASS / 0 FAIL.

- Vulnerable build, file low pointer `0x41414141`: ASan `SEGV on unknown
  address 0x50f041414155`, `WRITE`, frame 0
  `drwav__read_cue_to_metadata_obj()` at pinned `dr_wav.h:2306`, reached from
  `drwav_init_file_with_metadata()` at `:5390` and unmodified
  `decode_test_file()` at `wav_decoding.c:319`. Process exits 1. This is rung 3
  in a real library consumer through the public on-disk file API, with no
  harness source patch.
- Vulnerable build, matching `smpl` loop count: consumer passes, rc 0, no
  sanitizer error. Fixed 0.14.6 build with the same attack file: consumer
  passes, rc 0, no sanitizer error.
- Chosen-pointer row: with the file carrying low half `0x40`, a gdb breakpoint
  at `wav_decoding.c:326` shows `wav.pMetadata = 0x50f000000040`,
  `metadataCount = 1` for two parsed chunks, and the file words
  `0x4841434b`/`0x42424242` at `wav.pMetadata+24` (`0x50f000000058`).

## Conditions and negatives (preserved)

- `0x40` is the low half of the live metadata array measured under
  `setarch -R gdb` in this build. It is not attacker-known without an address
  leak or a matching deterministic layout; this is an instrumented observation,
  not an RCE claim.
- In the ASan build, the application-owned 150-byte buffer
  `libsndfile.pFileData` sits at `0x50e000000040` while the metadata array sits
  at `0x50f000000040`. Because only the low 32 bits are file-controlled, that
  particular buffer is out of reach in that allocator layout. W2 below shows
  a different, plain-build layout where a same-heap application buffer is
  reachable.
- No wire input, pointer-to-IP overwrite, control-flow diversion, command,
  shell, live service or witness verdict for this lane. Rung 5 is not claimed.

## Application-owned destination (W2, 2026-11-25 11:13Z)

`run-appdest.sh` builds the unmodified consumer without ASan against both
pinned headers. Under `setarch -R gdb` it measures the live
`libsndfile.pFileData` address (the consumer's own whole-file buffer) and
writes a 150-byte file whose pointer low half is `pFileData - 24`. No source
is patched and no address is put into the file by any harness hook: the file
bytes alone retarget the cue write. At `wav_decoding.c:326` the file words
`0x4841434b`/`0x42424242` are read back at `libsndfile.pFileData`; the
uninstrumented consumer then passes with rc 0. Same-file fixed-header and
matching-`smpl` controls leave the buffer unchanged.

`sh consumer/run-appdest.sh` → 11 PASS / 0 FAIL; raw output is in
`evidence/appdest-*.out`. This is rung 4 with an application-owned destination,
still leak-dependent: the low pointer came from a fixed-ASLR lab measurement,
not from the file. No wire, pointer-IP, control flow, command, shell, rung 5
or witness verdict.

All runs are local; no probe left the host.

## Leak-free fixed-address write (W3, 2026-11-25 12:16Z)

`run-nopie.sh` builds the same unmodified consumer with `-no-pie`. The brk
heap and the binary's globals then both sit below 4 GiB (measured
`wav.pMetadata=0x42d850`, `libsndfile.pFileData=0x42da40`, globals at
`0x41e108`/`0x41e118`), so the high 32 bits of the hijacked cue pointer are
zero. The RIFF's pointer-low field is the full write address: a file with
`0x41e0f0` puts the chosen words in `g_libsndfile` at `0x41e108`, and
`0x41e100` puts them in the function-pointer global `libsndfile__sf_close`
at `0x41e118` — no address leak, no `setarch -R`, no debugger write, no
source patch. `sh consumer/run-nopie.sh` → 11 PASS / 0 FAIL; fixed-header
and safe-loop controls clean; uninstrumented replay faults later (rc 139)
when the corrupted global is used. Raw output in `evidence/nopie-*.out`.
This is rung 4 at a fixed application address in a non-PIE build, not a
control-flow hijack or rung 5; no witness verdict.

## File-chosen control-flow diversion (W4, 2026-11-25 12:53Z)

`run-marker.sh` (14 PASS / 0 FAIL) uses `make_marker_wav.py` to set six cue
fields that, through the same desync, overwrite `libsndfile__sf_close`
(0x41e118), `libsndfile__sf_readf_short` (0x41e120) and
`libsndfile__sf_readf_int` (0x41e128) in the -no-pie consumer. The file names
a lab-only benign marker object built at fixed text segment 0x50000000 and
loaded with `LD_PRELOAD`; the vulnerable consumer calls it from
`libsndfile_uninit` and the marker writes an observed file, confirmed by gdb
backtrace. Fixed 0.14.6 and safe-loop controls leave no marker file. Raw
output in `evidence/marker-*.out`. This is rung-4 mechanics — the marker is
lab-injected, with no wire/request input, command, shell or r5 — and remains
author replay with no witness verdict.

## Exact consumer dependency headers (W8, 2026-11-25 19:10Z)

The unchanged `../harness/harness.c` was also compiled against the exact
dr_wav bytes pinned by three real consumers: sphaira 0.14.1, Moondust 0.14.1
and yup 0.14.3. Each header reproduces the same chosen-word write and
`metadataCount=1` desync; the `0x41414141` control faults on an ASan WRITE at
`0x50f041414155`; the matching-loop control is clean with count 2 and no
chosen word. Raw output is in `evidence/w8-*-{chosen,bad,safe}.out`; exact
source URLs, revisions and SHA-256 values are in
`evidence/w8-consumer-headers.txt`.

This is header-byte replay, not execution of those applications. Source
tracing separately found that sphaira can pass network-mounted file bytes to
`drwav_init_with_metadata()` through its music player, but sphaira is a
Nintendo Switch/Switch 2 application with no native Linux target. No live
wire-triggered corruption or r5 was observed. Moondust is local-file-only and
yup's stream origin is caller-supplied.

## One-command replay and indexed-caller negatives (W10, 2026-11-25 20:18Z)

From a clean archive of this lane, the whole lab replays with one command:

```
git archive HEAD lab/frontier/drwav2shell | tar x -C /tmp/drwav-replay
cd /tmp/drwav-replay/lab/frontier/drwav2shell
sh replay-frontier.sh
```

At commit `1ac6b479` this produced harness 25 PASS / 0 FAIL, consumer 18/0,
appdest 11/0, nopie 11/0, marker 14/0 and `REPLAY_FRONTIER_OK` (rc 0, 24 s).
The summary and raw per-lane output land in `evidence/replay/`. This is an
author replay, not a witness verdict.

Two source-index angles bound the remaining r5 prerequisite:

- Debian Code Search's `/grep` endpoint returned only vendored `dr_wav.h`
  definitions: 21 hits for `drwav_init_with_metadata`, 28 for
  `drwav_init_file_with_metadata`, 14 for `drwav_init_memory_with_metadata`
  and 24 for `DRWAV_WITH_METADATA`; adding `-path:dr_wav.h` gave 0 results for
  each. Raw queries and hits: `evidence/w10-debian-codesearch.txt`.
- Vulnerable `dr_wav.h:3897` shows `drwav_init_ex()` does not set
  `DRWAV_WITH_METADATA`; only `drwav_init_with_metadata()` (`:3906`, bit OR
  at `:3912`) does. Consumers using `init`, `init_ex`, `init_file` or
  `init_memory` therefore cannot reach the desync even on vulnerable bytes.
- A Sourcegraph literal search for `DRWAV_WITH_METADATA -file:dr_wav.h` found
  one caller, yup's `WaveAudioFormatReader` at
  `modules/yup_audio_formats/formats/yup_WaveAudioFormat.cpp:78-85`, already
  known from W8 and without an in-repo network stream origin.

No native remote-input metadata-API caller was measured. Index coverage is
not proof of absence, and no wire-driven corruption, command, shell or r5 is
claimed.
