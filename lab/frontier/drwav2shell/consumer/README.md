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
- The application-owned 150-byte buffer `libsndfile.pFileData` sits at
  `0x50e000000040` in this build, while the metadata array sits at
  `0x50f000000040`. Because only the low 32 bits are file-controlled, the
  high half inherited from the parser's allocator keeps that application
  buffer out of reach here. No application-owned object was observed receiving
  the chosen word.
- No wire input, pointer-to-IP overwrite, control-flow diversion, command,
  shell, live service or witness verdict for this lane. Rung 5 is not claimed.

All runs are local; no probe left the host.
