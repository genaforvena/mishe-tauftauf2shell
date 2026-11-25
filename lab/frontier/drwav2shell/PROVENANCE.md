# drwav2shell — provenance

## Provisioning

- Public claim: Cisco Talos TALOS-2026-2442, published 2026-11-24,
  https://talosintelligence.com/vulnerability_reports/TALOS-2026-2442 ,
  CVE-2026-11316 / CWE-787, CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H,
  confirmed vulnerable dr_libs 0.14.5. Vendor had not replied; the advisory
  gives no fix commit. Read-only provisioning; no external target probed.
- Upstream source fetched 2026-11-25 from https://github.com/mackron/dr_libs
  at tags `wav-0.14.5` (`fa931f3285ced10ace628f7f1ac951e1951e7ea6`) and
  `wav-0.14.6` (`35b5c392cc15456736c440a68dbe073178bbffe0`) into
  `src/vuln/` and `src/fixed/` (shallow clones, provisioning only).
- `pins/vuln/dr_wav.h` and `pins/fixed/dr_wav.h` are verbatim copies of the
  single header from those tags; `pins/pins.sha256` records all three hashes.
  Rendered line numbers are claims; the pinned bytes and hashes are evidence.

## Stand-in boundary and edits

- `harness/harness.c` is locally written. No dr_wav source was modified.
  Both builds include the verbatim public single header with
  `DR_WAV_IMPLEMENTATION` and call the real public API
  `drwav_init_memory_with_metadata()` on a 150-byte in-memory RIFF file
  built by the harness (`fmt`, `data`, mismatched `smpl`, two-point `cue`).
- The harness patches the 32-bit low half of a lab-chosen buffer address into
  the first cue point's `blockStart` field before calling the library. This is
  heap grooming, not a pure wire-only pointer claim. The 0x41414141 control
  uses file bytes verbatim. The `value` word (`0x4841434b`, "HACK") and all
  other cue bytes are file-carried.
- Only the memory allocator, ASLR and lab heap layout make the high half of
  the hijacked pointer equal to the destination's high half; this is recorded
  as a condition, not as attacker-controlled pointer width.

## Build matrix and results (2026-11-25 07:02Z, this host)

```
gcc  -O0 -g -fsanitize=address -I ../pins/vuln  -o vuln-asan harness.c
gcc  -O0 -g                  -I ../pins/vuln  -o vuln-plain harness.c
gcc  -O0 -g -fsanitize=address -I ../pins/fixed -o fixed-asan harness.c
gcc  -O0 -g                  -I ../pins/fixed -o fixed-plain harness.c
clang -O0 -g -fsanitize=address -I ../pins/vuln  -o vuln-asan-clang harness.c
```

`sh harness/run-all.sh` → 25 PASS / 0 FAIL (`harness/evidence/run-all.log`).

- Vulnerable 0.14.5, ASan and clang ASan `chosen`: clean exit, file-chosen
  `4b43414842424242` read back in the lab-chosen destination; 
  `init=OK metadataCount=1` while two metadata chunks were parsed.
- Vulnerable 0.14.5, ASan and clang ASan `bad` (cue point low pointer
  `0x41414141`): ASan `SEGV on unknown address 0x50f041414155`, WRITE access,
  stack `drwav__read_cue_to_metadata_obj` → `drwav__metadata_process_chunk` →
  `drwav_init__internal` → `drwav_init_memory_with_metadata`.
- `safe` (matching `smpl` loop count): metadataCount=2, no chosen word, no
  sanitizer error. Fixed 0.14.6 `chosen`, `bad` and `safe`: all clean; no
  chosen word and no ASan error. Plain and fixed-plain lanes agree.
- Negative preserved: an earlier 64-byte global destination in a different
  ASan allocator region did not receive the write; because only the low
  pointer half is overwritten, the high half stays in the metadata allocator's
  region. This is why the destination is a heap buffer of the same size class
  as the metadata block.

## Clean archive replay (2026-11-25 07:03Z)

`git archive HEAD lab/frontier/drwav2shell | tar -x -C /tmp/drwav-clean`,
then `sha256sum -c pins/pins.sha256` (3 files OK) and `sh harness/run-all.sh`
in the extracted tree: 25 PASS / 0 FAIL in
`harness/evidence/run-all-archive.log` (not committed; replay log lives in the
throwaway tree). Commit that carried the archive: `0a0ec93f`.

## W8 consumer dependency replay (2026-11-25 19:10Z)

Public source indexes and raw GitHub reads identified three real consumers
whose pinned dr_wav bytes contain the same `smpl`/`cue` desync: sphaira,
Moondust and yup. The exact headers were fetched from the revisions recorded
in `consumer/evidence/w8-consumer-headers.txt` and compiled unchanged with
`harness/harness.c`. No consumer or library source was modified. The replay
used the same in-memory 150-byte RIFF and ASan build flags as the primary
0.14.5 lane; raw output is in `consumer/evidence/w8-*-{chosen,bad,safe}.out`.

This proves the dependency bytes, not execution of the applications. Source
tracing found sphaira's network-mount -> file browser -> music player ->
`drwav_init_with_metadata()` path, but its Switch-only toolchain prevents a
native loopback replay in this plant. All network access was source
provisioning; no external target was probed.
