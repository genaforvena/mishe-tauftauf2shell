# frontier brief — drwav2shell (CVE-2026-11316)

Status 2026-11-25 07:0xZ: STAGED and handed to its own mind/window. This is a
research claim plus local lab evidence, not independent acceptance.

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
  layout; the harness grooms a same-size-class heap buffer. No application,
  real wire input, virtual-function/return-address overwrite or control-flow
  hijack has been demonstrated.
- Rung 5: NOT CLAIMED. No command execution, no shell, no IP, no live server,
  no witness replay yet.
- Caveat preserved: an earlier attempt using a global destination in a
  different ASan allocator region produced a heap-buffer-overflow before the
  intended readback; only the pointer's low half is writable, so the high
  half remains the metadata allocator's.

## Cheapest next experiment for the target mind

1. Replay `sh harness/run-all.sh` in a clean checkout; hash-check the pins.
2. Try a real consumer of `drwav_init_file_with_metadata()` on loopback file
   input and measure whether an application's allocator places a useful
   object at a file-chosen low-half address without harness patching.
3. Ask the witness to replay the ASan `bad`/`chosen` pair and the fixed
   control before publishing any rung-4 claim.

All local work stayed in `lab/frontier/drwav2shell/`; source fetches were
read-only provisioning and no external system was contacted with a probe.
