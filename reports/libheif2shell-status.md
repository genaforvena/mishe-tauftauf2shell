# libheif2shell — status

Admitted 2026-11-23 ~12:3xZ under standing approval #6 as the 112th engine
route. Frontier staged this lane in W157 (commit `366690f`) with pinned libheif
tag `v1.23.6` and fix `9ec655f76b6fe298092aaeb063f821f53b8eb901`, verbatim
`pixelimage.cc` / `heif_image.cc` slices and byte-exact hashes. Brief:
`reports/frontier-libheif2shell.md`; pins: `lab/frontier/libheif2shell/PINS.sha256`;
provenance, verbatim slices, generated drivers and raw evidence:
`lab/frontier/libheif2shell/PROVENANCE.md`. The two-pane inner tmux window 117
and its registry entry were already live; admission adopted them and created
no second window.

The hy4-flash `max_parallel: 3` route was added as the 112th role. The path,
debounce and `@libheif2shell` slice drop-in were minted with the exact
full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`), followed by `systemctl --user daemon-reload`; the path
unit is enabled and active. Both `m2shell-wake@libheif2shell.service` and
`m2shell-wake-libheif2shell.path` were added to the site's owner resolver map
(225 entries). The pinned full-flag doctor returned rc 0 with `PASS local plant
out of Git` / `GREEN`; `check-omp-only.py` returned `GREEN (112 declared roles)`.
Admission changes no grade.

- Claim: GHSA-hpg4-g2gc-pq42, published 2026-10-26, High 7.5,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-122; no CVE stated
  (UNKNOWN). Affected libheif >= 1.15.0, < 1.23.7 (the advisory calls 1.23.7
  the planned patched release); vulnerable pin tag `v1.23.6`, fixed by
  `9ec655f`. The advisory's 1,155-byte Motion-JPEG sequence, 36,879-byte
  allocation, 64-byte write and release-build SIGSEGV are claims, not lab
  observations. The AV:N vector is advisory text, not a lab result.
- Primitive: `HeifPixelImage::extend_padding_to_size()` at
  `pixelimage.cc.vuln:623-624` reallocates when either memory dimension is
  smaller than the requested subsampled one; the replacement plane at `:629`
  is allocated at exactly `subsampled_width x subsampled_height`, but the copy
  loop at `:643-647` copies every old row at the old width using the NEW
  stride. A 64x65 plane asked to pad to 512x64 becomes a 512x64 plane (32768
  bytes); row 64 starts at offset 32768 and the right-edge fill reaches 33279.
  Fixed `9ec655f` adds a logical-size guard (`:611-615`), a per-plane preflight
  before any plane changes (`:619-643`) and restores logical dimensions after
  reallocation (`:687-690`).
- Evidence: `lab/frontier/libheif2shell/harness/run.sh` generates two C++
  drivers with verbatim pinned slices under `#line` and builds gcc/clang plain
  and ASan variants; `check.sh` asserts the trace and rung observations.
  Operator admission replay from `git archive 366690f lab/frontier/libheif2shell`
  into a fresh `/tmp/omp-libheif-replay.*` returned rc 0 and exactly
  `PASS=101 FAIL=0 TRACE=9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43`
  (101 assertions over three scenarios plus repeats). Rung 1: the vulnerable
  build returns success for a 64x65 plane padded to 512x64 with a 512-byte
  stride and declared size 32768. Rung 2: the fixed build returns 2
  (`heif_error_Usage_error`) with "Cannot extend padding to a size smaller than
  the image." and copies nothing. Rung 3: gcc and clang ASan report
  `heap-buffer-overflow`, `WRITE of size 64`, 0 bytes after a 32768-byte
  region at pinned `pixelimage.cc.vuln:644`, called through
  `heif_image.cc.vuln:403`. Rung 4: plain builds print
  `b32768=5a b32769=5a b32770=5a b32771=5a` against a `0xa5` canary; gdb prints
  `rc=0 stride=512` and four `0x5a` bytes at `mem + 32768`.
- Ceiling: rungs 1-4 on a direct call to the public API wrapper with a
  verbatim method body; the enclosing types, component struct and plane
  allocator are stubs (exact under ASan, canary-backed in plain builds). No
  HEIF or Motion-JPEG file, decoder, x265/x264 encoder plugin, libheif build,
  image consumer, process, socket, wire input, real allocator study, ASLR
  study, pointer control, ROP, command, marker side effect or rung 5. Chosen
  `0x5a` bytes are harness source bytes, not file-derived bytes or execution.

Next for the target mind: build pinned `v1.23.6` and `9ec655f` with a real
x265/x264 sequence encoder, drive the advisory's mixed-size frames under ASan
and measure whether the overwrite reaches a pointer used before the process
aborts. Hand any new claim to `witness`; the author report is not acceptance.

## W161 real-build file-triggered lane (2026-11-23)

New evidence beyond the harness: pinned `v1.23.6` (f81f28a) built with x265
and JPEG plugins under ASan, and a crafted MJPEG HEIF sequence whose second
frame's SOF declares 64x512 while the track and first frame are 512x64.
`lab/frontier/libheif2shell/real/reencode_sequence.cc` decodes both frames
(512x64 then 64x512) and re-encodes through the fixed-size x265 encoder.
`rebuild_and_run.sh` replays decode-only, mixed and same-size safe inputs;
full commands, hashes and negatives are in `real/PROVENANCE-real.md`.

Observed: vulnerable build aborts with ASan `heap-buffer-overflow`,
`WRITE of size 64`, 0 bytes after a 32783-byte plane at
`pixelimage.cc:644` via `heif_image.cc:403`, `encoder_x265.cc:1139`,
`hevc_enc.cc:189` and `track_visual.cc:620`; same-size input is clean
(rc 0 with LeakSanitizer disabled); patched `9ec655f` build rejects the
mixed file with rc 2 "All frames of a sequence must have the size of the
first frame" and no ASan report. This moves rung 3 from direct-call harness
to the advisory's real decoder-to-encoder file path. Still absent: wire or
remote input, live process, pointer/control-flow target, command or marker,
and witness replay of this new lane. Rung 5 remains UNKNOWN. A third,
non-sanitized Release build of the same pin crashes with SIGSEGV (rc 139) on
the mixed file and exits 0 on the safe input; gdb places the fault in the same
`extend_padding_to_size` memcpy, so the advisory's release SIGSEGV is observed
locally. Its 36,879-byte allocation remains a claim; this build's plane is
32783 bytes.

## W162 file-derived chosen bytes on the real file path (2026-11-23)

Charter option 2 measured what lies past the reallocated plane and whether a
crafted file controls those bytes. On the pinned Release build's plain driver,
gdb breaks on `calloc(1,32783)` and on each 64-byte row copy landing at or
after `plane+32768`. The first neighbours are a malloc chunk header and a
**free** chunk, initially zero; the plane's own chunk header is `0x8021`.
With the W161 uniform JPEG the overwrite bytes were uniform `0x40`. A
patterned second JPEG (committed generator `real/neighbour/make_pattern_sequence.py`,
input `real/neighbour/pattern-mixed.heif` SHA-256
`8f09b93c85341e9e120e75304379a79df11518cb7def4cc2fc6cdee7da151c1c`) decodes
to position-dependent bytes `74*8 82*8 8e*8 9c*8 a8*8 b6*8 c2*8 1a*8`; gdb
reads those exact 64 bytes at `plane+32768` and `plane+33280` after the
stores, and the next free chunk's size field changes `0x3b41` ->
`0x9c9c9c9c9c9c9c9c`. `real/neighbour/check_neighbour.py` asserts the byte
match and metadata overwrite against the saved log (PASS). Full method,
hashes, controls and limits: `real/PROVENANCE-real.md` W162 section.

This is rung 4 on the real decoder-to-encoder file path, limited to file-
derived chosen bytes at chosen offsets and malloc-metadata corruption. The
neighbour is free memory, not a live pointer; the process faults after
~16 KB of further row copies. No wire input, live server, pointer target,
grooming, marker or command. No independent witness verdict on this new lane
yet; rung 5 remains UNKNOWN. A replay request is on the chat tape.
