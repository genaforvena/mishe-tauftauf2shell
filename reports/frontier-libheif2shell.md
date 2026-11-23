# Frontier brief: libheif mixed-size padding heap overflow — GHSA-hpg4-g2gc-pq42 (libheif2shell)

**STAGED 2026-11-23 W157 — direct-call harness evidence, a live registered
two-pane window (inner socket index 117, name `libheif2shell`) and a staging DM
to the operator (#2596) exist; operator admission and an independent witness
verdict are pending.** Byte-exact pins and hashes:
`lab/frontier/libheif2shell/PINS.sha256`; harness provenance including preserved
negative results: `lab/frontier/libheif2shell/PROVENANCE.md`. Frontier owns no
further work on this target.

## 1. Verified ground truth

- Advisory: GHSA-hpg4-g2gc-pq42, published 2026-10-26 by farindk, High 7.5,
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, CWE-122, "Heap buffer overflow
  when padding mixed-size sequence frames" —
  https://github.com/strukturag/libheif/security/advisories/GHSA-hpg4-g2gc-pq42
  No CVE number is stated in the advisory: **UNKNOWN**. Credit: Anthropic's OSS
  Scanner, ANT-2026-QL0PMTMT.
- Affected: libheif >= 1.15.0, < 1.23.7 (public padding API); the file-triggered
  x265 sequence path first shipped in 1.21.0. Patched: 1.23.7, described as the
  planned release at advisory time. The vulnerable pin is tag `v1.23.6`.
- Upstream fix `9ec655f76b6fe298092aaeb063f821f53b8eb901` is named by the
  advisory. The advisory's 1,155-byte Motion-JPEG sequence, 36,879-byte
  allocation, 64-byte write and release-build SIGSEGV are **claims from the
  advisory**, not reproduced in this lab.
- No target by this name appears in the plant's do-not-duplicate list, brief set
  or window registry.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; pinned bytes live in
`src/pixelimage.cc.{vuln,fixed}` and `src/heif_image.cc.{vuln,fixed}` and are
included verbatim under `#line` control in the generated drivers.

In `HeifPixelImage::extend_padding_to_size()` at `pixelimage.cc.vuln:597-690`,
the reallocation condition at `:623-624` fires when either memory dimension of
the plane is smaller than the requested subsampled dimension. The replacement
plane is allocated at exactly `subsampled_width x subsampled_height` (`:629`),
but the copy loop at `:643-647` copies every row of the old plane at the old
width using the *new* stride. Nothing checks that the old plane fits the new
allocation in both dimensions. A 64x65 plane asked to pad to 512x64 is
reallocated as 512x64 (32768 bytes), then 65 rows of 64 bytes are written at a
512-byte stride; row 64 starts at offset 32768, and the right-edge fill reaches
offset 33279.

The advisory documents the same mismatch from the x265/x264 sequence path: a
512x64 first frame fixes the encoder's coded size, then a 64x512 later frame is
padded to 512x64 while its 512 rows are copied.

Fix `9ec655f` adds three things to the method: a logical-size guard
(`width < m_width || height < m_height`) at `pixelimage.cc.fixed:611-615`, a
preflight loop verifying every plane fits the requested subsampled dimensions
before any plane is changed (`:619-643`), and restoration of the plane's logical
dimensions after reallocation (`:687-690`). It also rejects negative sizes in
the public API wrapper at `heif_image.cc.fixed:403-407` and adds fixed-size
frame checks in the sequence encoder plugins. Only the two source files needed
for the direct-call path are pinned here.

## 3. Cheapest local experiment

Two generated C++ drivers include verbatim slices of the pinned method and the
public API wrapper. Stubs are the surrounding enums/value types, a reduced
component struct, the documented Y/monochrome identity for
`get_subsampled_size`, and a plane allocator that is exact under ASan and
canary-backed in plain builds. No codec, image file, sequence encoder, process,
socket or network is involved.

```
cd lab/frontier/libheif2shell/harness
./run.sh && ./check.sh
```

Three scenarios: an unchanged 64x65 request, the 64x65 -> 512x64 mismatch, and
a valid 64x64 -> 512x128 growth. Debugger commands are in `PROVENANCE.md`.

## 4. Rung-4 feasibility and risks

Favorable: the vacuous dimension check, the reallocation and the row-copy loop
are all in verbatim pinned bytes; both gcc and clang ASan classify the store at
`pixelimage.cc.vuln:644`; the fixed pin rejects the same request before any
copy; plain builds and gdb show chosen bytes landing byte-exact past the
declared plane. 101 PASS / 0 FAIL on three runs; trace
`9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43`.

Limits: the harness calls the public API wrapper with a verbatim method body,
but the enclosing types and allocator are stubs. There is no HEIF or Motion-JPEG
file, no decoder, no x265/x264 encoder plugin, no libheif build, no image
consumer, and no process, socket or wire input. The advisory's file-triggered
path and its 36,879-byte allocation are claims this wake did not test. Chosen
bytes are harness-supplied source bytes, not bytes derived from a crafted file.
No pointer or control-flow corruption was exercised.

## 5. Observations

- Rung 1: a 64x65 plane with a 512x64 padding request returns success on the
  vulnerable build; the new plane's stride is 512 and its declared size is 32768.
- Rung 2: the fixed build returns 2 (`heif_error_Usage_error`) with "Cannot
  extend padding to a size smaller than the image." and copies nothing.
- Rung 3: gcc and clang ASan report `heap-buffer-overflow`, `WRITE of size 64`,
  0 bytes after a 32768-byte region, at pinned `pixelimage.cc.vuln:644`, with
  the call stack through `heif_image.cc.vuln:403`.
- Rung 4: plain builds report `b32768=5a b32769=5a b32770=5a b32771=5a` against
  a `0xa5` canary; gdb reports `rc=0 stride=512` and four `0x5a` bytes at
  `mem + 32768`.
- Preserved negatives: a C-compiler link failure, LeakSanitizer noise from
  harness buffers, a too-small canary tail that broke `free`, and a gdb attempt
  with an out-of-scope local. All were corrected and are described in
  `PROVENANCE.md`.

## 6. Ceiling / handoff

Ceiling measured: direct-call CODE/HARNESS rungs 1-4 only. No witness verdict,
no real libheif build or file path, no wire input, no pointer control, no
command execution. Rung 5 is UNKNOWN and unproven. A dedicated `libheif2shell`
mind would need to reproduce the advisory's mixed-size sequence against patched
and unpatched libheif builds with a real x265/x264 encoder, then measure whether
the overwrite reaches a pointer that is used before the process aborts. Frontier
owns no further work on this target.
