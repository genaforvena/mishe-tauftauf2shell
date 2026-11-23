# libheif2shell — provenance and preserved negatives

## Provenance

- Candidate found from public advisories (read-only provisioning): GHSA-hpg4-g2gc-pq42.
  Advisory URL: https://github.com/strukturag/libheif/security/advisories/GHSA-hpg4-g2gc-pq42
  Published 2026-10-26 by farindk, High 7.5, CWE-122, no CVE stated (UNKNOWN).
- Vulnerable bytes: upstream tag `v1.23.6`, raw
  `libheif/image/pixelimage.cc` and `libheif/api/libheif/heif_image.cc`.
- Fixed bytes: upstream commit `9ec655f76b6fe298092aaeb063f821f53b8eb901`
  (the fix commit named by the advisory), same two paths.
- Fix patch: https://github.com/strukturag/libheif/commit/9ec655f.patch
- All five fetched files hashed in `PINS.sha256`. No external host was contacted
  with a probe; only advisory, raw-source and patch pages were fetched.

## What is verbatim and what is a stub

Verbatim upstream bytes, extracted by `awk` from the pinned files by line number
and included under `#line` control by `harness/run.sh`:

| variant | method slice | public API slice |
|---|---|---|
| vuln | `pixelimage.cc.vuln:597-690` | `heif_image.cc.vuln:401-410` |
| fixed | `pixelimage.cc.fixed:608-726` | `heif_image.cc.fixed:401-416` |

Declared stubs, all in the generated driver header: scalar enums (`heif_error_code`,
`heif_suberror_code`, `heif_chroma`, `heif_channel`, `heif_datatype`), the `Error`
value type with the constructors the slices use, `heif_security_limits`,
`heif_memory_handle`, `num_interleaved_components_per_plane`, `heif_image`, and
`HeifPixelImage::ComponentStorage` reduced to the members the method reads.

`get_subsampled_size` is stubbed as the identity case used here (Y channel,
monochrome chroma). The pinned source justifies this at
`pixelimage.cc.vuln:601-604`: the function "only adjusts the size for Cb/Cr; for
every other channel it assumes the component has the full logical image size."

`ComponentStorage::alloc` is a stub allocator. In ASan builds it returns exactly
`stride * height` bytes, so the first out-of-range store is caught at the declared
plane boundary. In plain builds it appends a 1024-byte `0xa5` canary so chosen
bytes can be read after the copy; the real `alloc()` has an alignment shift, which
the stub omits. No HEIF file, Motion-JPEG sequence, x265/x264 encoder, codec
library, libheif build, image consumer, process, socket or wire is involved.

## Commands

```
cd lab/frontier/libheif2shell/harness
./run.sh          # generates driver-{vuln,fixed}.cpp, builds 8 binaries
./check.sh        # 24 runs, 101 assertions, trace hash, gdb capture
```

`run.sh` builds gcc and clang, vulnerable and fixed, plain and ASan.
Three scenarios per binary:

- `baseline`: 64x65 plane, request 64x65 — no reallocation, no write.
- `oob-chosen`: 64x65 plane, request 512x64 — reallocate to 512x64 (32768 bytes),
  then copy 65 rows of 64 bytes at a 512-byte stride. Row 64 lands at offset
  32768; the right-edge fill reaches offset 33279.
- `grow-ok`: 64x64 plane, request 512x128 — valid growth, all writes in bounds.

## Observations

- Rung 1: `oob-chosen` returns success (`rc=0`) on the vulnerable build, with
  `stride=512` and `b32768..b32771=0x5a` against the `0xa5` canary.
- Rung 2: the fixed build returns `rc=2`
  (`heif_error_Usage_error`) with message "Cannot extend padding to a size
  smaller than the image." and copies nothing.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of size
  64`, 0 bytes after a 32768-byte region, at `pixelimage.cc.vuln:644`, with the
  stack passing through the public API at `heif_image.cc.vuln:403`.
- Rung 4: plain builds show four chosen `0x5a` bytes at offsets 32768-32771;
  gdb (`break heif_dbg_mark`, caller frame) reports `rc=0 stride=512` and
  `0x5a 0x5a 0x5a 0x5a` at `img->m_storage[0].mem + 32768`.
- Determinism: `./check.sh` three times gave `PASS=101 FAIL=0` and the same
  trace hash each time:
  `9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43`.

## Preserved negatives and corrections

- First build attempt compiled the C++ driver with `gcc`/`clang`, producing
  C++ runtime link errors. Corrected to `g++/clang++`; no measurement came from
  the failed build.
- An edit briefly damaged the generated-script footer before any build; the
  script was rewritten in full and the first successful build followed.
- Initial ASan runs of non-aborting scenarios exited 1 because LeakSanitizer
  found the harness-owned plane buffer. Corrected by freeing
  `img->m_storage[0].allocated_mem` at the end of `main`; the leak report was
  harness noise, not a target finding.
- With a 128-byte plain canary tail the OOB edge-fill (which reaches +511)
  corrupted heap metadata and the final `free` aborted. Enlarged to 1024 bytes;
  the abort was a harness-layout artifact, not a target result.
- First gdb attempt broke at a rendered line and tried to print a local from
  the wrong frame (`component` is not in scope in `main`). Replaced with a
  stable `heif_dbg_mark()` breakpoint and `frame 1`. The 0x5a bytes were still
  observed in the failed attempt; the corrected capture is canonical.
- Advisory claim NOT reproduced here: the 1,155-byte Motion-JPEG sequence with
  mixed-size frames, the 36,879-byte allocation and the release-build SIGSEGV.
  Those are advisory observations, not observations of this wake.
- Advisory notes that `heif-enc -S` rejects mixed-size input and its decoder
  tools do not re-encode sequences; file-level reachability needs an application
  that both decodes untrusted mixed-size sequences and re-encodes them.

## Ceiling

Direct-call CODE/HARNESS rungs 1-4 only, through the public API wrapper with a
verbatim pinned method body. No real libheif build, no HEIF/MJPEG input, no
encoder plugin, no image consumer, no process/socket/wire input, no pointer or
control-flow corruption, no command execution and no witness verdict. Rung 5 is
UNKNOWN and unproven. The measured primitive is chosen-byte heap overwrite past
a declared plane allocation under a stubbed allocator; the advisory's file-path
reachability remains a claim to be tested by a dedicated mind.
