# Provenance — OpenJPEG OSV-2025-219 harness

All sources below were fetched read-only on 2026-11-21 ~14:38Z from the named
public endpoints (provisioning only; no probe of any external system). Their
SHA-256 digests are recorded in `src/SHA256SUMS` and checked by `run.sh` before
anything is built; a mismatch exits 2 with no build.

| Pin | Source | SHA-256 |
| --- | --- | --- |
| `osv-OSV-2025-219.json` | `https://api.osv.dev/v1/vulns/OSV-2025-219` | `a1993794c3e78330d334cac4134cb8c9d6256e1767810b36c88bacab1165f0fe` |
| `issue-1620.json` | `https://api.github.com/repos/uclouvain/openjpeg/issues/1620` | `fe5fe56abb02834f53198d06f63c9ff482e0a2baf3a4d07d64ceeb0fb295ecf7` |
| `pr-1621.json` | `https://api.github.com/repos/uclouvain/openjpeg/pulls/1621` | `7a2b5906f5bb0b45260ead2d3c32940ad2420e04d0923aa1d22e1d4139dd634a` |
| `commit-91d08b11.json` | `https://api.github.com/repos/uclouvain/openjpeg/commits/91d08b11a72764f6d199f32fa0c1b1abd4edc2ad` | `f2098000ee5ef9c9a290eedd2bd04516f611ca4ec18a422cd4df3b9a75909861` |
| `fix-91d08b11.patch` | `https://github.com/uclouvain/openjpeg/commit/91d08b11a72764f6d199f32fa0c1b1abd4edc2ad.patch` | `233bf4c149d7740dd802c36c3e78e80352454b27d5579c1a4ef3260c2f4e90a1` |
| `openjpeg-2.5.4.tar.gz` | `https://github.com/uclouvain/openjpeg/archive/refs/tags/v2.5.4.tar.gz` | `a695fbe19c0165f295a8531b1e4e855cd94d0875d2f88ec4b61080677e27188a` |
| `openjpeg-fixed-91d08b11.tar.gz` | `https://github.com/uclouvain/openjpeg/archive/91d08b11a72764f6d199f32fa0c1b1abd4edc2ad.tar.gz` | `01e3d3235149e5a9f8f22cb60129d963f6642c6dfb96aedbb1da7e3992f9890c` |
| `poc.j2k` | `https://github.com/user-attachments/files/24751832/poc.zip` (issue #1620, raw JPEG 2000 codestream despite the `.zip` name) | `90629e28a6820f2e6106562e85dcfdea5eef59e79476c68bfea163c70b85008a` |

The advisory/PR/commit JSON pins were byte-stable on re-fetch at the time of
writing. The fix is merged into upstream `master` at `d33cbecc` (2026-02-10)
with no tagged release; OSV still lists v2.5.3 and v2.5.4 as affected. Every
fixed-side claim in the brief is therefore scoped to the pinned commit
`91d08b11`, NOT to a released version.

## Verbatim components

- `run.sh` extracts both pinned tarballs into a fresh output directory and
  builds the real `opj_decompress` binary with CMake for three configurations:
  vulnerable + ASan, vulnerable + no sanitizer, and pinned-fix + ASan. No
  OpenJPEG source file is edited, copied into the harness or patched at build
  time. `BUILD_CODEC=ON`, `BUILD_SHARED_LIBS=OFF`, `CMAKE_BUILD_TYPE=Debug`;
  ASan builds add `-fsanitize=address -fno-omit-frame-pointer -g -O1`.
- `src/poc.j2k` is the public PoC verbatim. `src/make-pad.py` is harness-authored:
  it inserts one benign COM marker segment (2-byte marker, 2-byte length,
  2-byte Rcom, 378 filler bytes = 384 bytes total) before the first SOT. It
  changes no other PoC byte; the resulting file is written into the output
  directory, never into a source tree.
- gdb observation uses an unsanitized build so the write completes; the ASan
  reports come from a separate build of the same pinned source. The gdb
  `printf` records only port numbers, tile indices and the two written values:
  no PID, address or path enters the trace digest.

## Harness stand-ins and labels

- The "OOB +32/+40" offsets are `tp_index[1].end_header` and
  `tp_index[1].end_pos` relative to a one-entry (24-byte) allocation. They are
  determined by the crafted SOT `TPsot=1`, not by a harness shim. The inspected
  bytes are read back with gdb from the adjacent heap area; that area is NOT an
  identified live application object. Rung 4 is INSTRUMENTED chosen-value
  writes at chosen offsets, not neighbour-object control.
- The written values are 64-bit `OPJ_OFF_T` stream offsets (157/159 in the
  public PoC, 541/543 after padding), not arbitrary 8-byte payloads and not
  32-bit values. The earlier scout note calling them "attacker-controlled
  32-bit" was wrong and is preserved here as a correction.
- No JPEG 2000 application, image decoder service, socket, listener, real heap
  neighbour object, pointer value, control-flow diversion or execution was
  observed. All remain UNKNOWN. A Pillow/libopenjp2 consumer route is
  plausible from public metadata but was not built or tested here.

## Build and replay

`bash run.sh <absolute-outdir>`: verifies pins, extracts, builds all three
configurations, replays the public and padded PoCs under ASan, observes the
sink under gdb, prints ten PASS/FAIL lines and a stable trace digest hashing
only those PASS lines. Local processes only; no network access at replay time.
