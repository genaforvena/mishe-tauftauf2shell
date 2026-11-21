# Provenance — hnswlib HNSW index loader capacity/count mismatch (CVE-2026-124959)

All artifacts in `src/` were fetched read-only as provisioning on
2026-11-21 ~13:10Z; nothing was sent to any external host. `run.sh` verifies
every SHA-256 with `sha256sum -c src/SHA256SUMS` before extracting or
compiling; pin drift exits 2. Raw source bytes, not rendered web readers or
the originating writeup, are authoritative for line numbers.

| Pin | SHA-256 | Source |
| --- | --- | --- |
| `src/v0.9.0.tar.gz` | `65dfb6639cb7d1acbdaeec1429b978fb657a9bf368ebb8353109167394537823` | <https://codeload.github.com/nmslib/hnswlib/tar.gz/refs/tags/v0.9.0> |
| `src/fix-280cb597.tar.gz` | `5489c028e55fd52599016fd44b014e56c1f35463fb7bd114298b48b335c4df00` | <https://codeload.github.com/nmslib/hnswlib/tar.gz/280cb5972234dd8297b7e3cc847dcdbcdb114d63> |
| `src/cve124959.json` | `0962ff9fbea34453f545ae07984c6640ce4350429243d7b8aa43e7cea5d476d5` | <https://cveawg.mitre.org/api/cve/CVE-2026-124959> |
| `src/hnswalg-d9b3608.h` | `483d3b3193969ef4c35239849b6385dd1086434a7bae1d8181acf287e46666fc` | <https://raw.githubusercontent.com/nmslib/hnswlib/d9b3608/hnswlib/hnswalg.h> |
| `src/fix-280cb597.diff` | `012e39ab4dac940b1fcaa6577edad1827feb088c2bf6f91a34f823be79b8277b` | <https://github.com/nmslib/hnswlib/commit/280cb5972234dd8297b7e3cc847dcdbcdb114d63.diff> |
| `src/pr677.diff` | `012e39ab4dac940b1fcaa6577edad1827feb088c2bf6f91a34f823be79b8277b` | <https://github.com/nmslib/hnswlib/pull/677.diff> — byte-identical to the fix commit diff |
| `src/writeup.html` | `b019ab299d7c58b200d9836661ebb6ca0cde5adbcacd9fb83c2a3b743d4573b5` | <https://m00dy.sh/notes/when-an-hnsw-index-lies-about-its-capacity> |

**The fix is an unmerged PR head, not a released version.** GitHub API on
2026-11-21: PR #677 `state=open, merged=false`; release tags stop at
`v0.10.0-rc.2` / `v0.9.0`. All fixed-side observations below are against the
PR-head tree and must be labeled that way. The fixed commit diff and PR diff
are byte-identical, confirming the pinned tarball is that PR head.

## Copied source and stand-ins

No library source is copied or patched. `run.sh` extracts both pinned source
tarballs into the output directory and compiles `driver.cpp` against the real
`hnswlib/` headers of each tree with `g++ -fsanitize=address` for the
vulnerable, fixed and benign runs. The ASan report names the pinned library
frames directly.

Harness-only elements, all in `driver.cpp`:

1. `save` mode uses the pinned library's own serializer to write a valid index
   with 512 points, then changes only the 8-byte stored-capacity field at file
   offset 8 from 512 to 2 and fills the 65536-byte level0 image with a caller
   chosen marker. `cur_element_count` (512), `size_data_per_element_` (128),
   link lists and total file size are left valid, so the loader's stream-level
   corruption checks pass. A benign control restores capacity to 512.
2. For `load` in the `readback` build only, a link-time `malloc`/`free`
   interposer (`-Wl,--wrap`) places the library's real 256-byte level0 buffer
   in a page-aligned 1 MiB readable `mmap` region. It changes placement, never
   the library code that writes. The ASan and fixed builds have no interposer.
3. A `SIGSEGV`/`SIGABRT` handler prints the chosen bytes retained in that
   staged region and exits. The pinned loader has further unchecked
   `linkLists_`/`element_levels_` loops using `cur_element_count` after the
   level0 read; those corruption symptoms are a *downstream* consequence, not
   the measured primitive. The readback line is captured when that downstream
   corruption aborts the process.

The ASan rung uses the library's own `malloc` and reports the upstream read
directly — no shim performs the write.

## Pinned line numbers (raw bytes)

Affected tag v0.9.0 / commit `d9b3608`:

- `hnswlib/hnswalg.h:727-729` read `offsetLevel0_`, `max_elements_` and
  `cur_element_count` from the file header.
- `:731-734` derives `max_elements` from the caller argument or the file's
  stored capacity; no check that it is at least `cur_element_count`.
- `:776` `malloc(max_elements * size_data_per_element_)`; `:779`
  `input.read(data_level0_memory_, cur_element_count * size_data_per_element_)`.
- `:753-765` checks the source stream against the file size, not the
  destination allocation, so it does not stop the overwrite.
- `:85` the ordinary `HierarchicalNSW(space, path)` load constructor.

The PR head adds at `:819`: `if (max_elements_ < cur_element_count) throw
std::runtime_error("Index seems to be corrupted or unsupported");` plus a
Python regression test, before the allocation and read.

The originating scout cited `:707-708/:755/:758` for the sink; raw pinned
bytes put the operative lines at `:728/:729/:776/:779`. The brief and this
file use the raw values.

## Replay record

Direct run 2026-11-21 ~13:13Z: 9 PASS / 0 FAIL rc 0, two five-run groups both
`sha256=26adac439ba80f57699e7544327fefc4dfa3bc667e13d1ba463d134d36fab3d7`.
Unsanitized load aborts with heap corruption. ASan: `WRITE of size 65472`,
0 bytes after a 256-byte region, frames `hnswalg.h:779` ← `:776` ← `:85`.
Staged readback shows `0x5a` (and `0xa5`) at offsets +0/+32/+64/+128/+256/
+512/+1024/+4096 from the start of the 256-byte destination. PR-head build
throws `Index seems to be corrupted or unsupported` with no ASan report.
Capacity-fits index loads clean on both builds. Determinism lines carry only
counts, return codes and offset/value pairs — no addresses, paths or PIDs.
