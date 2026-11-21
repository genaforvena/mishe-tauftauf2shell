# Frontier brief — hnswlib HNSW index loader mismatch (HnswLib2Shell)

**Status: ADMITTED under standing approval #6 (operator, tape #916, ~13:35Z);
the earlier ~13:22Z hold (#906/#908) was withdrawn because #6 requires a fixed
pin, not a released version.** Witness W73 (#913) returned ESTABLISHED AS
CLAIMED at the labeled grade. Rungs 1/2/3 are ESTABLISHED on the real,
verbatim-pinned v0.9.0 library: rung 3 is the ASan
report, rungs 1/2 run unsanitized. Rung 4 shows attacker-chosen bytes at chosen
offsets past the 256-byte level0 buffer through the library's own
`std::istream::read`, reached by the ordinary `HierarchicalNSW(space, path)`
load constructor. The fixed side is an **UNMERGED PR head** (PR #677, commit
`280cb597…`), not a released version — label it that way in every claim. No
index-loading application, network listener, real heap neighbour object,
pointer, control-flow diversion or execution was observed — all UNKNOWN.

## Verified ground truth (claim sources + raw pins)

- **Advisory**: CVE-2026-124959, CNA CERT/CC (`providerMetadata.shortName =
  certcc`), CWE-787, no CVSS score in the CVE record. Verbatim: "The loadIndex
  function in nmslib hnswlib and Spotify Voyager does not verify that the
  element count in a serialized HNSW index is within the stored capacity used
  to allocate the heap buffer. An attacker can supply a crafted index file
  with an element count greater than the stored capacity, causing the loader to
  write beyond the allocated buffer and potentially crash the application when
  it loads the file."
- **Affected**: hnswlib `0.5.0`–`0.9.0`; Spotify Voyager `2.0.7`–`2.1.1`.
  Tag `v0.9.0` is commit `d9b3608c…`, the revision pinned below.
- **Fix**: PR #677, commit `280cb5972234dd8297b7e3cc847dcdbcdb114d63`
  ("fix(hnswalg): reject loadIndex when max_elements_ < cur_element_count").
  **UNMERGED and unreleased as of 2026-11-21**: GitHub API reports
  `state=open, merged=false`; the current release tags stop at
  `v0.10.0-rc.2` / `v0.9.0`. The fixed side would have to be compiled from the
  PR head, not from a released tarball. This is weaker evidence than a released
  fix and must be labeled as such in any future claim.
- **Pins** (all in `lab/frontier/hnswlib/src/`, SHA-256 in `SHA256SUMS`):

| Pin | SHA-256 | Source |
| --- | --- | --- |
| `cve124959.json` | `0962ff9fbea34453f545ae07984c6640ce4350429243d7b8aa43e7cea5d476d5` | <https://cveawg.mitre.org/api/cve/CVE-2026-124959> |
| `hnswalg-d9b3608.h` | `483d3b3193969ef4c35239849b6385dd1086434a7bae1d8181acf287e46666fc` | <https://raw.githubusercontent.com/nmslib/hnswlib/d9b3608/hnswlib/hnswalg.h> |
| `fix-280cb597.diff` | `012e39ab4dac940b1fcaa6577edad1827feb088c2bf6f91a34f823be79b8277b` | <https://github.com/nmslib/hnswlib/commit/280cb5972234dd8297b7e3cc847dcdbcdb114d63.diff> |
| `pr677.diff` | `012e39ab4dac940b1fcaa6577edad1827feb088c2bf6f91a34f823be79b8277b` | <https://github.com/nmslib/hnswlib/pull/677.diff> — byte-identical to the fix commit diff |
| `writeup.html` | `b019ab299d7c58b200d9836661ebb6ca0cde5adbcacd9fb83c2a3b743d4573b5` | <https://m00dy.sh/notes/when-an-hnsw-index-lies-about-its-capacity> |

Cross-check: <https://github.com/nmslib/hnswlib/issues/673>. The public writeup
is a claim; none of its exploit narrative was reproduced here.

## Source-bound mechanism (raw pinned bytes, tag v0.9.0 / `d9b3608`)

1. `hnswlib/hnswalg.h:727` reads `offsetLevel0_`; `:728` reads `max_elements_`
   (the stored capacity) and `:729` reads `cur_element_count` — both directly
   from the index file header.
2. `:731-734` sets `max_elements = max_elements_i`; if it is below
   `cur_element_count`, it is replaced by the file's `max_elements_`. With the
   ordinary `max_elements_i = 0` load path, an index whose `cur_element_count`
   exceeds its stored `max_elements_` leaves `max_elements < cur_element_count`.
   There is no check at this point.
3. `:776` allocates `malloc(max_elements * size_data_per_element_)`; `:779`
   executes `input.read(data_level0_memory_, cur_element_count *
   size_data_per_element_)`. Both the write length and the payload bytes come
   from the file; only the allocation uses the smaller capacity.
4. The optional link-list walk at `:753-765` checks the *source stream* against
   `total_filesize`, not the destination allocation, so it does not stop the
   overwrite. The fix adds a five-line guard after `:734`:
   `if (max_elements_ < cur_element_count) throw std::runtime_error(...)`.
   The same commit adds `tests/python/bindings_test_loadindex_corruption.py`,
   which shrinks the 8-byte `max_elements_` header field from 2 to 1.

**Citation correction worth preserving**: the originating scout reported the
sink at `:707-708`, `:755`, `:758` (21 lines early). Those are `writeBinaryPOD`
and the link-list walk in the pinned bytes. The operative lines in raw
`d9b3608` are `:728`, `:729`, `:776` and `:779` as above. Raw pins win.

## Lab evidence

`cd lab/frontier/hnswlib && bash run.sh <outdir>`:

- 9 PASS / 0 FAIL, exit 0. Two independent five-run groups both
  `sha256=26adac439ba80f57699e7544327fefc4dfa3bc667e13d1ba463d134d36fab3d7`.
- Rung 1: an unsanitized load of the crafted index aborts on heap corruption.
- Rung 2: the file's `cur_element_count` (512) drives the level0 read into an
  allocation sized from the stored capacity (2 × 128 = 256 bytes).
- Rung 3 (ASan): `heap-buffer-overflow`, `WRITE of size 65472`, 0 bytes after a
  256-byte region, frames `hnswalg.h:779` ← `:776` ← `:85`.
- Rung 4 (INSTRUMENTED chosen-byte control): with the level0 buffer placed in
  page-aligned memory by the harness allocator, `0x5a` and `0xa5` each read
  back at offsets +0/+32/+64/+128/+256/+512/+1024/+4096 from that 256-byte
  destination after the library's own `std::istream::read`.
- Negative controls: the PR-head guard throws `Index seems to be corrupted or
  unsupported` with no ASan report; an index with a capacity that fits loads
  clean on both builds.

**Harness boundary, stated plainly**: the ASan rung uses the library's own
`malloc` and reports the upstream read directly — no shim performs the write.
For chosen-byte observation a link-time `malloc` interposer relocates the
library's real level0 buffer into readable page-aligned memory; that changes
placement, never the library code that writes. A signal handler prints the
retained bytes when the loader's *downstream* unchecked link-list loops corrupt
the heap; those loops are a consequence, not the measured primitive. No guard
page proof was obtained for this find. Determinism lines carry no addresses,
paths or PIDs.

## Rung-4 feasibility assessment

Primitive quality is high: a file-deserialization count drives a bulk heap
write with attacker-chosen length *and* content, through an ordinary public
load path (`HierarchicalNSW<float>(&space, "index.bin")`, and the Python
`Index.load()` binding). No auth, no network service, no non-default option.
The blockers are (a) no released fixed version — the fixed-side negative is a
PR-head build and must stay labeled as such, and (b) the consumer question:
which applications load untrusted index files, their allocator and heap
layout, and whether chosen bytes can reach an object header or pointer. None
of that was measured here — all UNKNOWN.

**Cheapest rung-raising experiment**: write a loopback-only service that
accepts an index file from a local socket and calls the pinned v0.9.0 load
constructor under ASan and gdb. Send the crafted 5a index; confirm the WRITE at
`hnswalg.h:779` inside the service process, freeze the first past-end bytes and
inspect the real heap neighbour under gdb before any pointer claim. A second
harness should cover the Spotify Voyager path, whose header layout differs.
This belongs to a dedicated target mind after admission, not this
extracted-driver lane.

## Scope and boundaries

Read-only provisioning of advisories and source; all process runs stay local
with no network, broker or external probe. Harness stand-ins and copied ranges
are enumerated in `PROVENANCE.md`. No other plant, node or external system was
touched. The unmerged fixed side and the UNKNOWN consumer are the two explicit
limits on this claim.
