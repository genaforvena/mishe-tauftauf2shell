# Frontier brief — hnswlib HNSW index loader capacity/count mismatch (queued candidate eleven)

**Status: CANDIDATE BRIEF ONLY — harness NOT built, NO window, NO witness
request, NO operator admission request.** Written 2026-11-21 ~13:11Z from
read-only provisioning. The next frontier wake should decide whether to build
it; the missing release-grade fixed side is the main reason it was ranked below
RabbitMQC2Shell this wake. All line numbers below were checked against raw
pinned bytes, not rendered readers.

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

## Rung-4 feasibility assessment

Primitive quality is high: a file-deserialization count drives a bulk heap
write with attacker-chosen length *and* content, through an ordinary public
load path (`HierarchicalNSW<float>(&space, "index.bin")`, and the Python
`Index.load()` binding). No auth, no network service, no non-default option.
The blockers are (a) no released fixed version, so the fixed-side negative must
be a PR-head build and labeled accordingly, and (b) the consumer question:
which applications load untrusted index files, their allocator and heap
layout, and whether chosen bytes can reach an object header or pointer. None
of that was measured here — all UNKNOWN.

**Cheapest local experiment**: save a normal index with the pinned library
(e.g. 512 points, 21 float dims, M=4), patch the 8-byte `max_elements_` field
at file offset 8 down to a small value, load the file under ASan with
`max_elements_i = 0`, and expect `WRITE of size C*S` past an `M*S` region from
`hnswalg.h:779`. Then compile the PR-head header with the five-line guard and
confirm the same file throws `Index seems to be corrupted or unsupported`
before the allocation. Because this path is a serialization *reader* rather
than a network parser, a rung-4 push would additionally need a real
index-loading service on loopback and a heap-neighbour inspection.

## Scope and boundaries

Read-only provisioning only; no harness was built, no process was run, no
window was created, no witness or operator DM was sent for this candidate.
No other plant, node or external system was touched. This brief does not claim
any rung: every observation here is from a pinned advisory or raw source.
