# frontier brief — assimp glTF 1.0 accessor element-size OOB write (CVE-2026-134861)

Status: **STAGED** by frontier 2026-11-24 under the standing similar-things
mandate; operator admission pending. Brief + live two-pane window are both
present. Target mind: `assimp2shell`. Evidence:
`lab/frontier/assimp2shell/PROVENANCE.md`, `PINS.sha256`, `evidence.log`.

## Verified ground truth (claim, not acceptance)

- Claim source: VulnCheck CNA, published 2026-11-22, via
  <https://api.osv.dev/v1/vulns/CVE-2026-134861> and
  <https://www.vulncheck.com/advisories/assimp-through-6.0.6-out-of-bounds-write-via-gltf-1.0-accessor-element-size>.
  CVE **CVE-2026-134861**, CWE-787,
  `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.
- Affected: Assimp through **6.0.6** (OSV GIT range ends
  `a79ff6bbce54d3e01186a918dc6374ed55317426`). No numeric fixed release at
  observation time. Both referenced fixes are **open, unmerged** PRs
  [#6860](https://github.com/assimp/assimp/pull/6860) and
  [#7090](https://github.com/assimp/assimp/pull/7090): they are evaluated here
  as proposed fix hunks, never as a released fixed version.
- Claimed primitive: a crafted glTF 1.0 file with a VEC4 `POSITION` accessor or
  a VEC3 index accessor makes Assimp copy 16/12 bytes into destinations whose
  elements are 12/4 bytes, corrupting memory during import.

## Source-bound mechanism (pinned bytes, not advisory prose)

- Pinned tarball v6.0.6, sha256
  `5f7ed412b76575621df0525a762b31da5874afff352b3a890c6308db4ac7204c`.
  `code/AssetLib/glTF/glTFAsset.inl` sha256
  `7536766857f7d29fec524557aa6e84c36a24132e7090fbfa8ee019ff92e75e15`.
- `Accessor::ExtractData<T>()` (:424-449) computes `elemSize` from the declared
  accessor type and copies it into `new T[count]`:
  `memcpy(outData + i, data + i*stride, elemSize)`. Its two guards are
  `ai_assert(...)`; `ai_assert.h` defines them only under
  `ASSIMP_BUILD_DEBUG`, so a release build has **no bounds or size check**.
- Real call sites in pinned `glTFImporter.cpp`
  (sha256 `e5d97a5f3fdec437c7f125e8a411487853c93bb4c2b37e7da039298d9f7f1fb4`):
  `ImportMeshes` passes `POSITION` to `ExtractData(aim->mVertices)` (:282,
  `aiVector3D` = 12 bytes) and reads indices through `Accessor::Indexer`
  (:311). A glTF 1.0 VEC4/FLOAT position has `elemSize=16`; a VEC3/uint index
  has `elemSize=12` into a 4-byte `uint32_t`.
- `Accessor::Indexer::GetValue<T>()` (:464-477) does
  `memcpy(&value, data + i*stride, elemSize)` into a `T value` local — the same
  element-size mismatch on the index path.
- PR 6860's hunk (sha256
  `d4e1510316f941bdbe6436481f720bf469cb0fcdd3b1c8debcef09f492471db0`)
  adds `CheckDataRange()` and hard `elemSize > targetElemSize` rejection to
  `ExtractData`, plus bounds in the Indexer. PR 7090 adds importer-side index
  type and normal-count checks.

## Local evidence (harness, rung by rung)

`harness/build.sh` re-extracts the verbatim pinned functions on every run,
builds vulnerable/fixed × gcc/clang ASan plus plain binaries;
`harness/run-all.sh` runs the matrix and writes `evidence.log` and
`evidence.sha256`. Latest run (log regenerated 02:17:01Z, operator re-verified
02:2xZ): **13 PASS / 0 FAIL**, raw log sha256
`e6341f37f5cf98b854c9bfb41d29ba2f38fced610c80c980c7c147ad380bf41e`
(the earlier `128596cc…f257f6` was the pre-02:17 run). Clean `git archive
585e1c7` replay rebuilt all binaries and repeated 13 PASS / 0 FAIL; after
normalizing PIDs, addresses, paths, build ids, the pins header and per-build
binary hashes, both traces are byte-identical (`913b23f5…3ca938`, `REPLAY.md`).

| Rung | Observed | Evidence |
|---|---|---|
| 1 — trigger | VEC4/FLOAT `elemSize=16`, `count=3`, destination `new V3[3]` = 36 bytes, source 48 bytes | `direct-vuln-g++-vec4pos` |
| 2 — state failure | every element write overruns its own slot; the last write crosses the allocation | ASan region report |
| 3 — corruption | gcc **and** clang ASan `heap-buffer-overflow`, `WRITE of size 16`, 0 bytes after a 36-byte region, frame `Accessor::ExtractData<V3>`; VEC3/uint path `WRITE of size 12` after a 12-byte region | `direct-vuln-{g++,clang++}-vec4pos`, `direct-vuln-g++-vec3idx` |
| 3b — index path | ASan `stack-buffer-overflow`, `WRITE of size 12`, frame object `[32,36) 'value'` | `direct-vuln-g++-idx3` |
| 4 — scoped impact | plain allocator: chosen `54 41 55 46` ("TAUF") at destination offsets **36..39**, exactly 4 bytes past the 36-byte allocation; VEC3 path writes source bytes 20..23 past offsets 12..15 | `direct-vuln-plain-vec4pos`, `direct-vuln-plain-vec3idx` |

Controls: `elemSize=12` into `V3` is ASan-clean and returns success; with the
PR 6860 hunk both mismatched `ExtractData` cases return false with no write and
no allocation (gcc and clang, ASan and plain). The crafted glTF inputs are
tracked in `harness/cases/` for the next lane.

## Honest ceiling / preserved negatives

- Direct calls into verbatim pinned functions with stub `Buffer`/`BufferView`
  shapes and a deterministic allocator. No completed Assimp library build, no
  `Assimp::Importer::ReadFileFromMemory` observation, no real .gltf file
  through the importer: a Release+ASan CMake build was attempted and timed out
  at 21% (13 translation units in 600 s) on this host. File reachability and
  the advisory's "crashing applications" claim remain **UNKNOWN**, not passes.
- The proposed fix is incomplete: with the PR 6860 hunk applied, the VEC3
  `Indexer::GetValue<uint32_t>` case still produces the same ASan
  `stack-buffer-overflow` (`fixed-g++` idx3). PR 7090's importer-side index
  check is a separate unmerged change; neither is an upstream release.
- Rung 4 is scoped: chosen bytes land past a synthetic heap allocation, not in
  a live Assimp mesh object or a function pointer. No grooming, ASLR,
  control-flow, pointer/IP, command, witness or rung 5. Advisory vector is
  `AV:L/UI:P` (local file import), not a remote listening service.
- No prior brief, charter, window or registry entry existed for Assimp; it is
  not on the plant's do-not-duplicate or screened-out lists.

## Cheapest experiment to move this up a rung

Build the pinned library with only the glTF importer enabled
(`-DASSIMP_BUILD_ALL_IMPORTERS_BY_DEFAULT=OFF -DASSIMP_BUILD_GLTF_IMPORTER=ON`,
`-O1 -g0` to shorten the build) and link `harness/real_driver.cpp`; call
`ReadFileFromMemory` on `harness/cases/vec4pos.gltf` and `idx3.gltf`.
`PR 7090`'s unit test already records the exact VEC3-index document shape.
An ASan report with a frame in `glTFImporter::ImportMeshes` would promote rung
3 from slice to the real import path and settle file reachability; only then
consider a marker in a live `aiMesh`. Never relabel this as RCE without
observation.
