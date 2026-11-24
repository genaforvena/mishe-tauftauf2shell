# PROVENANCE — assimp2shell (W192)

## Claim (external, not accepted)

- CVE **CVE-2026-134861**, "Assimp through 6.0.6 Out-of-Bounds Write via glTF
  1.0 Accessor Element Size", VulnCheck CNA, published 2026-11-22 21:21Z.
  CWE-787; CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N.
  OSV record: <https://api.osv.dev/v1/vulns/CVE-2026-134861>. Source article:
  <https://www.vulncheck.com/advisories/assimp-through-6.0.6-out-of-bounds-write-via-gltf-1.0-accessor-element-size>.
- Affected: assimp through **6.0.6**; OSV's GIT range ends at
  `a79ff6bbce54d3e01186a918dc6374ed55317426`. No numeric fixed release was
  published at observation time. Both referenced fixes are **open, unmerged**
  pull requests: <https://github.com/assimp/assimp/pull/6860> and
  <https://github.com/assimp/assimp/pull/7090> (API read 2026-11-24).
  They are used here as *proposed* fix hunks, not as an upstream release.

## Pinned bytes (source-bound)

- Upstream tarball: `https://codeload.github.com/assimp/assimp/tar.gz/refs/tags/v6.0.6`,
  sha256 `5f7ed412b76575621df0525a762b31da5874afff352b3a890c6308db4ac7204c`
  (146 MB, intentionally not committed).
- `code/AssetLib/glTF/glTFAsset.inl`, sha256
  `7536766857f7d29fec524557aa6e84c36a24132e7090fbfa8ee019ff92e75e15`:
  - 385-402 `Accessor::GetPointer()` — `byteOffset + bufferView->byteOffset`,
    no range check;
  - 404-421 anonymous-namespace `CopyData`;
  - 424-449 `Accessor::ExtractData<T>()` —
    `ai_assert(elemSize <= targetElemSize)` and
    `ai_assert(count * stride <= bufferView->byteLength)` are compiled out in
    release (`ai_assert.h`: both only defined when `ASSIMP_BUILD_DEBUG`);
    `outData = new T[count]`, then `memcpy(outData + i, data + i*stride, elemSize)`;
  - 464-477 `Accessor::Indexer` ctor / `GetValue<T>()` — `memcpy(&value,
    data + i*stride, elemSize)` with `T value` of `sizeof(T)` bytes.
- `code/AssetLib/glTF/glTFImporter.cpp`, sha256
  `e5d97a5f3fdec437c7f125e8a411487853c93bb4c2b37e7da039298d9f7f1fb4`:
  `ImportMeshes` passes position accessors to `ExtractData(aim->mVertices)`
  (:282, `aiVector3D` = 12 bytes), normals (:286), texcoords (:290) and reads
  indices through `Accessor::Indexer::GetUInt` (:311 onward).
- Fix hunk `pr6860-gltfAsset.inl.patch` sha256
  `d4e1510316f941bdbe6436481f720bf469cb0fcdd3b1c8debcef09f492471db0`,
  applied verbatim to a copy of the pinned blob
  (`pin` + patch = `e74e18a06ada124ec80d0f94683d93364137e0ffca7187d2bcf2665f229a082b`):
  adds `Accessor::CheckDataRange()`, replaces both asserts with hard checks
  (`elemSize > targetElemSize` returns false), and bounds the Indexer read.
- `pr7090-gltfImporter.patch` sha256
  `9bffa4de61e6e0c87bc5f760450cb5322b12c2b599d40f117dbfc9ab2f3c36a3`
  adds normal-count and index-type checks in `ImportMeshes`; it is a test-side
  corroboration of the VEC3-index primitive, not part of the fixed control
  used by the harness.

## Harness construction

`harness/build.sh` extracts those exact line ranges from the pinned (or
patched) `.inl` into `pinned.inc` on every build. Supported shapes are stubs:
`FakeBuffer`/`FakeBufferView`/`Accessor` mirror only the fields those functions
touch; `ai_assert` is a no-op, matching a release Assimp build. Neither the
extraction loop nor the chosen source bytes come from advisory prose.

- `V3` is a 3-float struct (12 bytes) standing in for `aiVector3D`.
- VEC4/FLOAT position: `elemSize=16`, `count=3`, destination `new V3[3]` = 36
  bytes; source holds 3 x 16 bytes with `MISHE-OO`/`TAUF` at source 36..47.
- VEC3/uint32 index: `elemSize=12`, `count=3`, destination `new uint32_t[3]` =
  12 bytes, and a separate `Indexer::GetValue<uint32_t>(0)` writes 12 bytes
  into a 4-byte stack local.
- Safe control: VEC3/FLOAT (`elemSize=12`) into `V3` — equal sizes, no write.
- `PLAIN_ARENA` overrides `new[]` with a deterministic zero-filled arena so
  the plain build can show exact bytes past the allocation; ASan builds use
  the default allocator and redzones.

`bootstrap.sh` fetches only the pinned tarball and verifies all tracked pins.
`harness/run-all.sh` rebuilds, executes the matrix and writes `evidence.log`
plus `evidence.sha256`.
