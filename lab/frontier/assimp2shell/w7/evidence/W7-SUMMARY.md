# W7 — NORMAL accessor site, author measurement only (2026-11-24 08:1xZ)

Scope: pinned v6.0.6 glTF-only minimal ASan and plain libraries and drivers
built by `harness/run-w5.sh`; document `harness/cases/mat4norm-count1.gltf`
through the public `Assimp::Importer::ReadFileFromMemory`. Script:
`bash harness/run-w7.sh` => **11 PASS / 0 FAIL** (per-case stdout/stderr and
run-log hashes appended to `w7.log`). Author-measured, unwitnessed.

Source bound: `glTFImporter.cpp:285-287` extracts a present NORMAL accessor
into `aim->mNormals` with the same unchecked `Accessor::ExtractData` call as
POSITION; glTF 1.0 declares the element size from the accessor type and does
not compare it to `sizeof(aiVector3D)`. W6 enumerated this site but did not
exercise it.

Observations:
- Vulnerable ASan build: `WRITE of size 64`, `0 bytes after 12-byte region`,
  frames `memcpy` → `Accessor::ExtractData<aiVector3t<float> >` →
  `ImportMeshes` → `ReadFileFromMemory`.
- PR6860 overlay build: `scene=ok`, no ASan report — this hunk blocks the
  NORMAL extraction as it does POSITION.
- ASan callback build: `ASAN_CB addr=...`, `POST_WRITE addr=...`, `scene=ok`.
  The last 12 bytes of the callback's `before24` dump decode to
  `TAUFW6MARK01`, the document's first 12 MAT4 bytes, inside the 12-byte
  destination; the first 12 bytes after the reported address decode to the
  next source bytes (`2345...`). No chosen byte was shown in a live `aiMesh`
  field.
- Plain build: SIGSEGV (rc 139).

Grade unchanged: rung-4 write at the last enumerated unchecked accessor call
site; no chosen byte in a valid `aiMesh` field, no pointer/IP, no command, no
listener, no rung 5. Advisory vector is `AV:L/UI:P`; never infer RCE from a
crash. This claim is outside witness verdict #3277 and the pending #3290
W1/W2 replay.
