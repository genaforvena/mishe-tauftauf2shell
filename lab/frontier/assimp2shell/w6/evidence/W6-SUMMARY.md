# W6 — untested accessor→destination sites, author measurement only (2026-11-24 06:2xZ)

Scope: pinned v6.0.6 glTF-only minimal ASan and plain libraries built by
`harness/run-w5.sh` from the pinned tarball; driver is the committed
`harness/real_driver.cpp` (or the W5 callback variant, instrumentation only).
Documents are `harness/cases/mat4tex-count1.gltf`, `texcount-mismatch.gltf`
and `texsafe-count1.gltf`. Script: `bash harness/run-w6.sh` => 18 PASS / 0 FAIL
(per-case stdout/stderr and run-log hashes are appended to `w6.log`).

Source-bound enumeration (pinned bytes, no type checks in glTF 1.0):
- `glTFImporter.cpp:289-302` extracts TEXCOORD_0 with
  `ExtractData(aim->mTextureCoords[tc])`, then `mNumUVComponents[tc] =
  GetNumComponents()` and a Y-flip loop bounded by `aim->mNumVertices`
  (set from POSITION at `:281`). Neither the accessor type nor the TEXCOORD
  count is checked against POSITION in v6.0.6.
- `glTFImporter.cpp:285-287` NORMAL is the same unchecked ExtractData shape;
  not exercised this wake.
- glTF 2's `ExtractData` hard-fails on `elemSize > sizeof(T)` and its Indexer
  clamps with `min`, so these two lanes are specific to the pinned glTF 1.0
  path.

Observations:
1. `mat4tex-count1.gltf` (POSITION VEC3 count=1 safe; TEXCOORD_0 MAT4/FLOAT
   count=1, elemSize=64 into a 12-byte `aiVector3D`): ASan heap-buffer-
   overflow, `WRITE of size 64`, `0 bytes after 12-byte region`, frames
   `memcpy` → `Accessor::ExtractData<aiVector3t<float> >` → `ImportMeshes`
   → `InternReadFile` → `ReadFileFromMemory`. Instrumented callback run:
   `ASAN_CB addr=...`, `POST_WRITE ...`, `scene=ok`; the dump shows the
   document's chosen bytes at the in-bounds start of the destination and
   adjacent heap contents at the reported OOB address — no chosen byte was
   demonstrated in a live `aiMesh` field. Plain build: SIGSEGV (rc 139).
   With the PR6860 overlay hunk: `scene=null`, "failed to extract data for
   texcoord 0", no ASan report: that proposed fix rejects this site.
2. `texcount-mismatch.gltf` (POSITION VEC3 count=3; TEXCOORD_0 VEC3 count=1,
   both element sizes correct): the Y-flip loop uses POSITION's count and
   ASan reports `READ of size 4`, `4 bytes after 12-byte region` (the first
   out-of-array element's `.y` at offset 16), frame `ImportMeshes` (read
   before the computed `.y` store). Plain build aborts `double free or corruption (out)` (rc 134), i.e. the store reaches
   the adjacent heap metadata. With the PR6860 overlay hunk the same READ is
   still reported: that hunk does not add a TEXCOORD count check; PR7090's
   local patch adds a NORMAL count check only, not TEXCOORD. This is a
   DISTINCT missing-count-check defect, not the element-size mismatch of
   CVE-2026-134861.
3. `texsafe-count1.gltf` (matched VEC3 counts): `scene=ok`, ASan-clean on both
   vulnerable and PR6860 builds.

Grade unchanged: raw rung-4 write at a new call site and an additional
read-then-store heap overrun; no chosen byte in a valid `aiMesh` field, no
pointer/IP, no command, no listener, no rung 5. Author measurement, unwitnessed,
outside witness verdict #3277 and the pending #3290 W1/W2 replay. Advisory
vector is `AV:L/UI:P`; never infer RCE from a crash.
