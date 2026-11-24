# W8 — do OOB bytes survive in a live aiMesh field? (2026-11-24 08:5xZ)

Author measurement only, unwitnessed; no grade change, no rung 5. Question
left open by W5/W6/W7: the 64-byte MAT4/FLOAT copy into a 12-byte
`aiVector3D` writes chosen file bytes past the array; does any of that chosen
data remain in a field of the `aiScene`/`aiMesh` returned by
`Assimp::Importer::ReadFileFromMemory`?

Scope: pinned v6.0.6 glTF-only libraries built by `harness/run-w5.sh`.
`harness/w8_field_driver.cpp` registers the same ASan report callback as W5
(instrumentation only: it unpoisons the report region so the importer's own
`memcpy` completes), then walks `scene->mMeshes[i]` and scans the mesh struct,
`mVertices`, `mNormals`, `mTangents`, `mBitangents`, `mColors[]`,
`mTextureCoords[]`, `mFaces` and `mName` for a distinctive 16-byte sequence
taken only from the OUT-OF-BOUNDS source offsets. `bash harness/run-w8.sh`
=> **17 PASS / 0 FAIL**; per-case output and hashes in `w8/evidence/`.

Observations:

1. `mat4pos-livefield.gltf` — count=1 MAT4 POSITION; chosen
   `TAUFLIVE8MARKXYZ` at source offsets 40..55, all past the 12-byte
   destination. Vulnerable build: `ASAN_CB addr=0x…`, `scene=ok`,
   `POST_WRITE … at24=00000000544155464c49564502020000` (the marker's
   `TAUFLIVE` prefix survives at dest+40..47). `__asan_locate_address` puts
   the reported address in the 12-byte `mVertices` region and `dest+40` in a
   separate 8-byte heap region at `0x…90`; no returned `aiMesh` field matches
   that address and no field contains the marker. The suffix was overwritten
   by later allocator activity (`02020000` in the dump).
2. `mat4pos2-norm-livefield.gltf` — count=2 MAT4 POSITION plus a VEC3 NORMAL
   array. The POSITION overflow range covers the address later occupied by
   `mNormals` (`LOCATE dest+40 cat=heap region=0x…e0 size=24`,
   `mesh0.mNormals ptr=0x…e0 bytes=24`), but `POST_WRITE … at24=
   000000000000803f0000000000000000` shows the NORMAL extraction's `1.0f`
   data there instead: later legitimate writes overwrite the chosen bytes.
   No `LIVE_HIT` in any scanned field.
3. Scanner validity: `scanner-positive.gltf` puts the same marker in a live
   mesh name (`LIVE_HIT field=mesh0.struct off=240`,
   `LIVE_HIT field=mesh0.mName off=0`) — the scan is not returning
   `SCAN_CLEAN` vacuously.
4. Controls: `safe.gltf` on the vulnerable build gives `scene=ok`, no
   `ASAN_CB`, no hit. The tracked PR6860 overlay (open, unmerged) gives
   `scene=ok`, no ASan report, no callback, no hit on case 1.

Limits: the callback changes ASan shadow state, so this inspects a state the
plain build cannot reach (plain build aborts in glibc metadata checks, W2/W5).
A 16-byte exact-match scan can miss transformed or partially overwritten
bytes; this is a negative for these two layouts, not a proof for all counts,
allocators or grooming. No chosen byte in a live field, no pointer/IP, no
command, no listener, no r5. Grade unchanged.
