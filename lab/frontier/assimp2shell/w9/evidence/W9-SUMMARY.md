# W9 — PR7090 hunk as a proposed-fix control (2026-11-24 10:0xZ)

Author measurement only, unwitnessed; no grade change, no rung 5. Both
referenced fixes (PR 6860, PR 7090) are open/unmerged; neither is a released
fixed version. This wake measured what the *second* referenced hunk actually
blocks, so the two proposed fixes are not conflated.

Method: the pinned hunk `pins/pr7090-gltfImporter.patch` (sha256 in
`PINS.sha256`) is applied with `patch -p0` to a local copy of the pinned
v6.0.6 tree at `pins/fixed7090-6.0.6/`. That hunk adds two checks in
`ImportMeshes`: a NORMAL-count check and a rejection of index accessors whose
component count is not 1 or whose component size exceeds `uint32_t`. It does
not touch `Accessor::ExtractData`. A glTF-importer-only ASan library is built
from the overlay (`build-min-7090`), and the existing real-path driver
(`harness/real_driver.cpp`, `Importer::ReadFileFromMemory`) is linked against
it. `bash harness/run-w9.sh` => **22 PASS / 0 FAIL**; all transcripts and
their sha256 values are in `w9/evidence/w9.log`.

Observations (exact build: pinned v6.0.6 plus the pinned PR7090 hunk, ASan,
`-O1 -g0`, gcc, glTF importer only):

1. Index legs blocked. `idx3.gltf` (VEC3 index) and `mat4idx-count1.gltf`
   (MAT4 index) both give `scene=null err=GLTF: indices of mesh "tri" are not
   scalars of unsigned integers`, with no ASan report. Both transcripts are
   byte-identical (sha256 `570d7c65…00fa961`). The unpatched pinned library
   still gives `stack-buffer-overflow` on both cases. This closes the
   preserved Indexer negative from PR6860: PR7090's check stops it before
   `Accessor::Indexer::GetValue`, at the cost of rejecting the crafted file.
2. Element-size legs NOT blocked. `vec4pos.gltf` (the advisory's VEC4/FLOAT
   POSITION into `aiVector3D`) still gives ASan `WRITE of size 16`,
   `0 bytes after a 36-byte region`; `mat4pos-count1.gltf`,
   `mat4norm-count1.gltf` and `mat4tex-count1.gltf` still give ASan
   `WRITE of size 64`, `0 bytes after a 12-byte region`, with
   `ExtractData<aiVector3t<float> >` → `ImportMeshes` frames. PR7090 alone is
   therefore not a fix for the CVE's element-size defect.
3. The distinct TEXCOORD-count mismatch from W6 is also unfixed by PR7090:
   `texcount-mismatch.gltf` still gives ASan `READ of size 4` in
   `ImportMeshes`. It remains a separate defect, explicitly outside this
   CVE's grade.
4. Control: `safe.gltf` gives `scene=ok` with no ASan report on the overlay
   build.

Limits: this is a proposed-hunk control, not a vendor release; the overlay
was built locally from the pinned bytes. File reachability is the already
measured real `ReadFileFromMemory` path, not a network or GUI route. No chosen
byte in a live `aiMesh` field from this work, no pointer/IP, no command, no
listener, no r5. Author-only; independent replay is owed.

Clean-archive replay: `git archive f1769aa` into `/tmp/w9-assimp-replay`
(local pinned tarball copied in, no fetch); `bootstrap.sh` rc 0, `run-w5.sh`
13 PASS / 0 FAIL with all libraries rebuilt, `run-w9.sh` 22 PASS / 0 FAIL.
All 14 normalized W9 `.out` traces are byte-identical to the author tree
(combined sha256
`e6768c12445a97c64b094c41900b2702845d97db57bbf1af6341fd434791fb81`,
normalizing PIDs, addresses, checkout paths and build ids as in `REPLAY.md`).
Author replay, not witness acceptance.
