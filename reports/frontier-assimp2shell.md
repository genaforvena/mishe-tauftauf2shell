# frontier brief — assimp glTF 1.0 accessor element-size OOB write (CVE-2026-134861)

Status: **ADMITTED** by operator 2026-11-24 02:2xZ (124th route); witness
verdict #3277 (03:51Z) ESTABLISHED rungs 1-4 at the direct-call /
stub-Accessor / deterministic-arena scope, NO r5. The W1 real-importer and W2
chosen-byte legs are author-measured and await independent replay. Brief +
live two-pane window are both present. Target mind: `assimp2shell`. Evidence:
`lab/frontier/assimp2shell/PROVENANCE.md`, `PINS.sha256`, `evidence.log`,
`realpath/evidence/`, `placement/evidence/`.

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
| 4 — scoped impact | plain allocator: chosen `54 41 55 46` ("TAUF") at destination offsets **36..39**, exactly 4 bytes past the 36-byte allocation; VEC3 path puts source bytes 20..23 at offsets 12..15 on iteration i=1, overwritten on i=2 by `src[28..31]` = `7d 7e 7f 80` (final-state attribution) | `direct-vuln-plain-vec4pos`, `direct-vuln-plain-vec3idx` |

Controls: `elemSize=12` into `V3` is ASan-clean and returns success; with the
PR 6860 hunk both mismatched `ExtractData` cases return false with no write and
no allocation (gcc and clang, ASan and plain). The crafted glTF inputs are
tracked in `harness/cases/` for the next lane.

## Witness verdict — baseline only (#3277, 2026-11-24 03:51Z)

The witness replayed a clean `git archive 585e1c7` into `/tmp/w182-assimp`,
live tree untouched and the pinned tarball reused locally (no network fetch):
10/10 pins OK, bootstrap OK, `harness/run-all.sh` rc 0, 13 PASS / 0 FAIL.
Author raw log sha256 `e6341f37…bf41e` was confirmed by `git show`; witness
raw `df11113a…c9524d0`; both normalize to `913b23f5…3ca938` under the
`REPLAY.md` rules with an empty normalized diff. All baseline legs reproduced
(gcc+clang ASan WRITE-16 after a 36-byte region in `ExtractData<V3>`, VEC3/uint
WRITE-12 after a 12-byte region, idx3 stack WRITE-12 into `[32,36) 'value'`,
plain TAUF at offsets 36..39), including the fixed-idx3 negative.

Verdict **ESTABLISHED rungs 1-4 at the labeled direct-call / stub-Accessor /
deterministic-arena scope; NO r5, no pointer, IP, marker or command**. The
witness explicitly left real importer/file reachability UNKNOWN: no library
or `ReadFileFromMemory` build was part of that claim, so W1 and W2 below are
not covered by this verdict. Its NIT on the VEC3 final-state attribution is
corrected in the rung-4 row above; no grade impact.

## Honest ceiling / preserved negatives

- The baseline direct-call legs use stub `Buffer`/`BufferView` shapes and a
  deterministic allocator; that scope is witness-backed (#3277), but it is
  not a completed importer. W1/W2 since built a minimal pinned library and
  reached the code through `ReadFileFromMemory` (below), so file reachability
  is now author-measured rather than UNKNOWN; those legs are not witness
  acceptance. The first full Release+ASan CMake build attempt did time out at
  21% (13 translation units in 600 s) on this host; the glTF-only build worked.
- The proposed fix is incomplete: with the PR 6860 hunk applied, the VEC3
  `Indexer::GetValue<uint32_t>` case still produces the same ASan
  `stack-buffer-overflow` (`fixed-g++` idx3). PR 7090's importer-side index
  check is a separate unmerged change; neither is an upstream release.
- Rung 4 is scoped: baseline chosen bytes land past a synthetic heap
  allocation; W2 chosen bytes land at the end of a live 24-byte vertex array
  in the real importer, not in a valid `aiMesh` field or a function pointer.
  The W2 ASan callback unpoisons 16 redzone bytes for observation only; it is
  instrumentation, not attacker control. No grooming, pointer/IP, command or
  rung 5, and no witness verdict for W1/W2. Advisory vector is `AV:L/UI:P`
  (local file import), not a remote listening service.
- No prior brief, charter, window or registry entry existed for Assimp; it is
  not on the plant's do-not-duplicate or screened-out lists.

## W1 — real importer reachability (2026-11-24 02:35Z, commit `8713ea4`)

Built the verbatim pinned library with only the glTF importer enabled
(`-DASSIMP_BUILD_ALL_IMPORTERS_BY_DEFAULT=OFF -DASSIMP_BUILD_GLTF_IMPORTER=ON`,
`-O1 -g0`, Ninja, `-j2`); all 111 build edges completed.
`harness/real_driver.cpp` calls `Assimp::Importer::ReadFileFromMemory` on the
tracked cases. `vec4pos.gltf` gives ASan `heap-buffer-overflow`, `WRITE of size
16`, 0 bytes after a 36-byte region, frames `memcpy` →
`glTF::Accessor::ExtractData<aiVector3t<float> >` → `glTFImporter::ImportMeshes`
→ `InternReadFile` → `ReadFileFromMemory`; `idx3.gltf` gives
`stack-buffer-overflow WRITE of size 12` in `ImportMeshes`; `safe.gltf` is
clean. The PR6860 hunk overlay blocks vec4pos but not idx3.
`harness/run-realpath.sh`: **8 PASS / 0 FAIL**, evidence
`realpath/evidence/`. Author-measured; outside verdict #3277, not replayed.

## W2 — chosen bytes on the real path (2026-11-24 03:02Z, commit `8725d56`)

Tracked `harness/cases/vec4pos-count2.gltf` (count=2 VEC4/FLOAT `POSITION`,
chosen `54 41 55 46` in the last component): ASan `WRITE of size 16`, 0 bytes
after a 24-byte region, same real import frames. An ASan report callback
records the reported address, unpoisons only those 16 redzone bytes with
`halt_on_error=0` so the importer's own `memcpy` completes, then dumps
`POST_WRITE ... at16=54415546` at offset 24 of the 24-byte array with
`scene=ok`. The callback is instrumentation only; it does not supply the
bytes. A plain non-ASan build aborts with `malloc(): invalid size (unsorted)`
(rc 134); fixed-hunk and safe controls are clean. `run-placement.sh`:
**11 PASS / 0 FAIL**, evidence `placement/evidence/`. Author-measured;
witness replay owed.

## Next lane

Replay W1/W2 independently, preserving any contradiction as a negative. Only
after acceptance: probe whether the tail write can reach a live `aiMesh` field
or a controlled heap object rather than the array end and allocator metadata.
Never relabel placement as control flow or RCE without observation.
