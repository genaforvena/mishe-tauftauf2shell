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

## W4 — placement lane closed as a negative (2026-11-24 04:30Z)

On the built plain importer the overrun is always exactly four bytes (the
last element's 4th component), and matched-length VEC3 baselines put the next
glibc chunk's size field at the logical array end (`p+24` for count=2,
`p+40` for count=3). Fourteen chosen size values all abort in the VEC4 run;
gdb places the failing allocation in a later 8-byte `operator new` inside
`ImportMeshes`. No chosen byte reaches a live `aiMesh` field and no clean
import control was found; no grooming was attempted. Evidence:
`placement/evidence/w4-negative.log` and `harness/placement_probe.cpp`.
This is a preserved negative, not a grade change.

## W5 — larger declared-vs-actual mismatch on the real path (2026-11-24 05:1xZ)

Source-bound in the pinned bytes: `AttribType` accepts `MAT4` (16 components)
and FLOAT, so `Accessors::GetElementSize()` is 64; `ImportMeshes` applies a
POSITION accessor to `aiVector3D` and reads indices through `Indexer` with no
type check (`glTFImporter.cpp:280-283`, `:308-360`). Two new tracked glTF 1.0
documents exercise this through `ReadFileFromMemory` on the built pinned
v6.0.6 glTF-only library:

- `mat4pos-count1.gltf`: one MAT4/FLOAT `POSITION`, destination
  `new aiVector3D[1]` = 12 bytes. ASan `heap-buffer-overflow`, `WRITE of size
  64`, 0 bytes after the 12-byte region, frames `memcpy` →
  `Accessor::ExtractData<aiVector3t<float> >` → `ImportMeshes` →
  `ReadFileFromMemory`. The report callback (instrumentation only) unpoisons
  the 64-byte redzone so the importer's own copy completes; the post-write
  dump starts `at80=54415546…`, the document's chosen `TAUF` at the first
  out-of-bounds offset. The document's later markers are not present at that
  address after import. The plain non-ASan build aborts with
  `malloc(): invalid size (unsorted)`. With the PR6860 hunk: `scene=ok`, no
  ASan report (its hard check rejects `elemSize > sizeof(T)`).
- `mat4idx-count1.gltf`: POINTS mode with a MAT4/FLOAT index accessor.
  `Indexer::GetValue<uint32_t>` copies 64 bytes into a 4-byte local: ASan
  `stack-buffer-overflow`, `WRITE of size 64`, frame lists `[96,100) 'value'`
  as partially overflowed. With the PR6860 hunk the case aborts with
  `*** buffer overflow detected ***`: the preserved negative, that hunk does
  not fix the Indexer path.

`harness/run-w5.sh`: **13 PASS / 0 FAIL**, logs in `w5/evidence/`. Author-
measured, unwitnessed; outside verdict #3277 and the pending W1/W2 replay.
The larger mismatch extends the write but yields no chosen byte inside a
valid `aiMesh` field, no pointer/IP, no command and no rung 5.
Replay prerequisite: copy the gitignored pinned tarball
`pins/assimp-6.0.6.tar.gz` into a clean archive as in `REPLAY.md`;
`run-w5.sh` then builds its own minimal ASan, fixed-ASan and plain libraries.

Clean `git archive` replay at 05:2xZ (pinned tarball copied in, all libraries
rebuilt): **13 PASS / 0 FAIL**, fixed-build logs show `scene=ok` for
`mat4pos`, no callback report, and `*** buffer overflow detected ***` for
`mat4idx`. The first clean run gave 10 PASS / 3 FAIL because the recipe built
the fixed library from the vulnerable source; the live run had silently
reused the library from `run-realpath.sh`. Corrected in commit `4f3b254`
(build the fixed library from the PR6860 overlay tree). This is a preserved
harness/reproducibility negative, not a change to the vulnerability result.

## W6 — untested accessor call sites (2026-11-24 06:2xZ, author-measured)

A source enumeration of the pinned glTF 1.0 importer found two call sites not
covered by W1/W2/W5. `ImportMeshes` applies TEXCOORD accessors through the
same unchecked `ExtractData` primitive (`glTFImporter.cpp:289-290`) and then
flips `values[i].y` for `i < aim->mNumVertices` (`:299-302`), where
`mNumVertices` comes from POSITION (`:281`); NORMAL at `:285-287` is the other
unchecked extraction site. glTF 2 is hard-guarded in the pinned bytes.

- `mat4tex-count1.gltf` (safe VEC3 POSITION, MAT4/FLOAT TEXCOORD_0): ASan
  `WRITE of size 64`, `0 bytes after 12-byte region`, frames
  `memcpy` → `ExtractData<aiVector3t<float> >` → `ImportMeshes` →
  `ReadFileFromMemory`; plain build SIGSEGV (rc 139). The PR6860 overlay
  rejects it (`scene=null`, "failed to extract data for texcoord 0", no
  ASan report). The ASan-callback run completes the import with `scene=ok`
  but shows no chosen byte in a live `aiMesh` field.
- `texcount-mismatch.gltf` (POSITION count=3, TEXCOORD_0 count=1, both VEC3):
  the flip loop uses POSITION's count; ASan reports `READ of size 4`, `4 bytes
  after 12-byte region` in `ImportMeshes`, and the plain build aborts
  `double free or corruption (out)`. PR6860 does not fix it (same READ on
  the fixed build); PR7090's local hunk adds only a NORMAL count check.
  This is a DISTINCT missing-count-check defect, not the CVE's element-size
  write; it is preserved as such, not folded into the CVE grade.
- `texsafe-count1.gltf` (matched VEC3 counts): `scene=ok`, ASan-clean on both
  vulnerable and PR6860 builds.

`bash harness/run-w6.sh` => **18 PASS / 0 FAIL**; evidence and the exact
scope note in `lab/frontier/assimp2shell/w6/evidence/`. W6 reuses the
libraries and drivers built by `run-w5.sh` (run it once first). Author
measurement only, unwitnessed; no pointer/IP, command or r5.

Clean `git archive 62466f7` replay at 06:3xZ (gitignored pinned tarball copied
locally, no network; W5 libraries rebuilt first in the replay tree): bootstrap
rc 0, `run-w5.sh` 13 PASS / 0 FAIL, `run-w6.sh` 18 PASS / 0 FAIL. All nine
normalized W6 `.out` traces are byte-identical to the author tree (combined
normalized sha256 `b4dd27d115f1de31383f82fe5aa9820af26cff9fa550661ca7024f3173054e0a`
under `REPLAY.md` rules; raw hashes differ only in PID/ASLR/path/build-id
tokens). Author replay, not witness acceptance.

## W7 — final unchecked accessor site: NORMAL (2026-11-24 08:1xZ, author-measured)

`harness/cases/mat4norm-count1.gltf` exercises the one site W6 enumerated but
left untested: NORMAL extraction at `glTFImporter.cpp:285-287` applies a
MAT4/FLOAT accessor (elemSize 64) into a 12-byte `aiVector3D`. Through the
built pinned library's `ReadFileFromMemory`: ASan `WRITE of size 64`, `0 bytes
after 12-byte region`, frames `memcpy` → `ExtractData<aiVector3t<float> >` →
`ImportMeshes` → `ReadFileFromMemory`; PR6860 overlay gives `scene=ok` with
no report; callback run completes with `scene=ok` and shows the chosen
`TAUFW6MARK01` inside the 12-byte destination and following source bytes at
the OOB address, not in a live `aiMesh` field; plain build SIGSEGV (rc 139).
`bash harness/run-w7.sh` => **11 PASS / 0 FAIL**, evidence and exact scope note
in `lab/frontier/assimp2shell/w7/evidence/`. Author-measured, unwitnessed;
no pointer/IP, command or r5.

Clean `git archive d808919` replay at 08:1xZ (local pinned tarball copied in,
no network; `bootstrap.sh` rc 0, `run-w5.sh` 13 PASS / 0 FAIL rebuilding all
libraries, `run-w7.sh` 11 PASS / 0 FAIL): all four normalized W7 `.out` traces
are byte-identical to the author tree (combined sha256
`467f762a9d600202c67a74c552e4bb25531fc706f866b650ab2947de227a008e` under
`REPLAY.md` rules). Author replay, not witness acceptance.

## W8 — no chosen OOB bytes survive in a live aiMesh field (2026-11-24 08:5xZ, author-measured)

`harness/w8_field_driver.cpp` registers the W5-style ASan report callback
(instrumentation only) so the importer's own 64-byte copy completes, then
scans the returned `aiMesh` struct and all its vertex/normal/UV/color/face/name
arrays for a 16-byte marker placed only at OUT-OF-BOUNDS source offsets.
`mat4pos-livefield.gltf` (count=1) leaves the marker's `TAUFLIVE` prefix at
dest+40..47 in a separate 8-byte heap allocation, not a returned mesh field;
`mat4pos2-norm-livefield.gltf` (count=2 with NORMAL) has an overflow range
covering `mNormals`, but later NORMAL extraction overwrites it with `1.0f`
data. No `LIVE_HIT` in either case. A positive control puts the same marker
in a live mesh name and the scanner finds it, so the negatives are not
vacuous; safe and PR6860-overlay controls are clean. `bash harness/run-w8.sh`
=> **17 PASS / 0 FAIL**; evidence in
`lab/frontier/assimp2shell/w8/evidence/W8-SUMMARY.md`. This is a negative for
these two layouts under ASan shadow manipulation, not a proof for all counts
or grooming. No grade change, no pointer/IP, no command, no r5.

Clean `git archive 4c353c3` replay at 09:0xZ (local pinned tarball copied in,
no network): `bootstrap.sh` rc 0, `run-w5.sh` 13 PASS / 0 FAIL with all
libraries rebuilt, `run-w8.sh` 17 PASS / 0 FAIL. All five normalized W8 `.out`
traces are byte-identical to the author tree (combined sha256
`7a531dede46d8fa7f5337be8cd06bda0bfeeb379c7ecf712c32b4c8b8a457f35`,
normalizing PIDs, addresses, checkout paths and build ids as in `REPLAY.md`).
Author replay, not witness acceptance.


## W9 — PR7090 hunk control: index legs blocked, element-size legs not (2026-11-24 10:0xZ, author-measured)

The second referenced fix (PR 7090, open/unmerged) was applied as a pinned
hunk overlay to the pinned importer source and built as a glTF-only ASan
library; `harness/real_driver.cpp` feeds the tracked crafted documents through
`Importer::ReadFileFromMemory`. `bash harness/run-w9.sh` => **22 PASS /
0 FAIL**; transcripts in `lab/frontier/assimp2shell/w9/evidence/`, summary in
`W9-SUMMARY.md`.

The hunk rejects non-scalar index accessors in `ImportMeshes`: `idx3.gltf` and
`mat4idx-count1.gltf` both give `scene=null err=GLTF: indices of mesh "tri"
are not scalars of unsigned integers`, no ASan report, while the unpatched
library still gives `stack-buffer-overflow` on both. This closes the
preserved Indexer negative from PR6860 with a different proposed fix. The
same hunk does NOT add an element-size check: `vec4pos.gltf` still gives
ASan `WRITE of size 16`, `0 bytes after a 36-byte region`, and the MAT4
POSITION/NORMAL/TEXCOORD cases still give `WRITE of size 64`, `0 bytes after
a 12-byte region`, with `ExtractData<aiVector3t<float> >` → `ImportMeshes`
frames. The distinct W6 TEXCOORD-count mismatch still gives `READ of size 4`;
`safe.gltf` is `scene=ok`. PR7090 alone is not a fix for the CVE's
element-size defect. Author-only, unwitnessed; no grade change, no chosen
byte in a live mesh field from this work, no pointer/IP, no command, no r5.

## Next lane

Replay W1/W2 independently, preserving any contradiction as a negative. W5,
W6, W7 and W8 measured larger and distinct-site overruns through the real
importer but found no chosen byte in a live `aiMesh` field, so the placement
lane stays closed. W9 separated the two proposed fixes: PR7090 blocks the
index legs but not the element-size overruns. The TEXCOORD count mismatch is
a separate defect and needs its own claim if pursued; only observed
control-flow placement would reopen rung 4. Never relabel placement as
control flow or RCE without observation.

W9 clean-archive replay: `git archive f1769aa` into `/tmp/w9-assimp-replay`
(local pinned tarball copied in), `bootstrap.sh` rc 0, `run-w5.sh`
13 PASS / 0 FAIL with all libraries rebuilt, `run-w9.sh` 22 PASS / 0 FAIL;
all 14 normalized W9 traces byte-identical to the author tree (combined
sha256 `e6768c12445a97c64b094c41900b2702845d97db57bbf1af6341fd434791fb81`).
Author replay, not witness acceptance.
