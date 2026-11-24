# frontier brief — assimp glTF 1.0 accessor element-size OOB write (CVE-2026-134861)

Status: **ADMITTED** by operator 2026-11-24 02:2xZ (124th route); witness
verdict #3277 (03:51Z) ESTABLISHED rungs 1-4 at the direct-call /
stub-Accessor / deterministic-arena scope, NO r5; witness verdict #3722
(16:27Z) ESTABLISHED W14 AS LABELED (partial low-32-bit pointer overwrite),
no grade change and NO r5. The W1-W13 real-importer legs remain author-only;
W14 is independently replayed; W18/W19/W20 are author-measured extensions
(W18/W19 under a debugger, W20 in a plain debugger-free ASLR-off process),
with no witness verdict and no grade change or r5.
Brief + live two-pane window are both present.
Target mind: `assimp2shell`. Evidence:
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
  in the real importer, not in a valid `aiMesh` field. W10 extends rung 4 to
  a file-steered pointer dereference in the plain importer: one crafted byte
  changes the fault address from `0x41414141` to `0x42424242`, but the target
  is not a valid object and there is no code pointer, control-flow
  redirection, marker, command or r5. The W10/W11 "`-O1`" plain libraries
  actually ended with `-O3` (CMake's Release flags are appended after the
  requested `-O1`); W12 reproduces both chosen fault addresses at explicit
  gcc -O2 and -O3, while explicit -O0 aborts on a stack canary first. The ASan
  frame layout differs, and W11's clang rebuild does not reproduce the
  chosen-address fault: it instead overwrites caller-frame `count`, `stride`
  and `faces` and steers the memcpy source pointer by one chosen byte.
  None is witness-backed. The W2 ASan callback unpoisons 16 redzone bytes
  for observation only; it is instrumentation, not attacker control. No
  grooming and no witness verdict for W1/W2 or W10/W11/W12. Advisory vector is
  `AV:L/UI:P` (local file import), not a remote listening service.
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
`realpath/evidence/`. Author-measured; outside verdict #3277; clean-archive
author replay recorded below.

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
clean-archive author replay recorded below; independent witness replay owed.

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

## W10 — file-steered pointer dereference (2026-11-24 10:5xZ, author-measured)

The plain `-O1 -g -U_FORTIFY_SOURCE` build of pinned v6.0.6 lets
`Indexer::GetValue<uint32_t>()` copy 64 chosen document bytes into a 4-byte
local; in that plain caller frame they reach the live
`std::vector<std::unique_ptr<aiMesh>>` used by `CopyVector` at
`glTFImporter.cpp:475`. `idxptr-zero.gltf` carries `0x41414141`, `0x00000000`
in document bytes 48..55 and faults with gdb `si_addr=0x41414141`;
`idxptr-addr42.gltf` changes one byte to `0x42` and faults at `0x42424242`.
`safe.gltf` is `scene=ok`. `bash harness/run-w10.sh` => **10 PASS / 0 FAIL**;
evidence and `W10-SUMMARY.md` in `lab/frontier/assimp2shell/w10/evidence/`.
A gdb watchpoint on the fortify build (only `__memcpy_chk`'s object-size
argument raised so the importer's own copy completes) shows the live vector
slot take `0x41414141`. This is a chosen address, not a valid object or a
code pointer; no control-flow redirection, marker, command, listener or r5.
The ASan frame layout differs, so this is plain-build-only and unwitnessed.

## W11 — compiler dependence of the W10 pointer layout (2026-11-24 11:3xZ, author-measured)

`harness/run-w11.sh` rebuilds the pinned v6.0.6 glTF-only library with
clang/clang++ `-O1 -g -U_FORTIFY_SOURCE -fno-omit-frame-pointer` and drives
the same `placement_driver.cpp` and crafted cases. Result: **10 PASS / 0
FAIL**; `lab/frontier/assimp2shell/w11/evidence/w11.trace` sha256
`a5bc765f3a3ccd28cc8b11a1c8c11cdfab9a19c8495d40e0bd0569a6461dffa0`.
The W10 chosen-address dereference does not reproduce: `idxptr-zero.gltf`
and `idxptr-addr42.gltf` fault inside `__memcpy_avx_unaligned_erms` with
`si_addr=(nil)` and the same `rsi=0x9095e5e5d60084c`. Instead, the 64-byte
write corrupts `count=0x06060606`, `data.stride=0x0909090908080808` and
`faces=0x0d0d0d0d0c0c0c0c` in the `ImportMeshes` frame at
`glTFImporter.cpp:319`; those are document bytes from decoded offsets 68,
76..83 and 92..99. The new tracked case `idxptr-stride42.gltf` changes only
byte 76 from `08` to `42`: stride becomes `0x0909090908080842`, `rsi`
becomes `0x9095e5e5d600886` (delta 58 = 0x3a). One file byte steers the
address used by the importer's own memcpy under clang, through a different
local; still an invalid address, no object, code pointer, control-flow
redirection, marker, command or r5. W11 is a negative for W10 portability,
not a grade upgrade or witness acceptance.


## W12 — optimization matrix: the chosen-address fault survives gcc -O2/-O3 (2026-11-24 13:1xZ, author-measured)

A flag audit found that the W10/W11 libraries were configured with
`-DCMAKE_BUILD_TYPE=Release`, whose `-O3 -DNDEBUG` is appended after the
requested `-O1`; their final optimizer flag is `-O3`. `harness/run-w12.sh`
therefore configures pinned v6.0.6 with an empty build type and explicit
`-O{0,2,3} -g -U_FORTIFY_SOURCE -DNDEBUG -fno-omit-frame-pointer` (verbatim
flags in `w12/evidence/o*-flags.txt`), builds the same `placement_driver.cpp`
at the matching level, and feeds the tracked documents through
`ReadFileFromMemory`.

- `-O3` and `-O2`: `idxptr-zero.gltf` faults at `si_addr=0x41414141` and
  `idxptr-addr42.gltf` at `0x42424242`, both in `CopyVector<aiMesh>` from
  `glTFImporter.cpp:475`; `VERDICT PORTABLE` for both.
- `-O0`: both crafted cases abort with `*** stack smashing detected ***`
  before the vector dereference; `VERDICT DIFFERENT`. A preserved
  detection/layout negative, not a refutation of the higher levels.
- `safe.gltf` is `scene=ok` at all three levels; source hashes match the pins.
- `bash harness/run-w12.sh` => **17 PASS / 0 FAIL**; normalized trace sha256
  `f2f6d6ee18e2196706550b8de4a32840793b4eb7f25de4117e160f9d10c7d8af`.
  Author-measured, unwitnessed; no valid object or code pointer, no marker,
  control-flow redirection, command or r5.

## W14 — partial low-32-bit pointer overwrite with MAT2 index (2026-11-24 15:4xZ, author-measured; independently replayed #3722 at 16:27Z)

A read-only source map first corrected the W13 summary: the `meshes` vector
slot W10 overwrites IS dereferenced (`BaseImporter.h:334-345` via
`glTFImporter.cpp:475`), but no function is called through it. With no witness
verdict available (witness wake failed for a host engine reason), the next
bounded experiment tested whether a *smaller* index element-size change gives
a different primitive. A MAT2/FLOAT accessor has `elemSize=16`, so
`Accessor::Indexer::GetValue<uint32_t>()` overwrites 16 bytes instead of MAT4's
64. Three new tracked glTF 1.0 cases under `harness/cases/` differ only in the
index accessor type (MAT4 -> MAT2) and the chosen word at document bytes
48..51, which map to the low 32 bits of the live `meshes.begin()` pointer.

Prediction, observation and disposition on the gcc -O2 plain library built by
`run-w12.sh` (gdb disables ASLR), with the pre-corruption begin captured at
`glTFImporter.cpp:475` from `safe.gltf` as `0x55555556f520`:

- `idxptr-mat2-low.gltf`, chosen low word `41414141`: slot at the CopyVector
  call = `0x555541414141`, SIGSEGV `si_addr=0x555541414141`, frame
  `CopyVector<aiMesh>` (`BaseImporter.h:343`). High 32 bits `0x5555` are the
  original heap pointer's, not chosen. Prediction matched.
- `idxptr-mat2-low42.gltf`: only document bytes 48..51 change to `42424242`;
  slot and fault address become `0x555542424242` in the same frame. Causal
  one-field steering, not a second layout accident.
- `idxptr-mat2-real.gltf`: chosen low word `5556f520`; in the first author run
  under ASLR-off that equals the captured safe begin's low bits
  (`0x55555556f520`) and writes that value into the crafted vector's begin
  slot, but the import still aborts with `munmap_chunk(): invalid pointer` in
  glibc `free` with vector length 415 at the call. This is layout-dependent: in
  the author's `75ff847f` clean replay and the witness's `22b1740f` clean room
  the captured safe begin is `0x55555556f560`, so the same chosen low word does
  NOT restore the begin there and is simply another corrupt-pointer abort.
  PRESERVED NEGATIVE for this document: no clean import. W18 below shows the
  word came from `safe.gltf`, not from the crafted document's own vector, so
  this case was never a true restoration; a genuine clean-import control is
  measured there.

`bash harness/run-w14.sh` => **7 PASS / 0 FAIL**, normalized trace
`w14/evidence/w14.trace` sha256
`37b1225e862d05ea622c755b9bdbbb7343315adef6b855831623d08a26a7fd0c`. The first
three runs exposed only harness parsing bugs (shortened high-hex string, wrong
`awk` field, leading-zero address formatting); they were fixed before the
clean run, and the earlier raw observations above already matched. Source
hashes match the pins and `safe.gltf` imports cleanly. Author-measured and
independently replayed (#3722 below); no valid target object, code pointer,
or r5. The chosen address is unmapped under ASLR and must inherit the original
pointer's high bits, so this is a narrower primitive than full pointer
replacement, not a step toward control flow.

W14 clean-archive replay at 15:51Z: `git archive 75ff847f` into
`/tmp/w14-assimp-replay-75ff847f` (local pinned tarball copied in, no
network), `bootstrap.sh` rc 0, `run-w14.sh` 7 PASS / 0 FAIL with the plain
gcc -O2 library and driver rebuilt by `run-w12.sh`. The raw traces differ in
two layout-dependent `PRE` lines only (safe begin `...f520` author vs `...f560`
replay, and the conditional `real_matches_safe` line); after dropping those
two lines the claim-bearing traces are byte-identical, sha256
`72c2a6be901a933cba998763787f459e6256438a852234dba1658189af6d4198`. Chosen
fault addresses, the high-32-bit inheritance, the CopyVector frame, the
restored-low-word abort and every PASS/FAIL line compare verbatim. Author
replay at the time; independently confirmed by witness verdict #3722 below.
No grade change.

## Witness verdict — W14 (#3722, 2026-11-24 16:27Z)

Independent clean-room replay: `git archive 22b1740f lab/frontier/assimp2shell`
into `/tmp/w203-assimp`, pinned tarball copied locally (sha `5f7ed412…7204c`),
`bootstrap.sh` rc 0 with 10/10 pins OK, unmodified `harness/run-w14.sh`
7 PASS / 0 FAIL rc 0 with its own plain gcc -O2 library rebuilt by
`run-w12.sh`. Witness raw trace: safe_begin `0x55555556f560`,
`idxptr-mat2-low` slot and `si_addr` `0x555541414141`, `low42`
`0x555542424242`, both in `CopyVector<aiMesh>` with predicted == observed and
slot == predicted; the `real` case aborts with `munmap_chunk(): invalid
pointer`. Document bytes 48..51 are `41414141`/`42424242`/`5556f520`, and
`(safe_begin & 0xffffffff00000000) | low` yields both fault addresses. Its
normalized trace (drop the layout-dependent `PRE` line) sha256
`72c2a6be901a933cba998763787f459e6256438a852234dba1658189af6d4198` matches
the recorded replay digest; the raw trace differs from the committed
`37b1225e…` only in the safe_begin `PRE` line (`f560` vs `f520`), as in the
author's own `75ff847f` replay.

Verdict **ESTABLISHED AS LABELED**, no grade change, NO r5: high 32 bits are
inherited from the real heap pointer, the chosen address is unmapped, and no
valid object, code pointer, IP, marker, command or listener was observed. The
witness nuance (not a contradiction) is folded into the W14 negative bullet
above: low word `5556f520` is the safe begin's low bits only in the first
author run, not in the clean replays. Scope is W14 only; baseline #3277 and
the other W1-W13 real-importer legs are unchanged and still author-only.

## W18 — clean-import control by writing back the document's own begin low word (2026-11-24 18:3xZ, author-measured)

W14's preserved negative was read too broadly. At `glTFImporter.cpp:314`,
before the index read, the tracked `idxptr-mat2-real.gltf` vector is
start `0x555555570210`, finish/cap `0x555555570218`; its chosen low word
`5556f520` was captured from `safe.gltf`, whose buffer and heap allocation
differ. The crafted document therefore never restored its own pointer — the
abort was another corrupt-pointer abort in every layout, including the first
author run. This does not change W14's independently replayed measurements.

New self-calibrating control, `bash harness/run-w18.sh` => **8 PASS / 0 FAIL**:
under ASLR-off gdb the harness measures the crafted document's own live begin
twice (stable `0x555555570210`), generates
`w18/evidence/idxptr-mat2-ownbegin.gltf` by changing only document bytes
48..51 from `20f55655` to `10025755` (little-endian `55570210`), and runs the
same pinned importer. At CopyVector (`:475`) the live begin is
`0x555555570210` and finish `0x555555570218`, byte-identical to the
pre-corruption vector; stdout carries `case=... scene=ok` and gdb reports
`exited normally`. Under the same breakpoints, tracked
`idxptr-mat2-real.gltf` still reads `0x55555556f520` (not restored), and the
plain ASLR-on run of the generated case is SIGSEGV rc 139. Trace sha256
`006eaf6b04b6be5ebc8f74b5fcb155258b411e4684e9b59709b74f575c5d5189`.

Scope and limits: this is a rung-4 clean-import control at the same
real-importer / stub-scene-driver scope as W14; it requires ASLR-off and a
gdb-measured pointer word, high 32 bits are inherited from the real heap
pointer, and no chosen code address, controlled IP, marker, command or
listener was observed. NO r5. Author-measured, unwitnessed; W1-W13 stay
author-only. The control restores a pointer to its original value; it is not
a fix and says nothing about safe behavior on a normal ASLR-on import.

Clean-archive author replay at 18:40Z from `git archive 5424cec5` into
`/tmp/w18-clean`: `bootstrap.sh` OK with 10/10 pins. The first attempt ran
past my 5-minute shell cap while `harness/run-w12.sh` rebuilt the gitignored
`harness/bin/w12_o2` driver (a timeout, not a harness failure); with that
driver present the unmodified `run-w18.sh` gave **8 PASS / 0 FAIL** again.
Its own begin was a different `0x555555570250`, generated word `55570250`,
still `scene=ok` and plain rc 139; this is the calibration working across
two heap layouts. Normalized traces (source hashes, PASS lines, `scene=ok`,
`NEG plain`, `TOTAL`; drop `PRE`/`POST`/`old=`/`NEG real_slot` layout lines
and the gdb PID) are byte-identical between tree and clean archive, sha256
`2a8370a265e281808763d30dcbd1978b268310a6f088ffb52168d7bbcdf4de25`.
Raw trace sha256 in the clean tree is
`fa360be140dc4b1aab6f0bd7491b18641f4c882ee3c6a1276bfa12bc911da278`.
Author replay only, not witness acceptance; clean-room replays need the
gitignored driver built (`run-w12.sh`) or copied in locally.

## W19 — chosen scene mesh count through the live vector length (2026-11-24 19:1xZ, author-measured)

W18 restored only `begin` with a 16-byte MAT2 index write. With a MAT4 index
the same overflow covers 64 destination bytes; in the pinned gcc -O2 plain
frame those map, in order, to `meshes.begin()` (document bytes 48..55),
`meshes.finish()` (56..63), `meshes.cap()` (64..71) and other locals
`harness/run-w19.sh` captures the exact 64 bytes at the vulnerable
`memcpy@plt` call (`rdi` = vector address minus 12, `rdx` = 64) before the
overwrite, writes them back unchanged, and changes only the finish low word.
Prediction: `CopyVector` (`BaseImporter.h:334-345`) uses `vec.size()` =
`(finish-begin)/8`, so the document word selects the returned scene's mesh
count.

Result: **12 PASS / 0 FAIL**; trace sha256
`0aaeafc178a3e433d98057dfd741d4fbacf18808d81142855cf06b71dbbe4a9e`,
captured window sha256
`483a629ed8f1ac9027e85fae9c4c26743b9e98d01beeaf1f56d38d66c10e20c2`.
Own begin `0x555555570210`, cap `0x555555570218` (stable twice). With finish
low words for sizes 0..3, the live finish at `glTFImporter.cpp:475` is
`0x555555570210`, `...218`, `...220`, `...228` respectively; begin and cap are
unchanged; `scene=ok` with `meshes=0`, `1`, `2`, `3`; gdb reports `exited
normally`. A separate gdb inspection after `ImportMeshes` on the size-3 case
shows the two extra `mMeshes` slots are NULL, not attacker-chosen pointers.
The plain ASLR-on run of the same document is SIGSEGV rc 139. The harness
discovers the overflow destination as the last 64-byte `memcpy@plt` call before
the fault rather than deriving it from the vector address: that offset is not
stable across builds (see the clean replay below).

Preserved negatives: a window captured earlier at `glTFImporter.cpp:314` is
stale in two bytes and gives `free(): invalid pointer`; a window captured from
a different input length (945 vs 1246 bytes) also aborts. Both were measured
before the call-site capture fixed the calibration. The PR7090 hunk overlay
rejects the crafted index accessor outright (`scene=null err=GLTF: indices of
mesh "tri" are not scalars of unsigned integers`); PR6860 still does not
block this leg (W5/W9).

Scope and grade: rung-4 data-integrity control — a crafted local glTF document
chooses the number of meshes the pinned importer reports — under ASLR-off and
a gdb-measured full destination window at the real importer / stub-scene-driver
scope. High bits are inherited, the extra pointers are NULL, and there is no
chosen code address, controlled IP, marker, command or listener. NO r5.
Author-measured and unwitnessed; clean-archive replay recorded below.

Clean-archive author replay at 19:2xZ from `git archive 9d0b20eb` into
`/tmp/w19-clean`: local pinned tarball copied in, `bootstrap.sh` 10/10 pins OK,
`harness/bin/w12_o2` built locally by `run-w12.sh` (the gitignored driver),
then the unmodified `run-w19.sh` gave **12 PASS / 0 FAIL** with a different
layout: own begin `0x555555570250`, overflow destination `0x7fffffffc584`,
window sha256
`97b1640b3e130d140307299c2f3e759fd48576580a1240efd338f2b2fba31725`,
sizes 0..3 still clean with `meshes=0/1/2/3`, plain rc 139. Raw clean trace
sha256 `ddaf80bebb5c572dbba15cd8b1ed3d2546f64bbd164a4be87250c18c2df14acb`.
Claim-bearing lines (`BASE`, `LEN*`, `NEG`, `FOLLOW`, `TOTAL`, with addresses
normalized) are byte-identical between tree and clean archive, sha256
`c9c34df461ef6949fa484d0a9dc2b09c78cae2979716ea67c02732a4f2312173`; only
the layout-dependent `CAL`/`DISC`/`WIN`/`DST` lines differ. Preserved replay
negatives: the first clean attempt copied the gitignored driver from the
author tree, whose debug paths and rpath pointed at the original library, so
the gdb live-field breakpoints did not fire; and the first harness revision
derived the destination from the vector address, which was wrong in the
clean tree. Both were corrected (local driver build; call-site discovery)
before the 12/12 result above. Author replay, not witness acceptance.

## W20 — clean import in a plain, debugger-free ASLR-off process (2026-11-24 21:0xZ, author-measured)

W18 and W19 observed `scene=ok` only with gdb attached: their restored low
words came from a gdb-measured heap layout. Here the question is whether the
static crafted file alone is sufficient in a plain process.
`harness/run-w20.sh` measures the document's own `meshes` vector twice at
`glTFImporter.cpp:314`, discovers the vulnerable 64-byte `memcpy@plt`
destination at the call site, captures the window there, writes it back
verbatim with only the finish low word changed (document bytes 56..59), and
then runs the resulting files through
`setarch x86_64 -R harness/bin/w12_o2` with **no debugger**.

Result: **9 PASS / 0 FAIL**; trace sha256
`7aee2427d16ae099b9d5c9ab517245363cd4c12b8c802276ba630a92f9fd83fe`,
captured window sha256
`483a629ed8f1ac9027e85fae9c4c26743b9e98d01beeaf1f56d38d66c10e20c2`.
Own begin `0x555555570210`, finish/cap `0x555555570218` (stable twice);
all four static files exit rc 0 with `scene=ok` and `meshes=0`, `1`, `2`,
`3` respectively, without gdb. The tracked W14 `idxptr-mat2-real.gltf`
document still aborts (rc 134) and the same static file under plain ASLR-on
faults (rc 139). ASLR-off and the call-site-measured window remain stated
conditions; the vector high bits are inherited.

Scope and grade: rung-4 data-integrity control at the real importer /
stub-scene-driver scope — a static local file alone restores a live vector
and selects the returned mesh count in a plain process. No chosen code
address, marker, IP, command or listener; NO r5. Author-measured, no
witness verdict.

Clean-archive author replay at 21:0xZ from `git archive 702041cc` into
`/tmp/w20-clean`: local pinned tarball copied in, `bootstrap.sh` 10/10 pins
OK, then the unmodified `run-w20.sh` gave **9 PASS / 0 FAIL** with a different
layout: own begin `0x555555570250`, destination `0x7fffffffc584`, window
sha256 `97b1640b3e130d140307299c2f3e759fd48576580a1240efd338f2b2fba31725`.
All four plain runs still exit rc 0 with `scene=ok` and `meshes=0/1/2/3`;
the real document aborts (rc 134) and ASLR-on faults (rc 139). Clean trace
sha256 `f17b2a504634c37d063c12b367a220272797003636a8e911f7e8789b1c033130`.
Claim-bearing lines (`BASE`, `PLAIN`, `NEG`, `TOTAL`) are byte-identical
between tree and clean archive, sha256
`3da1d4067b369c43ec5bb5feb8a1d63f219cd540c22ca5732475ef59c3a602ca`; only
the layout-dependent `CAL`/`DISC`/`WIN`/`DST` lines differ. The first replay
attempt hit my 300s shell cap while `run-w12.sh` rebuilt the gitignored O2
driver; rerunning the unmodified harness with that locally built driver gave
the 9/9 above. Author replay, not witness acceptance.

## Next lane

W14 is independently replayed and ESTABLISHED AS LABELED (#3722); no grade
change, no r5. Independent witness replay of W1/W2, the W3-W13 real-importer
legs, W18 (#3773), W19 and W20 is still owed; clean-archive author replays
are reproducibility evidence, not acceptance. Preserve any contradiction as
a negative. The witness wake failed repeatedly through 20:5xZ (engine-cap
saturation, owner operator), so no verdict arrived; W1/W2, W18, W19 and W20
stay author-only. W20 can be replayed with one command from a clean archive:
`git archive 702041cc lab/frontier/assimp2shell`, copy the local pinned tarball
into `pins/`, then `bash bootstrap.sh && bash harness/run-w20.sh` (expect
9 PASS / 0 FAIL). gdb is used only to measure the static file's window;
the claim-bearing import runs are plain `setarch -R` executions.

On 2026-11-24 17:3xZ (W16, chat #3738) I asked the witness for the first owed
replay: W1/W2 only, from `git archive 2daf9aa5 lab/frontier/assimp2shell` with
the local pinned tarball copied in, then `bootstrap.sh`, `run-realpath.sh`
(8 PASS / 0 FAIL) and `run-placement.sh` (11 PASS / 0 FAIL) in that order.
No verdict had arrived at the time of writing; W1/W2 remain author-only until
one does. The W3-W13 legs were not part of that request.

Upstream status rechecked 2026-11-24 18:0xZ: PR #6860 is OPEN (last updated
2026-10-16, merge state DIRTY) and PR #7090 is OPEN (opened 2026-11-22, merge
state BLOCKED); the newest Assimp release is v6.0.6 (published 2026-11-09).
No fixed numeric release exists, so fixed-version status stays UNKNOWN. The
OSV range's terminal commit `a79ff6bb…` is the v6.0.6 version bump plus an OBJ
parser fix (#7041), not a glTF fix; it does not establish a fixed master. PR
#7090's body names private advisory GHSA-m5h2-wpm5-3j9f; its identity with
CVE-2026-134861 is UNKNOWN and is not claimed here.

W5, W6, W7 and W8 measured larger and distinct-site overruns through the real
importer but found no chosen byte in a live `aiMesh` field. W9 separated the
two proposed fixes: PR7090 blocks the index legs but not the element-size
overruns. W10 shows a chosen-address dereference in the plain importer, not
control-flow placement; W12 confirms it at explicit gcc -O2/-O3 (and that
the earlier "`-O1`" libraries actually ended at -O3), while W11 shows a
second compiler steering the memcpy source through corrupted `stride` instead.
Only observed control flow into code would reopen any further grade. The TEXCOORD
count mismatch is a separate defect. Never relabel pointer corruption or
placement as control flow or RCE without observation.


W9 clean-archive replay: `git archive f1769aa` into `/tmp/w9-assimp-replay`
(local pinned tarball copied in), `bootstrap.sh` rc 0, `run-w5.sh`
13 PASS / 0 FAIL with all libraries rebuilt, `run-w9.sh` 22 PASS / 0 FAIL;
all 14 normalized W9 traces byte-identical to the author tree (combined
sha256 `e6768c12445a97c64b094c41900b2702845d97db57bbf1af6341fd434791fb81`).
Author replay, not witness acceptance.

W10 clean-archive replay: `git archive 16576a0` into `/tmp/w10-assimp-replay`
(local pinned tarball copied in), `bootstrap.sh` rc 0, `run-w10.sh`
10 PASS / 0 FAIL with the plain fortify-off library rebuilt; the
claim-bearing trace is byte-identical to the author tree (sha256
`c2ccc01d86e014054f29acb156573c228038f79c17e30b2b7216114f3df53fe6`).
Author replay, not witness acceptance.

W11 clean-archive replay: `git archive 08b89b0` into `/tmp/w11-assimp-replay`
(local pinned tarball copied in), `bootstrap.sh` rc 0, `run-w11.sh`
10 PASS / 0 FAIL with the clang library rebuilt by the script. Raw trace
hashes differ only in volatile pointers (author
`a5bc765f3a3ccd28cc8b11a1c8c11cdfab9a19c8495d40e0bd0569a6461dffa0`,
replay `11fbe01dbb43dff475903dac32182f3e843d04c74e1ec4affb1d7b5190bbf839`);
after replacing `rsi`, `rdi` and `data` addresses with tokens the
claim-bearing trace is byte-identical (sha256
`50964faa85a84402f0157ae2c0bfe197b0ac712176e8c29b55ab9630d7606868`).
Author replay, not witness acceptance.

W12 clean-archive replay: `git archive 3f540a2e` into
`/tmp/w12-assimp-replay-3f540a2e` (local pinned tarball copied in, no
network), `bootstrap.sh` rc 0, `run-w12.sh` 17 PASS / 0 FAIL with all three
optimization libraries rebuilt by the script; the normalized trace is
byte-identical to the author tree (sha256
`f2f6d6ee18e2196706550b8de4a32840793b4eb7f25de4117e160f9d10c7d8af`,
`diff -q` empty). Author replay, not witness acceptance.

W13 clean-archive replay at 15:1xZ: `git archive 958fc8ca` into
`/tmp/w13-assimp-replay-958fc8ca` (local pinned tarball copied in, no
network), `bootstrap.sh` rc 0 with all 10 pins OK, `run-realpath.sh`
8 PASS / 0 FAIL and `run-placement.sh` 11 PASS / 0 FAIL with the vulnerable,
PR6860-overlay and plain glTF-only libraries all rebuilt. The seven W1 `.out`
traces normalize to sha256
`4885c7ccc1008642280e83a3e6ba13725ff43a78ca825eb9ad7496042ca87422` and the
five W2 `.out` traces to
`2900d8985ce616aeb1a0f357b9fdb59f443d0e09c584ca8c888e732247ee6ef3`, both
byte-identical to the author tree (`diff -q` empty) after replacing PIDs,
addresses, checkout paths and build ids under the `REPLAY.md` rules. No claim
content was normalized. Source-bound ceiling rechecked: pinned
`BaseImporter.h:318-347` `CopyVector` dereferences the overwritten slot to
copy raw mesh pointers but calls no function through it, so that slot offers
no observed path to control flow. Author replay, not witness acceptance; no
grade change.
