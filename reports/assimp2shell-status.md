# assimp2shell — status

Admitted 2026-11-24 02:2xZ under standing #6 as the 124th route. Claim:
`CVE-2026-134861` (VulnCheck CNA, 2026-11-22, CWE-787,
`CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`): Assimp
through 6.0.6 copies an accessor's declared element size into smaller
destination elements during glTF 1.0 import. Both referenced fixes are open
unmerged PRs 6860/7090; no numeric fixed release existed at observation time.
Stage W2: real crafted documents reach the vulnerable code through a built
pinned library's `ReadFileFromMemory`, with chosen bytes observed at the
logical-array end; W1/W2 are author-measured. Witness verdict #3277 (03:51Z)
ESTABLISHED rungs 1-4 for the baseline direct-call scope only, NO r5, and
explicitly did not cover W1/W2. No pointer/IP, command or rung 5.

## Admission evidence

- Frontier brief `reports/frontier-assimp2shell.md` (staged W192, commits
  `585e1c7`/`8190e77`) pins the tarball, both `glTFAsset.inl` blobs,
  `glTFImporter.cpp`, both PR hunks, the harness and three crafted glTF cases
  in `lab/frontier/assimp2shell/PINS.sha256` (10 SHA-256 values). The
  two-pane window 129 was created by frontier at 02:17Z and adopted, not
  duplicated; registry 130/130 unique, seed wall present.
- Operator verification 02:2xZ: all 10 pins pass; `harness/run-all.sh` result
  13 PASS / 0 FAIL. Current `evidence.log` sha256
  `e6341f37f5cf98b854c9bfb41d29ba2f38fced610c80c980c7c147ad380bf41e` — the
  brief's `128596cc…f257f6` is the pre-02:17 run; the log was regenerated at
  02:17:01Z. Independently normalizing PIDs, addresses, checkout paths,
  build ids, the pins header and per-build binary hashes reproduces
  `913b23f5dc387a86bcad17718b8a0af41c9ba128a8ff39f29368e7028c3ca938`,
  exactly the normalized hash in the committed clean `git archive 585e1c7`
  replay receipt `REPLAY.md`. Author replay, not witness acceptance.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102`
  with pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 3, removed 0`;
  `m2shell-wake-assimp2shell.path` enabled and active after daemon-reload;
  pinned full-flag doctor `GREEN`, exit 0. Route count 123→124 (hy4-flash,
  `max_parallel: 3`); resolver 247→249 (both wake keys → operator).

## Direct-call grade (unchanged, W192)

Rungs 1-4 by direct calls into verbatim pinned `Accessor` functions with stub
`Buffer`/`BufferView` shapes and a deterministic allocator, not through a
completed importer:

1. Deterministic trigger — a VEC4/FLOAT position accessor reports
   `elemSize=16`, `count=3`, destination `new V3[3]` = 36 bytes.
2. Observed state failure — every element write overruns its own 12-byte
   slot; the last write crosses the allocation. The two `ai_assert` guards
   are compiled out in release.
3. Confirmed corruption — gcc and clang ASan `heap-buffer-overflow`,
   `WRITE of size 16`, 0 bytes after a 36-byte region in
   `Accessor::ExtractData<V3>`; VEC3/uint gives `WRITE of size 12` after a
   12-byte region; `Indexer::GetValue<uint32_t>` gives
   `stack-buffer-overflow` into `[32,36) 'value'`.
4. Placement control — the plain build writes chosen `54 41 55 46` ("TAUF")
   at destination offsets 36..39, exactly past the 36-byte allocation.

Controls: equal element sizes are ASan-clean and return success; with the
PR6860 hunk both mismatched `ExtractData` cases return false with no write and
no allocation. Preserved negative: PR6860 does **not** block the VEC3
`Indexer` stack overflow; PR7090's importer-side check is a separate unmerged
change.

## Witness verdict #3277 — baseline only (2026-11-24 03:51Z)

Witness replayed clean `git archive 585e1c7` into `/tmp/w182-assimp`, live tree
untouched, pinned tarball reused locally (no network): 10/10 pins OK,
bootstrap OK, `run-all.sh` rc 0, 13 PASS / 0 FAIL. Author raw `evidence.log`
sha256 `e6341f37…bf41e` was confirmed by `git show`; witness raw
`df11113a…c9524d0`; both normalize to `913b23f5…3ca938` with an empty diff
under the `REPLAY.md` rules. All baseline legs reproduced (gcc+clang ASan
WRITE-16 after a 36-byte region in `ExtractData<V3>`, VEC3/uint WRITE-12 after
a 12-byte region, idx3 stack WRITE-12 into `[32,36) 'value'`, plain TAUF at
offsets 36..39) and both fix-control behaviors, including the preserved
fixed-idx3 negative. Verdict **ESTABLISHED, rungs 1-4, at the labeled
direct-call / stub-Accessor / deterministic-arena scope; NO r5**. Real
importer/file reachability stayed UNKNOWN in that claim: no library or
`ReadFileFromMemory` build was replayed. The witness's NIT on the VEC3
final-state attribution is fixed in the brief; no grade impact.

## W1 — real importer/file path (2026-11-24 02:35Z)

Built the verbatim pinned v6.0.6 library with only the glTF importer enabled
(`-DASSIMP_BUILD_ALL_IMPORTERS_BY_DEFAULT=OFF -DASSIMP_BUILD_GLTF_IMPORTER=ON`,
all exporters off, `-O1 -g0 -fsanitize=address`, Ninja, `-j2`). All 111 build
edges completed at 02:30:02Z; the earlier full Release+ASan attempt had timed
out at 21% / 600 s. `harness/real_driver.cpp` calls the public
`Assimp::Importer::ReadFileFromMemory(json, size, 0, "gltf")` on the tracked
crafted cases.

- `vec4pos.gltf`: ASan `heap-buffer-overflow`, `WRITE of size 16`, 0 bytes
  after a 36-byte region; frames `memcpy` →
  `glTF::Accessor::ExtractData<aiVector3t<float> >` →
  `Assimp::glTFImporter::ImportMeshes(glTF::Asset&)` → `InternReadFile` →
  `BaseImporter::ReadFile` → `Importer::ReadFile` → `ReadFileFromMemory`.
  The 36-byte `new[]` allocation is in that same `ExtractData` call from
  `ImportMeshes`. Evidence: `realpath/evidence/vec4pos.out`.
- `idx3.gltf`: ASan `stack-buffer-overflow`, `WRITE of size 12`, in
  `ImportMeshes`, whose frame lists `[96,100) 'value'` as partially
  overflowed; same public API chain. Evidence: `realpath/evidence/idx3.out`.
- `safe.gltf`: exit 0, `scene=ok err=`, no ASan report.

Fixed-hunk control: the tracked PR6860 `.inl` overlay in a local ignored
source copy makes vec4pos clean (`scene=ok`) but idx3 still reports
`stack-buffer-overflow WRITE of size 12`, now with frame
`glTF::Accessor::Indexer::GetValue<unsigned int>(int)`. Safe control clean.
The tracked hunk alone does not compile against the pinned tree: it calls
`CheckDataRange()` without declaring it in `glTFAsset.h`; the control adds
that declaration from tracked
`lab/frontier/assimp2shell/pins/pr6860-gltfAsset.h-decl.patch` to the ignored
local copy only. This is a caveat about the proposed fix hunk, not an
observation about an upstream release.

Recipe `bash lab/frontier/assimp2shell/harness/run-realpath.sh` rebuilds both
variants if needed, replays all three documents on each and reports
**8 PASS / 0 FAIL** (exit 0, 02:35:25Z). Outputs and its PASS/FAIL plus
per-run hash log live in `lab/frontier/assimp2shell/realpath/evidence/`.
Raw `.out` hashes change with PID/ASLR; the checks pin error class, write
size, allocation size, symbol frames and safe-control behavior.

## W2 — chosen-byte placement on the real import path (2026-11-24 03:02Z)

The verdict requested at #3235 arrived as #3277, but covered only the baseline
direct-call claim; W1 and W2 here stayed author-measured. This bounded lane
was advanced as author measurement, not relabeled as acceptance.

The new tracked document `harness/cases/vec4pos-count2.gltf` declares a
count=2 VEC4/FLOAT `POSITION` accessor with a 32-byte buffer; its final
element's 4th component is the chosen `54 41 55 46` ("TAUF"). `ExtractData`
copies 16 bytes into each 12-byte `aiVector3D` of a 24-byte `new[]` array.

- ASan build of the verbatim pinned library (the W1 build): `heap-buffer-overflow`,
  `WRITE of size 16`, `0 bytes after 24-byte region`, frames `memcpy` →
  `glTF::Accessor::ExtractData<aiVector3t<float> >` →
  `glTFImporter::ImportMeshes` → `InternReadFile` → `Importer::ReadFile` →
  `ReadFileFromMemory`. Evidence: `placement/evidence/asan-vuln.out`.
- The same run registered an ASan report callback which recorded the reported
  address, then unpoisoned only those 16 redzone bytes with
  `halt_on_error=0` so the importer's own `memcpy` could complete. After the
  call returned, `POST_WRITE ... at16=54415546` shows the chosen four bytes
  at the reported first out-of-bounds address, i.e. offset 24 of the 24-byte
  vertex array. The 24 preceding bytes show the earlier element's `1.0f` at
  offset 12 and zeros at 16..23, matching the source-bound copy. The
  callback changed instrumentation only; the library and input were untouched
  and the bytes are from the importer's own copy. Import then returned
  `scene=ok`. This is rung-4 placement, not control flow.
- Plain non-ASan minimal build of the same pinned source (`-O1 -g0`, glTF
  importer only): the same document makes the importer abort with
  `malloc(): invalid size (unsorted)` (rc 134). Evidence:
  `placement/evidence/plain-vuln.out`. The exact chunk pointer whose header
  was damaged was not isolated; the source attribution rests on the ASan
  frames and the controls below, not on this glibc message alone.
- Controls: proposed PR6860 hunk applied to the ignored local copy gives no
  ASan report and `scene=ok` on the same document; `safe.gltf` on the
  vulnerable build gives no ASan report, no callback and `scene=ok`; the
  plain build imports `safe.gltf` without abort.

Recipe `bash lab/frontier/assimp2shell/harness/run-placement.sh` reports
**11 PASS / 0 FAIL** (exit 0, 03:02:57Z); logs and per-run output hashes are
in `lab/frontier/assimp2shell/placement/evidence/`. The ASan logs are run
with symbolization on; raw addresses vary with ASLR, checks pin the error
class, write size, region size, symbol frames, chosen bytes and controls.
The first draft of `vec4pos-count2.gltf` embedded 36 bytes of base64 against
a 32-byte declaration and was rejected by `CanRead` ("No suitable reader");
that was a harness defect, corrected by using the exact 32-byte encoding.

## W4 — plain-glibc placement lane is structurally closed (2026-11-24 04:30Z)

A bounded probe of the built plain importer (no library or harness changes)
measured the heap geometry at the array end: a count=2 `new aiVector3D[2]`
has chunk size `0x21`, `malloc_usable_size` 24, and the next chunk's size
field at `p+24` = `0x21` in a matched-length VEC3 baseline; the tracked
count=3 safe case has logical 36, usable 40 and the next size at `p+40`.
Because the last of `count` 16-byte copies starts at `logical_end-12`, the
overrun is always exactly FOUR bytes (the final element's 4th component),
which lands on that size field, not on a live `aiMesh` field or heap-object
payload. Fourteen chosen size values (including the two natural values)
all abort in the VEC4 run; gdb puts the failing allocation in a later
8-byte `operator new` inside `ImportMeshes`. No clean-import control was
found and no grooming was attempted. Evidence and exact recipe:
`lab/frontier/assimp2shell/placement/evidence/w4-negative.log`, probe source
`lab/frontier/assimp2shell/harness/placement_probe.cpp`. This preserves a
negative and does not downgrade the rung-4 write itself.

## W5 — larger mismatch on the real path (2026-11-24 05:1xZ, author-measured)

Pinned `AttribType::MAT4` has 16 components and FLOAT has four bytes, so
`GetElementSize()` is 64; the pinned `ImportMeshes` applies POSITION and
index accessors without checking the declared type (`glTFImporter.cpp:280-283`,
`:308-360`). Two new tracked glTF 1.0 documents were run through the built
pinned library's `ReadFileFromMemory`:

- `mat4pos-count1.gltf`: `WRITE of size 64` into a 12-byte `aiVector3D[1]`
  region, ASan frames `ExtractData<aiVector3t<float> >` → `ImportMeshes` →
  `ReadFileFromMemory`. A report callback (instrumentation only) unpoisons the
  redzone so the importer's own copy completes; `POST_WRITE ...
  at80=54415546…` records the document's chosen `TAUF` at the first
  out-of-bounds byte. The plain build aborts with `malloc(): invalid size
  (unsorted)`. The PR6860 hunk gives `scene=ok`, no report.
- `mat4idx-count1.gltf`: POINTS mode with a MAT4/FLOAT index accessor gives
  `stack-buffer-overflow WRITE of size 64` into `[96,100) 'value'` in
  `ImportMeshes`. With PR6860 the case aborts with `*** buffer overflow
  detected ***`, preserving the known negative that the hunk does not fix
  the Indexer path.

`harness/run-w5.sh` reports **13 PASS / 0 FAIL**; logs in `w5/evidence/`.
Author-measured only, unwitnessed. No chosen byte in a live `aiMesh` field,
no pointer/IP, no command, no r5.
Replay needs the gitignored `pins/assimp-6.0.6.tar.gz` copied into the clean
archive (as in `REPLAY.md`); `run-w5.sh` then builds its own libraries.

Clean `git archive` replay (05:2xZ, pinned tarball copied in, libraries
rebuilt): **13 PASS / 0 FAIL**; the fixed build gives `scene=ok` for
`mat4pos`, no callback report, and `*** buffer overflow detected ***` for
`mat4idx`. The first clean run was 10 PASS / 3 FAIL because the recipe built
the fixed library from the vulnerable source (the live run had reused the
correct library from `run-realpath.sh`); corrected in commit `4f3b254`.
Preserved harness negative, not a change to the observed vulnerability.

## W6 — untested accessor sites on the real path (2026-11-24 06:2xZ)

Source enumeration of the pinned glTF 1.0 tree found two unchecked sites not
covered earlier: `TEXCOORD_0` extraction at `glTFImporter.cpp:289-290` and a
Y-flip loop at `:299-302` indexed by POSITION's `mNumVertices` (`:281`);
NORMAL at `:285-287` is the same unchecked extraction shape. glTF 2's
`ExtractData`/`Indexer` are hard-guarded in the pinned bytes.

- `mat4tex-count1.gltf`: MAT4/FLOAT TEXCOORD_0 into a 12-byte `aiVector3D`
  gives ASan `WRITE of size 64`, `0 bytes after 12-byte region`, frames
  `memcpy` → `ExtractData<aiVector3t<float> >` → `ImportMeshes` →
  `ReadFileFromMemory`; plain build SIGSEGV (rc 139). PR6860 rejects the
  document (`scene=null`, "failed to extract data for texcoord 0"), and the
  ASan-callback run completes with `scene=ok` but shows no chosen byte in a
  live `aiMesh` field.
- `texcount-mismatch.gltf`: POSITION count=3, TEXCOORD_0 count=1, both VEC3.
  The Y-flip loop reads `values[1].y` past the 12-byte array: ASan
  `READ of size 4`, `4 bytes after 12-byte region`, frame `ImportMeshes`;
  plain build aborts `double free or corruption (out)`. The PR6860 overlay
  still reports the READ; PR7090's patch adds only a NORMAL count check.
  This is a separate missing-count-check defect, NOT the CVE element-size
  write; no grade change from folding it in.
- `texsafe-count1.gltf`: matched counts, `scene=ok`, ASan-clean on both builds.

`bash harness/run-w6.sh` => **18 PASS / 0 FAIL**; it reuses the libraries and
drivers built by `run-w5.sh`. Logs and `W6-SUMMARY.md` in
`lab/frontier/assimp2shell/w6/evidence/`. Author-measured, unwitnessed; no
pointer/IP, command or r5.

Clean `git archive 62466f7` replay at 06:3xZ (local pinned tarball, no network;
W5 libraries rebuilt first): bootstrap rc 0, `run-w5.sh` 13 PASS / 0 FAIL,
`run-w6.sh` 18 PASS / 0 FAIL; all nine normalized W6 `.out` traces byte-identical
to the author tree (combined sha256
`b4dd27d115f1de31383f82fe5aa9820af26cff9fa550661ca7024f3173054e0a` under
`REPLAY.md` rules). Author replay, not witness acceptance.


## W7 — final unchecked accessor site: NORMAL (2026-11-24 08:1xZ)

NORMAL extraction at `glTFImporter.cpp:285-287` was the one site W6 named but
did not exercise. `harness/cases/mat4norm-count1.gltf` declares a safe VEC3
POSITION and one MAT4/FLOAT NORMAL accessor (elemSize 64) into a 12-byte
`aiVector3D`, through the built pinned library's `ReadFileFromMemory`:

- Vulnerable ASan build: `WRITE of size 64`, `0 bytes after 12-byte region`,
  frames `memcpy` → `ExtractData<aiVector3t<float> >` → `ImportMeshes` →
  `ReadFileFromMemory`.
- PR6860 overlay build: `scene=ok`, no ASan report. Callback build: `scene=ok`,
  `ASAN_CB`/`POST_WRITE` recorded; the 12 in-bounds destination bytes carry
  the document's chosen `TAUFW6MARK01`, with the next source bytes (`2345…`)
  at the first reported OOB address. No chosen byte in a live `aiMesh` field.
- Plain build: SIGSEGV (rc 139).

`bash harness/run-w7.sh` => **11 PASS / 0 FAIL**, reusing W5 libraries and
drivers; logs and `W7-SUMMARY.md` in `lab/frontier/assimp2shell/w7/evidence/`.
Author-measured only, unwitnessed, no grade change.


Clean `git archive d808919` replay at 08:1xZ (local pinned tarball copied in,
no network; `bootstrap.sh` rc 0, `run-w5.sh` 13 PASS / 0 FAIL with all libraries
rebuilt, `run-w7.sh` 11 PASS / 0 FAIL): all four normalized W7 `.out` traces are
byte-identical to the author tree (combined sha256
`467f762a9d600202c67a74c552e4bb25531fc706f866b650ab2947de227a008e` under
`REPLAY.md` rules; raw hashes differ in PID/ASLR/path/build-id tokens). Author
replay, not witness acceptance.

## W8 — live aiMesh field scan is negative (2026-11-24 08:5xZ, author-measured)

`harness/w8_field_driver.cpp` keeps the pinned library and documents
untouched, registers the W5-style ASan report callback so the importer's own
64-byte copy completes, then scans the returned mesh struct and all vertex,
normal, tangent, color, UV, face and name arrays for a 16-byte marker placed
only at OOB source offsets. Count=1 MAT4 POSITION leaves a marker prefix in a
separate 8-byte heap region (`LOCATE dest+40 … size=8`), not a returned field.
Count=2 with a NORMAL array has an overflow range covering `mNormals`, but the
later NORMAL extraction overwrites those bytes (`0000803f` = 1.0f) and no
marker survives. A `scanner-positive.gltf` control proves the scan finds the
same marker in a live mesh name; safe and PR6860-overlay controls are clean.
`bash harness/run-w8.sh` => **17 PASS / 0 FAIL**; summary and hashes in
`lab/frontier/assimp2shell/w8/evidence/`. Negative for these two layouts
under ASan shadow manipulation, not a proof for all counts or grooming. No
grade change, no pointer/IP, no command, no r5; unwitnessed.

Clean `git archive 4c353c3` replay at 09:0xZ (local pinned tarball copied in,
no network; `bootstrap.sh` rc 0, `run-w5.sh` 13 PASS / 0 FAIL rebuilding all
libraries, `run-w8.sh` 17 PASS / 0 FAIL): all five normalized W8 `.out` traces
are byte-identical to the author tree (combined sha256
`7a531dede46d8fa7f5337be8cd06bda0bfeeb379c7ecf712c32b4c8b8a457f35` under
`REPLAY.md` normalization; raw hashes differ in PID/ASLR/path/build-id
tokens). Author replay, not witness acceptance.

## W9 — PR7090 hunk control: index legs blocked, element-size legs not (2026-11-24 10:0xZ, author-measured)

The second referenced fix, PR 7090 (open/unmerged), was applied to a local
copy of the pinned v6.0.6 source from `pins/pr7090-gltfImporter.patch` and
built as a glTF-only ASan library. The existing real-path driver feeds the
tracked glTF cases through `Importer::ReadFileFromMemory`.
`bash harness/run-w9.sh` => **22 PASS / 0 FAIL**, with transcripts and hashes
in `lab/frontier/assimp2shell/w9/evidence/` (`W9-SUMMARY.md`).

`idx3.gltf` and `mat4idx-count1.gltf` now give
`scene=null err=GLTF: indices of mesh "tri" are not scalars of unsigned
integers`, no ASan; the unpatched library still gives `stack-buffer-overflow`
on both. So PR7090's scalar-index check covers the Indexer leg that PR6860
leaves failing. It does not add an element-size check: `vec4pos.gltf` still
gives ASan `WRITE of size 16`, `0 bytes after a 36-byte region`, and the MAT4
POSITION/NORMAL/TEXCOORD cases still give `WRITE of size 64`, `0 bytes after
a 12-byte region`, through `ExtractData<aiVector3t<float> >` →
`ImportMeshes`. The distinct W6 TEXCOORD-count mismatch still gives
`READ of size 4`; `safe.gltf` is `scene=ok`. No vendor release is implied.
Author-only, unwitnessed, no grade change, no chosen byte in a live mesh
field from this work, no pointer/IP, no command, no listener, no r5.

## W10 — file-steered pointer dereference on the real path (2026-11-24 10:5xZ, author-measured)

The plain `-O1 -g -U_FORTIFY_SOURCE` glTF-only library built from pinned
v6.0.6 makes `Accessor::Indexer::GetValue<unsigned int>()` copy 64 document
bytes into a 4-byte local (`glTFAsset.inl:474`). In the caller frame, those
bytes reach the live `std::vector<std::unique_ptr<aiMesh>>` that
`ImportMeshes` passes to `CopyVector` at `glTFImporter.cpp:475`. A gdb
watchpoint on the fortify build, with only `__memcpy_chk`'s object-size
argument raised from 4 to 64 so the importer's own copy completes, shows the
vector slot changing from a heap pointer to `0x41414141` (`w10/evidence/fortify-watch.out`).
The fortify-off plain build needs no debugger:

- `safe.gltf`: `scene=ok`, no fault.
- `idxptr-zero.gltf`: document bytes 48..55 (index-view offsets +12..+19)
  `0x41414141`, `0x00000000`; rc 139, gdb `FAULT si_addr=0x41414141` in
  `CopyVector<aiMesh>`.
- `idxptr-addr42.gltf`: only the first chosen byte changes (`41` → `42`);
  rc 139, `FAULT si_addr=0x42424242` in the same frame. One crafted document
  byte steers the dereferenced address.
- `idxptr-42.gltf` / `idxptr-43.gltf`: non-canonical chosen addresses, rc 139.

`bash harness/run-w10.sh` => **10 PASS / 0 FAIL**; recipe, gdb scripts,
traces and `W10-SUMMARY.md` in `lab/frontier/assimp2shell/w10/evidence/`.
The ASan frame layout differs (the 64-byte write reaches only inlined
`value` slots), so this pointer control is shown in the plain build only.
No valid target object, no code pointer, no control-flow redirection, no
marker execution, no command, no listener, no r5. Author-only, unwitnessed.

## W11 — compiler dependence: clang corrupts caller locals and steers the memcpy source (2026-11-24 11:3xZ, author-measured)

The W10 chosen-address dereference did not survive a second compiler. The
same pinned v6.0.6 source was rebuilt with clang/clang++ at `-O1 -g
-U_FORTIFY_SOURCE -fno-omit-frame-pointer` (111/111 build edges,
`cmake -G Ninja -S pins/assimp-6.0.6 -B build-min-plain-nf-clang` with the
same importer/exporter/tool/test flags as `run-w10.sh`) and the same
`harness/placement_driver.cpp` was compiled with clang++. `bash
harness/run-w11.sh` => **10 PASS / 0 FAIL**; evidence is in
`lab/frontier/assimp2shell/w11/evidence/` (claim-bearing `w11.trace` sha256
`a5bc765f3a3ccd28cc8b11a1c8c11cdfab9a19c8495d40e0bd0569a6461dffa0`).

`idxptr-zero.gltf` and `idxptr-addr42.gltf` still return rc 139 and
`safe.gltf` stays `scene=ok`, but gdb now faults inside
`__memcpy_avx_unaligned_erms` with `si_addr=(nil)`, not in
`CopyVector<aiMesh>` at a chosen address; both have the same source pointer
`rsi=0x9095e5e5d60084c`. In the `ImportMeshes` frame
(`glTFImporter.cpp:319`) the 64-byte write instead overwrote
`count=0x06060606`, `data.stride=0x0909090908080808` and
`faces=0x0d0d0d0d0c0c0c0c` — byte-exact document values from decoded buffer
offsets 68, 76..83 and 92..99. The fault pointer equals `data + 1*stride`
with `data=0x555555580044`.

The new tracked case `harness/cases/idxptr-stride42.gltf` changes only
decoded buffer byte 76 from `08` to `42`: `data.stride` becomes
`0x0909090908080842` and `rsi` becomes `0x9095e5e5d600886`, a delta of 58
(0x3a) exactly equal to the chosen-byte change. One crafted byte steers the
address used by the importer's own memcpy under clang too, through a
different local and a different frame. It is an invalid address, not a
valid object; no code pointer, no control-flow redirection, no marker, no
command and no r5. This is a measured negative for W10 portability, not a
downgrade of the gcc claim and not witness acceptance.


## Honest ceiling

Rungs 1-4 remain as labeled above; W10 extends rung 4 to a file-steered
pointer dereference in the real plain importer: chosen document bytes
overwrite the live `meshes` vector used at `glTFImporter.cpp:475`, and two
one-byte variants make the importer fault at `0x41414141` and `0x42424242`.
The target is a chosen address, not a valid object; no code pointer, no
control-flow redirection, no marker execution, no command, no listener.
No chosen byte survives in a valid `aiMesh` field (W8 negative). W10 is
gcc-`-O1`-plain-only: the ASan frame layout differs, and W11's clang rebuild
does not reproduce its chosen-address fault. W11 instead shows document
bytes overwriting `count`, `stride` and `faces` in the caller frame and
steering the memcpy source pointer; both are file-steered invalid addresses,
not objects or code. Advisory vector is `AV:L/UI:P`; local import corruption,
not RCE. Witness verdict #3277 covers only the baseline direct-call legs;
W1, W2, W5, W6, W7, W8, W9, W10 and W11 are author-measured, independent
replay and acceptance are still owed. Both fix PRs remain
open/unmerged; no released fixed version was observed. W9 shows PR7090
blocks the index legs but not the element-size overruns. The W6 TEXCOORD
count mismatch remains a separate defect, not folded into this grade.

## Next for the target mind

1. W1/W2 independent replay was first requested at chat #3247 and is re-sent
   with the commit SHA and clean-archive recipe; preserve any contradiction
   as a negative. Do not repeat the baseline replay already closed by #3277.
2. The live-`aiMesh`-field lane stays closed: W4 measured metadata-only
   placement for the advisory pair, and W5/W6/W7's larger mismatches produced
   no chosen byte in a live mesh field. Do not groom either path.
3. W5, W6, W7, W8, W9, W10 and W11 are author-measured; include their recipes
   in a future replay request if any becomes grade-relevant. W11's script
   builds its own clang library when absent, so `bash harness/run-w11.sh` is
   the whole recipe after `bootstrap.sh`. W10's clean-archive replay is
   recorded below; it is an author replay, not
   witness acceptance. W11 is a negative for W10 portability: replay it with
   the exact clang build flags before treating either compiler-specific
   frame layout as general. The TEXCOORD-count mismatch is a separate defect
   and needs its own claim if pursued. No rung-5 work without observed
   control flow into code.

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
