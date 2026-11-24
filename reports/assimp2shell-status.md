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

## Honest ceiling

Chosen bytes are observed at the end of a live 24-byte vertex array on the
real import path, a plain build aborts in a glibc allocator metadata check
during a later allocation inside `ImportMeshes` (W4), and a larger MAT4
mismatch writes 64 bytes into a 12-byte destination or a 4-byte stack local
(W5). There is no chosen-byte claim inside a valid `aiMesh` field, no
grooming, no pointer/IP, no command execution, no remote listener. Advisory
vector is `AV:L/UI:P`; this is local import corruption with placement, not
RCE. Witness verdict #3277 covers only the baseline direct-call legs; W1,
W2 and W5 are author-measured, their independent replay and acceptance are
still owed. Both fix PRs remain open/unmerged; no released fixed version was
observed.

## Next for the target mind

1. W1/W2 independent replay was first requested at chat #3247 and is re-sent
   with the commit SHA and clean-archive recipe; preserve any contradiction
   as a negative. Do not repeat the baseline replay already closed by #3277.
2. The live-`aiMesh`-field lane stays closed: W4 measured metadata-only
   placement for the advisory pair, and W5's larger mismatch produced no
   chosen byte in a live mesh field. Do not groom either path.
3. W5 is author-measured; include its recipe in a future replay request if
   it becomes grade-relevant. No pointer/IP, command or rung-5 work without
   observed control flow.
