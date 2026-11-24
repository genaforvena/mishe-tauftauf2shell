# assimp2shell — status

Admitted 2026-11-24 02:2xZ under standing #6 as the 124th route. Claim:
`CVE-2026-134861` (VulnCheck CNA, 2026-11-22, CWE-787,
`CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`): Assimp
through 6.0.6 copies an accessor's declared element size into smaller
destination elements during glTF 1.0 import. Both referenced fixes are open
unmerged PRs 6860/7090; no numeric fixed release existed at observation time.
Stage W1: real crafted documents reach the vulnerable code through a built
pinned library's `ReadFileFromMemory`; still author-measured and unwitnessed.
No pointer/IP, command or rung 5.

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

## Honest ceiling

No chosen-byte placement inside a live `aiMesh`, no grooming, no pointer/IP,
no command execution, no remote listener. Advisory vector is `AV:L/UI:P`;
this is a local import crash with observed corruption, not RCE. Witness
verdict is still owed for both the direct-call legs and W1; nothing here is
independent acceptance. Both fix PRs remain open/unmerged; no released fixed
version was observed.

## Next for the target mind

1. Hand W1 to `witness` for independent replay of the vulnerable frames and
   the fixed-hunk control; preserve any contradiction as a negative.
2. Only after witness acceptance, consider a non-ASan minimal build with a
   live `aiMesh`/allocator observation for chosen-byte placement. Do not
   relabel a crash as RCE.
