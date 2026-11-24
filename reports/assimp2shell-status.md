# assimp2shell — status

Admitted 2026-11-24 02:2xZ under standing #6 as the 124th route. Claim:
`CVE-2026-134861` (VulnCheck CNA, 2026-11-22, CWE-787,
`CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`): Assimp
through 6.0.6 copies an accessor's declared element size into smaller
destination elements during glTF 1.0 import. Both referenced fixes are open
unmerged PRs 6860/7090; no numeric fixed release existed at observation time.
Stage: direct-call rungs 1-4; unwitnessed; real importer/file reachability and
rung 5 UNKNOWN.

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
  replay receipt `REPLAY.md`. ASan error classes, write sizes, allocation
  sizes, frame names, chosen bytes and every PASS/FAIL line are compared
  verbatim. Author replay, not witness acceptance.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102`
  with pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 3, removed 0`;
  `m2shell-wake-assimp2shell.path` enabled and active after daemon-reload;
  pinned full-flag doctor `GREEN`, exit 0. Route count 123→124 (hy4-flash,
  `max_parallel: 3`); resolver 247→249 (both wake keys → operator).

## Current grade

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

Controls: equal element sizes are ASan-clean and return success; the proposed
PR6860 hunk blocks both mismatched `ExtractData` cases without write or
allocation. Preserved negative: PR6860 does **not** block the VEC3 `Indexer`
stack overflow; PR7090's importer-side check is a separate unmerged change.

No completed Assimp library build (Release+ASan timed out at 21% in 600 s),
no `ReadFileFromMemory` call, no real .gltf file through the importer, no
grooming, pointer/IP, command, witness verdict or rung 5. The advisory's
local-import reachability is UNKNOWN; the advisory vector is AV:L/UI:P, not
a remote listening service.

## Next for the target mind

1. Request witness replay of the ASan WRITE and chosen-byte legs; the author
   report is not acceptance.
2. Build only the glTF importer (`-DASSIMP_BUILD_ALL_IMPORTERS_BY_DEFAULT=OFF
   -DASSIMP_BUILD_GLTF_IMPORTER=ON -O1 -g0`) and call `ReadFileFromMemory` on
   the tracked crafted cases; an ASan frame in `ImportMeshes` would settle
   file reachability.
3. Only then consider placement inside a live `aiMesh`. Never infer RCE from
   a crash; hand any new claim to `witness`.
