# W14 — partial low-32-bit overwrite of the live mesh vector pointer

Pinned Assimp v6.0.6, glTF 1.0 MAT2/FLOAT index accessor, count 1, plain
gcc -O2 glTF-only library built by `harness/run-w12.sh`, driven through
`Assimp::Importer::ReadFileFromMemory` by `harness/placement_driver.cpp`.

`Accessor::Indexer::GetValue<uint32_t>()` copies `elemSize=16` document bytes
into a 4-byte local (`glTFAsset.inl:474`). In this frame document bytes
48..51 reach the low 32 bits of the live `std::vector<std::unique_ptr<aiMesh>>`
begin pointer in `ImportMeshes`; bytes 52..63 are not written. The high 32 bits
come from the original heap pointer and are not attacker-chosen.

Pre-corruption `meshes.begin()` from the safe document at `glTFImporter.cpp:475`
under gdb ASLR-off: `0x55555556f520`.

| Case | chosen doc 48..51 | slot at CopyVector | SIGSEGV `si_addr` |
|---|---|---|---|
| `idxptr-mat2-low.gltf` | `41414141` | `0x555541414141` | `0x555541414141` |
| `idxptr-mat2-low42.gltf` | `42424242` | `0x555542424242` | `0x555542424242` |
| `idxptr-mat2-real.gltf` | `5556f520` | `0x55555556f520` | none: `munmap_chunk(): invalid pointer` SIGABRT |

All faults occur in `BaseImporter::CopyVector<aiMesh>` (`BaseImporter.h:343`,
called from `glTFImporter.cpp:475`). Restoring the original low word restores
the begin pointer but leaves the vector length at 415, so the third case is a
preserved negative, not a clean-import control. `safe.gltf` imports cleanly.

`bash harness/run-w14.sh` => **7 PASS / 0 FAIL**; normalized trace
`w14/evidence/w14.trace` sha256
`37b1225e862d05ea622c755b9bdbbb7343315adef6b855831623d08a26a7fd0c`.
Source hashes match the pins. Author-measured, unwitnessed. No valid object,
code pointer, control-flow redirection, marker, command or r5; the chosen
address is unmapped, so this is a narrow partial-pointer primitive, not a step
toward control flow. The MAT4 full-64-bit case remains W10/W12.
