# W10 — file-steered pointer corruption in the real importer

Pinned Assimp v6.0.6, glTF 1.0 MAT4/FLOAT index accessor, count 1, on the
plain `-O1 -g -U_FORTIFY_SOURCE` library through `Importer::ReadFileFromMemory`.
`Accessor::Indexer::GetValue<unsigned int>()` copies 64 document-chosen bytes
into a 4-byte local (`glTFAsset.inl:474`); in this plain frame the copy also
overwrites the live `std::vector<std::unique_ptr<aiMesh>>` that
`ImportMeshes` passes to `CopyVector` at `glTFImporter.cpp:475`.

- `safe.gltf`: `scene=ok`, no fault.
- `idxptr-zero.gltf`: index-view bytes +12..+19 (document offsets 48..55)
  `0x41414141`, `0x00000000`;
  SIGSEGV, gdb `FAULT si_addr=0x41414141` in `CopyVector<aiMesh>`.
- `idxptr-addr42.gltf`: only the first chosen byte changes to `0x42424242`;
  SIGSEGV, gdb `FAULT si_addr=0x42424242` in the same frame. One crafted
  document byte steers the dereferenced address.
- `idxptr-42.gltf` / `idxptr-43.gltf`: non-canonical chosen addresses, rc 139.

The ASan build has a different frame layout (the 64-byte write reaches only
inlined `value` slots), so this pointer control is shown in the plain build
only. This is a chosen-address dereference, not a valid target object, not
control-flow redirection and not remote execution. No grooming, no listener,
no command, no r5. Author-measured, unwitnessed; both fix PRs remain unmerged.
