# sdimatrix2shell — provisioning provenance

All fetches were read-only public provisioning. The harness is entirely
in-process with local files: no listener, socket, model, external system or
network target is contacted at run time.

## Advisory and tags

- GHSA-6q7q-2v9c-x8m7 (leejet/stable-diffusion.cpp, 2026-09-27):
  https://github.com/leejet/stable-diffusion.cpp/security/advisories/GHSA-6q7q-2v9c-x8m7
  — duplicate tensor name with a larger second `nval` writes attacker-chosen
  floats/ints past `values`/`counts`. Affected
  `master-742-1a13107 -> master-763-4fcc6fe`; patched `master-763-4fcc6fe`.
- CVE-2026-70659: https://cvefeed.io/vuln/detail/CVE-2026-70659 (CWE-787,
  CWE-1284). RCE/exploitability prose is an advisory claim.
- Fix commit `4fcc6fef10c6f686801c6e257b22cd6a3deb906b`:
  https://github.com/leejet/stable-diffusion.cpp/commit/4fcc6fef10c6f686801c6e257b22cd6a3deb906b.patch
  — four added lines at `src/runtime/imatrix.cpp:290-294`.
- `git ls-remote --tags https://github.com/leejet/stable-diffusion.cpp.git`
  verified `master-742-1a13107 = 1a13107bac236b0cd6fadbf5c264f3644874ba4f`
  and `master-763-4fcc6fe = 4fcc6fef10c6f686801c6e257b22cd6a3deb906b`.

## SHA-256 pins (verified 2026-11-26)

| artifact | SHA-256 |
| --- | --- |
| `src/master-742-1a13107.tar.gz` (codeload by commit SHA) | `863e674f6b8d00422e4a35d13b7ed91f2b76977f35d4499f9162a488c3315c00` |
| `src/master-763-4fcc6fe.tar.gz` (codeload by commit SHA) | `a070f629972355e936e5b4decbe12d91c179c1f412feac2915cd7dde799577d8` |
| `src/fix-4fcc6fef.patch` (raw commit patch) | `792c4d07666ad59720653345d0b68beded615a55b6e3dedf79e182d939f659d6` |
| verbatim vulnerable function body (lines 253..308) | `6d1a5fc1b09cefafe2fefaed1bc5fdae4ca8e425fa424facab99b257103362d1` |
| verbatim fixed function body (lines 253..312) | `b45cf140d68f49e419876f433990bbe2ef6aff378c2feb1711530c16d5d8375a` |
| `mkinput.cpp` | `9d5ea511cb942848b3fc6e5b51043dc7d7d029e3aec98a0fc7c4d43574e7450b` |
| `poc.cpp` | `4a26967209966ff9f209d0ff4f70bf84c22c978b25f370c2399b0c3f9845e19f` |
| `run-all.sh` (canonical runner) | `65ca30af615053e6ef0056cd3db3d7c40bc71851178ffb7f121bfd0904d7e741` |

The runner fetches by commit SHA from codeload. Earlier tag-URL archive bytes
(`ce9bf4b7…`, `f9b27fe7…`) differ in archive metadata, but both forms extract
the same pinned function bodies (`6d1a5fc1…`, `b45cf140…`). The table pins the
bytes the canonical runner actually fetches.

The runner rechecks tarballs, fix patch, generator and driver before building;
it also checks that the extracted bodies equal the pinned hashes and that the
fix hunk contains `inconsistent size for a repeated entry`.

## Pinned source facts

- Both tags' verbatim `src/runtime/imatrix.cpp:253` starts
  `bool IMatrixCollector::load_imatrix(const char* fname) {` and ends at EOF
  (`:308` vulnerable, `:312` fixed). `run-all.sh` copies those lines verbatim
  and prefixes `#line 253 "src/runtime/imatrix.cpp"` so reports use upstream
  line numbers. No branch, index, allocation or loop is reimplemented.
- Vulnerable `:287-289`: resize `values`/`counts` only when `e.values.empty()`.
  Vulnerable `:301-303`: `for (int i = 0; i < nval; i++) { e.values[i] += tmp[i]; e.counts[i] += ncall; }`.
  Fixed `:290-294` rejects a repeated entry with `values.size() != nval`; the
  loop moves to `:305-307`.
- `poc.cpp` uses `#define private public` (harness-only) to read the named
  `IMatrixStats::counts` field after the call. The two OOB int readbacks use
  `counts.data()[1]`/`[2]` and are compiled only in plain builds: libstdc++
  container annotations poison those slots under ASan, so reading them there
  would manufacture a second, harness-caused ASan report.
- Crafted file: `n_entries=2`; entry A name `blk.0`, `ncall=0x41414141`,
  `nval=1`, one float `0x11111111`; entry B name `blk.0` (attack) or `blk.1`
  (safe), `ncall=0x41414141`, `nval=3` (attack) or `1` (safe), float payload
  with `tmp[1]=0x5a5a5a5a`. The 3-element overflow stays inside adjacent
  malloc chunks on plain builds, so the chosen-int write is observable before
  allocator metadata is touched.

## Observed result

`run-all.sh` at the pinned hash: `RESULT PASS=10 FAIL=0`, rc 0, console
`evidence/run-all-console.log`. Vulnerable GCC+Clang ASan:
`ERROR: AddressSanitizer: heap-buffer-overflow`, `READ of size 4`, 0 bytes
after a 4-byte region, frame `#0 ... src/runtime/imatrix.cpp:302`. Fixed
GCC+Clang ASan: `inconsistent size for a repeated entry (1 vs 3)`, `ok=0`, no
ASan. Plain vulnerable GCC+Clang: `ok=1 ... counts_oob1=0x41414141
counts_oob2=0x41414141`; safe: `counts_oob1=0x00000000 counts_oob2=0x00000000`.
Note the sink's first invalid access is a **READ** because `+=` reads before
writing; the chosen bytes come from the subsequent `counts[i] += ncall` store.

## Negatives and dead ends preserved

- First input used `nval=8` for the repeated entry. Under plain builds the
  overflow reached allocator metadata and aborted with
  `munmap_chunk(): invalid pointer` before any readback. Narrowed to `nval=3`.
- Second input kept `nval=3` but tried to observe the chosen float `0x5a5a5a5a`
  in a named adjacent `counts` field. Plain builds printed `counts0=0`: a
  4-byte `values` allocation has 24 usable bytes, so `values[1]`/`[2]` land in
  that chunk's padding, not in the `counts` chunk 32 bytes away. Switched the
  observable primitive to the attacker-controlled `ncall` int written two
  slots past the 1-element `counts` vector, still inside its malloc chunk.
- Structural blocker for a named adjacent object: with equal-sized chunks the
  `values` overflow needs `i >= chunksize/4` to reach the next object, while
  the same-index `counts` overflow has already left its own 24-byte usable
  area at `i >= chunksize/4 - 3`. No layout was found that gives chosen bytes
  in a named adjacent field without corrupting the `counts` chunk header.
- ASan readback of `counts.data()[1]`/`[2]` produced a harness-caused
  `READ of size 4` at `poc.cpp:45` even on safe inputs (libstdc++ container
  annotations). Gated those reads to plain builds only.
- Draft build errors (`uint32_t` without `<cstdint>`, `std::exit` without
  `<cstdlib>`, GCC rejecting `__has_feature` inside `defined(...)`) were fixed;
  each intermediate hash was replaced in the runner, not left stale.
- No `sd-cli` build, model conversion, wire input, pointer control, command
  execution or r5 is claimed. Advisory exploitability prose is a claim.
- First clean-archive replay at commit `05369943` failed with `PIN_FAIL` on
  the vulnerable tarball: the runner fetched codeload by commit SHA while the
  pin had been computed from a tag-URL fetch. Re-pinned both archives to the
  SHA-URL bytes (extracted bodies unchanged) rather than changing the fetch
  URL; the corrected runner hash is recorded above.
