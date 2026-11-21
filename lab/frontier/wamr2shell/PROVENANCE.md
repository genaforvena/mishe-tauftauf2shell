# Provenance — WAMR2Shell frontier candidate (CVE-2026-54912)

Created 2026-11-21 ~21:05Z by `frontier`. Provisioning only: public advisory and
upstream source reads; no build, no local service, no traffic, no probes off
loopback.

## Claim sources (fetched read-only)

- Maintainer security advisory GHSA-jjv3-x3jf-cg49:
  `https://github.com/wasm-micro-runtime/wasm-micro-runtime/security/advisories/GHSA-jjv3-x3jf-cg49`
  (published 2026-08-04). Read verbatim; supplies affected `<=2.4.4` / patched
  `2.4.5`, the two-pass desync mechanism, the WAT generation recipe, the ASan
  trace, and the fast-interpreter build configuration.
- CVE record: `https://www.cve.org/CVERecord?id=CVE-2026-54912` (published
  2026-11-05); page body was cookie-gated, so the machine-readable OSV record
  was used for the vector and FIX reference.
- OSV: `https://osv.dev/vulnerability/CVE-2026-54912` (modified 2026-11-14).
  Supplies CVSS 4.0 vector `AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H`,
  aliases, and the fix commit id.
- Public PoC generator gist referenced by the advisory:
  `https://gist.github.com/shumbo/b710c35b005ed871447fce385d1ab760`
  (not fetched; the upstream regression `.wasm`/`.wat` are pinned instead).
- Secondary, not relied on for bytes: NVD, Rapid7, Tenable, EUVD-2026-117617,
  WAMR-2.4.5 release page.

## Pinned source bytes

`src/SHA256SUMS` lists five files, all fetched from the URLs below and verified
`sha256sum -c SHA256SUMS` 5/5 OK at 2026-11-21 ~20:57Z. GitHub raw tag files,
the commit patch and the regression artifacts have no published digests, so
these are self-computed fingerprints of the exact bytes read; re-fetch and
compare before relying on them.

| File | URL |
| --- | --- |
| `src/WAMR-2.4.4-wasm_loader.c` | `https://raw.githubusercontent.com/bytecodealliance/wasm-micro-runtime/WAMR-2.4.4/core/iwasm/interpreter/wasm_loader.c` |
| `src/WAMR-2.4.5-wasm_loader.c` | `https://raw.githubusercontent.com/bytecodealliance/wasm-micro-runtime/WAMR-2.4.5/core/iwasm/interpreter/wasm_loader.c` |
| `src/b1353b5.patch` | `https://github.com/wasm-micro-runtime/wasm-micro-runtime/commit/b1353b5e8983047ff68829c99abf1355d5f389cf.patch` |
| `src/const_table_overflow.wasm` | `https://raw.githubusercontent.com/bytecodealliance/wasm-micro-runtime/b1353b5e8983047ff68829c99abf1355d5f389cf/tests/regression/ba-issues/issues/issue-980004/const_table_overflow.wasm` (49,430 bytes) |
| `src/const_table_overflow.wat` | `https://raw.githubusercontent.com/bytecodealliance/wasm-micro-runtime/b1353b5e8983047ff68829c99abf1355d5f389cf/tests/regression/ba-issues/issues/issue-980004/const_table_overflow.wat` (32,915 lines, 411,625 bytes) |

## Key raw observations

- `WAMR-2.4.4-wasm_loader.c:9329-9332`: Pass-1 `code_compiled_peak_size` becomes
  the exact `loader_malloc` size and `p_code_compiled_end` bound.
- `WAMR-2.4.4-wasm_loader.c:9958-9961` and `:9983-9986`: slot-overflow handlers
  return inline (`*offset = 0`) with no lookup; `:9964`, `:9989` skip dedup scan
  above ten entries; `:9979` appends duplicates unconditionally.
- `WAMR-2.4.4-wasm_loader.c:11663-11666` and `:11730`: between-pass `qsort` and
  duplicate removal shrink the i64/i32 const arrays.
- `WAMR-2.4.4-wasm_loader.c:10242`, `:12387`, `:12450`: `reserve_block_ret()`
  definition and call sites; advisory claims it emits extra copy operands in
  Pass 2.
- `WAMR-2.4.4-wasm_loader.c:14264-14269`: inline `i64.const` emits opcode plus
  8-byte immediate when `operand_offset == 0`.
- `WAMR-2.4.5-wasm_loader.c:8246`, `:9999`, `:10031`, `:10067`: fix introduces
  `FAST_INTERP_CONST_DEDUP_SCAN_MAX 32` and raises the threshold.
- `b1353b5.patch`: adds a linear scan to all three slot-overflow handlers so
  both passes make the same inline/table decision; adds the regression artifacts.

Advisory line numbers refer to main-branch commit `dd0fee27` and differ from
these tag pins; the pinned bytes are authoritative.

## Local build and experiment artifacts (W90)

- `src/wamr-2.4.4/`, `src/wamr-2.4.5/`: shallow upstream tag clones used for the
  clean builds (`build-asan-2.4.4/`, `build-asan-2.4.5/`). CMake flags:
  `-DWAMR_BUILD_TARGET=X86_64 -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=1
  -DWAMR_BUILD_AOT=0 -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_FAST_JIT=0
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-fsanitize=address
  -fno-omit-frame-pointer -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address'`.
  Configure/build logs `cfg.log`, `build.log` live in each build dir.
- `out-asan-2.4.4.txt`, `out-asan-2.4.4-loadonly.txt`: ASan heap-buffer-overflow
  WRITE (exit 134) on the pinned PoC with `-f test` and in load-only mode.
- `out-asan-2.4.5.txt`, `out-asan-2.4.5-loadonly.txt`,
  `out-asan-2.4.5-bigstack.txt`: fixed control; no ASan fault, post-load
  failures only.
- `src/wamr-2.4.4-instr/`: copy of the affected tree with local instrumentation;
  `instr-overflow.patch` is its `git diff` against the tag. It logs would-be
  writes past `p_code_compiled_end`, skips the real store and keeps the cursor
  advancing. `build-asan-2.4.4-instr/` and `out-instr-oob.txt` hold the build
  and the 61-write OOB log. This instrumentation is not upstream and exists only
  to measure the write content.

Rungs 1–3 ESTABLISHED locally; rung 4 NOT REACHED (see brief). No window, no
wire traffic, no witness claim.
