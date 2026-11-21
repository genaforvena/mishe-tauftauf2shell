# Frontier brief: WAMR2Shell — CVE-2026-54912 (fast-interpreter loader const-table desync)

Status: RANKED CANDIDATE / RUNGS 1–3 LOCALLY REPRODUCED, RUNG 4 NOT REACHED
(ASan WRITE confirmed; no chosen bytes; no window). Written 2026-11-21
~21:02Z by `frontier`. Ranked #1 unadmitted at write time: Perl
CVE-2026-15534 moves to #2 (still unadmitted, DM #1135 pending), MsQuic
CVE-2026-62815 stays #3 (deferred per operator #1110). This is a standing-#6
ranked candidate, not a request for a decision already made elsewhere.

## Verified ground truth

- **Claim sources.** Maintainer advisory
  `https://github.com/wasm-micro-runtime/wasm-micro-runtime/security/advisories/GHSA-jjv3-x3jf-cg49`
  (published 2026-08-04, "WAMR fast interpreter loader heap buffer overflow via
  constant deduplication mismatch", High 8.8), CVE record
  `https://cve.org/CVERecord?id=CVE-2026-54912` (published 2026-11-05, updated
  2026-11-05; CNA GitHub maintainer advisories), and OSV
  `https://osv.dev/vulnerability/CVE-2026-54912` (modified 2026-11-14). All three
  read; the advisory's recipe and ASan trace were also reproduced locally
  (below). Secondary: NVD, Rapid7, Tenable, EUVD-2026-117617 (not relied
  on for bytes).
- **Severity vector (advisory).** CVSS 4.0 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H`
  — network attack vector, no privileges and no interaction in the reporter's
  model. This is a published claim about applications that load untrusted WASM;
  WAMR itself is a library with no in-tree network listener. Wire reachability
  for a specific deployment stays UNKNOWN until a consumer is named.
- **Identifier / file / routine.** CVE-2026-54912; GHSA-jjv3-x3jf-cg49;
  `core/iwasm/interpreter/wasm_loader.c`, `wasm_loader_get_const_offset()`,
  `reserve_block_ret()`, `wasm_loader_prepare_bytecode()`. CWE-787 (out-of-bounds
  write).
- **Version range (maintainer).** Affected `<= 2.4.4`, patched `2.4.5`. Affected
  configuration is `WAMR_BUILD_FAST_INTERP=1`, the default interpreter mode;
  `-DWAMR_BUILD_FAST_INTERP=0` (classic interpreter) avoids the loader.
- **Upstream fix commit (OSV FIX reference).**
  `b1353b5e8983047ff68829c99abf1355d5f389cf` (Stephen Berard, 2026-06-25,
  "security(fast-interpret): fixed heap buffer overflow via constant
  deduplication mismatch"), 50 changed lines in `wasm_loader.c` plus a 49,430-byte
  regression `.wasm` and its 32,915-line `.wat` under
  `tests/regression/ba-issues/issues/issue-980004/`. The patch body was fetched
  verbatim.
- **Pinned raw bytes.** `lab/frontier/wamr2shell/src/SHA256SUMS`: affected
  `WAMR-2.4.4-wasm_loader.c`, fixed `WAMR-2.4.5-wasm_loader.c`, `b1353b5.patch`,
  and the upstream regression `const_table_overflow.{wasm,wat}`. Five of five
  `sha256sum -c` OK at write time (self-computed digests; upstream raw files and
  auto-generated commit patches carry no published sidecar). Provenance in
  `lab/frontier/wamr2shell/PROVENANCE.md`. The advisory cites main-branch commit
  `dd0fee27` line numbers; the pinned *tag* files have different line numbers,
  so all line numbers below come from the pinned bytes and are authoritative.

## Source-bound mechanism (raw pinned bytes)

Pass 1 sizes the compiled-code buffer exactly once. Affected tag
`WAMR-2.4.4-wasm_loader.c:9329-9332`:

```c
    ctx->p_code_compiled = loader_malloc(ctx->code_compiled_peak_size, NULL, 0);
    ...
    ctx->p_code_compiled_end = ctx->p_code_compiled + ctx->code_compiled_peak_size;
```

`code_compiled_peak_size` is accumulated while `p_code_compiled == NULL` and
becomes the allocation bound. Correctness requires Pass 2 to emit exactly the
same byte count.

The desync is in `wasm_loader_get_const_offset()` at
`WAMR-2.4.4-wasm_loader.c:9948-9980`:

```c
        if (type == VALUE_TYPE_I64 || type == VALUE_TYPE_F64) {
            /* No slot left, emit const instead */
            if (ctx->i64_const_num * 2 + ctx->i32_const_num > INT16_MAX - 2) {
                *offset = 0;
                return true;
            }
            /* Traverse the list if the const num is small */
            if (ctx->i64_const_num < 10) {
                for (uint32 i = 0; i < ctx->i64_const_num; i++) {
                    if (ctx->i64_consts[i] == *(int64 *)value) {
                        *offset = -1;
                        return true;
                    }
                }
            }
            ...
            ctx->i64_consts[ctx->i64_const_num++] = *(int64 *)value;
        }
```

Above ten entries the dedup scan is skipped, so duplicates are appended
unconditionally. Once `i64_const_num * 2 + i32_const_num > INT16_MAX - 2` the
handler returns `*offset = 0` and the caller emits the constant inline
(`WASM_OP_I64_CONST` path at `:14264-14269`: both an opcode and an 8-byte
immediate). Between passes, the `re_scan` block sorts the const arrays
(`qsort(i64_consts_old, ...)` at `:11663`) and removes duplicates (`:11666`,
i32 at `:11730`), collapsing thousands of duplicate `i64.const 0` entries to a
handful. Pass 2 then uses `bsearch` against the shrunken table, so the slot
overflow no longer triggers: constants that were inline in Pass 1 become table
references in Pass 2, `dynamic_offset` diverges, and `reserve_block_ret()`
(`:10242`, called at `:12387` and `:12450`) emits copy operands in Pass 2 that
Pass 1 never counted. The buffer was sized from Pass 1 alone, so Pass 2 writes
past `p_code_compiled_end`.

Fix `b1353b5e` adds a linear scan inside each of the three slot-overflow
handlers (i64/f64, v128, i32/f32) so the inline/table decision matches Pass 2's
`bsearch`, raises the dedup scan threshold from `10` to the named constant
`FAST_INTERP_CONST_DEDUP_SCAN_MAX 32` (`WAMR-2.4.5-wasm_loader.c:8246`, used at
`:9999`, `:10031`, `:10067`), and documents the cross-pass invariant.

Advisory's numeric recipe: 11 unique i64 constants
to cross the `< 10` scan threshold, 16,373 duplicate `i64.const 0` entries to
push `16,384 * 2 = 32,768 > INT16_MAX - 2 = 32,765`, then 50 i32 constants that
are inline in Pass 1 but table-referenced after dedup, plus a 21-result
multi-value block to invoke `reserve_block_ret()`. Upstream ASan trace from the
advisory: `WRITE of size 2` at `STORE_U16` (`wasm_runtime_common.h:68`) via
`wasm_loader_emit_int16` (`wasm_loader.c:9630`), `reserve_block_ret` (`:10660`),
`wasm_loader_prepare_bytecode` (`:12617`), `load_from_sections` (`:6691`),
`load` (`:7111`), `wasm_loader_load` (`:7288`), `wasm_runtime_load_ex`
(`wasm_runtime_common.c:1515`), `wasm_runtime_load` (`:1568`) — during module
load, before guest code executes. The advisory's frames use `dd0fee27`
line numbers; they identify the call chain, not pinned-tag line numbers.

## Observed local results (W90, 2026-11-21 20:58–21:02Z)

Both tags were built from source with `WAMR_BUILD_FAST_INTERP=1`, ASan and
debug symbols (`build-asan-2.4.4/`, `build-asan-2.4.5/`; ~30 s each). No
traffic, no service.

- **Vulnerable 2.4.4, rungs 1–3.** `iwasm -f test
  src/const_table_overflow.wasm` → exit 134, ASan `heap-buffer-overflow`,
  `WRITE of size 2`, 0 bytes past a 1020-byte region. Pinned-tag stack:
  `STORE_U16 wasm_runtime_common.h:68` ← `wasm_loader_emit_int16
  wasm_loader.c:9420` ← `reserve_block_ret :10449` ←
  `wasm_loader_prepare_bytecode :12450` ← `load_from_sections :6493` ←
  `load :6921` ← `wasm_loader_load :7098` ← `wasm_load wasm_runtime.c:65` ←
  `wasm_runtime_load_ex wasm_runtime_common.c:1477` ← `wasm_runtime_load :1530`
  ← `main :934`. Allocation: `loader_malloc :345` ←
  `wasm_loader_ctx_reinit :9329` ← `wasm_loader_prepare_bytecode :11651`.
  Raw trace `lab/frontier/wamr2shell/out-asan-2.4.4.txt`.
- **Fixed 2.4.5 control.** Same flags, same PoC: no ASan fault. `-f test`
  reaches WAMR's native-stack guard during *execution* and exits 1;
  load-only exits 1 at CLI entry-point lookup. Both failures are post-load,
  so the load-time OOB write is absent. Raw traces `out-asan-2.4.5.txt`,
  `out-asan-2.4.5-loadonly.txt`. A 64 MB `ulimit -s` does not change the
  execution-side guard result (`out-asan-2.4.5-bigstack.txt`).
- **Rung-4 probe (negative).** `instr-overflow.patch` adds a local-only
  `wamr_oob_log()` to all five emit helpers of a copied 2.4.4 tree; it logs
  each would-be write past `p_code_compiled_end`, skips the real store, and
  advances the cursor so the whole Pass-2 sequence is visible. On the PoC:
  61 would-be OOB writes — 38 × 2-byte const-table indices (e.g. `0c00`,
  `0b00`, …, `0100`, `ffff`, at 1, 3, 5, … 79 bytes past the end) and 23 ×
  8-byte host branch pointers (e.g. `34b57c8611590000`, at 75/87 bytes past).
  **No `const` / inline-immediate write appears past the end.** The 2-byte
  values are small deduplicated table indices derived from module structure;
  the 8-byte values are the loader's own host code pointers. Raw log
  `out-instr-oob.txt`.

## Rung-4 feasibility assessment (after measurement)

- **Rungs 1–3: ESTABLISHED locally.** Deterministic trigger, ASan WRITE,
  fixed-version control.
- **Rung 4: NOT REACHED and not plausible via the published mechanism.**
  The OOB stream contains const-table indices and host branch pointers, not
  attacker-chosen 4/8-byte immediates. Values are structure-derived and the
  offsets are the emit sequence (1, 3, 5 … past the end), not freely chosen.
  The advisory's "partially attacker-controlled content" and "DoS; further
  consequences depend on host heap layout" are consistent with this; do not
  upgrade it to chosen-byte control. A neighbouring-object pointer overwrite
  with a loader-generated branch pointer remains conceivable but is not a
  pointer-control primitive in this plant's sense.
- **Rung 5: UNKNOWN / lower.** The overflow fires inside `wasm_runtime_load()`,
  so a consumer that accepts WASM bytes from the network would reach it before
  guest execution. No such consumer is named in the advisory; a loopback
  wire-facing host would have to be built. This is a library-level parser bug
  in the same class as the admitted htslib/openjpeg parser targets, where
  rung 4 was the stopping point.

## Ranking rationale

Higher tractability than the current #2 Perl: published exact PoC (no derived
pattern), network/PR:N advisory vector, default build configuration affected,
a one-line build flag control, and rungs 1–3 already reproduced locally.
Capped at rung 3 by the measured write content. Lower than an already-admitted
target only because no wire-facing consumer is named. Recommend handoff to a
dedicated target mind on admission; a rung-4 attempt there would need a
different overflow shape where chosen immediates reach past the end.
