# WAMR2Shell — chosen-immediate OOB write in the fast-interpreter loader (rung 4)

Status: **RUNG 4 ESTABLISHED in the lab build and INDEPENDENTLY REPLAYED by witness verdict #1168 (2026-11-21 ~21:59Z) at the labeled scope**. Rung 5
is UNKNOWN: a genuine wire-facing consumer is named (Envoy v1.39.3, below)
but was NOT built or driven; no guest code executes and no benign command
side effect exists. Written 2026-11-21 ~21:26Z by `wamr2shell`, updated
~21:50Z with the wake-2 real-store verification, ~22:02Z with verdict
#1168 and 2026-11-27 ~07:16Z with the offset-shift depth addendum. Rungs 1-3
were independently established by witness #1146 and are not re-proved here.
The 2026-11-27 ~07:35Z addendum names the destination as the live i64 const
table; the 2026-11-27 ~08:00Z addendum records the confinement sweeps and a
synthetic forced-survival copy observation.

## Result in one paragraph

The upstream PoC for CVE-2026-54912 only writes loader-generated table indices
and host pointers past `p_code_compiled_end`: the measured rung-4 negative in
`lab/frontier/wamr2shell/out-instr-oob.txt` stands for that exact byte stream.
A **different module shape** — the same pinned PoC with eight `i64.const
<chosen>; drop` pairs inserted after the multi-value block's `end` and before
the trailing `drop`s — reaches inline-immediate emit sites *after* the
two-pass byte-count desync. Two variants with different chosen values write
different attacker-chosen 8-byte sequences at the same deterministic offsets
(11, 29, 47, 65 bytes past `p_code_compiled_end`). The unmodified ASan build
reports a load-time `heap-buffer-overflow`, `WRITE of size 8`, in
`wasm_loader_emit_const()`; the fixed 2.4.5 build has no ASan error. This is
chosen bytes at chosen offsets in a lab process, not chosen-byte execution and
not a wire result.

## Builds and inputs

Builds: `lab/frontier/wamr2shell/build-asan-2.4.4/iwasm-2.4.4` and
`build-asan-2.4.5/iwasm-2.4.5`, configured with
`-DWAMR_BUILD_TARGET=X86_64 -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=1
-DWAMR_BUILD_AOT=0 -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_FAST_JIT=0
-DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-fsanitize=address
-fno-omit-frame-pointer -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address'`
(provisioned by `frontier`; flags and logs in `PROVENANCE.md` and each build
directory). The instrumented build is `build-asan-2.4.4-instr/iwasm-2.4.4`
with `instr-overflow.patch`: `wamr_oob_log()` logs would-be writes when
`cursor + size > p_code_compiled_end`, skips the real store, and advances the
cursor so the whole Pass-2 sequence is observable.

Inputs (SHA-256):

| File | Digest | Meaning |
| --- | --- | --- |
| `src/const_table_overflow.wasm` (pinned) | `f4fdff5fb53c44d3ba253dcaa0434485cdf33dddcaf0ff2abb826ac912bd511b` | upstream regression PoC, unchanged |
| variant 1, base `0x4142434445464700` | `ecfce96af2464857ca41947ea4c7c5563217c674ece5da71834cdaa6f014c1f9` | 8 chosen `i64.const`/`drop` pairs |
| variant 2, base `0x7eadbeefcafeb000` | `ea4e5083028289206d9eccbcb8e38d0c578ec0d989027ede724d11aeed66ea7f` | same shape, different chosen bytes |
| padding control (6 extra `i32.const 0`/`drop` pairs) | `03b0b11df94a57da06d51d985c9d108848fde617802430b8e660c2581352c27c` | offsets unchanged by this padding |

`lab/frontier/wamr2shell/make_chosen_variant.py` regenerates variant 1 and 2
byte-for-byte from the pinned PoC (`python3 make_chosen_variant.py OUT
4142434445464700 8`). The script edits only the code section's two LEB sizes
and inserts payload bytes at body offset 49347; the pinned WAT recipe and all
five admission pins are untouched. Raw outputs live in the gitignored site at
`.mishe-tauftauf/artifacts/wamr2shell/` (`variant-instr.out`,
`variant2-instr.out`, `pad-instr.out`, `variant-asan-244.out`,
`variant-asan-245.out`, `variant2-asan-244.out`, `variant2-asan-245.out`).

## Observed writes

Instrumented 2.4.4, variant 1, `iwasm -f test <variant>`:

```
WAMR_OOB tag=const size=8 past=11 bytes=0447464544434241
WAMR_OOB tag=const size=8 past=29 bytes=0547464544434241
WAMR_OOB tag=const size=8 past=47 bytes=0647464544434241
WAMR_OOB tag=const size=8 past=65 bytes=0747464544434241
```

Variant 2, same offsets:

```
WAMR_OOB tag=const size=8 past=11 bytes=04b0fecaefbead7e
WAMR_OOB tag=const size=8 past=29 bytes=05b0fecaefbead7e
WAMR_OOB tag=const size=8 past=47 bytes=06b0fecaefbead7e
WAMR_OOB tag=const size=8 past=65 bytes=07b0fecaefbead7e
```

Those little-endian 8-byte sequences are exactly the chosen `i64.const`
immediates. The offsets are fixed by the desync/emit sequence (the six-pair
padding control produced the same four offsets), so the attacker chooses the
*values* and which instructions occupy the window, not an arbitrary byte
address. The other OOB writes in the same window remain loader pointers and
frame-offset `i16`s as in the upstream PoC.

Unmodified ASan 2.4.4, variant 1 and 2, exit 1:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 8
#1 b_memcpy_s (bh_common.c:95)
#2 wasm_loader_emit_const (wasm_loader.c:9382)
#3 wasm_loader_prepare_bytecode (wasm_loader.c:14269)
...
is located 3 bytes after 1164-byte region
allocated by loader_malloc -> wasm_loader_ctx_reinit (wasm_loader.c:9329)
SUMMARY: AddressSanitizer: heap-buffer-overflow ... in memcpy
```

The fault is during `wasm_runtime_load()` (`wasm_load` → `wasm_runtime_load_ex`
→ `wasm_runtime_load` → `main`), before any guest instruction runs. Fixed
2.4.5 on both variants: no ASan error; the only failure is the already-known
post-load `Exception: native stack overflow` from the CLI, identical to its
behaviour on the original PoC.

## Why the upstream PoC stopped at negative and this shape does not

Source analysis (pinned `WAMR-2.4.4-wasm_loader.c`): the only cross-pass
decision flip in the original PoC is the final `i64.const 0`, inline in Pass 1
because the i16 const-slot budget is exhausted, table-referenced in Pass 2
after the between-pass sort/dedup shrinks the table. `reserve_block_ret()`
(`:10242–10463`) then emits an `EXT_OP_COPY_STACK_VALUES` record Pass 1 never
counted. In the original WAT the 21-result block is the last instruction,
followed only by `drop`s, which emit nothing (`:13098–13100`); no inline
immediate is emitted after the cursor passes the end. Appending real
`i64.const` instructions after the block supplies inline-immediate emit sites
(`:14241–14310`) inside the overflow window.

## Rung assessment and limits

- **Rungs 1–3**: ESTABLISHED by witness #1146 and unchanged.
- **Rung 4**: ESTABLISHED with conditions — chosen 8-byte immediate values at
  deterministic offsets past the compiled-code buffer, observed in the
  instrumented build and corroborated by a real ASan `WRITE of size 8` in the
  inline-immediate emitter; fixed-version control clean. Not a pointer-control
  primitive of attacker-chosen addresses, not code execution.
- **Rung 5**: UNKNOWN. A genuine wire-facing consumer is now named (Envoy
  v1.39.3 with `envoy.wasm.runtime.wamr`, below) but was NOT built or driven;
  load aborts before guest execution; no benign command side effect, no
  ASLR/heap-shape escalation. The advisory's `AV:N` vector is still a
  reporter's model.
- **Witness replay ESTABLISHED (#1168, 2026-11-21 ~21:59Z)**: independent
  rebuild from clean pinned-tag copies in the witness's own `/tmp/w93-wamr`,
  3/3 pins OK, same patch digest and byte-for-byte variant regeneration;
  `in == mem` at the same four offsets with both value sets and real heap
  corruption, plus an unmodified-ASan `WRITE of size 8` at
  `wasm_loader.c:9382` on 2.4.4 and a clean 2.4.5 control. Witness-ESTABLISHED
  at the labeled scope, not merely an author claim; details and the honest
  digest divergence from ASLR are in the addendum below.

Negative results preserved: the upstream PoC's OOB window still contains no
chosen immediates; eight appended `i64.const` pairs with `0xDEAD...`-style
values above the signed 64-bit LEB range were rejected by the loader
(`integer too large`) and were regenerated with in-range values; six
`i32.const 0`/`drop` padding pairs did not move the four OOB offsets.

## Addendum: named consumer, NOT built and NOT driven (2026-11-21 ~21:29Z)

A read-only consumer survey by this wake names **Envoy v1.39.3** as a genuine
network-to-loader path on the exact affected pin. Source evidence at that tag:
`bazel/repository_locations.bzl:527-532` pins `WAMR-2.4.4`;
`bazel/foreign_cc/BUILD:439-440` sets `WAMR_BUILD_FAST_INTERP=1`;
`api/envoy/extensions/wasm/v3/wasm.proto:97-100` says the WAMR runtime is not
in the official build, while `:110-111` makes `VmConfig.code` an
`AsyncDataSource`; `source/extensions/common/wasm/wasm.cc:317/322` detects a
remote URI, `:444-465` fetches bytes, `:419-441` `fetch_callback(code)` calls
`complete_cb(code)`, and `:400-404` calls `proxy_wasm::createWasm(...)`. The
pinned proxy-wasm-cpp-host `f2db56af...` `src/wamr/wamr.cc:144-163` passes those
bytes to `wasm_module_new()`, and WAMR 2.4.4
`core/iwasm/common/wasm_c_api.c:2360/2389` reaches `wasm_runtime_load()`.
Traffic Server and Fluent Bit use WAMR but load from local config files;
mod_wasm and NGINX Unit do not use WAMR. Local `iwasm` and WAMR samples are
synthetic harnesses, never rung 5.

Feasibility checked on this host, read-only and time-boxed: `envoy`, `bazel`
and `bazelisk` are absent; no apt package provides them; the Docker daemon is
reachable (29.1.3) but its images are postgres/temurin/python/dragonfly only,
with no WAMR-enabled Envoy image or local tarball. A WAMR-enabled Envoy needs
a full Bazel/hermetic-toolchain source build, infeasible in this wake's
budget. Therefore the consumer is **named but NOT built, NOT driven**; rung 5
stays UNKNOWN. If a WAMR-enabled Envoy is later supplied, the minimal genuine
drive is a 127.0.0.1 HTTP server serving `const_table_overflow.wasm` (or the
chosen-immediate variant), a bootstrap with `runtime:
envoy.wasm.runtime.wamr` and `code.remote.http_uri` pointing at it, ASan on
the Envoy process, plus vulnerable/fixed/safe-input controls and witness
replay. A socket wrapper around `iwasm` would remain synthetic.

## Addendum: the chosen bytes come from real stores, not instrumentation (2026-11-21 ~21:49Z)

The original `instr-overflow.patch` **skips** the real store for an OOB write
(`wamr_oob_log()` returns true), so its `WAMR_OOB tag=const` lines are
would-be values. Cursor advancement is identical with and without the skip,
but that is an inference. Two new non-ASan 2.4.4 builds from the pinned tag
settle it by letting the emitter's own store run and reading the destination
back:

- `lab/frontier/wamr2shell/passive-oob.patch` (sha256
  `1e4199eace52064722771ee410ef2f5ff50776db49d0149090b872d619f4fba9`):
  on OOB, the probe performs the 8/2-byte store at the real destination and
  logs both input and resident bytes. Built into
  `build-plain-2.4.4-passive/` with the report's CMake flags minus
  `-fsanitize=address`; run `iwasm-2.4.4 -f test <variant>`.
- `lab/frontier/wamr2shell/caller-store.patch` (sha256
  `9c0e79073eac423b15b5ead6302fb1cd87653719f414785ec9ab3569e1b5302e`):
  the probe logs `phase=before` and always returns **false**, so the
  emitter's own `bh_memcpy_s` / `STORE_U*` / `STORE_PTR` performs the real
  store; `wamr_oob_readback()` logs `phase=after` from the destination.
  Built into `build-plain-2.4.4-callerstore/` with the same flags.

Variants were regenerated byte-for-byte from the pinned PoC at HEAD:
`python3 lab/frontier/wamr2shell/make_chosen_variant.py /tmp/w2-v1.wasm
4142434445464700 8` -> `ecfce96a...`, and base `7eadbeefcafeb000` ->
`ea4e5083...`, matching the table above.

Caller-store v1, `iwasm-2.4.4 -f test /tmp/w2-v1.wasm` (log
`.mishe-tauftauf/artifacts/wamr2shell/callerstore-v1.out`, sha256
`dc126e66ab54f60fef87f9d919d66538b9fc98bf7cec89594c08a8b32e61f026`):

```
WAMR_CALLER tag=const phase=before size=8 dest=0x5d39394b5b2f past=11 in=0447464544434241
WAMR_CALLER tag=const phase=after  size=8 dest=0x5d39394b5b2f past=11 mem=0447464544434241
... past=29 in=0547464544434241 / mem=0547464544434241
... past=47 in=0647464544434241 / mem=0647464544434241
... past=65 in=0747464544434241 / mem=0747464544434241
```

Caller-store v2 gives `04b0fecaefbead7e` / `05b0fecaefbead7e` /
`06b0fecaefbead7e` / `07b0fecaefbead7e` at the same four offsets, with
`in == mem` in every case. The passive build independently logs 48 OOB
writes for v1, all with `in == mem`, including the same four `tag=const`
records (log `passive-v1.out`, sha256
`9899fc54b16968ba9f33fc38ce1d5c9297e7a8885ac5d087132a93ba907d75ac`). Both
non-ASan processes end with glibc `double free or corruption (out)` after
the writes, i.e. real heap corruption, not merely a skipped-store trace.

This retires the "instrumentation artefact" objection at the labeled scope:
the emitter's own store places the chosen immediate at the chosen offset and
the bytes are physically resident there. Limits are unchanged: the four
offsets are fixed by the desync/emit sequence, the attacker chooses values
not addresses; no pointer control, no guest execution, no wire traffic, no
rung-5 claim. Both build trees and the raw logs are gitignored lab artifacts;
the two patch files above are committed so the experiment is reproducible
from the pinned tag.

## Addendum: witness replay ESTABLISHED (#1168, 2026-11-21 ~21:59Z)

Witness `wamr2shell` verdict #1168 replayed the claim from clean pinned-tag
copies in its own `/tmp/w93-wamr` builds: 3/3 hashes matched (PoC `f4fdff5f`,
loaders `b0029210` / `5b932606`), pristine tag `WAMR-2.4.4=8c18e3f6` clean,
`caller-store.patch` sha256 `9c0e7907` matched the report, and both variants
were regenerated byte-for-byte (`ecfce96a` / `ea4e5083`) by
`make_chosen_variant.py`.

- Caller-store binary (witness sha256 `c2cd0713`, built from the clean tag
  plus the committed patch with the report's CMake flags minus ASan): v1 logs
  `phase=before` and `phase=after` at `past=11/29/47/65` with `in == mem`
  values `0447464544434241`, `0547464544434241`, `0647464544434241`,
  `0747464544434241`; v2 gives `04/05/06/07 b0fecaefbead7e` at the same four
  offsets, `in == mem` in all eight pairs. Both end rc 134 with glibc
  `double free or corruption (out)`.
- Unmodified ASan (witness 2.4.4 sha256 `6b6e00c5`, 2.4.5 sha256 `168be9bb`):
  each variant on 2.4.4 gives `heap-buffer-overflow WRITE of size 8` in
  `wasm_loader_emit_const`, `wasm_loader.c:9382`, 3 bytes after a 1164-byte
  region, during load; 2.4.5 on both variants has no ASan error, only the
  post-load CLI "Exception: native stack overflow" guard.

Destination addresses ASLR-vary (witness `0x5941a0...` / `0x5eab4a...` vs
author `0x5d39...`), so raw digests differ while the invariants match: four
fixed offsets, chosen values, real emitter stores, clean fixed control. No
pointer control, guest execution or wire traffic; Envoy v1.39.3 remains named
but not built or driven; rung 5 stays UNKNOWN. The witness made no repo edits.

## Addendum: attacker-adjusted offsets by module shape (2026-11-27 ~07:16Z)

Operator request #6173 bounded one wake to the question left open by the
settled claim: are the four chosen-immediate offsets fixed at
`past=11/29/47/65`, or can the module author adjust them? Answer: **they are
adjustable by module shape, in discrete steps, but still not by arbitrary
byte address**. This is rung-3/4 depth, not a new rung and not rung 5.

`lab/frontier/wamr2shell/make_shift_variants.py` (sha256
`6411b130e15fe3678c40051f2751f1b381fcdbd07cc967f8775ef7532bb5283a`)
does byte-level surgery on the pinned PoC `f4fdff5f…`; all five admission
pins are untouched. It copies the existing 45-byte 21-result block
(`02 01 41 01 … 41 15 0b`) and/or appends chosen `i64.const`/`i32.const`
pairs at the block's `end`, then rewrites the code-section and body LEB
sizes. No WAT compiler is on the host. Variant SHA-256:

| Variant | Shape | sha256 |
| --- | --- | --- |
| `n4` / `n8` / `n16` | 4 / 8 / 16 appended `i64.const` pairs | `17f16803…` / `ecfce96a…` / `7716bbc3…` |
| `dup_before` | copied 21-result block + 21 drops, then 8 pairs | `756cabf8…` |
| `dup2_before` | two copies, then 8 pairs | `7f4339e9…` |
| `dup_after` | 8 pairs, then one copied block | `3dc66921…` |
| `split` | 4 pairs, copied block, 4 pairs | `849d6dc9…` |
| `i32` | 8 appended `i32.const` pairs | `46aba96e…` |
| `small1/2/4_before` | 1/2/4 one-result blocks, then 8 pairs | `33dc2264…` / `c422df9b…` / `018397f0…` |

Builds are the already-committed artifacts: caller-store
`build-plain-2.4.4-callerstore/iwasm-2.4.4` (sha256
`de75c5e691e7700a3c159100cff61a7a1dcdf7bd9c1b381d1c7d07e19f875eac`;
source loader sha256 `97b07155…` = pinned `b0029210…` + committed
`caller-store.patch` `9c0e7907…`, verified by reapplying the patch),
`build-asan-2.4.4/iwasm-2.4.4` (sha256 `a7217920…`, clean 2.4.4 tag) and
`build-asan-2.4.5/iwasm-2.4.5` (sha256 `1799eabc…`, clean 2.4.5 tag).
Raw logs are `.mishe-tauftauf/artifacts/wamr2shell/shift-*-callerstore.out`,
`shift-*-asan244.out`, `shift-*-asan245.out`.

Caller-store observations (real emitter stores; `phase=before` input equals
`phase=after` readback in every listed pair; three repeat runs of
`dup_before` gave identical offsets while destination addresses ASLR-varied):

- `n4`, `n8`, `n16`: chosen 8-byte writes stay at `past=11/29/47/65`
  regardless of appended-pair count. Count is not an offset knob.
- `dup_before`: chosen writes at `past=46/64/82/100/118/136/154/172`, values
  `00/01/02/03/04/05/06/07 47464544434241`; +35-byte shift and all eight
  pairs now out of bounds.
- `dup2_before`: `past=153/171/189/207/225/243/261/279`, same value ladder;
  +142-byte shift. The offset lattice is discrete (0, 1, 2 copies), not a
  continuous address control.
- `split`: only the four pairs **after** the copied block land OOB, at
  `past=118/136/154/172`; the four before it stay in bounds. `dup_after`
  gives zero chosen `tag=const` OOB writes. Placement relative to the
  desync generator, not merely its existence, selects which values land in
  the overflow window.
- `i32`: chosen **4-byte** immediates land at `past=9/23/37/51/65` with
  values `03/04/05/06/07 474645`; the write width and offsets both change.
- `small1/2/4_before`: offsets remain `11/29/47/65`. A one-result block
  does not create the extra copy-record desync; the 21-result shape does.

ASan 2.4.4 still faults during load on every shifted variant, but the
**first** fault site moves: `n8` and `small1_before` give `WRITE of size 8`
in `wasm_loader_emit_const` (`:9382`), 3 bytes after a 1164/1178-byte region;
`dup_before` gives `WRITE of size 2` in `reserve_block_ret` (`:10451`), zero
bytes after a 1458-byte region; `dup2_before` gives `WRITE of size 2` in
`wasm_loader_push_frame_offset` (`:9775`), zero bytes after 1752 bytes;
`dup_after` gives `WRITE of size 4` in `prepare_bytecode` (`:14251`);
`i32` gives `WRITE of size 8` in `wasm_loader_emit_ptr` (`:9458` from
`:11763`). So ASan corroborates real heap corruption for each shape but
does not itself witness the shifted chosen 8-byte stores — those are proven
by the caller-store emitter's own stores and readback, plus glibc heap
abort (rc −6). Fixed 2.4.5 ASan has **no** error on `n8`, `dup_before`,
`dup2_before`, `small1_before` or `i32` (only the known post-load CLI
"Exception: native stack overflow"). Safe-input control: the unchanged
pinned PoC produces zero `tag=const` OOB writes in the caller-store build
and rc 0; its known ASan error is loader-generated data only.

Preserved negatives: appended-pair count and inert small blocks do not move
the offsets; placing the desync generator after the chosen pairs removes
them from the window; the earlier `0xDEAD…` LEB rejection and six-pair
`i32.const 0` padding negative from the main report stand. No pointer
control, no guest execution, no wire traffic: rung 5 stays UNKNOWN.

## Addendum: the overflow lands in the live i64 constant table (2026-11-27 ~07:35Z)

A gdb measurement on the committed caller-store binary names the destination
region for the first time. This is rung-4 depth: no new rung and no wire result.

Method (all artifacts already described above): regenerate `dup_before` with
`python3 lab/frontier/wamr2shell/make_shift_variants.py dup_before
/tmp/w5-dup.wasm` (sha256 `756cabf8…`, byte-for-byte), then under
`gdb -q -batch` break at `wasm_loader_ctx_reinit` line 9332 and at
`wamr_oob_log` with condition
`ctx->p_code_compiled + size > ctx->p_code_compiled_end`; print the context
pointers at the first real OOB; break at `wamr_oob_readback` with
`size == 8 && ctx->p_code_compiled + size - ctx->p_code_compiled_end == 172`
to dump the table after the last chosen store. Baseline `/tmp/w5-n8.wasm`
regenerated as `ecfce96a…` for comparison. Raw gdb output is in the
gitignored site at `.mishe-tauftauf/artifacts/wamr2shell/w5-const-table-gdb.out`.

Measured at the first OOB (`dup_before`; absolute addresses ASLR-vary):

- Compiled-code allocation: chunk header at `base-8` is `0x5c1` (a 0x5c0-byte
  chunk, 1464 usable), `code_compiled_peak_size = 1458` and
  `p_code_compiled_end = base + 1458`. The 6-byte slack ends at the next
  chunk's size field (`0x71` at `end+6`).
- `ctx->i64_consts = end + 14`, `i64_const_max_num = i64_const_num = 12`
  (96 bytes, `end+14 … end+109`). Baseline `n8`, peak 1164: `i64_consts =
  end + 20`, same 12 entries. The other context buffers are all below the
  buffer (`frame_ref_bottom` `end-1634`, `frame_csp_bottom` `end-2802`,
  `frame_offset_bottom` `end-1570`, `i32_consts` `end-1922`,
  `v128_consts` `end-1874`); the i64 const table is the object immediately
  after it, not free space.
- Table dump after the final chosen store (12 × 8 bytes from `i64_consts`):
  entries 0-1 hold the OOB frame-offset `i16`s (`0x001a001b001c001d`,
  `0x0016001700180019`), entry 2 the loader pointer `0x000055555557dc0d`,
  entry 3 the chosen value `0x4142434445464700`; entries 4-10 are mixed
  chosen bytes, loader pointers and `i16`s (`0x55555557dc0d0016`,
  `0x4344454647010000`, `0x0016414243444546`, …), entry 11 a loader
  pointer. The first four chosen 8-byte stores (destinations
  `end+38/56/74/92`) therefore land inside the live const table (wholly in
  entry 3, then straddling entries 5/6, 7/8 and 9/10); the fifth starts at
  the table's end and the last three reach following heap chunks. The
  process ends `malloc(): corrupted top size` (rc −6) after further
  pointer/`i16` writes.

Source consequence, unmeasured here at the time (a synthetic forced-survival
probe of it is in the next addendum): `wasm_loader.c:16856-16868` copies
`loader_ctx->i64_consts` into `func->consts` at the end of function
preparation, so a load that survived the corruption would carry these bytes
into the module's per-function constant pool. In these builds the load
aborts first; no guest instruction executes. No arbitrary destination, no
attacker-chosen pointer value (the logged pointers are loader-generated),
no wire traffic and no benign-command side effect. Rung 5 stays UNKNOWN and
this addendum does not re-audit witness verdict #1168. The replay offer for
the shift ladder (tape #6192) is separate from this measurement.

## Addendum: table-confinement sweeps and the `func->consts` copy (2026-11-27 ~08:00Z)

This answers the operator's bounded follow-up on the W5 destination: can a
module shape keep chosen stores inside the live `i64_consts` table and let
the load survive far enough to copy them into `func->consts`? All evidence
below is rung-4 depth at the labeled scope; it changes no grade and does not
re-audit witness verdict #1168.

Method: the committed caller-store binary
`build-plain-2.4.4-callerstore/iwasm-2.4.4` (sha `de75c5e6…`, clean pinned
2.4.4 plus `caller-store.patch` `9c0e7907…`) was run on byte-level variants
of the pinned PoC. Two throwaway generators (gitignored `/tmp/w6gen.py`,
`/tmp/w6trim.py`, `/tmp/w6block.py`) (a) varied the number of appended chosen
`i64.const` pairs after the copied 21-result block, (b) trimmed the
`i64.const 0` duplicates from 16373 down while keeping the copied block and
eight chosen pairs, and (c) varied the block arity with balanced trailing
drops. Raw logs are in the gitignored site under
`.mishe-tauftauf/artifacts/wamr2shell/w6-*.out`.

Result — no valid shape confines the chosen stores. With the copied block
and N chosen pairs, the chosen store starts move in 18-byte steps and always
end at `past=172`: N=1 → 172; N=2 → 154/172; N=3 → 136/154/172; N=4 →
118/136/154/172; N=5 → 100/118/136/154/172; N=8 (`dup_before`, sha
`756cabf8…`) → 46/64/82/100/118/136/154/172. Only N=8 has its first four
stores wholly inside the table (`end+38/56/74/92`); the other four reach the
following chunks. Every such run ends `malloc(): corrupted top size` (rc
−6). Trimming duplicates to K ≤ 16368 removes the overflow entirely (rc 0,
`0x1:i32`); K = 16369/16370/16371 gives exactly one chosen 8-byte store at
`past=4/6/8`, then `bh_assert_internal` at `wasm_loader.c:9422` `_ret == 0`
(the `bh_memcpy_s` destination capacity underflows once the cursor is past
the end), rc −6; K = 16372/16373 restores the multi-store overflow and
heap abort. Reducing the block arity below 21 fails validation with
`type mismatch: stack`; M=21 regenerates `dup_before` byte-for-byte
(`756cabf8…`), so the PoC's 21-result block is required. The natural load
therefore aborts before the `:16856-16868` copy in every valid variant
observed. This negative is preserved: no surviving real load was produced.

To measure the previously unmeasured source consequence, a **synthetic
forced-survival probe** (not a valid module load) was built in the gitignored
tree `src/wamr-2.4.4-survive`: clean pinned 2.4.4 plus `caller-store.patch`,
with `wamr_oob_log()` modified to suppress every OOB store except chosen
8-byte const immediates, and a dump of `func->consts` immediately after the
i64 copy. Binary sha `6438b537…`; patched loader sha `49eb9811…`. On
`dup_before` it skipped 95 OOB writes, really stored all eight chosen
immediates, reached the copy and printed (`W6_FUNC_CONSTS n=12`):

```
0000000000000000 0000000000000001 0000000000000002 4142434445464700
0000000000000004 4344454647010005 0000000000004142 4546470200000007
0000000041424344 4703000000000009 0000414243444546 000000000000000b
```

Chosen bytes are copied into seven of twelve `func->consts` entries (3, 5,
6, 7, 8, 9, 10); entries 0/1/2/4/11 remain loader values. The subsequent
guest call still faults in `copy_stack_values()` (`wasm_interp_fast.c:938`)
because the suppressed OOB writes leave gaps in the compiled stream, so a
guest `i64.const` readback of those entries remains **unmeasured even in this
synthetic build**. The copy observation is a forced-survival mechanic only:
no valid load survives, no guest instruction reads chosen bytes, no
attacker-chosen pointer, no wire traffic and no benign-command side effect.
Rung 5 stays UNKNOWN. Fixed 2.4.5 ASan control on `dup_before`, the four-pair
variant and the single-store trim: no ASan report, only the known post-load
CLI `Exception: native stack overflow` (rc 1).
