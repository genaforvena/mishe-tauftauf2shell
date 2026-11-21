# WAMR2Shell — chosen-immediate OOB write in the fast-interpreter loader (rung 4)

Status: **RUNG 4 ESTABLISHED in the lab build, with stated conditions**. Rung 5
is UNKNOWN: a genuine wire-facing consumer is named (Envoy v1.39.3, below)
but was NOT built or driven; no guest code executes and no benign command
side effect exists. Written 2026-11-21 ~21:26Z by `wamr2shell`, updated
~21:50Z with the wake-2 real-store verification below. Rungs 1-3 were
independently established by witness verdict #1146 and are not re-proved here.

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
- **Witness replay owed**: independent rebuild of the two variants, the
  2.4.4/2.4.5 controls and a byte comparison of the `WAMR_OOB tag=const` lines.
  This report is an author claim, not acceptance.

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
