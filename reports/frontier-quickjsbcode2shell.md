# frontier-quickjsbcode2shell — QuickJS bytecode integer overflow (CVE-2026-88378)

Status: **staged, rung 3 ASan-confirmed heap OOB WRITE in verbatim pinned
source (W271 2026-11-26)**. Second find of the wake, staged after handing
libsmpp342shell to its own window. Chosen because the upstream fix carries an
exact 21-byte regression input for a public single-call API; no release tags
exist, so both pins are commit hashes. Hashes and refetch commands are in
`lab/frontier/quickjsbcode2shell/PROVENANCE.md`.

## Claim source and scope

- CVE-2026-88378 / GHSA-jww9-7qmq-6hv5, GitHub Advisory Database
  https://github.com/advisories/ghsa-jww9-7qmq-6hv5 (unreviewed, published
  2026-09-24; Critical 9.8, AV:N). Claim: untrusted compiled bytecode passed
  to `JS_ReadObject()` can drive a negative function count into an
  under-sized allocation and heap OOB write.
- Upstream: https://github.com/bellard/quickjs . Fix commit
  `42526037cfc0b2a94a875c0de0f4bbeaf597a542` ("Reject overflowing integers in
  bytecode reader"); GitHub commit API confirms its parent is the vulnerable
  pin `04be246001599f5995fa2f2d8c91a0f198d3f34c`. The patch touches
  `quickjs.c`, `tests/bjson.c`, `tests/test_bjson.js`; the upstream regression
  supplies the exact 21 bytes used below. The repository has no release tags,
  so no numeric affected/fixed version is claimed.
- Checked before staging: no brief, charter, manifest row, lab lane or wall
  receipt for bellard/quickjs. QuickJS-NG GHSA-r6vf-p8wr-4vg9 is a different
  project and its advisory page fetched as 404; it remains an unresolved wall
  backup, not a duplicate or a source for this finding.

## Source-bound mechanism (pinned bytes)

- `bc_get_leb128_int()` at `quickjs.c:38501` in the vulnerable commit did
  `return bc_get_leb128(s, (uint32_t *)pval);`: an encoded `0xFFFFFFFF` LEB128
  value is written through a `uint32_t*` into an `int*`, becoming `-1`.
- `JS_ReadFunctionTag()` reads that value into `bc.cpool_count` (`:38791`)
  and computes `function_size += (uint64_t)bc.cpool_count * sizeof(JSValue)`
  (`:38803`). The 64-bit product wraps, so the allocation at `:38816` is
  smaller than the 96-byte header copy at `:38820` (`memcpy(b, &bc,
  offsetof(JSFunctionBytecode, debug))`).
- The fix decodes into `uint32_t val`, rejects decode failure and
  `val > INT_MAX` with `SyntaxError: integer overflow while reading bytecode`,
  then assigns the checked value. The verbatim source diff between the two
  pins is 13 changed lines, all in that one function.

## Local experiment and observed bytes

`lab/frontier/quickjsbcode2shell/run-all.sh` (sha256
`7031c42086ccaad2ee329b18c597cd0fc2b62fe98dd9a6c30f249bc3c09b1cd5`)
extracts both pinned tarballs, checks hashes and the one-function diff, then
compiles `harness/driver.c` against the **unmodified** upstream `quickjs.c`,
`dtoa.c`, `libregexp.c`, `libunicode.c` and `cutils.c`. The build-only defines
are `-D_GNU_SOURCE`, `-DCONFIG_VERSION` from upstream `VERSION`, and
`-include limits.h` (the fixed patch uses `INT_MAX` without including it).
Console `evidence-run-console.log`: `RESULT PASS=25 FAIL=0 rc 0`.

- Attack input (exact upstream test bytes): `05 00 0c 00 00 00 00 00 00 00
  01 00 00 ff ff ff ff 0f 00 00`, passed as
  `JS_ReadObject(ctx, buf, 21, JS_READ_OBJ_BYTECODE)`.
- GCC 12 ASan: `heap-buffer-overflow`, `WRITE of size 96`, `0 bytes after
  88-byte region`, frame `JS_ReadFunctionTag build/vuln/quickjs.c:38820`
  through `JS_ReadObjectRec` and `JS_ReadObject`; rc 1.
- Fixed build on the same bytes: rc 0, exception
  `SyntaxError: integer overflow while reading bytecode`, no ASan report.
- Safe control: real bytecode written with `JS_WriteObject(...,
  JS_WRITE_OBJ_BYTECODE)`, read back with `JS_READ_OBJ_BYTECODE` and evaluated
  with `JS_EvalFunction` yields `value=2` in both builds, no ASan report.
- **Preserved compiler negative:** Clang 18 ASan produced no report on the
  attack input (rc 0, `exception=0`). The runnable check asserts that silence
  rather than hiding it; GCC is the detecting compiler here.

## Honest grade

Rung 3: ASan-confirmed heap OOB WRITE in verbatim pinned upstream source,
driven by the upstream regression input through the public bytecode API.
Rung 4 **NOT CLAIMED**: the crafted bytes are fixed upstream bytes, no chosen
value is observed at a chosen heap offset, no pointer/control-flow target is
steered, and no live wire consumer, command or r5 is present. The advisory's
AV:N is a claim; this lab used no socket.

## Cheapest next experiment to move up a rung

Vary the LEB128 count and surrounding function-header fields while keeping the
same under-sized allocation, and use a plain build with heap grooming to see
whether chosen bytes can be made to land at a chosen offset relative to the
allocation; record read-back, not just a fault. Separately, drive the same
21 bytes from a loopback service that accepts bytecode from a local client and
calls `JS_ReadObject()` on the received buffer, with fixed and safe controls.
A rung-4 claim needs observed chosen bytes at chosen offsets; rung 5 needs a
live wire path and a lab-chosen command side effect.

## Ranked alternatives retained

- musl CVE-2026-107891 `regcomp()` int overflow (fix `7813e911…`, untagged):
  one-file patch and short repetition pattern, but needs a regex-parser
  harness; MED.
- Apache Axis2/C CVE-2026-124023 (fix commits `23110287…`/`f01683ec…`):
  network-facing XML parser, but requires real `axutil_env_t` objects; MED.
- libmikmod CVE-2026-105837 (DSM loader track-count wrap) and TinyUSB
  CVE-2026-61495 (MTP string OOB write) are local/physical and lower value.
- ntfs-3g CVE-2026-42618 needs a crafted NTFS image and a wholesale
  decompressor rewrite; screened down from the earlier unverified backup list.

## Do-not-duplicate and boundaries

No admitted target or screened lane is reused; QuickJS-NG is not touched.
All testing is local against pinned source; no external system was probed.
Admission is the operator's; wake units and full-flag sync stay with the
person. Witness replay from clean tarballs is owed before ESTABLISHED.
