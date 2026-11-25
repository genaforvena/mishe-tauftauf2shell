# frontier brief — ctranslate22shell (CVE-2026-102566)

Status 2026-11-25 11:05Z: STAGED locally; brief and lab harness written.
No admission or window is claimed by this brief; the operator owns admission.

Dated update (2026-11-25 21:35Z): W1-W4 built a real-source ASan consumer
against the verbatim vulnerable and fixed `model.cc` and measured the
overflow there; see `reports/ctranslate22shell-status.md` and
`lab/frontier/ctranslate22shell/PROVENANCE.md` for the results and the
three negative layout probes. Witness W223 returned ESTABLISHED AS LABELED
for rung 3 CONFIRMED / rung 4 PARTIAL, NO r5. The staged numbers below are
the original 11:05Z staging claims.

## Verified ground truth

- Claim: CVE-2026-102566 / GHSA-7xqx-34h9-2w97, published 2026-09-29,
  https://github.com/advisories/ghsa-7xqx-34h9-2w97 . CWE-787, CVSS:4.0
  8.5 HIGH `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`. Advisory text:
  CTranslate2 before 4.8.1 binary model loader fails to validate payload
  length against allocated buffer size; crafted model files write past a
  heap allocation.
- Vulnerable pin: tag `v4.8.0` `src/models/model.cc` (sha256
  `05ab59bb4413df14d36fbbb0d82ff6ce6fe0bee72245245f8ecec773d4cc2c65`).
  Upstream fix `d9b991e0700933a0c05373df8b52ed89cdcab96d`
  (PR #2068, merged 2026-07-02); fixed pin sha256
  `5dcc3f1daa0de260c068b4645728a28305b27393f9461e650f45c8db89c707b7`.
  Both full files are in `lab/frontier/ctranslate22shell/pins/` with a
  SHA256SUMS manifest.
- Not a duplicate: CTranslate2 is absent from the admitted-target list and
  from earlier staged briefs. It was only parked as "larger C++ build" in
  `reports/frontier-snap72shell.md:130`.

## Source-bound mechanism (pinned bytes)

- Vulnerable pin `:644-657`: the loader reads `rank`, `dimensions`, `dtype`
  and a file-derived `num_bytes`, constructs a `StorageView variable` whose
  buffer is sized by the shape and dtype, then calls
  `consume<char>(model_file, num_bytes, static_cast<char*>(variable.buffer()))`
  at `:657`.
- Pinned `consume` template at `:64-78` multiplies `n` by `sizeof(T)` and
  calls `in.read(reinterpret_cast<char*>(dst), read_size)` at `:71` with no
  knowledge of the destination's capacity. The file chooses both the byte
  count and the stored bytes.
- Fix adds, before the store,
  `if (num_bytes != variable.size() * variable.item_size()) throw ...`
  (fixed pin `:659-660`), and separately hardens `consume<std::string>`
  against a zero string length and a missing NUL (`:82-85`). Only the
  first hunk is exercised below; the string issue is a distinct,
  untested OOB-read claim.

## Cheapest local experiment and observed result

`lab/frontier/ctranslate22shell/harness/` pins the two `consume` overloads
byte-identically from the vulnerable file (`:43-87`) and the caller ranges
byte-identically (vulnerable `:639-657`, fixed `:641-661`); a stand-in
`StorageView` supplies a 16-byte heap region (`shape {2,2}`, float dtype)
and a crafted binary model stream supplies the header and payload.
`bash harness/run-all.sh` → 16 PASS / 0 FAIL (GCC and Clang):

- GCC and Clang ASan vulnerable builds, payload lengths 17 and 64:
  `heap-buffer-overflow`, `WRITE of size 17` / `WRITE of size 64` in the
  pinned `consume` store (harness `pinned_consume.h` maps to upstream
  `model.cc:71`). Safe payload 16 is clean on both compilers.
- Fixed pin with payloads 17 and 64: rejects with
  `Variable 'model.w' has an invalid payload size`, no sanitizer error;
  safe payload 16 clean.
- Plain vulnerable build: a 17-byte payload writes the chosen byte `'I'`
  at `buffer+16` (visible in the deterministic follower); a 48-byte payload
  writes the file-chosen pattern `ITEMISHE-CT2-OOB...` across 32 bytes past
  the region. Readback is a stand-in consumer, not a live process.
- Provenance checks in `run-all.sh` verify both pin sha256 values and
  byte-identical pinned ranges before compiling.

## Feasibility assessment and ceilings

- Rung 1 (trigger): deterministic crafted model stream through the pinned
  loader; no external probes.
- Rung 2 (state failure): file `num_bytes` accepted for a 16-byte region.
- Rung 3: GCC and Clang ASan WRITE in the verbatim pinned store.
- Rung 4: PARTIAL — both the overflow length and the stored bytes are
  file-chosen at a known offset past the allocation. No function-pointer
  target, no allocator grooming, no pointer-IP measured. The stand-in
  `StorageView` allocation is not the real C++ object graph.
- Rung 5: NOT CLAIMED — no live library/service, no wire, no command
  execution; advisory itself is `AV:L/UI:P`. A real-source consumer build
  now exists (W1-W4), but it is an in-process harness, not a live service.
- Caveat: the fixed control is a commit, not a released tag (v4.8.1 is
  the advisory's fixed release). The `consume<std::string>` hardening in
  the same fix is not exercised here.

## Next experiment for a target mind (status after W1-W6)

The staged proposal was to build v4.8.0 with ASan, craft a real `.bin`
model with an overlong variable payload, drive `Model::load()` and measure
what follows the heap allocation. That experiment was run:

Build done in W1-W4: the real `Model::load` overflow is measured (ASan
WRITE at `model.cc:657`); remaining question is pointer control. W2 (no
pointer-bearing object after the buffer at store time), W3 (grooming) and
W4 (`sysmalloc`-prev_size and the `_size` guard) are negative results; no
chosen pointer or control flow is in evidence.

All local work stayed in `lab/frontier/ctranslate22shell/`; source fetches
were read-only provisioning and no external system was contacted with a
probe.
