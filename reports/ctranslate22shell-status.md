# ctranslate22shell — admitted status (2026-11-25 11:2xZ)

**ADMITTED under standing #6 as the 148th route** by operator at 11:2xZ:
hy4-flash `max_parallel: 3` route, both resolver keys, three wake units
minted with the exact full-flag sync (`written 3, removed 0`), path enabled
and active, pinned full-flag doctor PASS / GREEN rc 0. Window 155 was
already live and registered (panes %312/%313); it was adopted, not
duplicated. No grade, rung cell or R5 cell moved by admission; witness
verdict stays UNKNOWN.

## Stage 0 — frontier staging (frontier W229, commit 7ae21617)

- CVE-2026-102566 / GHSA-7xqx-34h9-2w97, CTranslate2 before 4.8.1,
  CWE-787, CVSS4 8.5 `AV:L/UI:P`. Fix `d9b991e` (PR #2068), vulnerable
  pin `v4.8.0` `src/models/model.cc` (sha256 `05ab59bb…`), fixed pin
  sha256 `5dcc3f1d…`; both in `lab/frontier/ctranslate22shell/pins/`.
- Mechanism at pinned `:644-657`: file-derived `num_bytes` is passed to
  `consume<char>(model_file, num_bytes, variable.buffer())` at `:657`;
  `consume` at `:71` reads that many bytes into a shape-sized heap buffer.
  Fix adds the size equality check at fixed `:659-660`.
- Verbatim pinned functions + stand-in 16-byte `StorageView`:
  `bash harness/run-all.sh` = 16 PASS / 0 FAIL, GCC and Clang ASan
  `WRITE of size 17` / `WRITE of size 64`, fixed pin rejects both, safe
  payload 16 clean, plain readback shows file-chosen bytes past the region.
- Clean `git archive HEAD` replay at 11:06Z: 16 PASS / 0 FAIL.
- Grade: rung 3 confirmed in a real consumer (GCC ASan `WRITE of size 17`
  and `48` at `model.cc:657`, 0 bytes after a real 16-byte `posix_memalign`
  `StorageView` allocation); rung 4 PARTIAL file-chosen length and bytes.
  Fixed pin rejects the same file; safe 16-byte input is clean. No pointer
  control, wire, command or R5. Witness UNKNOWN; replay owed before any
  rung-4 publication.
- Brief: `reports/frontier-ctranslate22shell.md`; details and negatives in
  `lab/frontier/ctranslate22shell/PROVENANCE.md`.

## Real-source consumer — completed W1 (2026-11-25 12:05-12:08Z)

`lab/frontier/ctranslate22shell/realbuild/build.sh` builds the verbatim
upstream v4.8.0 `model.cc` (sha256 `05ab59bb…`) and fixed `d9b991e` model.cc
(sha256 `5dcc3f1d…`) against the real `StorageView`/allocator under ASan,
with only logging and unused quantization/tensor-parallel branches stubbed.
Crafted 109-byte binary_version-6 file (`realbuild/evidence/crafted-n17.bin`)
sets a shape-{2,2} FLOAT32 variable to `num_bytes=17`. ASan reports `WRITE of
size 17`, `0 bytes after 16-byte region`, allocated by `posix_memalign` via
`cpu::AlignedAllocator::allocate` ← `StorageView::reserve`; write stack
`consume<char>` ← `Model::load model.cc:657`. `num_bytes=48` writes 48 bytes;
`num_bytes=16` is clean; the fixed pin rejects the same file with
`Variable 'origin' has an invalid payload size`; the plain build aborts with
`malloc(): corrupted top size` at 48/64/80 bytes. Exact bytes and raw output
in `lab/frontier/ctranslate22shell/PROVENANCE.md` and `realbuild/evidence/`.

Next: ask the witness to replay `build.sh`; then measure whether a chosen
value can reach a dereferenced pointer in a real consumer (the remaining gap
to full rung 4). No rung 5 without a loopback wire path and command side
effect.
