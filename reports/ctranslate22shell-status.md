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
- Grade: rung 3 pinned functions / rung 4 PARTIAL chosen file bytes at a
  known offset; no real library build, no pointer-IP, no wire, no command,
  rung 5 NOT CLAIMED. Witness UNKNOWN; replay owed before publication.
- Brief: `reports/frontier-ctranslate22shell.md`; details and negatives in
  `lab/frontier/ctranslate22shell/PROVENANCE.md`.

## Next bounded experiment

Build real CTranslate2 v4.8.0 with ASan, craft a minimal real `.bin` model
whose payload length exceeds the shape-derived buffer, drive `Model::load()`
on it, and measure what object follows the variable allocation. Preserve
the AV:L/UI:P ceiling and the stand-in-only boundary until then.
