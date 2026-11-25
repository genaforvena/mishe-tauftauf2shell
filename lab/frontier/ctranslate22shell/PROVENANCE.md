# PROVENANCE — ctranslate22shell staged harness

## Source pins (read-only provisioning, 2026-11-25)

- `pins/model-v4.8.0.cc` — https://raw.githubusercontent.com/OpenNMT/CTranslate2/v4.8.0/src/models/model.cc
  sha256 `05ab59bb4413df14d36fbbb0d82ff6ce6fe0bee72245245f8ecec773d4cc2c65`
  (898 lines).
- `pins/model-fixed.cc` — https://raw.githubusercontent.com/OpenNMT/CTranslate2/d9b991e0700933a0c05373df8b52ed89cdcab96d/src/models/model.cc
  sha256 `5dcc3f1daa0de260c068b4645728a28305b27393f9461e650f45c8db89c707b7`
  (902 lines).
- Advisory: GHSA-7xqx-34h9-2w97 / CVE-2026-102566, 2026-09-29.
- Fix: PR #2068, merge `d9b991e0700933a0c05373df8b52ed89cdcab96d`,
  patch read from https://github.com/OpenNMT/CTranslate2/commit/d9b991e.patch .

## Verbatim ranges

- `harness/pinned_consume.h` lines 10-54 are byte-identical to vulnerable
  pin lines 43-87 (`report_stream_error` and both `consume` overloads).
  The fixed pin's `consume<std::string>` hardening at fixed `:82-85` is
  deliberately not merged into this header; the exercised buffer overload
  is byte-identical in both pins.
- `harness/probe_vuln.cpp` lines 67-85 are byte-identical to vulnerable
  pin lines 639-657 (the variable-loading caller through the OOB store).
- `harness/probe_fixed.cpp` lines 66-86 are byte-identical to fixed pin
  lines 641-661 (the same caller, including the two fix lines). Fixed
  pin line 640's `auto name = consume<std::string>(...)` is replaced by a
  stand-in string; it is upstream of the exercised store.
- `run-all.sh` re-checks every range with `diff` and both pin hashes with
  `sha256sum -c` before compiling. Rendered-source line numbers are
  claims; these local pins and fix hunks are authoritative.

## Stand-ins and negative results

- Stand-in `StorageView` allocates 16 bytes for shape `{2,2}` and float
  dtype. Under `-DMISHE_ASAN` it is a real `new char[16]` region; in the
  plain build it is a 16-byte member followed by a 32-byte marker so
  chosen bytes can be read back deterministically.
- Earlier harness iterations failed: `/bin/sh` process substitution,
  Clang not defining `__SANITIZE_ADDRESS__`, LeakSanitizer flagging the
  un-freed stand-in buffer, and a 64-byte plain payload overrunning the
  whole 48-byte fixture (`malloc(): corrupted top size`). All were repaired
  in the committed `run-all.sh`; the 64-byte case is retained as an ASan
  case only, with a 48-byte bounded case for plain readback.
- No real CTranslate2 build, no real model file consumed by `Model::load`,
  no wire, no pointer-IP, no command, no rung 5. Witness replay UNKNOWN.
