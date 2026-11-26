# Provenance — oiiocineon2shell

## Claim sources (read 2026-11-26, provisioning only)

- GHSA advisory:
  https://github.com/AcademySoftwareFoundation/OpenImageIO/security/advisories/GHSA-xh8r-vmqq-56pp
  (published 2026-07-10, `lgritz`; CVE-2026-59181; CWE-121/CWE-787; CVSS 6.1;
  affected version stated as 3.2.0.2, patched `>= 3.0.20.0`, `>= 3.1.15.0`,
  `>= 3.2.0.3`). The advisory itself supplies the 2048-byte malicious-file
  generator, the focused libcineon harness shape and the expected ASan WRITE-8.
- Canonical CVE: https://cveawg.mitre.org/api/cve/CVE-2026-59181 (CNA
  `GitHub_M`, published 2026-09-18). Affected ranges: `< 3.0.20.0`,
  `>= 3.1.0.0, < 3.1.15.0`, `>= 3.2.0.0-dev, < 3.2.0.3-beta1`; fixed at
  3.2.0.3-beta1. OSV lookup for the GHSA returned 404 (negative preserved).
- Fix PR: https://github.com/AcademySoftwareFoundation/OpenImageIO/pull/5250;
  raw patch saved as `pins/fix-5250.patch` from
  https://patch-diff.githubusercontent.com/raw/AcademySoftwareFoundation/OpenImageIO/pull/5250.diff.
  It adds the `nchannels < 1 || nchannels > 8` guard in `CineonInput::open()`
  and uses the validated count in the metadata loops.

## Pinned bytes

`pins/vuln/` comes verbatim from the upstream tag
`v3.2.0.2-dev` archive
(https://codeload.github.com/AcademySoftwareFoundation/OpenImageIO/tar.gz/refs/tags/v3.2.0.2-dev,
SHA-256 `1c1283e87bcf270dff02037087b5b79eb08cd75f5ee41a72700a3b3b726ff4d2`):
`cineoninput.cpp` plus the complete `libcineon/` directory.

`pins/fixed/` comes verbatim from the upstream tag
`v3.2.0.3-beta1` archive
(https://codeload.github.com/AcademySoftwareFoundation/OpenImageIO/tar.gz/refs/tags/v3.2.0.3-beta1,
SHA-256 `a8beb7cbddfaf7efc2389ee34733110565b967716897632184329a295f2bc38f`).

`cineoninput.cpp` git blob identities (verified with `git hash-object` on the
pinned files, matching the advisory research claim):

| pin | git blob SHA-1 | SHA-256 |
|---|---|---|
| vulnerable `v3.2.0.2-dev` | `d64ac4ab3d67db003c70f04f8faaace3ada66356` | `8e1b22819400e068963d56d60f2b6b5506376a28af189359a62fa6048f34a2a6` |
| fixed `v3.2.0.3-beta1` | `6174e91630067d36562944144bf7dff2b62ac736` | `866942554a2d8509081b29b152fd87e6ea87bd04ea165d6dd5d6c457817db0b6` |

Every pinned file's SHA-256 is in `pins/PIN_HASHES.txt` (37 entries);
`run-all.sh` verifies all of them before building.

## Frontier-authored vs verbatim

Verbatim: all files under `pins/`, and the sink slices copied by
`gen_sink.py` from the pinned `cineoninput.cpp` (vulnerable raw lines
209-215; fixed raw lines 96-101 and 246-252). `#line` directives map ASan
frames back to those raw upstream lines; `run-all.sh` asserts both the slices
and the mappings.

Frontier-authored: `h/driver.cpp` (reads a real `.cin` through verbatim
upstream `InStream`/`Reader`, calls the sink slice), `h/common.h`, `gen.py`
(three local 2048-byte headers), `gen_sink.py`, `run-all.sh`.

`h/shim/OpenImageIO/{strutil,filesystem,sysutil}.h` are a minimal local build
shim for the three OIIO helpers the vendored libcineon headers use
(`safe_strcpy`, `fmt::format`, `stoi`, `Filesystem::fopen`,
`Sysutil::get_local_time`). They are **not** upstream OIIO sources and do not
participate in the sink; no full OIIO library build is claimed. The advisory's
own harness recipe likewise compiles only libcineon sources and the sink.

## Preserved negatives

- Plain (no ASan) vulnerable build exits 0 on the 255-element file: no rung 1
  or rung 2 claim from this harness.
- clang++ 18 at `-O1` optimized the out-of-bounds store away (rc 0, no ASan);
  the runner therefore builds clang at `-O0`, where it reproduces. GCC at
  `-O1` reproduces directly. Both facts are preserved, not hidden.
- Fixed pin rejects 255 (`open_like=0`) with no ASan; count 8 and count 1
  vectors are clean on both pins.
- No `.cin` was fetched or written outside this lab; no network service,
  socket or external target is contacted. Chosen bytes at chosen offsets,
  live-consumer control and remote execution are NOT claimed.
