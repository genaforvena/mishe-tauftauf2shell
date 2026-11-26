# PROVENANCE — libde265shell

All bytes fetched read-only from public GitHub endpoints; no host other than
GitHub was contacted, and every decode ran locally in this lab.

## Advisory and fix

- GHSA-653q-9f73-8hvg / CVE-2026-33165:
  https://github.com/strukturag/libde265/security/advisories/GHSA-653q-9f73-8hvg
  (published 2026-03-17, Moderate, CWE-787). Affected `<= 1.0.16`, patched
  `>= 1.0.17`. Advisory claim: stale `ctb_info.log2unitSize` after an SPS
  change with constant `PicWidthInCtbsY`/`PicHeightInCtbsY`; `set_SliceHeaderIndex`
  writes 2 bytes past a 2496-byte heap array, ASan frame `image.h:741` from
  `slice.cc:2866`. Advisory attaches POC.zip with a 254-byte minimized
  bitstream and a standalone `poc.c` using only public decoder APIs.
- Upstream fix commit `c7891e412106130b83f8e8ea8b7f907e9449b658`
  (https://github.com/strukturag/libde265/commit/c7891e412106130b83f8e8ea8b7f907e9449b658)
  raw `.patch` fetched to `src/fix.patch`; it adds
  `|| ctb_info.log2unitSize != sps->Log2CtbSizeY` to the reallocation guard in
  `libde265/image.cc` and narrows `MetaDataArray::log2unitSize` to `uint8_t`.
  Verified against pinned sources: 1.0.16 `image.cc:455-456` has no log2 test;
  1.0.17 `image.cc:417-419` has it.

## Pinned inputs (SHA-256, measured locally)

| Artifact | Origin | SHA-256 |
| --- | --- | --- |
| `src/libde265-v1.0.16.tar.gz` | https://codeload.github.com/strukturag/libde265/tar.gz/refs/tags/v1.0.16 | `ed12c931759c1575848832f70db5071a001ac813db4e4f568ee08aef6e234d4e` |
| `src/libde265-v1.0.17.tar.gz` | https://codeload.github.com/strukturag/libde265/tar.gz/refs/tags/v1.0.17 | `3a285024fa135fb962b4554e27ca54d7b0013d7084109a75cc9bef741ae57473` |
| `src/POC.zip` | https://github.com/user-attachments/files/26009899/POC.zip | `b3b57b422acf96b9ce8c8d116453bbf330c8414d4d3b4947974e56882f5aa1b2` |
| `src/poc/reproducer.bin` | advisory POC.zip (254 bytes) | `73afafa6dd3a1c8ecf403af746ed0e7e279b35c2ab9f4c5a953626fb5d8efa8b` |
| `src/poc/poc.c` | advisory POC.zip (public-API harness) | `c5b05a8cf45902c5cf23d112edf0c02c417364fb4cfde06f1d396e4604eb26f2` |
| `src/poc/safe.bin` | generated locally: 254 zero bytes, benign control | deterministic, not fetched |

Tag commits verified with `git ls-remote --tags`:
v1.0.16 `7ba65889d3d6d8a0d99b5360b028243ba843be3a`;
v1.0.17 `f3d916c8e63e510bda1f9cf5e8710259c22afece`.

## Build and run

`run-all.sh` verifies every pin, extracts the tarballs, builds each tag with
CMake (`BUILD_SHARED_LIBS=OFF`, `ENABLE_DECODER=OFF`, `ENABLE_SDL=OFF`,
`ENABLE_TOOLS=OFF`) under clang ASan, gcc ASan and gcc plain, links the
unmodified advisory `poc.c` against each static library, and runs both the
254-byte reproducer and the 254-byte benign control. It reports PASS/FAIL per
cell; raw stdout/stderr is kept under `evidence/`.

Negative preserved: an early autotools build path failed on the fixed tag
because v1.0.17 has no `autogen.sh` (CMake-only); the runner was switched to
CMake for both tags rather than treating that build failure as evidence.
Another early attempt linked `poc.c` with a C++ driver, which rejects the C
source (implicit `malloc` cast, goto across initialization); the runner links
with the C compiler plus `-lstdc++`, matching the advisory's build recipe.
