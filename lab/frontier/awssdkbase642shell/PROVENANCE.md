# Provenance — awssdkbase642shell

All provisioning was read-only fetching of public archives; all execution was
local CLI/GDB work. No network I/O from the harness, no listener, no external
probe.

## Advisory, fix and pinned sources

- CVE-2026-19642 / GHSA-wxx3-prfc-69xx, GitHub advisory fetched from
  `https://github.com/aws/aws-sdk-cpp/security/advisories/GHSA-wxx3-prfc-69xx`
  — SHA-256 `28ecc166e5261a609ed76faf3bbb4ca029e1ff9558d3ce5b910b2918bc0f6cb0`.
- Fix commit `8eeac049c37b2c4cca2a94bfb53f07ea7e4550f7`, single parent
  `2857dbc70b4b780810e304ba14514fa52d932a23`; patch fetched from the `.patch`
  URL — SHA-256 `d7c3cf23492b1040b2d11cd8e6f44b22ae48f2f084dd23e5d2cca1f1fe41606d`.
- Vulnerable SDK parent tarball fetched from codeload at `2857dbc7` —
  SHA-256 `2da18333f473f1bef74019aca3f606b2e8c2ffa7026c7f76a2b028c3cdef707d`.
  Sink: `src/aws-cpp-sdk-core/source/utils/base64/Base64.cpp:109/112/115`
  writes into the `ByteBuffer` allocated at `:99`; the length calculator is
  at `:123-139`.
- Header-only dependencies were fetched from the pinned CRT dependency
  revisions named in the fix's `prefetch_crt_dependency.sh`: aws-crt-cpp
  `72f84bc3` (`a10acc96…`), aws-c-common `3c69b871` (`a3097442…`), aws-c-io
  `54350963` (`c7ce64d2…`), plus the pinned mqtt/http/auth/event-stream/s3/
  sdkutils/checksums/cal/compression tarballs. Their exact SHA-256 values are
  in `SHA256SUMS`. Two cmake-generated headers (`SDKConfig.h`,
  `aws/common/config.h`) are stubbed under `harness/generated/` with hashes
  pinned; no feature macro is defined for this lab.

## Harness condition

`harness/decode_harness.cpp` calls the real pinned `Base64::Decode()` with a
CLI string and defines `Aws::Malloc`/`Aws::Free` as `malloc`/`free`, because
the SDK core allocator is a separate translation unit. This is a lab-only
allocator shim; the decoder body is verbatim pinned source and the ASan heap
region is a real `malloc` allocation. The fixed arm is NOT exercised: the
patch delegates to `aws-crt-cpp` v0.43.2, which is not linked in this lab, so
a fixed runtime control stays UNKNOWN. Debug `-DNDEBUG` behavior is the
observed control, not a fixed-code control.

## Duplicates

The frontier wall has `awslc2shell` (AWS-LC) but no AWS SDK for C++ / Base64
lane when this candidate was screened.
