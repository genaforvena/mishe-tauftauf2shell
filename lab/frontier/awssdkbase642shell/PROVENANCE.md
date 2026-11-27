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
- Fixed CRT v0.43.2 tarball fetched from codeload at `0463563f9f65` —
  SHA-256 `277a8b17eb8b0b3893ffd6fbca70ddfecb7c2dc54c49b609ab947446007e3ff4`.
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
  `harness/fixed_crt_shim.cpp` supplies `Aws::Crt::ApiAllocator()` and three
  tiny aws-c-common platform symbols (`aws_debug_break`,
  `aws_backtrace_print`, `aws_secure_zero`) so the fixed arm links without
  the full CRT IO/MQTT/logging runtime; the fixed `Types.cpp` Base64 bodies
  and the pinned common `encoding.c`/`allocator.c`/`byte_buf.c` bodies are
  verbatim. `harness/generated_client_harness.cpp` is pinned and builds a
  generated REST-JSON protocol-test model's wire response path.

## Harness condition

`harness/decode_harness.cpp` calls the real pinned `Base64::Decode()` with a
CLI string and defines `Aws::Malloc`/`Aws::Free` as `malloc`/`free`, because
the SDK core allocator is a separate translation unit; the decoder body is
verbatim pinned source and the ASan heap region is a real `malloc` allocation.

Two controls are now exercised. The fixed arm applies the pinned fix's two
Base64 hunks to a staging copy and compiles the patched decoder against
fixed CRT v0.43.2 `Types.cpp` plus pinned common sources; malformed inputs
return zero decoded bytes with no ASan report. The generated-client arm
builds the verbatim pinned `JsonBlobsResult.cpp`, `HashingUtils.cpp`,
`JsonSerializer.cpp` and `cJSON.cpp`: a CLI wire-format JSON payload
`{"data":"AAAA="}` reaches `Base64.cpp:115` through `HashingUtils.cpp:42`
and `JsonBlobsResult.cpp:27` and faults under ASan with WRITE-1 into a
2-byte region. The fixed generated-client arm rejects it cleanly. The
protocol-test model is generated SDK code, not a live AWS service endpoint;
no network I/O occurs. `-DNDEBUG` and
`-ffunction-sections -Wl,--gc-sections` are lab build conditions; the
latter only drops unused crypto functions from `HashingUtils.cpp`.
Allocator shims, debug-build assertion behavior and the fixed-arm link
shim are disclosed; no pointer, saved RIP, marker or command claim.

## Duplicates

The frontier wall has `awslc2shell` (AWS-LC) but no AWS SDK for C++ / Base64
lane when this candidate was screened.
