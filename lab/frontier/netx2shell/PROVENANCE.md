# Provenance — netx2shell (CVE-2026-93475)

All fetches were provisioning (GitHub release archives / raw source), no
external probes. All test runs were local, no network target.

## Primaries

- GHSA-rcv5-vfff-25gh — https://github.com/eclipse-threadx/netxduo/security/advisories/GHSA-rcv5-vfff-25gh
  Published 2026-10-02, critical 9.8, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,
  CWE-787 + CWE-1284. Affected NetX Duo <= 6.5.1.202602; patched 6.5.2.202603.
- NVD CVE-2026-93475 (same GHSA).
- Fix commit `4adb237093c1f578c876e28c3752affaaf159ee0`
  (parent `3033f0d2de15`), "Merge commit from fork", 2026-09-29.
  Patch: https://github.com/eclipse-threadx/netxduo/commit/4adb237093c1f578c876e28c3752affaaf159ee0.patch

## Pinned builds

| Role | Tag | Commit | Archive SHA-256 |
|---|---|---|---|
| affected | `v6.5.1.202602_rel` | `1a0e9e43a03e` | `31a30408cc1637e4be8510e8a864e927307d424f41227ceb0d50867cb30f5be6` |
| fixed | `v6.5.2.202603_rel` | `20046b122144` | `f090d4e5e12d162ea31b3b1084bea04d599819e9775d5fe3292ce872a4cdbaa7` |

Archives: `src/netxduo-6.5.1.202602.tar.gz`, `src/netxduo-6.5.2.202603.tar.gz`.
Upstream regression fixture (from the fix commit, not a local invention):
`src/netx-oversized-key-test-data.h`, SHA-256
`1cb8e3f2c713d0113d198066c5654380ac0cdcf6f573f27e1ede49776af7fff4`
— a real self-signed 8192-bit RSA certificate, DER length 2317.

ThreadX headers: shallow clone of `eclipse-threadx/threadx` into each tree's
`test/cmake/threadx` (build dependency only; no ThreadX source compiled into
the vulnerable path).

## Harness

`harness/netx_oversized.c` compiles the real pinned `nx_secure_x509_*.c`,
`nx_crypto_rsa.c`, `nx_crypto_huge_number.c` and
`nx_crypto_huge_number_extended.c` under clang 18.1.3 `-fsanitize=address`.
Only the hash method is a stub (NULL ops, SHA-256 ICV size 256): it exists so
`_nx_secure_x509_certificate_verify` reaches the RSA operation; no stub writes
into `decrypted_signature`. `harness/stubs.c` supplies host link symbols
`_nx_crypto_memcpy_ptr`, `_nx_crypto_memset_ptr`, `_tx_thread_sleep` only.
`harness/build.sh` rebuilds both pins; outputs `harness/netx_vuln` /
`harness/netx_fixed`.

## Observed outputs (byte-stable; no PID/address in the quoted lines)

- `harness/out-vuln-der.txt`: `parse_status=0 modulus_bytes=1024`;
  ASan `global-buffer-overflow`, `WRITE of size 1`, 0 bytes after global
  `decrypted_signature` (512 bytes) at
  `nx_secure_x509_certificate_verify.c:28`; stack
  `_nx_crypto_huge_number_extract` (`nx_crypto_huge_number.c:1783`) →
  `_nx_crypto_rsa_operation` (`nx_crypto_rsa.c:147`) →
  `_nx_crypto_method_rsa_operation` (`nx_crypto_rsa.c:393`) →
  `_nx_secure_x509_certificate_verify` (`nx_secure_x509_certificate_verify.c:230`).
- `harness/out-fixed-der.txt`: `parse_status=418 modulus_bytes=0`,
  `verify_status=131079`, no ASan report.
- `harness/out-vuln-manual.txt` / `out-fixed-manual.txt`: synthetic 0x9c
  modulus control, `verify_status=397` / `131074`, no write — negative
  control, not evidence of the defect.
