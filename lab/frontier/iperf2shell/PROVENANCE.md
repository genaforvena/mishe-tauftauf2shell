# Provenance — iperf2shell pinned bytes

All bytes are read-only provisioning fetched from `https://raw.githubusercontent.com/esnet/iperf/<tag>/src/`.
No external probe was run; the only execution is the local loopback-free
compiled harness in this directory.

## Pinned upstream source (sha256)

| File | Source | sha256 |
|------|--------|--------|
| `src/iperf_auth.c.3.20` | raw tag `3.20` | `8fd69637d947993c7d53b985900211b9e10c2e8abda7585f09ac13ec072c857f` |
| `src/iperf_auth.c.3.21` | raw tag `3.21` | `2e92982324e1bb7110de4f6b9be2253ffeac33031c1f914ad4fe9d5d013a98ce` |
| `src/iperf_auth.c.3.22` | raw tag `3.22` | `4d0112f6c0bbbdbd2f7ccc1d2ec8641569eb6c0c7fb092bab597dffdaf4916c1` |
| `src/iperf_auth.h` | raw tag `3.21` | `24c5aec662ff305fa28409f480d36b7eb74b8f76b3d6b51a349c8c861cefc2d6` |
| `src/iperf_auth.h.3.22` | raw tag `3.22` | `24c5aec662ff305fa28409f480d36b7eb74b8f76b3d6b51a349c8c861cefc2d6` |
| `src/iperf_api.c.3.21` | raw tag `3.21` | `1158429980b3b6ff9146ed11ddb682417b631fe1836a8dad57ffc753a4072e45` (trigger path lines 2318/2654) |
| `src/iperf_server_api.c.3.21` | raw tag `3.21` | `688b75f12d835cc1d9cb0acd6241f4db702bf8b95b8406b5fa5832e9ea754f73` |
| `src/iperf_client_api.c.3.21` | raw tag `3.21` | `505a612909484ce5e0e02a684a27799d50b60f1303c7a87aa5f0de28b6733792` |
| `src/iperf.h.3.21` | raw tag `3.21` | `64c8fcf4c5d275479743689056f0b3661e0717e47c26eef615fd9dfe2b2e6f2f` |

`run.sh` verifies the 3.21/3.22/header hashes on every replay (`PINNED_SOURCE_HASHES`).

## Claim sources (read-only)

- CVE-2026-101283, authoritative JSON: `https://cveawg.mitre.org/api/cve/CVE-2026-101283`.
  CNA Anthropic, published 2026-09-30, CVSS 4.0 9.2
  `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`. Affected versions explicitly
  listed as 3.20 and 3.21 (`defaultStatus unaffected`). Fixed in 3.22.
- GitHub advisory GHSA-pwcx-5qh6-2pxc: `https://api.github.com/advisories/GHSA-pwcx-5qh6-2pxc`.
  Unreviewed; severity critical; CWE-122.
- esnet/iperf 3.22 release (2026-09-29): `https://github.com/esnet/iperf/releases/tag/3.22`.
  Tag commit `926bd905501b792bd082d2200d1d1a84aa543e3a`. Security notes credit
  Claude and Ada Logics and name CVE-2026-101283.

## Fix commit (source-bound, exact patch)

`d08588aceee48fa45832cae5e32616abb33cb0fc` — "Fix for possible heap buffer
overflow in iperf_auth.c." (2026-07-10), one file `src/iperf_auth.c`:

```diff
-        fprintf(stderr, "Encrypted text of size %d truncated to %d; likely invalid input.\n", encryptedtext_len, output_buffer_len);
+        fprintf(stderr, "Encrypted text of size %d exceeds RSA modulus %d; rejecting.\n", encryptedtext_len, output_buffer_len);
+        goto errreturn;   /* or: return 0; — never read more than output_buffer_len bytes */
```

This commit is included in tag 3.22 (verified: the 3.22 file carries the new
`goto errreturn`). Source URL:
`https://api.github.com/repos/esnet/iperf/commits/d08588aceee48fa45832cae5e32616abb33cb0fc`.

## Discrepancy preserved, not resolved

The 3.22 release notes label CVE-2026-101283 a "remote use-after-free in
iperf_server_api.c (ANT-2026-E5BA80X9)", while the CVE record and GHSA describe
a heap buffer overflow in `decrypt_rsa_message()` and the exact fix commit
above changes that function's length guard. The release notes separately name
CVE-2026-101276 (ANT-2026-FXH14FHV) as a heap overflow in `iperf_auth.c`.
The harness follows the CVE record + patch (the patch is the stronger evidence);
the release-note label is recorded here as a conflicting claim, not corrected.

## Trigger path pinned (tag 3.21 raw bytes)

- `iperf_api.c:2654-2655` — server copies the client JSON `"authtoken"` string
  into `test->settings->authtoken`, before any credential check.
- `iperf_api.c:2318-2321` — server calls `decode_auth_setting(...)` when a
  private key is configured.
- `iperf_auth.c:392-400` — `Base64Decode` yields attacker-controlled
  `encrypted_len_b64`, passed to `decrypt_rsa_message`.
- `iperf_auth.c:316-324` — guard only warns; `rsa_buffer` is
  `OPENSSL_malloc(output_buffer_len)` (256 for RSA-2048); `BIO_read` writes
  `encryptedtext_len` bytes into it.

Precondition: the server must be started with an RSA private key (auth enabled).
The overflow itself is pre-auth — the oversized token *is* the attack input.
