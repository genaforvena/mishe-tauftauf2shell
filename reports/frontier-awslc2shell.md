# frontier brief — awslc2shell (CVE-2026-134056)

Status 2026-11-24 09:55Z: **local rung 3 confirmed, rung 4 partial**, in a
minimal harness against pinned real AWS-LC v5.6.0 source. Artifacts in
`lab/frontier/awslc2shell/`; replay `sh lab/frontier/awslc2shell/run-all.sh`.
No window, no handoff yet.

## Verified ground truth

- Claim: CVE-2026-134056, Amazon CNA, published 2026-11-23,
  [GHSA-h63c-583w-4qfw](https://github.com/aws/aws-lc/security/advisories/GHSA-h63c-583w-4qfw),
  CWE-787, CVSS 6.5
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H` (CVSS 8.3 v4).
  AWS-LC < 5.7.0; fixed in 5.7.0 (and FIPS branches, not tested here).
- Advisory conditions: CBC or ECB with PKCS#7 padding (default), two or more
  `EVP_DecryptUpdate` calls into a buffer sized to the documented minimum
  `in_len + block_len - 1`; one byte past the buffer can be written.
  Single-call decryption, padding disabled, CTR/CFB/GCM are not affected.
- Pinned bytes: v5.6.0 tarball sha256
  `2348c404…dd043d26`, `crypto/fipsmodule/cipher/cipher.c` sha256
  `72797ecc…51f6250cb`. Upstream fix commit
  `ed3d805d35b3cde60b5a407ea761e5c28b98fcd2` (PR #3460), patch sha256
  `bf6afd85…485893a9`; patched cipher.c sha256 `b40e7990…6000b2754e7`.
  Full hashes, build flags and logs in `lab/frontier/awslc2shell/PROVENANCE.md`.

## Source-bound mechanism

Pinned `EVP_DecryptUpdate` (`cipher.c:364-430`) decrypts the whole input into
`out` via `EVP_EncryptUpdate`, then, when the input ends on a block boundary,
subtracts one block from `*out_len`, leaving that decrypted block in the caller's
buffer past the reported output, and copies it into `ctx->final`. On the next
update, `ctx->final` is copied to `out` *before* `out` is advanced by one block:
the batch store then spans one byte beyond the documented-minimum buffer.
The fix withholds the last ciphertext block before the bulk decryption and
writes it into `ctx->final` instead, so bytes past `*out_len` are untouched.

## Observed evidence

Harness encrypts a 32-byte plaintext whose final byte is `0x48` ('H') into
48 bytes of AES-128-CBC ciphertext, then decrypts in three 16-byte updates with
a 31-byte heap buffer. `sh run-all.sh` -> 14 PASS / 0 FAIL (log `replay.log`).

- ASan vulnerable build with `OPENSSL_NO_ASM`: `heap-buffer-overflow`,
  `WRITE of size 16` at `aes_nohw.c:377` via `EVP_DecryptUpdate` at
  `cipher.c:411`, 0 bytes after the 31-byte region allocated in `harness.c`.
  Only the final byte of that batch store is outside the buffer (advisory's
  one-byte OOB).
- Default assembly build: ASan reports the subsequent `READ of size 16` at
  `cipher.c:420` (the `OPENSSL_memcpy` of the withheld block), 0 bytes after
  the same region; assembly stores are not ASan-instrumented.
- Chosen byte: stopping after two updates with one extra allocated byte, the
  canary `0xab` at offset 31 is replaced by `0x48`, the chosen plaintext byte;
  the fixed library leaves `0xab`. Fixed library with the exact 31-byte buffer
  exits 0 with no ASan report. Vulnerable single-call and padding-disabled
  controls are also clean.
- Negative: the full three-update run overwrites offset 31 with the padding
  byte `0x10` on the final update, so chosen-byte capture requires stopping
  after the boundary-crossing call.

## Rung-4 feasibility and ceiling

Rung 1 (deterministic trigger), rung 2 (buffer smaller than bytes written) and
**rung 3 (ASan-confirmed OOB write in the real upstream library)** are observed.
Rung 4 is **partial**: one attacker-chosen byte at a chosen offset in a minimal
harness; no pointer, IP or command control, no adjacent-object corruption,
no real application build, no network/wire input, no rung 5. No upstream issue
or public PoC was located; the claim source is the vendor advisory and patch.

## Cheapest next experiment

Compile a small network-facing consumer that decrypts attacker-supplied CBC
ciphertext in multiple updates into a documented-minimum heap buffer (e.g. an
embedded TLS/recordparser test), then use a guard-page allocator or heap groom
to place a pointer-adjacent object after the buffer and test whether the single
chosen byte can alter a control datum. Independently replay with the fixed
library and with a 32-byte buffer. Any r5 claim needs a witness replay.
