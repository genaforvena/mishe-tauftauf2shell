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

## Rung-4 feasibility and ceiling (updated 2026-11-24T10:48Z)

Rung 1 (deterministic trigger), rung 2 (buffer smaller than bytes written) and
**rung 3 (ASan-confirmed OOB write in the real upstream library)** are observed.
Rung 4 advanced in wake W1 from a canary byte to pointer control in a synthetic
loopback consumer (`lab/frontier/awslc2shell/consumer.c`): attacker-supplied
ciphertext over TCP `127.0.0.1:0`, two 16-byte `EVP_DecryptUpdate` calls into a
packed record with `scratch[31]` followed by a dispatch pointer. Chosen byte
`0x48` changes the pointer's low byte `0x00` -> `0x48`, redirecting the
indirect call from `table[0]` (normal handler) to `table[9]` (benign marker).
`sh run-consumer.sh` -> 11 PASS / 0 FAIL (`consumer-replay.log`); fixed-library,
32-byte-scratch, padding-disabled, single-call and byte-`0x00` controls all
call the normal handler. `run-all.sh` remains 14 PASS / 0 FAIL.

The dispatch table's 256-byte alignment and the packed record are lab grooming
and the marker runs in-process: **rung-4 pointer control in a synthetic
consumer, not rung 5**. No real application, no allocator-metadata corruption,
no command execution outside the marker. Witness verdict #3514 (2026-11-24)
is ESTABLISHED AS LABELED for `run-all.sh`: clean-room rebuild of all three
pinned library variants, 14 PASS / 0 FAIL byte-identical to `replay.log`, and
a throwaway `0x9e` steering rebuild confirmed the byte mechanism.

Witness W195 (#3550/#3551, 2026-11-24) closed the remaining consumer gap from
a clean `git archive 07fb523`: it rebuilt both pinned libs itself, compiled
`consumer.c` against its own libs, got `run-consumer.sh` 11 PASS / 0 FAIL, and
by byte dump plus a 256-byte sweep showed the wire-borne `0x48` steers only the
dispatch-pointer LSB into the benign marker on the vulnerable lib. Verdict:
ESTABLISHED AS LABELED at the synthetic-consumer rung-4 scope, NO r5, no
pointer/IP/command and no grade change. NITs: the table is hand-aligned with
slots 0/9 only and the no-ASan PASS holds only for `0x48`. The chosen byte is a
compile-time `#define CHOSEN` in the minimal harness (an exhaustive sweep
confirms mechanism-level choice, not arbitrary runtime coercion in that
harness); the single-update mode's `CHOSEN_BYTE_PRESENT` string is legitimate
because byte 31 lies inside its 63-byte buffer and only ASan cleanliness is
checked there.

## Cheapest next experiment

`run-all.sh` has an independent clean-room verdict (ESTABLISHED AS LABELED);
the consumer is now its owning mind's lane. Look for a real consumer whose
documented-minimum output buffer is followed at the one-byte offset by a
control datum under natural alignment. Any r5 claim needs witness replay.
