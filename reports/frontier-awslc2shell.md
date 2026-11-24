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

Natural-alignment extension (W204, 2026-11-24T11:23Z): two new `consumer.c`
modes remove `#pragma pack` and the aligned table. Under compiler-chosen
layout, a one-byte tag before `scratch[31]` places the OOB byte exactly on the
8-aligned handler's LSB: the vulnerable build changes it to the chosen `0x48`,
the fixed build leaves it at its initialized value. Without the tag the byte
lands in padding and the pointer is intact. `run-consumer.sh` -> 23 PASS /
0 FAIL, `run-all.sh` -> 14 PASS / 0 FAIL. Grade unchanged: layout realism
improved, jump-target grooming still required, no witness replay of W204.

W205 (2026-11-24T12:11Z) added `natural_call`: the same compiler-chosen layout
as `natural_tag` but with a table-slot pointer at offset 32, so the OOB byte
redirects a real indirect call without `#pragma pack`. Vulnerable: pointer LSB
`0x00` -> `0x48`, `BENIGN_MARKER_EXECUTED`; fixed and safe-input (`00`):
`NORMAL_HANDLER`. `run-consumer.sh` -> 31 PASS / 0 FAIL, `run-all.sh` -> 14
PASS / 0 FAIL. The aligned dispatch table is still lab grooming. A throwaway
stack-layout probe on GCC 13.3.0 found a 9-byte gap between the OOB index and
the compiler canary, so no natural stack-canary impact was observed. Grade
unchanged: rungs 1-4, r5 UNKNOWN; W204/W205 have no independent replay.

W206 (2026-11-24T14:25Z) closed the heap-metadata lane with plain, non-ASan
builds of both pinned libraries: `metadata.c` drives two boundary-crossing
updates into `malloc(31)` followed by a separate `malloc(16)` object. On host
glibc 2.39 `malloc_usable_size(31)` is 40: the CVE byte lands at offset 31 of
that usable region, 9 bytes before the next chunk's size word (at `buf+40`) and
17 bytes before the next object. Vulnerable: byte31 `0xab` -> `0x48`, next
header and neighbor unchanged; fixed: byte31 stays `0xab`, same controls.
`sh build-plain.sh` then `sh run-metadata.sh` -> 10 PASS / 0 FAIL
(`metadata-replay.log`); grade unchanged, no allocator/IP control. ASan
poisons the 9 slack bytes, which is why a plain build is needed here.

W207 (2026-11-24T15:42Z) made the earlier stack-layout probe reproducible:
`stack-layout.c` uses ordinary locals around `uint8_t out[31]` with no packing
or alignment attribute, and `run-stack-layout.sh` builds it against both plain
libraries with GCC and Clang at `-O0..-O3`. The one-past byte is `0x48` in all
eight vulnerable runs and `0xab` in all eight fixed runs, but no natural
control datum sits at `out+31`: adjacent-pointer deltas are 1, 9 or negative,
the tail array is before the byte, and the saved frame is 81..145 bytes above
it. `sh run-stack-layout.sh` -> 16 PASS / 0 FAIL
(`stack-layout-replay.log`); the original suites remain 14 / 31 / 10 PASS with
0 FAIL. This closes natural stack layouts for these compilers; pointer-LSB
control still needs the tagged struct record. Grade unchanged, no witness
replay.

## Cheapest next experiment

`run-all.sh` and the original consumer lane have independent clean-room
verdicts (ESTABLISHED AS LABELED); W204, W205, W206 and W207 are author-measured
only. A witness replay of `0d3fc55` (chat #3562) still covers W204, W205 was
requested in #3594 and W206 in #3668. The remaining gap is a real consumer
whose documented-minimum output buffer is followed at that offset by a control
datum; W207 rules out the natural stack layout as that consumer on this host.
Any r5 claim needs witness replay.
