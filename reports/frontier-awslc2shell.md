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

W208 (2026-11-24T17:11Z) covered the remaining storage class with
`global-datum.c`: a static-duration, normally aligned
`struct { uint8_t buf[31]; uint8_t state; void (*handler)(void); }` puts
`state` at offset 31 and the handler at 32 with no packing, tag or table.
Linked against the W206 plain pinned libraries, vulnerable `0x48` changes
`state` `0xa5 -> 0x48`, fixed `0x48` leaves `0xa5`, safe `0x00` leaves zero,
and a second chosen value `0x01` changes `0xa5 -> 0x01`; handler LSB stays
`0x29` in all four. `sh run-global-datum.sh` -> 15 PASS / 0 FAIL
(`global-datum-replay.log`). Unlike W1 and W204/W205, the control datum is
hit without grooming the layout. Still no real app, pointer/IP, command or
wire-to-command path; grade unchanged, author-only, no witness replay.

## Cheapest next experiment

`run-all.sh` and the original consumer lane have independent clean-room
verdicts (ESTABLISHED AS LABELED); W204, W205, W206, W207 and W208 are
author-measured only. A witness replay of `0d3fc55` (chat #3562) still covers
W204, W205 was requested in #3594 and W206 in #3668. W208 is a positive
rung-4 control-datum result in a natural global struct; it is a new replay
recipe if the witness wants it, queued behind those three (chat #3728).

W209 (2026-11-24T17:5xZ) is source-bound only. AWS-LC's own streaming PKCS#7
cipher BIO (`crypto/pkcs7/bio/cipher.c:93-101`, `enc_read`) is a real in-tree
multi-update `EVP_DecryptUpdate` caller that deliberately sizes to the
documented minimum via `to_read = sizeof(buf) - block_size + 1` (4081 for
AES-CBC into a 4096-byte `buf`). Its chunk arithmetic makes it immune: the
vulnerable library's withheld-block-plus-bulk store is at most
`16 + 4080 = 4096` bytes, exactly `sizeof(buf)`, so the CVE's one-byte OOB
cannot cross that in-tree buffer; `buf` is also the last field of the
`OPENSSL_zalloc`'d `BIO_ENC_CTX`, so no control datum follows it. A
throwaway mem-BIO ASan probe gave no report but only partially exercised the
path (`EVP_DecryptFinal_ex` consumed the withheld block at source EOF); the
source-bound bound, not the probe, is the load-bearing result.

W210 generalizes W209: with `B = kb + r` and chunk `t = B - b + 1`, a
carry-plus-bulk update writes `B - r` bytes for `r < b - 1` and `B + 1` only
for `r = b - 1`. AWS-LC's block sizes are 8 (DES/RC2) and 16 (AES), both
divisors of `B = 4096`; `b = 1` skips withholding. No supported cipher makes
`BIO_f_cipher` overflow. W211 adds the first non-AES lab case
(`des-oob.c` / `run-des.sh`, commit `3826ca48`): 3DES-EDE-CBC with `b = 8`,
two 8-byte updates into `malloc(15)`, vulnerable ASan `WRITE of size 1` 0 bytes
after the 15-byte region via `des.c:840` -> `e_des.c:93` ->
`cipher.c:259` -> `cipher.c:411`; vulnerable-wide and both fixed controls
clean. `run-des.sh` -> 11 PASS / 0 FAIL, also from a clean `git archive HEAD`
with provisioned pinned source/libraries. The overflow is not AES-specific;
still one byte per boundary-crossing update, author-only, no grade change.

The remaining gap is a real application whose documented-minimum output
buffer is followed at that offset by an attacker-relevant control datum.
W209 shows an in-tree caller exists but is immune by its own sizing, W207
rules out the natural stack layout and W206 rules out glibc heap metadata
with a lone minimum buffer on this host. Any r5 claim needs witness replay.

W212 (2026-11-24T19:0xZ) demonstrates a second-order effect:
`frame-datum.c` uses a natural `struct { uint8_t data[31]; uint8_t len;
uint8_t body[128]; }`, so the CVE byte lands on `len` at offset 31 with no
packing, tag or table. The vulnerable library changes `len` `1 -> 72`, and the
consumer's subsequent `memcpy(dest, body, len)` into an 8-byte allocation gives
ASan `heap-buffer-overflow`, `WRITE of size 72`, rc 1. Fixed (`len` stays 1),
safe (`0`) and steer (`2`) are clean. A `wire` mode feeds the 48-byte
ciphertext from stdin (generator emits it from a runtime byte), so the steering
value is attacker-supplied: wire `48` on vulnerable/ fixed and wire `02`/`00`
on vulnerable give the same outcomes. ASan is in the harness only, linked to
the plain pinned libs, so the report is the second-order copy, not the original
one-byte write. `sh run-frame-datum.sh -> 27 PASS / 0 FAIL`
(`frame-datum-replay.log`, two runs byte-identical). Still a synthetic consumer
with a deliberately undersized destination; no real app, pointer/IP, command
or wire-to-command path; author-only, no witness replay, grade unchanged.

W213 (2026-11-24T19:0xZ, source-bound) is a census of all 14 real
`EVP_DecryptUpdate`/`EVP_CipherUpdate` callers in the pinned tree. No in-tree
caller meets the full precondition: PEM, PKCS#8 and TLS session-ticket decrypt
are single-call on a fresh ctx; TLS CBC AEAD and the ACVP wrapper set padding
disabled so the withholding branch is unreachable; `bssl enc -d`
(`tool-openssl/enc.cc:168`) is multi-call but has 17 bytes of slack beyond the
documented minimum; `tool/speed.cc` over-allocates or uses custom ciphers; and
the PKCS#7 cipher BIO is immune as shown by W209/W210. No adjacent in-object
control datum is reachable from any real caller's output buffer in this tree.
This closes the in-tree consumer lane for the pinned library; an out-of-tree
application remains the only real-consumer path and is still unknown. Grade
unchanged: rungs 1-4, r5 UNKNOWN.

W214 (2026-11-25T03:2xZ, source-bound) narrows the remaining real-consumer
gap: a read-only census of out-of-tree application sources already provisioned
in this plant found no caller with two or more padded decryption updates into
a documented-minimum buffer. The ten named projects and roughly fifty other
provisioned roots were searched; four representative hits were re-read:
apr-util `apr_crypto_openssl.c:887-902` allocates `inlen +
EVP_MAX_BLOCK_LENGTH` (17 bytes of slack) before one update; cjose
`jwe.c:1451-1468` allocates `raw_len + AES_BLOCK_SIZE` for a single CBC update
(the two-update path is GCM AAD with `out=NULL`); libwebsockets
`aescbc.c:239-249` disables padding and calls the cipher once; picotls
`openssl.c:1275-1277` disables padding on decrypt. No qualifying buffer means
no adjacent control datum. Unprovisioned third-party applications remain
UNKNOWN. No build, no ASan, no witness replay; grade unchanged: rungs 1-4,
r5 UNKNOWN.

W215 (2026-11-25T03:4xZ, source-bound) tests the highest-value unprovisioned
consumer, s2n-tls: pinned v1.5.16 tarball sha256 `ab3e19f8…909214`, extracted
under gitignored `lab/frontier/awslc2shell/out-of-tree/`. Every CBC/ECB-capable
decrypt site is in-place and called exactly once per EVP context. Directly
read: `crypto/s2n_cbc_cipher_aes.c:48-58` checks `out->size >= in->size`,
re-inits with `EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv)` and makes one
`EVP_DecryptUpdate`; `tls/s2n_record_read_cbc.c:55,70,77` decrypts an in-place,
block-aligned `en` blob. The 3DES and composite AES-SHA paths share that shape;
stream ciphers have `b=1` and AEAD uses `EVP_AEAD_CTX_open` or an `out=NULL`
AAD update. Pinned `cipher.c:190` clears `final_used` on every
`EVP_CipherInit_ex`, including s2n's per-record re-init, so the withheld-block
carry at `cipher.c:405` cannot cross records; no buffer is sized to
`in_len + b - 1`, hence no adjacent control datum. Near-miss: s2n's
`set_padding(0)` precedes a cipher-selecting init and `cipher.c:131` resets
`flags` to 0, but with one update there is no carry-plus-bulk span either way.
SOURCE-BOUND NEGATIVE; no build, ASan or witness replay; grade unchanged:
rungs 1-4, r5 UNKNOWN.
