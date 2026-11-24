# awslc2shell — status

Admitted 2026-11-24 10:2xZ under standing #6 as the 131st route. Claim:
`CVE-2026-134056` (Amazon CNA, published 2026-11-23, CWE-787, CVSS 6.5
`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H`, CVSS4 8.3), advisory
`GHSA-h63c-583w-4qfw`: AWS-LC < 5.7.0 padded CBC/ECB decryption can write one
byte past a documented-minimum output buffer when decryption is split into
two or more `EVP_DecryptUpdate` calls. Fixed in 5.7.0; FIPS branches listed by
the vendor but not tested. The advisory's network-reachability prose and any
RCE claim remain claims in this lab.

## Admission evidence

- Frontier brief `reports/frontier-awslc2shell.md`; pins, build flags and
  observed bytes in `lab/frontier/awslc2shell/PROVENANCE.md`. Pinned v5.6.0
  tarball sha256 `2348c404dcb1166c09034aceb840bef21af440ae469cbc994f11ab57dd043d26`,
  vulnerable `cipher.c` sha256
  `72797ecccdd9fc8572962f00a7aba609a183eb1cf3dfd5e7b9a199d51f6250cb`;
  upstream fix `ed3d805d35b3cde60b5a407ea761e5c28b98fcd2` (PR #3460),
  patch sha256 `bf6afd852a6da2a88f920fd9efdee718302213f27b69d5b2f6a5a8ba485893a9`,
  patched `cipher.c` sha256
  `b40e79909b53a7e0eb6533e73ac328d099699fa4ea26fc18a859c6000b2754e7`.
- Operator verification 10:2xZ: re-ran `sh lab/frontier/awslc2shell/run-all.sh`
  from the committed lab tree — `RESULT: 14 PASS / 0 FAIL`, rc 0, matching
  `replay.log`; tarball hash recomputed `2348c404dcb1166c…`. This is an
  author-side transcript on this host, not an independent witness verdict.
  Frontier's two-pane window 136 was created 09:57:17Z and adopted without
  duplication (registry 137/137 unique names), seed wall present.
- Minted under the exact full-flag sync from `docs/runtime-pin.md` with pin
  `0d686bbad55c849e88334da64efff9da88ad528a`: `written 3, removed 0`;
  `m2shell-wake-awslc2shell.path` enabled and active after daemon-reload;
  pinned full-flag doctor `GREEN`, exit 0. Route count 130→131 (hy4-flash,
  `max_parallel: 3`); resolver 261→263 (both wake keys → operator);
  wake-failure signal registered with 7-day max age and 1-hour reoffer.

## Current grade

1. Deterministic trigger: 32-byte plaintext (last byte `0x48`) encrypted to
   48 bytes of AES-128-CBC ciphertext, decrypted in three 16-byte updates
   into a 31-byte buffer (`in_len + block_len - 1`).
   The same one-byte overrun was reproduced with an 8-byte block cipher
   (3DES-EDE-CBC, `b = 8`) in W211 below; it is not AES-specific.
2. Confirmed corruption: in the no-ASM ASan build, `heap-buffer-overflow`
   `WRITE of size 16` at `aes_nohw.c:377` via `EVP_DecryptUpdate
   (cipher.c:411)`, 0 bytes after the 31-byte region allocated in
   `harness.c`. Only the final byte of the batch store is outside the
   buffer. The default ASM build reports the subsequent `READ of size 16` at
   `cipher.c:420` because assembly stores are not ASan-instrumented.
3. Controls: fixed library with the exact minimum buffer is ASan-clean;
   vulnerable single-call and padding-disabled runs are clean; both pinned
   source hashes match.

Rung 4 is now demonstrated in a synthetic loopback consumer, not merely a
canary harness (`lab/frontier/awslc2shell/consumer.c`, `run-consumer.sh`,
`consumer-replay.log`: 11 PASS / 0 FAIL at 2026-11-24T10:48Z). A forked client
sends 48 bytes of AES-128-CBC ciphertext over TCP to `127.0.0.1:0`; the server
decrypts two 16-byte updates into a packed record whose `scratch[31]` is
immediately followed by a dispatch pointer. The chosen plaintext byte `0x48`
overwrites the pointer's low byte from `0x00` to `0x48`, redirecting the
subsequent indirect call from `table[0]` (normal handler) to `table[9]`
(benign marker). `BENIGN_MARKER_EXECUTED` is observed only in the vulnerable
build. Fixed-library, 32-byte-scratch, padding-disabled, single-call and
chosen-byte-`0x00` controls all leave the normal handler intact; the original
`run-all.sh` replay remains 14 PASS / 0 FAIL.

Limits: synthetic consumer, 256-byte-aligned dispatch table and in-process
benign marker are lab grooming. Pointer control is the low byte of a
hand-aligned 256-slot table with only slots 0 and 9 populated: other chosen
bytes jump to NULL or out of table (ASan SEGV / global-buffer-overflow on the
indirect call, not on the overflow write). No real application,
allocator-metadata corruption or command outside the marker. Rung 5 remains
UNKNOWN: no live non-synthetic target, no allocator/IP control, no
wire-to-command path.

## Witness verdicts and next bounded work

Witness W193 (#3530) independently replayed the original harness from a clean
`git archive 0714868`, built all three variants itself and got 14 PASS / 0 FAIL:
rungs 1-3 ESTABLISHED in the real pinned library, rung 4 PARTIAL for the one
compile-time chosen byte, NO r5, no wire, no pointer/IP/command.

Witness W195 (#3550/#3551, clean `git archive 07fb523`, 2026-11-24) replayed
the synthetic-consumer lane: it rebuilt BOTH pinned AWS-LC libraries from
clean source with the documented flags, compiled `consumer.c` against its own
libs, and got `run-consumer.sh` 11 PASS / 0 FAIL exactly. Its byte dump shows
vulnerable byte 31 = `0x48` and pointer bytes `48 9e 3a 12 04 58 00 00` —
only the LSB changed from `0x00`; fixed/safe/nopad controls leave the pointer
intact. An exhaustive 256-byte sweep fires `BENIGN_MARKER_EXECUTED` for exactly
one value (`0x48`) on the vulnerable library and zero on the fixed library;
the redirect follows the wire-borne byte, not a checker constant. Verdict:
**ESTABLISHED AS LABELED** — rung-4 pointer-LSB control in a synthetic
loopback consumer, NO r5, no contradiction to this row's grade. Scope NITs:
the aligned table with slots 0/9 only, and the no-ASan PASS being specific to
`0x48`. This supersedes the earlier "no independent witness replay of this
consumer lane" wording above and the README row's "unwitnessed" wording.
Never infer RCE from a harness marker or advisory reachability prose.

## Natural-alignment extension (W204, 2026-11-24T11:23Z)

Measured the source-bound layout inference in `consumer.c` without the aligned
dispatch table or `#pragma pack`: `natural_tag` puts scratch at struct offset 1
and the handler at offset 32, so the OOB byte is the pointer LSB; the vulnerable
build changes that LSB to the chosen `0x48`, the fixed build leaves it at its
initialized value. `natural_pad` puts scratch at offset 0 and compiler padding
at 31; the vulnerable build writes `0x48` into padding and leaves the handler
intact, the fixed build leaves `0xab`. `run-consumer.sh` -> 23 PASS / 0 FAIL,
`run-all.sh` -> 14 PASS / 0 FAIL. Packing is therefore not a prerequisite for
the *layout*, but the redirect still needs a groomed jump target and this
extension has no independent witness replay. Grade unchanged at rungs 1-4,
r5 UNKNOWN.

## Natural-alignment dispatch (W205, 2026-11-24T12:11Z)

`consumer.c` now has `natural_call`: a normally aligned struct with a one-byte
tag, `scratch[31]` at offset 1 and a table-slot pointer at offset 32 (no
`#pragma pack`). The vulnerable library writes the chosen `0x48` onto the
pointer LSB and the subsequent indirect call executes the benign marker;
the fixed library and the safe-input (`00`) control both call the normal
handler. `run-consumer.sh` -> 31 PASS / 0 FAIL, `run-all.sh` -> 14 PASS /
0 FAIL. This removes packing as a prerequisite for the pointer redirect, but
the aligned dispatch table remains lab grooming and the grade is unchanged:
rungs 1-4, r5 UNKNOWN, no independent witness replay of W204/W205 yet.

Throwaway stack-layout probes on GCC 13.3.0 (`-fstack-protector-strong
-fno-omit-frame-pointer -O0`) found a 9-byte gap between OOB index 31 of a
31-byte local array and the compiler canary; varying array sizes and alignment
attributes did not close it. No natural stack-canary corruption was observed.

## Plain-process allocator bound (W206, 2026-11-24T14:25Z)

`metadata.c` and `build-plain.sh` add non-ASan builds of both pinned libraries:
ASan redzones poison the slack bytes a plain glibc process actually has after
a 31-byte request. The probe drives two boundary-crossing updates into
`malloc(31)` with a separate `malloc(16)` object after it and reports both the
written byte and the next chunk's header. On glibc `2.39-0ubuntu8.12`,
`malloc_usable_size(31)=40`: vulnerable byte31 `0xab` -> `0x48`; fixed stays
`0xab`. In both, the next chunk size word at `buf+40` and the neighbor at
`buf+48` are unchanged; the OOB byte is 9 bytes short of metadata and 17 bytes
short of the next object. `sh run-metadata.sh` -> 10 PASS / 0 FAIL
(`metadata-replay.log`); `run-all.sh` 14 PASS / 0 FAIL, `run-consumer.sh` 31
PASS / 0 FAIL. This is a bounded negative for glibc heap-metadata corruption
with a lone documented-minimum buffer; it says nothing about other allocators.
Grade unchanged: rungs 1-4, r5 UNKNOWN; W206 has no independent witness replay.

## Natural stack layout bound (W207, 2026-11-24T15:42Z)

`stack-layout.c` replaces the earlier throwaway stack probes with a
reproducible one: ordinary locals around a 31-byte array, no struct packing,
no alignment attribute. `run-stack-layout.sh` compiles it against both plain
libraries with GCC and Clang at `-O0..-O3 -fno-omit-frame-pointer
-fno-stack-protector`, with the one-past index seeded to `0xab`. The byte
becomes `0x48` in all eight vulnerable configurations and stays `0xab` in all
eight fixed configurations. In none of the sixteen does a natural control
datum sit at `out+31`: the adjacent pointer deltas are 1, 9 or negative, the
tail-array delta is negative, and the saved frame is 81..145 bytes above the
one-past address. `sh run-stack-layout.sh` -> 16 PASS / 0 FAIL
(`stack-layout-replay.log`); `run-all.sh` 14 PASS / 0 FAIL, `run-consumer.sh`
31 PASS / 0 FAIL, `run-metadata.sh` 10 PASS / 0 FAIL. This closes the natural
stack-layout lane for these compilers and flags: pointer LSB control still
requires the explicitly tagged struct record used in W204/W205. Grade
unchanged: rungs 1-4, r5 UNKNOWN; author-only, no witness replay.

## Natural global-struct control datum (W208, 2026-11-24T17:11Z)

`global-datum.c`, `build-global-datum.sh` and `run-global-datum.sh` cover the
one storage class the W204-W207 lanes missed: a static-duration record with
ordinary C alignment, `struct { uint8_t buf[31]; uint8_t state;
void (*handler)(void); }`. The compiler places `state` at struct offset 31
and the 8-aligned handler at 32 with no `#pragma pack`, no tag byte and no
dispatch table, so the CVE's one byte at `buf[31]` lands directly on `state`.
The probe is linked against the W206 plain (non-ASan) pinned libraries; the
library performs the write.

Four modes: vulnerable `0x48` drives `state` `0xa5 -> 0x48`; fixed `0x48`
leaves `0xa5`; safe-input `0x00` on a zeroed state leaves `0x00`; a second
attacker value `0x01` drives `0xa5 -> 0x01`. All four keep the handler LSB at
`0x29`, confirming the byte hits offset 31, not the pointer at 32.
`sh run-global-datum.sh` -> 15 PASS / 0 FAIL (`global-datum-replay.log`);
existing suites remain 14 / 31 / 10 / 16 PASS, 0 FAIL. Re-verified the
documented minimum from pinned `cipher.h:155-158` (`in_len + block_len - 1`).
This upgrades the rung-4 control-datum demonstration to a natural, ungroomed
layout, but it is still a lab record with no real application, no pointer/IP,
no command and no wire-to-command path. Grade unchanged: rungs 1-4, r5
UNKNOWN; author-only, no witness replay of W208.

## In-tree documented-minimum consumer (W209, 2026-11-24T17:5xZ)

The "no real consumer" gap narrowed: AWS-LC's own PKCS#7 cipher BIO is an
in-tree, streaming, multi-update caller that deliberately uses the documented
minimum. Pinned `crypto/pkcs7/bio/cipher.c:93-101` (`enc_read`) sizes each read
with `to_read = sizeof(ctx->buf) - cipher_block_size + 1` — 4096 - 16 + 1 =
4081 for AES-CBC — and calls `EVP_DecryptUpdate(ctx->cipher, ctx->buf,
&ctx->buf_len, read_buf, bytes_read)`. Its own comment at lines 93-94 names
exactly the flaw's precondition: "`EVP_DecryptUpdate` may write up to
cipher_block_size-1 more bytes than requested." `BIO_ENC_CTX.buf` is a 4096-byte
array (line 19) allocated as the last field of a single `OPENSSL_zalloc` at
line 26.

This caller is immune by its own chunk arithmetic. In the vulnerable
`EVP_DecryptUpdate` (`cipher.c:405-427`), a previously withheld block adds `b`
bytes before the bulk `EVP_EncryptUpdate` store; for CBC decryption with
padding that bulk output is `bytes_read` rounded down to a multiple of `b`.
With `bytes_read <= 4081` and `b = 16`, the rounded value is at most 4080 =
`sizeof(buf) - b`, so the largest possible store is `16 + 4080 = 4096` bytes —
exactly `sizeof(ctx->buf)`, one byte short of an OOB. A throwaway memory-BIO
probe against the pinned no-ASM ASan library (16-byte boundary first update,
then 4081/4080/16/32-byte second update) reported no ASan error, but is only a
partial exercise: `enc_read` reached EOF on the memory source and called
`EVP_DecryptFinal_ex` after the first update, consuming the withheld block
before a second update. The load-bearing argument is the source-bound bound
above, not the probe. Even if the byte were written, it would land at struct
offset 4120 (one past the 4120-byte `BIO_ENC_CTX`), inside allocator slack on
this host — no control datum follows `buf` because it is the struct's last
field.

A direct throwaway against the pinned vulnerable no-ASM library, calling
`EVP_DecryptUpdate` with the BIO's exact two sizes into an oversized buffer,
reports `n1=0` for the 16-byte boundary update and `n2=4096` for the 4081-byte
second update (fixed library: also 4096), confirming the 4096-byte bound
numerically rather than only from source.

W210 (2026-11-24T18:10Z, source-bound) generalizes that bound beyond AES-CBC.
Let `B = sizeof(ctx->buf)` and `b` be the block size. `enc_read` supplies
`t = B - b + 1`; on a boundary-crossing update the vulnerable path writes a
`b`-byte carry and then `floor(t/b)*b` bulk bytes. With `B = kb + r`,
`0 <= r < b`, that total is `B - r` when `r < b - 1` and `B + 1` only when
`r = b - 1`. Every padded AWS-LC block cipher has `b = 8` (DES, RC2) or
`b = 16` (AES), and `B = 4096` gives `r = 0` for both; stream ciphers have
`b = 1`, which skips the withholding path (`cipher.c:405` requires `b > 1`).
So this one in-tree caller cannot overflow for any supported cipher, and the
missing precondition would be a buffer size congruent to `b - 1` modulo `b`.
No new lab artifact; grade unchanged.

Grade unchanged: rungs 1-4, r5 UNKNOWN. Source-bound, author-only; no witness
replay and no new lab artifact is claimed for this observation.

## 8-byte block confirmation (W211, 2026-11-24T18:14Z)

All earlier suites used AES with `b = 16`. `des-oob.c` and `run-des.sh` add a
3DES-EDE-CBC case with `b = 8`: a 16-byte plaintext (last byte `0x48`) is
encrypted to 24 bytes, then the first two 8-byte ciphertext blocks are
decrypted in two `EVP_DecryptUpdate` calls into `malloc(15)` — the documented
minimum `in_len + b - 1` for one update. Vulnerable no-ASM ASan reports
`heap-buffer-overflow`, `WRITE of size 1`, 0 bytes after the 15-byte region,
frame `DES_ede3_cbc_encrypt_ex (src/crypto/des/des.c:840)` ->
`des_ede3_cbc_cipher (e_des.c:93)` -> `EVP_EncryptUpdate (cipher.c:259)` ->
`EVP_DecryptUpdate (cipher.c:411)`. Controls: vulnerable with a 32-byte buffer
is clean (`n1=0 n2=8`, chosen byte `0x48` lands inside the buffer); fixed
library is clean at both 15 and 32 bytes (`0xab` tail). `sh run-des.sh` ->
11 PASS / 0 FAIL (`des-replay.log`); the other five suites still give
14 / 31 / 10 / 16 / 15 PASS, 0 FAIL. The overflow is therefore not AES- or
`b = 16`-specific; it remains exactly one byte per boundary-crossing update.
Author-only, no witness replay, no real consumer, grade unchanged: rungs 1-4,
r5 UNKNOWN.

## Second-order length corruption (W212, 2026-11-24T19:0xZ)

`frame-datum.c`, `build-frame-datum.sh` and `run-frame-datum.sh` test whether
the CVE's one byte can corrupt a datum a consumer actually *uses* for a memory
operation. Natural C layout, no `#pragma pack`, no tag, no table, no grooming:
`struct frame { uint8_t data[31]; uint8_t len; uint8_t body[128]; }` puts `len`
at offset 31, exactly where the CVE writes, and `body` at 32 with enough bytes
that a corrupted length cannot over-read the source. `data[31]` is the
documented-minimum output at the EVP boundary; a heap destination is sized for
the initial length (`1`, capacity `8`) and the consumer then copies `len`
bytes from `body` into it.

Harness-only ASan linked against the W206 plain (non-ASan) pinned libraries:
the library's original one-byte write stays inside the global struct, so ASan
reports only the second-order copy. Vulnerable byte-mode `0x48` changes
`len_before=1` -> `len_after=72` and the `memcpy` gives
`heap-buffer-overflow`, `WRITE of size 72`, rc 1. Fixed-library `0x48` leaves
`len=1` and is clean; safe `0x00` leaves `len=0` and is clean; a second value
`0x02` drives `len=2` and stays clean. A `wire` mode reads the 48-byte
ciphertext from stdin (`gen` emits it from a runtime byte), so the steering
value is attacker-supplied rather than a compile-time macro: wire `48` on the
vulnerable library gives the same 72-byte ASan write, wire `48` on the fixed
library and wire `02`/`00` on the vulnerable library are clean. Offsets
`data=0 len=31 body=32 size=160` and `decrypt_ok=1` in all eight runs.
`sh run-frame-datum.sh -> 27 PASS / 0 FAIL` (`frame-datum-replay.log`); the
output is normalized (PID/addresses stripped) and two consecutive runs are
byte-identical (sha256 `65d4723e…c67c1ec77ac`).

This is a causal amplification of the one-byte write into a larger,
ASan-confirmed heap overflow through a control datum at a natural offset, but
the consumer is still synthetic and the destination is deliberately sized for
the pre-decrypt length. No real application, no pointer/IP, no command, no
wire-to-command path. Grade unchanged: rungs 1-4, r5 UNKNOWN; author-only, no
witness replay.

## In-tree caller census (W213, 2026-11-24T19:0xZ, source-bound)

A full read-only census of every `EVP_DecryptUpdate`/`EVP_CipherUpdate` call in
the pinned v5.6.0 tree (14 real sites, excluding tests/fuzz/generated vectors)
compares against `src-fixed`. No real caller in this tree meets the full OOB
precondition:

- `crypto/pem/pem_lib.c:356-363` (`PEM_do_header`): single in-place call on a
  fresh local ctx, so `final_used=0`.
- `crypto/pkcs8/pkcs8.c:349,355-356` (`pkcs8_pbe_decrypt`): exact
  `OPENSSL_malloc(in_len)`, single call, fresh ctx.
- `ssl/extensions.cc:3841-3847` (session-ticket decrypt): exact-size heap
  `Array`, one call with a freshly initialized ctx.
- `crypto/cipher_extra/e_tls.c:85,247-288`: `EVP_CIPH_NO_PADDING`, so the
  vulnerable withholding branch (`cipher.c:405`) is unreachable.
- `tool-openssl/enc.cc:168,169,183` (`bssl enc -d`): multi-call, but
  `outbuf[BUF_SIZE + EVP_MAX_BLOCK_LENGTH]` = 1056 bytes versus the 1039-byte
  documented minimum for a 1024-byte chunk — 17 bytes of slack, so the stray
  byte stays inside the buffer.
- `crypto/pkcs7/bio/cipher.c:100`: the only multi-call documented-minimum
  site; W209/W210 already show its chunk arithmetic tops out at exactly 4096
  bytes and `ctx->buf` is the last field of the heap `BIO_ENC_CTX`.
- `tool/speed.cc` and the ACVP wrapper over-allocate, use XTS/custom ciphers,
  or set padding disabled and reinitialize each iteration.

No adjacent in-object control datum is reachable from any real caller's
output buffer in this tree. This closes the in-tree consumer lane for the
pinned library; it says nothing about out-of-tree applications linked against
it. No new lab artifact, no witness replay, grade unchanged: rungs 1-4, r5
UNKNOWN.
