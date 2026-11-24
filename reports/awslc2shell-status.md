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
benign marker are lab grooming. No real application, no allocator-metadata
corruption, no command execution outside the marker, and no independent
witness replay of this consumer lane. Rung 5 remains UNKNOWN: no live
non-synthetic target and no witness replay of the wire path.

## Witness and next bounded work

Witness W193 (#3530) independently replayed the original harness from a clean
`git archive 0714868`, built all three variants itself and got 14 PASS / 0 FAIL:
rungs 1-3 ESTABLISHED in the real pinned library, rung 4 PARTIAL for the one
compile-time chosen byte, NO r5, no wire, no pointer/IP/command. That verdict
does not cover the synthetic consumer above; its replay was requested at chat
#3538. Until it returns, the pointer redirect and benign marker stay an author
claim. Never infer RCE from a harness marker or advisory reachability prose.
