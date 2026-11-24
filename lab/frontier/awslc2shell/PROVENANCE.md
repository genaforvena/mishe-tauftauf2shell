# PROVENANCE — awslc2shell lab (CVE-2026-134056)

All artifacts under `lab/frontier/awslc2shell/`. Provisioning only: upstream
source and advisory pages were fetched read-only; no external probes.

## Pins

- Vulnerable release: AWS-LC v5.6.0 tarball from
  `https://github.com/aws/aws-lc/archive/refs/tags/v5.6.0.tar.gz`,
  sha256 `2348c404dcb1166c09034aceb840bef21af440ae469cbc994f11ab57dd043d26`.
  `src/crypto/fipsmodule/cipher/cipher.c` sha256
  `72797ecccdd9fc8572962f00a7aba609a183eb1cf3dfd5e7b9a199d51f6250cb`.
- Fix: upstream commit `ed3d805d35b3cde60b5a407ea761e5c28b98fcd2`
  ("Fix EVP_DecryptUpdate output handling (#3460)"), patch saved as
  `fix-cipher.patch`, sha256
  `bf6afd852a6da2a88f920fd9efdee718302213f27b69d5b2f6a5a8ba485893a9`.
  Applied to a byte-for-byte copy (`src-fixed/`); patched cipher.c sha256
  `b40e79909b53a7e0eb6533e73ac328d099699fa4ea26fc18a859c6000b2754e7`.
- Advisory: CVE-2026-134056, Amazon CNA, published 2026-11-23;
  `GHSA-h63c-583w-4qfw`. AWS-LC < 5.7.0, plus FIPS branches; fixed in 5.7.0.

## Builds

All builds: `-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=OFF -DDISABLE_GO=ON
-DDISABLE_PERL=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS='-fsanitize=address
-fno-omit-frame-pointer -g -O0'`, target `crypto`.

- `build-asan/` — vulnerable v5.6.0, default assembly AES.
- `build-asan-c/` — vulnerable v5.6.0 with `-DOPENSSL_NO_ASM`, so the AES
  batch store is ASan-instrumented and the actual OOB write is reported.
- `build-fixed/` — v5.6.0 plus the upstream fix patch.

Harnesses: `harness.c` compiled against each as `harness-vuln`, `harness-c`,
`harness-fixed`. Ciphertext is generated with the same fixed key/IV; plaintext
is 32 bytes with byte 31 set to `0x48` ('H'), padded by AES-128-CBC to 48 bytes.
Decryption uses three 16-byte `EVP_DecryptUpdate` calls with a heap buffer sized
to the pre-fix documented minimum `in_len + block_len - 1 = 31`.

## Observed bytes (2026-11-24T09:55Z)

- `harness-c asan`: ASan `heap-buffer-overflow`, `WRITE of size 16` at
  `aes_nohw.c:377` via `aes_nohw_cbc_encrypt` ->
  `EVP_EncryptUpdate (cipher.c:259)` -> `EVP_DecryptUpdate (cipher.c:411)`;
  address is 0 bytes after the 31-byte region allocated in `harness.c:56`.
  One byte of that batch store (offset 31) lies outside the caller's buffer.
- `harness-vuln asan`: ASan reports `READ of size 16` at `cipher.c:420`,
  0 bytes after the same 31-byte region. The assembly AES store itself is not
  instrumented; the subsequent `OPENSSL_memcpy(ctx->final, &out[*out_len], b)`
  reads the already-written OOB byte.
- Chosen byte: `harness-vuln byte2` allocates 32 bytes (one extra), stops after
  two updates and reports `byte31=0x48 chosen=0x48 CHOSEN_BYTE_PRESENT`; the
  canary `0xab` at offset 31 was overwritten by the file-derived plaintext byte.
  `harness-fixed byte2` reports `byte31=0xab ... CHOSEN_BYTE_ABSENT`.
- Controls: fixed library with the same 31-byte buffer exits 0 with no ASan
  report; vulnerable single-call decryption (63-byte documented minimum) and
  padding-disabled two-call decryption produce no ASan report.
- `sh run-all.sh` -> 14 PASS / 0 FAIL, rc 0, log `replay.log`.

## Known limits / negatives

- The release tarball is the pinned vulnerable source; no claim about other
  AWS-LC branches or the Rust wrapper was tested.
- The one-byte write is exercised in a minimal harness, not a network-facing
  application; no pointer, instruction pointer or command control; no wire
  replay; no rung 5.
- ASan's default assembly build reports the OOB read, not the write; the
  no-asm build is the write-detection control, not a different bug.
