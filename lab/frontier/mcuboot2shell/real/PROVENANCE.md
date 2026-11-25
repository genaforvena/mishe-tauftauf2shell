# mcuboot2shell — real-source build provenance (W1, 2026-11-25 09:03Z)

## Provisioning

- `git -C upstream fetch --depth=1 origin 6e1465c38e3d` and checkout:
  upstream fix commit. `git -C upstream fetch --depth=1 origin
  099379647ada83b31cc094e4c0c94a7d0e895639` and `git archive` into
  `upstream-parent/`: vulnerable parent commit. Both are local provisioning,
  not tests; no external target was contacted.
- The pinned whole files are byte-identical to the upstream commits:
  - `src/mcuboot-parent-boot_serial_encryption.c` sha256
    `a77260e48b26862b3a8690029184cd3172a365bfd585545898fb677b025ad160`
    = `upstream-parent/boot/boot_serial/src/boot_serial_encryption.c`.
  - `src/mcuboot-fixed-boot_serial_encryption.c` sha256
    `3825b917952fbbfbacabd93a49f40c1fd48f3c8372aceb56fdb3451002dd345b`
    = `upstream/boot/boot_serial/src/boot_serial_encryption.c`.
  - `upstream-parent/boot/bootutil/src/encrypted.c` sha256
    `6c60c354ddbce005851e9f07bf00e214b56cd6850eb654dc09eeafd7d7a6f1d5`.
- `git diff --stat parent fix` reports exactly one changed file:
  `boot/boot_serial/src/boot_serial_encryption.c` (+16/-10).

## What is real and what is local

Real translation units compiled unchanged:
`src/mcuboot-parent-boot_serial_encryption.c` (or the fixed pin),
`upstream-parent/boot/bootutil/src/encrypted.c`,
`ext/tinycrypt/lib/source/{aes_encrypt,aes_decrypt,ctr_mode,utils}.c`.
`encrypted.c` is compiled with `-Dboot_enc_decrypt=real_boot_enc_decrypt`
so `real-harness.c` can interpose a logging wrapper of the same signature;
the upstream function body is not edited. Only flash read/write/erase,
sector lookup, state init/clear, header load, TLV iteration and key retrieval
are local shims, plus the caller and chosen-plaintext readback.

Build flags (mirroring `sim/mcuboot-sys/build.rs:54-84`):
`-D__BOOTSIM__ -DMCUBOOT_HAVE_ASSERT_H
-DMCUBOOT_USE_FLASH_AREA_GET_SECTORS -DMCUBOOT_MAX_IMG_SECTORS=128
-DMCUBOOT_BOOT_MAX_ALIGN=8 -DMCUBOOT_IMAGE_NUMBER=1
-DMCUBOOT_ENC_IMAGES -DMCUBOOT_ENCRYPT_KW -DMCUBOOT_USE_TINYCRYPT
-DMCUBOOT_ENC_BUILTIN_KEY -DMCUBOOT_FIH_PROFILE_OFF`, with include paths
`sim/mcuboot-sys/csupport`, `boot/bootutil/include`, `boot/bootutil/src` and
`ext/tinycrypt/lib/include`.

`sh run.sh` builds `real-plain`, `real-asan`, `fixed-plain`, `fixed-asan` and
runs all four modes (`edge`, `attack`, `attack2`, `safe`) for each. Outputs are
under `evidence/`.

## Measured results

The real `boot_enc_decrypt()` (`encrypted.c:701-727`) is TinyCrypt AES-CTR
in-place: nonce = 12 zero bytes || big-endian `(off >> 4)`; `blk_off` selects
the byte within the first keystream block. All runs used a fixed 16-byte key
`00 01 .. 0f` installed with the real `boot_enc_init()` /
`boot_enc_set_key()`.

| build | mode | `off,len,blk_off` | `dst - buf` | result |
| --- | --- | --- | --- | --- |
| parent ASan | edge | `4096,4088,0` | `+4104` | `dynamic-stack-buffer-overflow`, `READ of size 1` at `tc_ctr_mode` → `real_boot_enc_decrypt` → pinned `decrypt_region_inplace():175` |
| parent plain | attack | `4096,2048,0` | `+6144` | rc 0; readback `4d495348452d5245414c2d4145532121` = `MISHE-REAL-AES!!` at `buf+6144` |
| parent plain | attack2 | `0,3000,0` | `+1024` | rc 0; same chosen bytes at `buf+1024` |
| parent plain | safe | `0,4096,0` | `+0` | rc 0; chosen bytes in bounds |
| fixed ASan/plain | edge | `0,4088,0` | `+8` | rc 0, no ASan error |
| fixed ASan/plain | attack | `0,2048,0` | `+2048` | rc 0, no ASan error |
| fixed ASan/plain | attack2 | `0,1976,0` | `+1024` | rc 0, no ASan error |
| fixed ASan/plain | safe | `0,4096,0` | `+0` | rc 0, no ASan error |

Chosen plaintext required deliberate stack grooming: AES-CTR XORs ciphertext
*read from* the destination, so the adjacent stack bytes must contain
`keystream XOR desired_plaintext`. The plain harness computes the keystream
with the real `boot_enc_encrypt()` and places those bytes at `buf+idx` via
the flash-read shim before the pinned call. This is an additional
exploitation condition; it is not a claim that arbitrary adjacent stack bytes
already hold attacker-chosen ciphertext. ASan runs set no grooming, so the
edge report is the real decryptor's own out-of-bounds access.

## Preserved negatives and limits

- ASan edge reports an OOB **read** first (AES-CTR reads OOB ciphertext before
  writing plaintext); the earlier stub harness reported a write because its
  store stub did not read. Do not re-label the real ASan report as a WRITE.
- GCC/Clang ASan do not flag the deep `+6144` jump in either harness (first
  access past the VLA redzone); fixed and safe controls are clean.
- Plain `edge` aborts before readback: the 4088-byte overwrite at `buf+4104`
  destroys the caller's stack frame.
- Valgrind on `real-plain attack` reports `ERROR SUMMARY: 0 errors` — no
  invalid-write detector in this real build; ASan is the detector.
- No full bootloader process, serial/USB wire, real encrypted image with a
  key TLV, pointer/IP/command control or witness replay. No rung-5 claim.
