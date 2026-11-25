# W2 loopback wire-to-sink provenance (2026-11-25 09:49Z)

## What is live

`wire-harness.c` includes `real-harness.c` (which includes the verbatim pinned
`src/mcuboot-parent-boot_serial_encryption.c`), renames its `main` to
`harness_main`, and adds a loopback-only TCP listener. One 127.0.0.1 client
sends a 32-byte little-endian MCUboot `struct image_header`; the server copies
those **wire bytes** into `hdr`, checks `IS_ENCRYPTED()`, and calls
`harness_decrypt_region()` → real pinned `decrypt_region_inplace()` → real
`boot_enc_decrypt()` (`boot/bootutil/src/encrypted.c` + TinyCrypt AES-CTR).
The interposing wrapper in `real-harness.c` logs the real decryptor's
destination offset and length. `wire-run.sh` compiles with the same flags as
`run.sh` (GCC `-O1 -g -fno-stack-protector`, `MCUBOOT_ENC_IMAGES`,
`MCUBOOT_ENCRYPT_KW`, `MCUBOOT_USE_TINYCRYPT`) and runs one server process per
header, binding only to `INADDR_LOOPBACK` on an ephemeral port.

Hashes (sha256):

- `wire-harness.c` `fa25714a2753999cdf7b5989eeb260d0a75f691aa6dc592288724e95a0d7c378`
- `wire-run.sh` `278925dbae746de34b908eb3dc44a98baa28e0660a1487b6ddb4ca3877e0717e`
- pinned parent source `a77260e48b26862b3a8690029184cd3172a365bfd585545898fb677b025ad160` (unchanged from W1)
- `encrypted-real.o` `6e74ce75d4e97303580e1258283cd9c67e06b58ac88b9b0fbd702fd99acb3012`

## Measured table

Client header bytes: magic `96f3b83d`, flags `4` (`IMAGE_F_ENCRYPTED_AES128`),
`ih_hdr_size` as listed, `ih_img_size = 0xffffffff - ih_hdr_size`, version/pad
zero. Flash shim is `0xcc`; no stack grooming in this experiment (see below).
Raw logs: `evidence/wire-<hdr>.log`, consolidated `evidence/wire-all.log`.

| `ih_hdr_size` (wire) | real decryptor `len` | destination | process result |
| --- | --- | --- | --- |
| 4104 | 4088 | `buf+4104` | SIGSEGV (rc 139) after the OOB call |
| 6144 | 2048 | `buf+6144` | rc 0, OOB destination reached |
| 7168 | 1024 | `buf+7168` | rc 0, OOB destination reached |
| 2048 (control) | 2048 | `buf+0` (in bounds) | rc 0 |

The `dst_delta` values are printed by the wrapper from the real call's
destination pointer minus the real VLA base. The 4104 case demonstrates a
wire-controlled header driving the real pinned sink to an out-of-bounds
destination and killing the live process. The 2048 case is the in-bounds
control: the same wire path with a small header stays at `buf+0`.

## Conditions and negatives

- This is **not** an MCUboot serial/SMP parser: no `boot_serial.c`, no CBOR,
  no image/key TLV, no real encrypted image. The wire carries a bare header
  and the harness supplies flash content and AES key shims.
- Stack grooming is deliberately disabled: writing 4088/2048 bytes past the
  4096-byte VLA in this server frame corrupt its own locals (an earlier run
  produced a bogus `len=1406863095` and a crash). Therefore there is **no**
  chosen-plaintext readback in this experiment; W1's chosen bytes remain the
  rung-4 evidence, with their stated grooming condition.
- The 4104 case is an OOB write/crash in the lab host build, not a pointer,
  IP or command-control demonstration. No ASan build was run here; W1's ASan
  result is the memory-corruption evidence.
- Rung 5 remains UNKNOWN: a live loopback process accepted attacker-chosen
  header bytes and reached the real sink, but through a lab transport shim,
  not an MCUboot wire protocol. Witness verdict remains UNKNOWN.
