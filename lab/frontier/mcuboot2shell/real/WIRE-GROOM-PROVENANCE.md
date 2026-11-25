# W3 wire-to-chosen-bytes provenance (2026-11-25 10:59Z)

## What is live

`wire-groom-harness.c` defines `WIRE_GROOM` and includes the same
`wire-harness.c` used by W2. The client sends a 32-byte MCUboot image header
**plus a 16-byte chosen plaintext** to a `127.0.0.1` listener. The listener
feeds the wire header to the verbatim pinned `decrypt_region_inplace()`
(`src/mcuboot-parent-boot_serial_encryption.c`) and the real TinyCrypt
AES-CTR `boot_enc_decrypt()` body. Under `WIRE_GROOM`, per-connection server
locals (`hdr`, `fa`, `enc`, `off`, `idx`, `dec_off`, `dec_len`) are `static`,
so the OOB write no longer corrupts the listener's frame; the W1 groom path
places ciphertext whose decryption is the *wire-supplied* string in the
adjacent stack, and the interposing wrapper reads the plaintext back from
the real decryptor's destination. No input, image, key or flash content is
hardcoded to the result: flash and key shims are W1's documented lab stand-ins.

`wire-groom-run.sh` compiles with the same GCC flags and real AES/flash
objects as W1/W2, runs one server process per header, and binds only
`INADDR_LOOPBACK` on an ephemeral port. Raw logs: `evidence/wire-groom-*.log`.

Hashes (sha256):

- `wire-groom-harness.c` `a87aef5ad056093b7da06775203bd5c66e4c734aaacd901c914d3b77707ae247`
- `wire-groom-run.sh` `5361b16e2a20d81673bf33d5609e168c7c7ff8375e5354df3ea66d8d6013c819`
- `wire-harness.c` (W2, now with `WIRE_GROOM` branches; default path unchanged)
  `32f9b99ecd74582407933096bbc0f4da784b9e4946f98fc7208ef536f4115bd1`
- pinned parent source `a77260e48b26862b3a8690029184cd3172a365bfd585545898fb677b025ad160`
- `encrypted-real.o` `6e74ce75d4e97303580e1258283cd9c67e06b58ac88b9b0fbd702fd99acb3012`

## Measured table

Client string: `WIRE-CHOICE-1234` (`574952452d43484f4943452d31323334`).
Header flags `IMAGE_F_ENCRYPTED_AES128`, magic `96f3b83d`, `ih_img_size` as
in `wire-run.sh`.

| wire `ih_hdr_size` | real decrypt `len` | destination | readback | process |
| --- | --- | --- | --- | --- |
| 6144 | 2048 | `buf+6144` | `WIRE-CHOICE-1234` | rc 0 |
| 7168 | 1024 | `buf+7168` | `WIRE-CHOICE-1234` | rc 0 |
| 4104 | bogus (1187576966 in the logged run) | `buf+4104` | none | SIGSEGV (139) |
| 2048 (in-bounds control) | 2048 | `buf+0` | `WIRE-CHOICE-1234` | rc 0 |

`dst_delta` is printed by the wrapper from the real decryptor's destination
pointer minus its VLA base. The 4104 case remains a crash: even with server
locals static, the 4088-byte write past the VLA corrupts the decryptor's
own frame state (the bogus length reproduces the earlier W2 negative). It is
preserved as a negative, not retried into a pass. The 2048 control shows the
same chosen bytes at an in-bounds destination, separating wire control of
the plaintext from the OOB destination claim.

## Conditions and negatives

- Default W2 path re-run after the `WIRE_GROOM` branches were added: same
  four rows (`dst_delta=4104/6144/7168/0`, 4104 SIGSEGV, others rc 0, no
  readback, `WIRE_DONE`). The W2 result is unchanged.
- This is still **not** MCUboot serial/SMP: no `boot_serial.c`, no zcbor/CBOR,
  no real encrypted image or key TLV, no real flash device, and no Zephyr or
  native_sim process. The chosen plaintext is groomed adjacent-stack
  ciphertext, not a field of the SMP upload.
- No pointer, IP address or command control; no benign command execution;
  rung 5 remains UNKNOWN. Witness verdict remains UNKNOWN (author evidence
  only).
- No ASan in W3; W1's ASan report remains the memory-corruption evidence.
