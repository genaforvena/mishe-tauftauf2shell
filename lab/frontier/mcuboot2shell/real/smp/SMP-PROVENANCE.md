# W4: real MCUboot SMP upload path drives the pinned OOB sink

Recorded 2026-11-25 14:44Z. Author evidence only; no witness verdict.

## What is live

This lane compiles **MCUboot's real `boot_serial.c`** (the parent commit
`099379647ada`), the real `zcbor_decode.c`, `zcbor_encode.c`,
`zcbor_common.c`, `zcbor_bulk.c`, the verbatim pinned
`boot_serial_encryption.c` and the real TinyCrypt AES-CTR decryptor into a
native host process. A loopback-only listener accepts one mcumgr SMP packet
(`op=WRITE`, `nh_len`, `nh_group=1`, `nh_id=1` IMGMGR upload) whose CBOR
`data` field carries a genuine 32-byte MCUboot image header, an encrypted
image body with a valid `IMAGE_TLV_INFO_MAGIC` TLV at
`BOOT_TLV_OFF = ih_hdr_size + ih_img_size`, followed by 16 wire-supplied
plaintext bytes. The real `boot_serial_input()` → `bs_upload()` →
`boot_handle_enc_fw()` → `decrypt_image_inplace()` →
`decrypt_region_inplace()` path runs unchanged.

Native host shims supply only what Zephyr/Mynewt would: flash area API,
UART callbacks, CRC16, base64, OS malloc and loader hooks. The two local
source copies `boot_serial-host.c` and `encryption-host.inc` are the
upstream files plus `printf` tracing only; deleting the trace lines
reproduces the pinned bytes (see diff commands in "Verification").

## Measured table (client string `WIRE-CHOICE-1234`)

| wire `ih_hdr_size` | real decrypt `len`/`off` at OOB | `dst_delta` | readback at OOB destination | process |
| --- | --- | --- | --- | --- |
| 6144 | 2048, off 4096 | 6144 | `574952452d43484f4943452d31323334` | rc 0 |
| 7168 | 1024, off 4096 | 7168 | same 16 bytes | rc 0 |
| 2048 (in-bounds control) | 2048, off 0 | 2048 | not chosen string (in-bounds ciphertext) | rc 0 |
| 4104 | 4088, off 4096 | 4104 | none | SIGSEGV 139 |

All four rows are in `evidence/smp-<hdr>.log`. The chosen-string readback is
recorded by the interposing `boot_enc_decrypt()` wrapper immediately after
the real decryptor returns; later in-bounds decrypt calls in the same
upload overwrite the final `g_readback`, so the per-call `READBACK` lines
are the evidence, not the last `SMP_DONE` line. Grooming (placing
ciphertext whose decryption is the wire string in the adjacent stack) is a
lab shim; the wire supplies the plaintext, the chosen `ih_hdr_size` comes
from the CBOR upload and the destination is computed by the verbatim
pinned function. `4104` stays a crash and is preserved as a negative.

## Negatives and boundaries

- Native host build, not Zephyr, not a real MCU: still no serial-port wire,
  no SMP-over-UART framing parser from `boot_serial_read_console()` (the
  packet is handed directly to `boot_serial_input()`), no base64/CRC
  transport decode, no real encrypted image/key TLV, no pointer/IP/command
  control, no benign command execution, no ASan in W4, no witness verdict.
  Rung 5 remains UNKNOWN.
- Early SMP rows with a 32-byte upload had `read_image_size` rc 3: the TLV
  at `BOOT_TLV_OFF` was erased. Fixed by sending a valid TLV block; the
  failed rows are preserved in this wake's history, not retried as passes.
- Ungated stack grooming initially overwrote the TLV read buffer (magic
  `ffff`/`7e44`), so `read_image_size` failed before reaching the sink. The
  shim now grooms only on reads of ≥512 bytes; the 4-byte TLV read stays
  clean. `7168` briefly returned rc 2 when `tlv_off + 8` exceeded the
  client's upload length; fixed by `IMG_SIZE=8192`. Both are recorded as
  experiment corrections, not claimed as results.
- `boot_enc_load()` in the native build is shimmed to supply the 16-byte
  key directly; a real wrapped-key TLV/KDF is not exercised.

## Hashes (sha256)

- pinned parent source `src/mcuboot-parent-boot_serial_encryption.c`
  `a77260e48b26862b3a8690029184cd3172a365bfd585545898fb677b025ad160`
- real `boot_serial.c` (parent tree)
  `15902950e4f609423bc9528bdad80a763580e03fe9e69f712157b406de35bfb9`
- `smp-host.c` `7813be3d831632c14f01485cb614ba97ea41764871e455d3c3d30c83c80b5671`
- `smp-shims.c` `686019d5fff9519800d29b8d555beb5ca8d73a7653ac21297d1ab77575d86925`
- `client.py` `45a4a44daccfab80e020d289363b83ec3e9fe02d5a28aaf4c97a4ed12ffc9fed`
- `run.sh` `6b1eefd05c101bd7c836dae14d4b36a4c1fc75757b74a646ba575891c8da071b`
- `build.sh` `9e66fcd039b5d1b38406b8c5a90e44154be32b367b789b77493ad869c6d2ae55`
- `boot_serial-host.c` (trace-only copy)
  `2cabba54fe4f7cae83269f23cd3ee4c54aa2bcf87e79efaedb53d5887f869ef1`
- `encryption-host.inc` (trace-only copy)
  `7ee51e25874d20ce4bca75a92c2aad9339d8ade5439ce34c4f207b160239c54e`

## Verification

From this lab directory: `sh run.sh` rebuilds and replays all four rows on
ephemeral 127.0.0.1 ports. Trace-only diffs:

```
diff <(grep -v 'printf(' encryption-host.inc | grep -v 'fflush(stdout);') \
     ../../src/mcuboot-parent-boot_serial_encryption.c
diff <(grep -v 'printf("BS_UPLOAD\|printf("PIN ' boot_serial-host.c | \
       grep -v 'fflush(stdout);') \
     ../../upstream-parent/boot/boot_serial/src/boot_serial.c
```

Both diffs must show no functional change (only continuation lines of the
removed `printf` calls).
