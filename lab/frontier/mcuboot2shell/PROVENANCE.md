# mcuboot2shell — provenance

## Provisioning

- Upstream `https://github.com/mcu-tools/mcuboot.git`, shallow fetch of the
  merge commit `6e1465c38e3dba4849caed650ad83d0ba5c277b6` on 2026-11-25.
  Parent `099379647ada83b31cc094e4c0c94a7d0e895639`; no working tree or
  build of MCUboot was created. Fetching is provisioning only; no external
  target was contacted beyond this source fetch.
- Public claim: maintainer advisory
  `https://github.com/mcu-tools/mcuboot/security/advisories/GHSA-7c8v-m3pm-wh74`
  (published 2026-11-24, CVE-2026-16663), global
  `https://github.com/advisories/GHSA-r62q-q5vc-23h5`, fix PR #3006. Projected
  patched release 2.5.1 is an advisory claim, not an observed tag.

## Verbatim source, stand-ins, edits

| Artifact | Origin | Modification |
| --- | --- | --- |
| `src/mcuboot-parent-boot_serial_encryption.c` | parent commit, `git show` | none |
| `src/mcuboot-fixed-boot_serial_encryption.c` | fix commit, `git show` | none |
| `harness/decrypt_region_inplace_vuln.inc` | parent file lines 118-204 | none; two-line origin comment above function |
| `harness/decrypt_region_inplace_fixed.inc` | fix file lines 118-210 | none; two-line origin comment above function |
| `harness/harness.c` | written locally | stand-in structs, flash stubs, AES store stub, caller, readback |
| `harness/run.sh` | written locally | build and check matrix |

Hashes in `pins.sha256`. Rendered source line numbers are claims; the stored
verbatim files and their hashes are the evidence.

## Stand-in boundary

`struct enc_key_data`, `struct flash_area`, `struct image_header`
(`ih_hdr_size` is the verbatim `uint16_t` type), `IS_ENCRYPTED`,
`BOOT_TLV_OFF`, flash read/erase/write, `bootutil_wipe_memory` and
`boot_enc_decrypt` are local. The store stub writes bytes from a 16-byte
attacker-chosen `g_plain` into the destination computed by the pinned
function; it does no bounds check. The VLA `buf[sz]` is inside the verbatim
function, not a stand-in. No MCUboot binary, flash driver, serial stack or
AES key was built or used.

## Build matrix and results (2026-11-25 05:52Z, this host)

```
gcc -O1 -g -fsanitize=address -DASAN_BUILD -o vuln-asan harness.c
gcc -O1 -g -fno-stack-protector -o vuln-plain harness.c
gcc -O1 -g -DFIXED_BUILD -fsanitize=address -DASAN_BUILD -o fixed-asan harness.c
gcc -O1 -g -DFIXED_BUILD -fno-stack-protector -o fixed-plain harness.c
clang -O1 -g -fsanitize=address -DASAN_BUILD -o vuln-asan-clang harness.c
```

`sh run.sh` → 22 PASS / 0 FAIL (`harness/evidence/run-all.log`).

- Inputs: `edge` (`off=4096`, `sz=4096`, `ih_hdr_size=4104`, TLV off
  `0xffffffff`): ASan dynamic-stack-buffer-overflow, `WRITE of size 1` at the
  first poisoned byte 8 bytes past the VLA; clang ASan reports
  stack-buffer-overflow on the same input.
- `attack` (advisory shape: `ih_hdr_size=6144`, `off=4096`): pinned `idx=6144`,
  `blk_sz=2048`; plain readback `dst=buf+6144`, first16
  `4d495348452d4d4355424f4f542121`; caller-chosen string
  `ABCD-MCUBOOT-XYZ` gives `414243442d4d4355424f4f542d58595a`. Valgrind:
  `Invalid write of size 1`, one error context. GCC/Clang ASan do **not**
  report this input: the first store lands past the VLA redzone. Preserved
  negative; do not claim ASan confirmed the deep case.
- `attack2` (TLV-clamp shape: `off=0`, `ih_hdr_size=1024`, `tlv_off=3000`):
  pinned `idx=1024`, `blk_sz=3000` → 924 bytes past the VLA; plain readback
  records `dst=buf+1024` and `decrypt_len=3000`.
- `safe` (`ih_hdr_size=0`): `dst=buf+0`, no sanitizer error. Fixed build:
  `edge` `dst=buf+8`, `attack` `dst=buf+2048`, `attack2` `dst=buf+1024`
  with `decrypt_len=1976`; all fixed ASan builds clean.

## Preserved negatives

- Plain `edge` build aborts before printing: 4088-byte overwrite destroys
  the stack frame; no chosen-byte readback from that input.
- GCC/Clang ASan deep-jump negative (see above); `-O0`, `-fno-inline`,
  `-fsanitize-address-use-after-scope` and `detect_stack_use_after_return=1`
  were tried and did not change it.
- An earlier clang ASan deep run aborted in `__asan_stack_free_7` (SEGV),
  not a clean heap/stack overflow report; superseded by the `edge` input.
- No real build, no serial wire, no AES key, no pointer/IP/command control,
  no witness replay, no rung 5.
