# Frontier brief — mcuboot2shell (CVE-2026-16663)

Status 2026-11-25 05:5xZ: **staged, handed off, no real build**. Rung 3 is
CONFIRMED in the verbatim pinned `decrypt_region_inplace()` function with
local stand-ins: gcc ASan reports `dynamic-stack-buffer-overflow`, `WRITE of
size 1` at the first poisoned byte 8 bytes past the 4096-byte VLA (mode
`edge`, `ih_hdr_size=4104`); clang ASan agrees; Valgrind reports an invalid
write past the VLA for the advisory's deep case (`ih_hdr_size=6144`, 2048
bytes past the 4096-byte buffer). Rung 4 is PARTIAL: chosen plaintext bytes
were read back at `buf+6144` in a plain build (16 bytes
`4d495348452d4d4355424f4f542121`, and a caller-chosen
`414243442d4d4355424f4f542d58595a`). No real MCUboot build, no serial/USB
wire, no real AES image, no pointer/IP/command control and no rung 5.
Witness verdict UNKNOWN. AV:L (serial recovery), pre-authentication but not
remote. Fix is merged on `main`; the projected 2.5.1 release was not observed.

## Verified ground truth (read-only provisioning)

- GitHub maintainer advisory
  https://github.com/mcu-tools/mcuboot/security/advisories/GHSA-7c8v-m3pm-wh74
  (`CVE-2026-16663`, published 2026-11-24, High 8.4,
  `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-787). Global record
  https://github.com/advisories/GHSA-r62q-q5vc-23h5 . Affected `>=1.9.0,
  <=2.5.0`; patched `2.5.1` is a **projection** in the advisory, not an
  observed release.
- Upstream fix `6e1465c38e3dba4849caed650ad83d0ba5c277b6` (PR #3006, 2026-11-20),
  parent `099379647ada83b31cc094e4c0c94a7d0e895639`. Provisioned by a shallow
  `git fetch` into `lab/frontier/mcuboot2shell/src/`; both versions of
  `boot/boot_serial/src/boot_serial_encryption.c` are stored verbatim there.
  Introduced by `953a761` (v1.9.0), moved by `c9fa608` (v2.0.0). The advisory
  reports a 2048-byte OOB write reproduced under ASan with `sz=4096`,
  `off=4096`, `ih_hdr_size=6144`.
- Duplicate screen FIRST: no `mcuboot` / `16663` / `7c8v-m3pm` match in
  `reports/frontier-*.md`, charters or operator files. Zephyr is an admitted
  target but MCUboot is a separate bootloader project; the admitted SRS RTCP
  bug (11/25) and Valkey UAF (11/24) were screened out as owned/excluded.
  Fetching/cloning is provisioning only; no external target was probed.

## Source-bound mechanism (verbatim pinned function, no hand-edited source)

`harness/decrypt_region_inplace_vuln.inc` is the unmodified parent function
(lines 118-204, sha256 `f7ba8c254a41312b3a7e3473ac228981d5010a7aaf9f6ec48e062f3b41ed2e87`):

```
uint16_t idx;
uint8_t buf[sz] __attribute__((aligned));
...
if (off + bytes_copied < hdr->ih_hdr_size) {
    ...
    blk_sz = off + bytes_copied + chunk_sz - hdr->ih_hdr_size;
    blk_off = 0;
    idx = hdr->ih_hdr_size;        /* absolute image offset, not sector-relative */
}
...
rc = boot_enc_decrypt(enc_data,
        (off + bytes_copied + idx) - hdr->ih_hdr_size, blk_sz,
        blk_off, &buf[idx]);       /* sector-sized VLA, no window check */
```

`decrypt_image_inplace()` calls it once per erase sector
(`boot_serial_encryption.c:286-287`), so `off=4096` is the second sector.
The sibling loader path `boot/bootutil/src/loader.c:876` uses the correct
`idx = hdr->ih_hdr_size - abs_off`. Validation before decryption is
`#if 0` at `boot_serial_encryption.c:245-252`; `bs_upload()` reaches
`boot_handle_enc_fw()` after upload (`boot_serial.c:1208`). The advisory also
describes a second window error at `:166-173` (TLV clamp measured from the
sector start, not from `idx`) — the harness reproduces that too.

The fixed function (`harness/decrypt_region_inplace_fixed.inc`, lines 118-210
of the fix commit, sha256
`e9f8366f8c69eeb6835e000bc51a0804c08c34fde241e3b9e8359780e2d53fda`) computes
`abs_off`, `idx = ih_hdr_size - abs_off`, `blk_sz = tlv_off - abs_off - idx`
and rejects the sector with
`if (idx > (uint32_t)chunk_sz || blk_sz > (uint32_t)chunk_sz - idx)`.
Both functions are compiled unchanged; only structs, flash stubs, the
`boot_enc_decrypt` store stub and the caller are local stand-ins.

## Lab evidence (`lab/frontier/mcuboot2shell/`)

`cd lab/frontier/mcuboot2shell/harness && sh run.sh > evidence/run-all.log`:
**22 PASS / 0 FAIL** (2026-11-25 05:52Z). Builds and inputs are listed in
`PROVENANCE.md`; evidence files are under `harness/evidence/`.

- `vuln-asan edge`: `dynamic-stack-buffer-overflow`, `WRITE of size 1`,
  stack `boot_enc_decrypt harness.c:78` → pinned
  `decrypt_region_inplace.inc:61` (the `&buf[idx]` call). `ih_hdr_size=4104`,
  `off=4096`, `sz=4096`: absolute `idx=4104`, 8 bytes past the VLA. clang
  ASan reports `stack-buffer-overflow` on the same input.
- `fixed-asan edge`, `fixed-asan attack`, `fixed-asan attack2` and all safe
  controls: rc 0, no ASan error. The fixed destination for the advisory case
  is `buf+2048` with `decrypt_len=2048`, ending exactly at the 4096-byte
  boundary; for the TLV case `buf+1024` with `decrypt_len=1976`.
- Deep advisory case (`ih_hdr_size=6144`): plain readback with
  `-fno-stack-protector` shows `dst=buf+6144`, `decrypt_len=2048`, chosen
  bytes at that OOB destination; Valgrind reports `Invalid write of size 1`
  and 1 error context. GCC/Clang ASan do **not** flag this deep jump (the
  first written byte is beyond the VLA redzone); that negative is preserved,
  and the ASan rung-3 claim rests on the `edge` input.
- Plain `edge` build aborts before printing (4088-byte overwrite destroys
  the stack frame); preserved as a negative, not used as an oracle.
- Safe control (`ih_hdr_size=0`): `dst=buf+0`, no sanitizer error.

## Rung assessment and cheapest next experiment

Ceiling is **rung 3 pinned function / rung 4 PARTIAL chosen bytes**, same
shape as the other staged frontier targets. Pre-authentication is real per
the advisory, but the attack vector is local serial/USB recovery with a
`MCUBOOT_ENC_IMAGES` build and a crafted *encrypted* image; no network wire,
no real bootloader process and no witness replay were observed. Fixed and
safe controls are the upstream patch and a zero header size.

Cheapest experiment for the target mind: rebuild the pinned parent and fix
under a real MCUboot unit-test configuration with `MCUBOOT_ENC_IMAGES`, drive
`decrypt_region_inplace()` through a real `flash_area` shim with a 4096-byte
sector and the three recorded inputs, and check whether the real
`boot_enc_decrypt()` writes chosen plaintext at the OOB offsets. Only after
that, investigate whether a host serial-recovery instance can expose the
upload path on 127.0.0.1. Do not claim a wire path, pointer control or rung 5
without measured evidence.

## Handoff receipt (2026-11-25 05:59Z)

Scoped commit `bf2a32ff` (47 files: pinned source, harness, evidence, brief,
status). A clean `git archive HEAD lab/frontier/mcuboot2shell` replay in a
throwaway directory ran `sh run.sh` again: **22 PASS / 0 FAIL**, same fixed
ASan output hash; raw vulnerable output hashes differ from the working tree
because ASan reports embed PID/address/path, not because checks changed.
Inner tmux window 151 (`%304`/`%305`, both alive) and registry 152/152 unique
names were verified after creation; operator DM #4142 states the window
already exists, witness replay DM #4143. No rung, charter or admission claim
is made by frontier beyond the staged grade above.
