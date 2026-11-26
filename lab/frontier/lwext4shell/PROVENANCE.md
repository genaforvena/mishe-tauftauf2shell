# PROVENANCE — lwext4shell staged evidence (W242, 2026-11-26)

## Source claim (read-only provisioning)

- NVD `CVE-2025-71473` (published 2026-11-20T01:17:07Z) and `CVE-2025-71474`
  (2026-11-20T01:17:08Z), both CWE-787, affected `<= 1.0.0`:
  `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-71473`,
  `...cveId=CVE-2025-71474`. Upstream:
  `https://github.com/gkostka/lwext4/issues/93`,
  `https://github.com/gkostka/lwext4/pull/111`.
- Upstream fix `b9c842f168e6044bd03fe34e1237eda33c299908` ("Validate
  superblock geometry at mount (#111)", 2026-11-18T23:27:08Z), parent
  `a2dacdc14ea45745a3d65d2a1ea62d1b3681bfdc`; second proposed fix
  `2f5714d42f729fbdf3e65fd24d57149619fa1f33`. Numeric fixed release UNKNOWN.
- Raw pinned full file fetched with plain HTTP GET from
  `https://raw.githubusercontent.com/gkostka/lwext4/<ref>/src/ext4_fs.c`:
  - `src/ext4_fs-vulnerable.c`, tag `v1.0.0`, 1724 lines, SHA-256
    `c14c4c3378abb985c28025f35d142c753e05bb6df5d171282ed83d7ccf6c09eb`.
  - `src/ext4_fs-fixed.c`, fix `b9c842f1…`, 1797 lines, SHA-256
    `b259a4bbe8a836d0ce7b78e6dbf0fb9eb29dbe056ce93b69cab7a2975de7bd1f`.
  - Parent `a2dacdc1…` was fetched during screening (1752 lines, SHA-256
    `d8bba0605dfba800ba38f84b5077bead76237fd688a7f8720aab1267472c7450`) but
    is not a pinned harness input.
- Verbatim excerpts (no edits to pinned bytes):
  - `pins/lwext4-vulnerable.inc` = vulnerable lines 382-423 (42 lines), SHA-256
    `c93eaa348724a76546e9d9af248d816569f948bf7823590fdab95f38e8df9e07`.
  - `pins/lwext4-fixed.inc` = fixed lines 421-468 (48 lines), SHA-256
    `516bdf3b178b121881fec04d9c4f9f63a8a6a1ed53fe83155357fa9ea8d644a5`.
  - `harness/driver.c` SHA-256
    `02d76df4f1ef5fdd231725e8d373f9f20a8bbf88feef144ebcac80c1a7549b42`.

No external host was probed; only public advisory and raw-source fetches.

## Source-bound mechanism

Vulnerable excerpt line 23: `memset(b.data, 0, (inodes_per_group + 7) / 8)`
against a one-block `b.data` returned by
`ext4_trans_block_get_noread()`; line 24 sets `start_bit = inodes_per_group`
and lines 25-28 call `ext4_bmap_bit_set(b.data, i)` up to the next 8-aligned
bit. With `block_size = 4096` and image-derived `inodes_per_group = 32777`
the zero fill is 4098 bytes (2 past the 4096-byte object) and the bit-set loop
sets bits 1..7 of byte 4097 (`0xfe`); input 32778 yields bits 2..7 (`0xfc`).
Fix excerpt lines 23-26 reject `inodes_per_group > block_size * 8` with `EIO`
before the store. The CVE-2025-71474 hunk in the same commit
(`bitmap_bits = block_size * 8`, `bit_max > bitmap_bits`) is read but not
staged.

## Harness boundary and evidence

`harness/driver.c` includes the pinned function verbatim under
`-DVARIANT_FIXED` / default. Stand-ins supply `ext4_sblock`, `ext4_fs`,
`ext4_bgroup`, `ext4_block_group_ref`, `ext4_block`, `ext4_get32`,
`ext4_sb_get_block_size`, `ext4_bg_get_inode_bitmap`,
`ext4_trans_block_get_noread`, `ext4_bmap_bit_set`,
`ext4_trans_set_block_dirty`, `ext4_ialloc_set_bitmap_csum`, `ext4_block_set`
and `EOK`/`EIO`; no lwext4 library, block device or ext4 image is built.
`memset()` and the stand-in bit-set are ASan-instrumented, so no consumer
substitution is needed (contrast the uninstrumented libz in W241).

GCC and Clang `-O0` ASan on the attack image report
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 4098`, 0 bytes after
a 4096-byte region. ASan frame #0 is `memset` (GCC interceptor / Clang
`__asan_memset`), frame #1 is the pinned call
`ext4_fs_init_inode_bitmap pins/lwext4-vulnerable.inc:23`, frame #2 is `main`;
the allocation frame is `ext4_trans_block_get_noread harness/driver.c:79`.
The fixed build returns `EIO` before the store; safe geometry (`ipg=8192`)
is clean in vulnerable and fixed builds. Under `-DPLAIN_MODE` the stand-in
allocator adds a 64-byte readable tail pre-filled with `0x4d`; the readback is
`CANARY_AT=4096 FIRST=00fe4d4d4d4d4d4d` for ipg=32777,
`00fc4d4d4d4d4d4d4d` for ipg=32778, and `4d4d…` for safe and fixed runs,
so the byte past the logical object tracks the image-derived field.

## Reproduction

`bash run-all.sh` — 31 PASS / 0 FAIL, rc 0. Logs in `out/` (gitignored).
`bash run-witness.sh` rehashes all five pins and the driver, deletes `out/`,
rebuilds and re-asserts every staged observation.

## Grade

Rung 3 pinned verbatim function with ASan-confirmed heap OOB WRITE and
vulnerable/fixed/safe controls. Rung 4 PARTIAL: image-chosen bit byte observed
past the logical block in a synthetic plain process. No real lwext4 mount, no
crafted ext4 image through the real allocator, no chosen-address pointer, no
command and no rung 5. CVE-2025-71474 is claimed but not staged locally.
