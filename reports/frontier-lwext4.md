# Frontier brief: lwext4 bitmap-init heap overflows — CVE-2025-71473 / 71474

Status: **STAGED 2026-11-26 W242**; window 167 created and registered
03:21:24Z (168 windows / 168 unique names), operator DM 4767 and witness DM
4768 sent. Operator admission owed, witness replay requested.
Rung 3 pinned verbatim function (GCC+Clang ASan heap WRITE); rung 4 PARTIAL
(image-chosen bit byte past the logical 4096-byte block in a synthetic plain
process). No real lwext4 build, no crafted ext4 image through the mount path,
no chosen-address pointer, no command and no rung 5. Only CVE-2025-71473
(`ext4_fs_init_inode_bitmap`) is staged; the sibling block-bitmap issue
CVE-2025-71474 is claimed and source-read but NOT staged here.

## Claims

- CVE-2025-71473, NVD published 2026-11-20T01:17:07Z: heap buffer overflow in
  `ext4_fs_init_inode_bitmap()` (`src/ext4_fs.c`) because
  `s_inodes_per_group` is not checked against the bitmap block size; a crafted
  ext4 image makes `memset()` write past the heap buffer. CWE-787, affected
  `<= 1.0.0`.
- CVE-2025-71474, NVD published 2026-11-20T01:17:08Z: OOB write in
  `ext4_fs_init_block_bitmap()` via oversized `s_reserved_gdt_blocks` and
  `EXT4_BG_BLOCK_UNINIT` geometry; the fix bounds `bit_max` to
  `block_size * 8`. Also CWE-787, affected `<= 1.0.0`.
- Sources: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-71473`,
  `...cveId=CVE-2025-71474`, upstream issue
  `https://github.com/gkostka/lwext4/issues/93`, pull request
  `https://github.com/gkostka/lwext4/pull/111`.
- Fix `b9c842f168e6044bd03fe34e1237eda33c299908` ("Validate superblock
  geometry at mount (#111)", 2026-11-18T23:27:08Z), parent
  `a2dacdc14ea45745a3d65d2a1ea62d1b3681bfdc`; a second proposed fix is
  `2f5714d42f729fbdf3e65fd24d57149619fa1f33`. Numeric fixed release UNKNOWN;
  no 1.0.1 tag was checked.

## Pins and source-bound mechanism

- Byte-exact full files fetched as raw HTTP GET from
  `https://raw.githubusercontent.com/gkostka/lwext4/<ref>/src/ext4_fs.c`:
  - `src/ext4_fs-vulnerable.c`, tag `v1.0.0`, 1724 lines, SHA-256
    `c14c4c3378abb985c28025f35d142c753e05bb6df5d171282ed83d7ccf6c09eb`.
  - `src/ext4_fs-fixed.c`, fix `b9c842f1…`, 1797 lines, SHA-256
    `b259a4bbe8a836d0ce7b78e6dbf0fb9eb29dbe056ce93b69cab7a2975de7bd1f`.
- Verbatim excerpts (no edits to pinned bytes):
  - `pins/lwext4-vulnerable.inc` = vulnerable lines 382-423 (42 lines),
    SHA-256 `c93eaa348724a76546e9d9af248d816569f948bf7823590fdab95f38e8df9e07`.
  - `pins/lwext4-fixed.inc` = fixed lines 421-468 (48 lines),
    SHA-256 `516bdf3b178b121881fec04d9c4f9f63a8a6a1ed53fe83155357fa9ea8d644a5`.
- Vulnerable excerpt line 23 (file line 404):
  `memset(b.data, 0, (inodes_per_group + 7) / 8);` with no comparison to the
  one-block buffer size. With `block_size = 4096` and image-derived
  `inodes_per_group = 32777`, the length is 4098 bytes: two bytes past the
  4096-byte block. Excerpt lines 25-28 then run
  `for (i = start_bit; i < ((start_bit + 7) & ~7UL); i++) ext4_bmap_bit_set(b.data, i);`,
  setting bits 1..7 of byte 4097 (value `0xfe`) for that input; changing the
  image field to 32778 yields bits 2..7 (`0xfc`).
- Fix excerpt lines 23-26 (file lines 443-446) reject
  `inodes_per_group > block_size * 8` with `EIO` before the `memset()`. The
  fix's block-bitmap function likewise computes `bitmap_bits = block_size * 8`
  and rejects `bit_max > bitmap_bits` (file lines 331, 352-355), which is the
  CVE-2025-71474 hunk; that function is not staged locally.

## Local evidence

`bash lab/frontier/lwext4shell/run-all.sh`: **31 PASS / 0 FAIL**, rc 0. The
harness includes the pinned function verbatim and supplies stand-in
`ext4_block`/`ext4_sblock`/`ext4_block_group_ref` structs, image-derived
accessors, a one-block heap allocation and an instrumented `ext4_bmap_bit_set`;
it does not build lwext4. GCC and Clang `-O0` ASan report
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 4098`, 0 bytes after a
4096-byte region, frame `ext4_fs_init_inode_bitmap pins/lwext4-vulnerable.inc:23`
and allocation frame `ext4_trans_block_get_noread harness/driver.c`. The fixed
build rejects the image geometry (`MODE=attack IPG=32777 RC=5 DIRTY=0`); safe
geometry (`ipg=8192`) is clean in both bodies. The plain build pre-fills a
readable tail with `0x4d` and reads `CANARY_AT=4096 FIRST=00fe4d4d…` for
`ipg=32777` and `00fc4d4d…` for `ipg=32778`, while safe/fixed show `4d4d…`.
Exact hashes, commands and logs: `lab/frontier/lwext4shell/PROVENANCE.md`.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in verbatim pinned
  bytes, with fixed and safe-input controls.
- **Rung 4 PARTIAL:** the byte past the logical block tracks the image-derived
  superblock field (`0xfe` vs `0xfc` at `block+4097`) in a synthetic plain
  process. No real lwext4 mount, no crafted ext4 image wire path, no
  chosen-address pointer and no command.
- **Not rung 5:** no live loopback target and no benign command side effect.

Cheapest next experiment: build lwext4's real `ext4_fs_init()` mount path
against a crafted ext4 image whose `s_inodes_per_group = 32777` and check the
real allocator under ASan, then pin `ext4_fs_init_block_bitmap()` with
`s_reserved_gdt_blocks` oversized to stage CVE-2025-71474. Keep the no-pointer,
no-command ceiling until a real consumer is measured.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning (W205 lesson): no lwext4 brief, lab or window
existed. No external host was probed; only NVD and public raw-source fetches.
