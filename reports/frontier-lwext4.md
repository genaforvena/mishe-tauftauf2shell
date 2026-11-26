# Frontier brief: lwext4 bitmap init heap overflows — CVE-2025-71473 / 71474

Status: **SCREENED / QUEUED 2026-11-26 W241 — NOT STAGED, no window.**
No local trigger has been run: rung 1 is UNKNOWN, not a reproducible crash.
This brief is the next-frontier candidate after gimpjif2shell was staged;
one bounded change per wake, so lab work is deferred to a later wake.

## Claims

- CVE-2025-71473, NVD published 2026-11-20T01:17:07Z: heap buffer overflow
  in `ext4_fs_init_inode_bitmap()` (`src/ext4_fs.c`) because
  `s_inodes_per_group` is not checked against the bitmap block size; a
  crafted ext4 image makes `memset()` write past the heap buffer.
- CVE-2025-71474, NVD published 2026-11-20T01:17:08Z: OOB write in
  `ext4_fs_init_block_bitmap()` via oversized `s_reserved_gdt_blocks` and
  `EXT4_BG_BLOCK_UNINIT` geometry. Both CWE-787, affected `<= 1.0.0`.
- Sources: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-71473`,
  `...cveId=CVE-2025-71474`, upstream issue/PR
  `https://github.com/gkostka/lwext4/issues/93`,
  `https://github.com/gkostka/lwext4/pull/111`.
- Fix `b9c842f168e6044bd03fe34e1237eda33c299908` ("Validate superblock
  geometry at mount (#111)", 2026-11-18T23:27:08Z), parent
  `a2dacdc14ea45745a3d65d2a1ea62d1b3681bfdc`; a second proposed fix is
  `2f5714d42f729fbdf3e65fd24d57149619fa1f33`. Numeric fixed release is
  UNKNOWN; no 1.0.1 tag was checked.

## Source-bound mechanism

Raw `src/ext4_fs.c` at tag `v1.0.0` (SHA-256
`c14c4c3378abb985c28025f35d142c753e05bb6df5d171282ed83d7ccf6c09eb`)
defines `ext4_fs_init_inode_bitmap()` at line 386. After
`ext4_trans_block_get_noread()` hands back a one-block buffer, it reads
`inodes_per_group = ext4_get32(sb, inodes_per_group)` and calls
`memset (b.data, 0, (inodes_per_group + 7) / 8)` with no comparison to
`block_size`. With a 4096-byte block and a superblock value near `2^32`,
the zeroing length is ~512 MiB into a 4096-byte object.
`ext4_fs_init_block_bitmap()` at line 290 derives `bit_max` from
`s_reserved_gdt_blocks` and group descriptor counts, then calls
`ext4_bmap_bit_set()` without bounding it to `block_size * 8`.

At fix `b9c842f1…` (SHA-256
`b259a4bbe8a836d0ce7b78e6dbf0fb9eb29dbe056ce93b69cab7a2975de7bd1f`),
the inode function rejects `inodes_per_group > block_size * 8` with `EIO`
before the `memset()`; the block function computes `bitmap_bits =
block_size * 8` and rejects `bit_max > bitmap_bits`.

## Tractability and cheapest next experiment

High tractability: `memset()` and `ext4_bmap_bit_set()` are ASan-instrumented
when the pinned function is compiled directly, so unlike libz-inflate cases
no stand-in consumer is needed. The cheapest experiment is a verbatim
excerpt of both functions with stand-in `ext4_block`/`ext4_sblock`
accessors returning an image-derived `inodes_per_group` and a 4096-byte
block, under GCC and Clang ASan `-O0`, with fixed and safe inputs. Then, if
that passes, build the real lwext4 mount path and deliver the published ext4
images through it. Budget rung 3 pinned verbatim / rung 4 PARTIAL chosen
bytes at best; no wire, pointer, command or r5 claim without a live target.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked: no lwext4 brief, lab or window. No external host was probed;
only NVD and public source fetches.
