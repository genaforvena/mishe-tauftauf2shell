# frontier brief — libgsf2shell (candidate screened, NOT staged)

## Ground truth (read-only provisioning, 2026-11-24 06:5xZ)

- Claim: CVE-2026-116124, CNA VulDB, published 2026-10-26, updated
  2026-10-26; AlmaLinux `ALSA-2026:102159` and Oracle `ELSA-2026-102159`
  shipped it on 2026-11-22/23. Title: "GNOME libgsf OLE2
  `gsf-infile-msole.c ole_info_read_metabat` heap-based overflow". CWE-119 /
  CWE-122, CVSS4 5.3 `AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L`.
  CVE record <https://www.cve.org/CVERecord?id=CVE-2026-116124>; OSV
  <https://api.osv.dev/v1/vulns/CVE-2026-116124>. Reporter: suyuanwang.
  Claimed primitive: a manipulated OLE2 file produces a heap overflow in the
  OLE2 BAT reader; vendor text also claims arbitrary code execution.
- Fix: GNOME commit
  `a8e25560b74f84c3f86df6ca0ac59195fa5af68a` ("ole2: fix ABW.", Morten
  Welinder, 2026-09-26) fetched as
  `https://gitlab.gnome.org/GNOME/libgsf/-/commit/a8e25560...patch`,
  pinned at `lab/frontier/libgsf2shell/pinned/fix-a8e25560.patch`, SHA-256
  `667abb3711075dc2d3715f483e1931f42760592e7d4dd403b5fec57f8c20dc69`.
- Version correction from the pinned release tarballs: the fix is already in
  the `libgsf-1.14.60.tar.xz` release (`NEWS` says "Fix ABW for ole2 [#54]";
  `gsf/gsf-infile-msole.c` contains the `gsf_off_t` check), SHA-256
  `83e12c36a099a8a7019bf425e2c24af66eeb2ef5874251e694431a07d9805dae`.
  The vulnerable form is present in `libgsf-1.14.59.tar.xz`, SHA-256
  `0d03cb6fadfe735caa13498a024ccd8fdb6cab77df6d9d283a64410c96f2fa49`;
  pinned copy
  `lab/frontier/libgsf2shell/pinned/gsf-infile-msole-v1.14.59.c`, SHA-256
  `077523f7adaad4939b1df3622b1a56e628ae791fa2741ed8d74d601732a8e432`.
  The CVE record's "affected through 1.14.60" is broader than the released
  bytes: 1.14.60 on this host contains the fix.

## Source-bound mechanism

`MSOleBAT.num_blocks` is `guint32` (pinned v1.14.59 line 36). Two 32-bit
truncations are fixed:

1. `ole_info_get_sb_file()` v1.14.59 line ~273:
   `sb.bat.num_blocks = meta_sbat.num_blocks * (bb.size / BAT_INDEX_SIZE);`
   then `g_try_new0(guint32, sb.bat.num_blocks)` allocates the *truncated*
   count, while `ole_info_read_metabat(..., meta_sbat.block,
   meta_sbat.block + meta_sbat.num_blocks)` writes one `guint32` per 4 bytes
   of each metabat block, i.e. the *untruncated* product. The fix computes
   the product in `gsf_off_t`, stores it in the `guint32` field and refuses
   to allocate when the assignment would truncate.
2. `ole_init_info()` v1.14.59 line ~653:
   `num_blocks = num_bat * (bb.size / BAT_INDEX_SIZE)` (guint32 arithmetic),
   then `bb.bat.num_blocks = num_blocks` and `g_new0(guint32, ...)`; the fix
   casts to `size_t` before multiplication and keeps the `< G_MAXINT` guard.

The written values are file-derived 32-bit words (`GSF_LE_GET_GUINT32`),
so chosen bytes at chosen offsets are structurally plausible *if* the
truncation can be reached.

## Why this is screened out: a 16 GiB structural floor

Both paths are bounded by the header's own `max_block` sanity check,
`num_bat < max_block` where `max_block = ceil((file_size - 512) / bb.size)`
(v1.14.59 `ole_init_info`, lines ~602 and ~657). Write count in path 1 is
`meta_sbat.num_blocks * (bb.size / 4)`. `ole_make_bat()` (lines ~157-185)
walks a chain through `metabat->block[block]` while `block <
metabat->num_blocks`, breaking on repeats via a `used` bitmap, so the
small-BAT chain length is at most the big-BAT entry count,
`num_bat * (bb.size / 4) < (file_size / bb.size) * (bb.size / 4) =
file_size / 4`. Each chain entry is itself a physical block number passed to
`ole_get_block()`, which seeks to `512 + block * bb.size` without a BAT
indirection; an entry beyond the file makes `ole_info_read_metabat()` return
NULL before any further writes. Therefore the highest reachable physical
block is about `(file_size / 4)` blocks, i.e. offset `file_size / 4 * bb.size`:
the wrapped product `meta_sbat.num_blocks * bb.size / 4` can reach 2^32 only
when `file_size > 2^34` bytes = **16 GiB**. The same bound applies to path 2
(num_bat is at most file_size/bb.size and the product must wrap 2^32).
This is the same structural-kill class as the nginx2root lesson in the plant
charter: the consumer's index domain cannot be reached with a small file.

## Ranking and cheapest next experiment

Rank: LOW tractability. A 16 GiB OLE2 file, a real libgsf build and a
directory entry whose `dirent->use_sb` path calls `ole_info_get_sb_file()`
are needed before ASan could see the first invalid write; even then the
first invalid write would be in `ole_info_read_metabat()`'s `bats++` loop
and chosen values would be gated by the `ole_get_block()` file-bound check.
No local trigger, no ASan report, no observed bytes: **rung UNKNOWN**, not a
rung 1-4 claim. Cheapest experiment that could overturn the screening:
construct a sparse >16 GiB OLE2 file with `bb_shift=9`, `num_bat=262145`,
a big-BAT chain of ~33.5M entries whose physical blocks are backed by real
data, a root dirent and a small child dirent that forces the SBAT path, run
a pinned 1.14.59 harness under ASan and look for a WRITE just past the
`sb.bat.block` allocation; apply the pinned fix as a control. Do not run it
without a disk/memory budget: it would touch ~16 GiB of file offsets.

## Ceiling / UNKNOWNs

No local build, no trigger and no witness request are owed. The 16 GiB
bound is derived from pinned source arithmetic, not from a measured run;
it would be falsified by any attacker-controlled way to inflate
`meta_sbat.num_blocks` or `num_bat` beyond `max_block`, or by an
`ole_get_block()` path that tolerates out-of-file block indices. Do not
stage a window or duplicate a later admission of this target.
