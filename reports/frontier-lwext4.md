# Frontier brief: lwext4 bitmap-init heap overflows — CVE-2025-71473 / 71474

Status: **ADMITTED 2026-11-26** (159th target, standing #6, window 167).
Witness W242 replay ESTABLISHED AS LABELED for the earlier stand-in-harness
grade only (no grade change, NO r5). Witness W273 independently replayed the
real-mount and adjacent-object lanes from a clean `git archive cbadc189`:
ESTABLISHED AS LABELED, no grade change, NO r5. Real-library lane staged
2026-11-26 14:1xZ: `run-real.sh` 17 PASS / 0 FAIL through the real
`ext4_fs_init()` mount path, and `run-victim.sh` 9 PASS / 0 FAIL showing
image-chosen bytes overwriting an adjacent live `ext4_buf` in the real plain
build. Grade: **rung 3 CONFIRMED / rung 4 DEMONSTRATED by the author in the
lab build, independently replayed as labeled by W273**. No chosen-address
pointer, no command and no rung 5. The 71473 lanes were independently
replayed; the 71474 sibling bit-write lane and its named-field / prefix-OR
ceiling probe are author-measured only.

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
  full fix also adds `ext4_sb_check_geometry()` at mount, which rejects the
  crafted images before any bitmap write with `ENOTSUP` (95 in the system
  errno build used here). Its block-bitmap guard bounds `bit_max` to
  `block_size * 8`; the CVE-2025-71474 hunk is staged in the real lane below.

## Local evidence

`bash lab/frontier/lwext4shell/run-all.sh`: **31 PASS / 0 FAIL**, rc 0. The
harness includes the pinned function verbatim and supplies stand-in
`ext4_block`/`ext4_sblock`/`ext4_block_group_ref` structs, image-derived
accessors, a one-block heap allocation and an instrumented `ext4_bmap_bit_set`;
it does not build lwext4. GCC and Clang `-O0` ASan report
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 4098`, 0 bytes after a
4096-byte region. ASan frame #0 is `memset`/`__asan_memset`; frame #1 is the
pinned call site `ext4_fs_init_inode_bitmap pins/lwext4-vulnerable.inc:23`;
the allocation frame is `ext4_trans_block_get_noread harness/driver.c:79`.
The fixed build rejects the image geometry (`MODE=attack IPG=32777 RC=5 DIRTY=0`); safe
geometry (`ipg=8192`) is clean in both bodies. The plain build pre-fills a
readable tail with `0x4d` and reads `CANARY_AT=4096 FIRST=00fe4d4d…` for
`ipg=32777` and `00fc4d4d…` for `ipg=32778`, while safe/fixed show `4d4d…`.
Exact hashes, commands and logs: `lab/frontier/lwext4shell/PROVENANCE.md`.

Witness W242 independently replayed the unmodified `run-witness.sh` from the
worktree and from a clean `git archive b4a7acd4` (wrapper SHA-256
`42d5b68df4e6c4d5ffc28011da2fd814fceeafeb636568f95a746d0bb30838f5` in both):
both `REPLAY_PASS=6/0`, `TOTAL: 31 PASS / 0 FAIL`, rc 0. Independently fetched
raw `src/ext4_fs.c` at v1.0.0 and b9c842f1: full and excerpt hashes match all
four pins and the EIO guard is present. GCC+Clang ASan frames, fixed/safe
controls and the `0xfe`/`0xfc` vs `0x4d` readback were reobserved. Verdict:
ESTABLISHED AS LABELED, no grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w242-lwext4shell/detail.md`.

## Real mount-path evidence (2026-11-26 14:1xZ)

Upstream clone fetched once for provisioning; two detached worktrees:
`v1.0.0` = `890484c72dbb321535127625c3686e51f1f424b9` and fix
`b9c842f168e6044bd03fe34e1237eda33c299908`. Both were built as the real
lwext4 library with `cmake -DLIB_ONLY=1` and GCC ASan `-O0`; a small driver
(`lab/frontier/lwext4shell/real/mount_driver.c`) opens a *file* block device
via lwext4's own `ext4_filedev`/`file_dev`, calls the real `ext4_fs_init()`,
binds a real 16-entry bcache, then calls the exported real
`ext4_fs_get_block_group_ref(&fs, 0, &ref)`. No function body is copied and no
struct is stubbed. The pristine image is created by the library's unmodified
`ext4_mkfs()` (4 KiB blocks, 8192 inodes/group, 16 MiB file); the two patchers
change only on-disk superblock/group-descriptor fields, never source bytes.

`bash lab/frontier/lwext4shell/run-real.sh`: **17 PASS / 0 FAIL**, rc 0.
Images (SHA-256): base
`1a74665db6ce64cbd63ccf3aca0ffde501855651cf29983dfe7ccd305aaf8adb`,
attack `965cacc7355656ffc86352d2ab73458444dfbef68780670ae2839dc3363a7445`
(`s_inodes_per_group=32777`, group-0 `INODE_UNINIT`), safe
`ad341307fd9733d0d799bf89cd97b0872c4c6b276f0dd3cfaf341933708e9d15`
(`8192`, same group flag), 71474 image `real/evidence/image-hashes.txt`
(`s_reserved_gdt_blocks=65535`, group-0 `BLOCK_UNINIT`).

- Vulnerable + attack: ASan `heap-buffer-overflow`, `WRITE of size 4098`,
  0 bytes after a 4096-byte region, from
  `ext4_fs_init_inode_bitmap src/ext4_fs.c:404` called by
  `ext4_fs_get_block_group_ref src/ext4_fs.c:611`; allocation trace
  `ext4_buf_alloc`/`ext4_bcache_alloc`/`ext4_trans_block_get_noread`.
  This is the image-derived field driving the real allocator's buffer.
- Fixed + attack: `FS_INIT_RC=95` (`ENOTSUP`) from
  `ext4_sb_check_geometry()` at mount, before any bitmap write; no ASan.
- Vulnerable/fixed + safe: `BG_REF_RC=0`, `BG_FLAGS=4` after the UNINIT bit
  is cleared, no ASan — the same group-ref path with sane geometry.
- CVE-2025-71474 vulnerable: ASan `heap-buffer-overflow`, `READ of size 1`
  (bit-set read-modify-write) at 0 bytes past the same 4096-byte region in
  `ext4_bmap_bit_set` from `ext4_fs_init_block_bitmap src/ext4_fs.c:333`,
  reached via `ext4_fs_get_block_group_ref src/ext4_fs.c:601`. Fixed + same
  image: `FS_INIT_RC=95`, no ASan.
- Raw logs: `lab/frontier/lwext4shell/real/evidence/real-*-asan.out`; build,
  compile, mkfs, craft and image-hash records in the same directory. Neither
  ASan report carries attacker-chosen pointer bits or a command side effect.

### Adjacent live-object corruption (rung 4 mechanics, author-observed)

`bash lab/frontier/lwext4shell/run-victim.sh`: **9 PASS / 0 FAIL**, rc 0.
The vulnerable full library is rebuilt as a *plain* `-g -O0` build; the
pristine image is repatched only at `s_inodes_per_group=65537`
(`real/evidence/craft-victim.out`), so the image-derived memset length is
8193 bytes. The driver uses a one-entry bcache and calls the real
`ext4_fs_get_block_group_ref()`. Gdb stops at `src/ext4_fs.c:404` before the
store and at `:416` immediately after:

- before: `b.buf->bc = 0x7fffffffdc60` (live), `b.buf - b.data = 4112`
  bytes — `ext4_buf_alloc()` calls `malloc(itemsize)` then
  `calloc(sizeof(struct ext4_buf))`, so the real transaction-layer object is
  the next heap chunk;
- after: the zero fill covers `b.data+4096` through `b.data+8191`; the live
  `ext4_buf` begins at `b.data+4112` (`sizeof(struct ext4_buf)=144`, so it
  spans to `b.data+4255`) and `b.buf->bc = 0x0`. `x/8bx b.data+8192` starts
  `0xfe`, the bit byte chosen by the image's `inodes_per_group` low bits;
  that byte is ~4 KiB past `ext4_buf`, not inside it — only the zero fill
  hits the live object.
- without gdb the same image crashes the plain process with SIGSEGV in
  `ext4_trans_set_block_dirty()` (rc=139), the natural consumer of the
  now-zeroed `bc` pointer.

Conditions, stated plainly: one-entry bcache, ipg=65537, plain build,
debugger readback; no attacker-chosen address is written (the values are
zeros and a bit-set byte), and no command runs. `ext4_buf` is lwext4's own
live heap object, not a driver-supplied stand-in. Raw records:
`real/evidence/real-vuln-victim-gdb.out` and
`real/evidence/real-vuln-victim-plain.out`. Witness verification of this
new lane (tape 5605) was independently replayed by W273 from a clean archive
(tape 5616): ESTABLISHED AS LABELED, no grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w273-lwext4/detail.md`.

### CVE-2025-71474 chosen-bit write into live `bc` (rung 4, author-observed)

`bash lab/frontier/lwext4shell/run-gdt-bit.sh`: **11 PASS / 0 FAIL**, rc 0.
The vulnerable full library is rebuilt plain (`-g -O0`, separate
`build-vuln-gdt` tree); the driver and the 71474 patcher are the same real
ones. No ASan here: ASan faults at the first OOB byte (`data+4096`) and cannot
reach the header. `bit_max = 2 + s_reserved_gdt_blocks` (the super-in-group
bit plus one group descriptor), so the loop at `src/ext4_fs.c:333` sets bits
0..`bit_max`-1 in `block_bitmap.data`. The adjacent `ext4_buf` header starts
at `data+4112` and its `bc` field at `data+4152`, so bit index 33216 begins
that pointer's low byte. Gdb at `:332` (before the loop) and `:335` (after)
reads, always with `buf - data = 4112`:

| `s_reserved_gdt_blocks` | `bc` before | `bc` after | mask OR-ed |
| --- | --- | --- | --- |
| 8 (in-bounds control) | `0x7fffffffdc50` | `0x7fffffffdc50` | `0x00` |
| 33215 | `0x7fffffffdc40` | `0x7fffffffdc41` | `0x01` |
| 33216 | `0x7fffffffdc40` | `0x7fffffffdc43` | `0x03` |
| 33217 | `0x7fffffffdc40` | `0x7fffffffdc47` | `0x07` |
| 33218 | `0x7fffffffdc40` | `0x7fffffffdc4f` | `0x0f` |
| 33220 | `0x7fffffffdc40` | `0x7fffffffdc7f` | `0x3f` |
| 33222 | `0x7fffffffdc40` | `0x7fffffffdcff` | `0xff` |

The pointer's upper bytes are unchanged in every readback (addresses vary
with ASLR); the in-bounds `gdt=8` image mounts cleanly (`BG_REF_RC=0`, rc 0)
and every crafted gdt faults the plain process with rc 139. A large field
(`65535`) sets all bytes from `data+4096` through `data+8192`, yielding
`bc = 0xffffffffffffffff`. The fixed build rejects the same crafted geometry
at mount with `FS_INIT_RC=95` in the ASan lane above.

Ceiling: this is a bitwise OR into the low byte of a live pointer field,
chosen from eight masks by one on-disk 16-bit field — not an arbitrary
address, not a full pointer replacement, no command. The header's own `data`
pointer is overwritten in the same window and is the likely cause of the
plain fault; no benign marker execution is claimed. Raw records:
`real/evidence/real-vuln-71474-gdt-gdb.out`,
`real/evidence/real-vuln-71474-gdt-summary.out` and the per-image
`real-vuln-gdt-*-plain.out` logs. W273 replayed the earlier two lanes, not
this one.

### Named-field reach and the prefix-OR ceiling (2026-11-26 22:0xZ)

`bash run-gdt-layout.sh`: **5 PASS / 0 FAIL**, rc 0. Answering the DM's
falsifiable question, this reuses the same plain vulnerable build and reads
all 18 eight-byte words of the live adjacent `ext4_buf` before `:332` and
after `:335` for nine `s_reserved_gdt_blocks` values (8 control; 33215,
33222, 33230, 33247, 33919, 33926, 33990, 34000). The summarizer checks
every one of the 144 bytes against `after = before | ((1<<n)-1)` with
`n = clamp(2 + gdt - 8*k, 0, 8)` and `k` the byte offset from `data`:
`LAYOUT_MATCHED=9/9`, `NO_CHOSEN_PTR_MATCHED=8/8`.

Result: the bit-set reaches **13 named fields** of the adjacent live object —
`flags`, `lba`, `data`, `lru_prio`, `lru_id`, `refctr`, `bc`, `on_dirty_list`,
`lba_node`, `lru_node`, `dirty_node`, `end_write`, `end_write_arg` — not just
`bc`'s low byte. The in-bounds `gdt=8` control leaves all 144 bytes unchanged.
There is **no full-pointer primitive**: a fully covered byte becomes `0xff`
and the boundary byte only a low-bit prefix mask, so a fully covered pointer
is `0xffffffffffffffff` (unmapped) and a straddling pointer keeps its high
bytes. The NULL function pointer `end_write` can only become `2^k-1`
(`0x01`…`0xff`, `0xffff`, …), never a valid code address. `data` is either
untouched or `0xffffffffffffffff`; `bc` ranges from one prefix-masked low
byte (`0x…dc41`) to all-ones. No chosen address and no benign marker
execution. Records: `real/evidence/real-vuln-71474-gdt-layout-gdb.out`,
`real/evidence/real-vuln-71474-gdt-layout-summary.out`,
`real/summarize_gdt_layout.py`. Author-measured; witness replay pending.

## Grade and tractability

- **Rung 3 CONFIRMED:** GCC/Clang ASan on verbatim pinned excerpts *and*
  GCC ASan on the full real library mount path, with real allocator frames,
  image-derived input, fixed and safe controls.
- **Rung 4 DEMONSTRATED (author, lab build; independently replayed as
  labeled by W273):** with a crafted image and a plain full-library build,
  the image-derived zero fill overwrites the adjacent live `ext4_buf` at
  `data+4112`, zeroing its `bc` pointer; the natural consumer then faults.
  The image-chosen `0xfe` bit byte sits at `data+8192`, ~4 KiB past that
  object — it is not written into `ext4_buf`. Earlier stand-in canary
  observation (`0xfe`/`0xfc` at `block+4097`) stands as the smaller
  4098-byte case. Conditions: one-entry bcache, ipg=65537, debugger
  readback; no chosen-address pointer control. W273 replay confirmed the
  adjacency and bit-byte provenance under ASLR; no grade change.
- **Rung 4 DEMONSTRATED (CVE-2025-71474 sibling, author only):** the real
  block-bitmap bit-set loop ORs an image-selected mask (`0x01`..`0xff`) into
  the low byte of the adjacent live `ext4_buf.bc`; the in-bounds `gdt=8`
  control leaves it untouched. A follow-up probe shows the same loop reaches
  13 named fields of that object, but the byte-level prefix-OR model rules
  out a chosen address: covered bytes become `0xff`, the boundary byte a
  low-bit prefix mask, and the `end_write` function pointer only `2^k-1`.
  Chosen bits, not a chosen address; not independently replayed, and the
  overall grade and r5 ceiling are unchanged.
- **Not rung 5:** no live network target, no benign command side effect and
  no attacker-chosen address; debugger-forced inspection stays rung-4
  mechanics.

Next bounded lane: seek a chosen-address pointer primitive or a live
loopback target with a benign command side effect; neither is measured here.
Do not relabel either adjacent-object byte write as remote code execution.
Both CVEs are staged as separate claims: 71473 zero-fills `bc` from
`s_inodes_per_group`, 71474 ORs a chosen mask into its low byte from
`s_reserved_gdt_blocks`.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning (W205 lesson): no lwext4 brief, lab or window
existed. No external host was probed; only NVD and public raw-source fetches.

## Witness W273 (independent replay, 2026-11-26 14:42Z)

From `git archive cbadc189` with all staged evidence deleted, the unmodified
`replay-clean.sh` reproduced runner hashes `fd9e7d3e…`, `e32862ed…`,
`80587918…`, `TOTAL: 31 PASS / 0 FAIL`, `REAL_PASS=17 REAL_FAIL=0`,
`VICTIM_PASS=9 VICTIM_FAIL=0`, `REPLAY_RC=0`. Fresh ASan again reported
`WRITE of size 4098` at 0 bytes past the 4096-byte region, frames
`ext4_fs.c:404` ← `:611`; fresh gdb again showed non-null `bc`, delta 4112
before the store and `bc = 0x0` after it, with `0xfe` at `data+8192`.
Counterexample hunt: three ASLR-on runs kept the delta and the live/zeroed
`bc`; an image with `ipg=65539` produced `0xf8` instead, showing the bit byte
is image-derived; no command, wire or pointer-control call exists in the
driver. Verdict ESTABLISHED AS LABELED, no grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w273-lwext4/detail.md`. The two NITs in
that detail (the byte-offset wording above and `replay-clean.sh` DEST/hash
reporting) were repaired after the verdict; neither changed the evidence.
