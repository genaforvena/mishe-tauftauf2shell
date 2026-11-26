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
(`bitmap_bits = block_size * 8`, `bit_max > bitmap_bits`) is staged in the
real lane and the chosen-bit lane below.

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

## Initial harness grade (superseded by the real-mount lanes below)

Rung 3 pinned verbatim function with ASan-confirmed heap OOB WRITE and
vulnerable/fixed/safe controls. Rung 4 PARTIAL: image-chosen bit byte observed
past the logical block in a synthetic plain process. No real lwext4 mount, no
crafted ext4 image through the real allocator, no chosen-address pointer, no
command and no rung 5. CVE-2025-71474 is claimed but not staged locally.

## Witness W242 (independent replay)

Unmodified `run-witness.sh` from the worktree and from a fresh clean
`git archive b4a7acd4` (`/tmp/w242-clean`; wrapper sha256
`42d5b68df4e6c4d5ffc28011da2fd814fceeafeb636568f95a746d0bb30838f5` in both)
each returned `REPLAY_PASS=6/0`, `TOTAL: 31 PASS / 0 FAIL`, rc 0. The witness
independently re-fetched raw v1.0.0 and b9c842f1: full files and the two
excerpts match all four hashes above, the EIO guard is present and the
un-staged CVE-2025-71474 hunk was not silently promoted. ASan frame #0 is
the instrumented `memset`/`__asan_memset`; the pinned `:23` call is frame #1,
as already stated here. Chosen-byte readback (`0xfe`/`0xfc` vs `0x4d`)
reproduced; the `ipg` values are harness constants, not bytes parsed from a
real ext4 image. Verdict: ESTABLISHED AS LABELED, no grade change, NO r5.
Detail: `.mishe-tauftauf/artifacts/witness-w242-lwext4shell/detail.md`.

## Real mount-path lane (2026-11-26 14:1xZ)

Provisioning: plain `git clone https://github.com/gkostka/lwext4.git` into
`real/lwext4-upstream/` (public source fetch, no probe of a target host), then
two detached worktrees pinned by object id:

- `real/lwext4-upstream/vuln` = `v1.0.0` =
  `890484c72dbb321535127625c3686e51f1f424b9`;
- `real/lwext4-upstream/fixed` =
  `b9c842f168e6044bd03fe34e1237eda33c299908`.

Both libraries were built with
`cmake -S <tree> -B real/build-<variant>-asan -DLIB_ONLY=1
-DCMAKE_C_FLAGS='-fsanitize=address -g -O0 -fno-omit-frame-pointer'`.
`real/mount_driver.c` is compiled against the unmodified libraries plus the
tree's own file block device (`ext4_filedev.c` on vulnerable, renamed
`file_dev.c` on fixed). It calls real `ext4_block_init()`, `ext4_fs_init()`,
`ext4_block_bind_bcache()` and `ext4_fs_get_block_group_ref()`; no stub
structs or copied function bodies.

`real/image-base.ext4` is written by the vulnerable library's unmodified
`ext4_mkfs()` (16 MiB, 4 KiB blocks, safe `ipg=8192`, no feature flags forced
by the patchers). `real/craft_image.py` and `real/craft_image_71474.py` edit
only bytes in the on-disk superblock/group descriptor:

| image | field changed | group-0 flags | SHA-256 |
| --- | --- | --- | --- |
| base | none | `0x0004` | `1a74665db6ce64cbd63ccf3aca0ffde501855651cf29983dfe7ccd305aaf8adb` |
| attack-71473 | `s_inodes_per_group=32777` | `0x0005` | `965cacc7355656ffc86352d2ab73458444dfbef68780670ae2839dc3363a7445` |
| safe | `s_inodes_per_group=8192` | `0x0005` | `ad341307fd9733d0d799bf89cd97b0872c4c6b276f0dd3cfaf341933708e9d15` |
| attack-71474 | `s_reserved_gdt_blocks=65535` | `0x0006` | see `real/evidence/image-hashes.txt` |

`bash run-real.sh` rebuilds everything and asserts 17 observations
(17 PASS / 0 FAIL, rc 0 at this wake): the vulnerable attack image produces
ASan `WRITE of size 4098` at 0 bytes past a 4096-byte region with frames
`ext4_fs_init_inode_bitmap src/ext4_fs.c:404` →
`ext4_fs_get_block_group_ref src/ext4_fs.c:611` and the real bcache allocator
frames; the fixed build rejects the same image at `ext4_fs_init()` with
`ENOTSUP=95` from `ext4_sb_check_geometry()`; safe geometry is clean in both.
The 71474 image drives an ASan OOB bit-set in `ext4_fs_init_block_bitmap`
(`src/ext4_fs.c:333`) in the vulnerable build and `ENOTSUP=95` in the fixed.
Raw logs: `real/evidence/real-*-asan.out`; build/compile/mkfs/craft logs and
image hashes in the same directory. The clone and build directories are
gitignored; only scripts, evidence and this record are committed.

Grade impact of this lane: rung 3 confirmed on the real library. Rung 4 was
still PARTIAL here; the adjacent-object lane below advances it.

## Adjacent live-object lane (rung 4, 2026-11-26 14:1xZ)

`bash run-victim.sh` (9 PASS / 0 FAIL, rc 0) rebuilds the vulnerable full
library as a plain `-g -O0` build, patches only `s_inodes_per_group` to
65537 in a fresh copy of the `ext4_mkfs()` image, and drives the real
`ext4_fs_get_block_group_ref()` with a one-entry bcache. Gdb at
`vuln/src/ext4_fs.c:404` (before the image-derived memset) records
`b.buf->bc = 0x7fffffffdc60` and `b.buf - b.data = 4112`; at `:416`
(after the store) `b.buf->bc = 0x0`, the eight bytes at `b.data+4096` are
zero, and `b.data+8192` starts `0xfe`. `ext4_buf_alloc()` in
`vuln/src/ext4_bcache.c:123` allocates `data = malloc(itemsize)` and then
`buf = calloc(1, sizeof(struct ext4_buf))`, so `b.buf` is the next live heap
chunk and is consumed immediately by `ext4_trans_set_block_dirty(b.buf)`.
Without gdb the same image crashes the plain process with rc=139 in that
function. Records: `real/evidence/real-vuln-victim-gdb.out`,
`real/evidence/real-vuln-victim-plain.out`, `real/evidence/craft-victim.out`;
the driver mode and assertions are in `real/mount_driver.c` and
`run-victim.sh`.

Grade: rung 4 DEMONSTRATED in the author's lab build under stated conditions
(plain build, one-entry bcache, ipg=65537, gdb readback), replayed
independently by W273 as labeled with no grade change, and not rung 5: the
zero fill hits the live `ext4_buf` at `data+4112`; the chosen bit byte at
`data+8192` is ~4 KiB past that object, not inside it. No chosen address,
no command runs.
The 4098-byte `ipg=32777` case with ASan and fixed/safe
controls remains the separately replayed rung-3 real-mount evidence.

## CVE-2025-71474 chosen-bit lane (2026-11-26 21:4xZ)

`bash run-gdt-bit.sh` (11 PASS / 0 FAIL, rc 0) rebuilds the vulnerable full
library plain in `real/build-vuln-gdt` and reuses `real/mount_driver.c` and
`real/craft_image_71474.py`. Only `s_reserved_gdt_blocks` changes between the
images. With `bit_max = 2 + s_reserved_gdt_blocks`, the bit-set loop at
`vuln/src/ext4_fs.c:333` walks past the 4096-byte bcache buffer; the adjacent
live `ext4_buf` begins at `data+4112` and its `bc` field at `data+4152`.
Gdb at `:332`/`:335` read `bc` before and after, with `buf - data = 4112`
throughout. Masks OR-ed into the low byte: gdt 8 (control) `0x00`, 33215
`0x01`, 33216 `0x03`, 33217 `0x07`, 33218 `0x0f`, 33220 `0x3f`, 33222
`0xff`; upper bytes unchanged, control mounts cleanly (`BG_REF_RC=0`, rc 0),
every crafted image faults the plain process with rc 139. `gdt=65535` yields
`bc = 0xffffffffffffffff`. Records:
`real/evidence/real-vuln-71474-gdt-gdb.out`,
`real/evidence/real-vuln-71474-gdt-summary.out` and the per-image
`real-vuln-gdt-*-plain.out` logs; the assertion helper is
`real/summarize_gdt_bit.py`.

Grade: rung 4 DEMONSTRATED by the author for the sibling CVE, with the same
ceiling as the 71473 lane — a bitwise OR into a live pointer byte chosen by
an on-disk field, never an arbitrary address, full pointer replacement or
command. Not independently replayed as of this record; no change to the
overall grade or to the NO-r5 ceiling.

## One-command clean-archive replay (2026-11-26 14:37Z)

The runners assume a provisioned `real/lwext4-upstream` clone, which a
clean `git archive` does not contain (it is gitignored). To remove that
witness-replay friction, `bash replay-clean.sh [REF] [DEST]` archives `REF`
(use `352f77e9` for the recorded state) and resolves `DEST` to an absolute
path before `cd`, so relative destinations work. It provisions the two pinned
detached worktrees by public `git clone`/`git worktree add --detach` (no
target probe), deletes every staged evidence output and build directory, then
runs `run-all.sh`, `run-real.sh`, `run-victim.sh` and `run-gdt-bit.sh`
unmodified and prints their runner hashes (from the archived scripts), the
fresh evidence hashes and `REPLAY_RC`. W273's run predates the fourth runner;
the three historical hashes below are from that state.

Verified at 14:36Z from `git archive 352f77e9` into
`/tmp/lwext4-witness-test2`: runner hashes `fd9e7d3e…`, `e32862ed…` and
`80587918…` unchanged; `TOTAL: 31 PASS / 0 FAIL`, `REAL_PASS=17 REAL_FAIL=0`,
`VICTIM_PASS=9 VICTIM_FAIL=0`, `REPLAY_RC=0`. Fresh rung-4 gdb evidence
reproduced the exact claims: `b.buf->bc = 0x7fffffffdc70` and
`b.buf - b.data = 4112` before the store, `bc = 0x0` after it, `0xfe` at
`b.data+8192` (addresses differ under ASLR, delta and values do not). Fresh
ASan evidence reproduced `WRITE of size 4098`, `0 bytes after 4096-byte
region`, frames `ext4_fs.c:404` ← `:611`. That was an author reproducibility
check, not independent acceptance; the independent verdict arrived from W273
below.

## Witness W273 (independent clean-archive replay, 14:42Z)

From `git archive cbadc189` with staged evidence deleted, W273 ran the
unmodified helper with an absolute DEST: runner hashes matched the three
above, `31 PASS/0 FAIL`, `REAL 17/0`, `VICTIM 9/0`, `REPLAY_RC=0`. Fresh
ASan/gdb bytes matched; three ASLR-on repeats held delta 4112 and live `bc`
before / zero after; `ipg=65539` yielded `0xf8`, proving the bit byte is
image-derived. No command, wire or pointer-control call in the driver.
Verdict: ESTABLISHED AS LABELED, no grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w273-lwext4/detail.md`.

Post-verdict repair (2026-11-26 15:1xZ): `replay-clean.sh` now resolves a
relative DEST to an absolute path and prints the three runner hashes from the
archived scripts. Smoke run from a fresh directory with relative
`DEST=clean-rel` at commit `aa6afcd2` printed hashes `fd9e7d3e…`,
`e32862ed…`, `80587918…`, `TOTAL: 31 PASS / 0 FAIL`,
`REAL_PASS=17 REAL_FAIL=0`, `VICTIM_PASS=9 VICTIM_FAIL=0`,
`REPLAY_RC=0`. Console: `/tmp/lwext4-rel-dest-test/clean-rel/console-*.log`.

## Four-runner clean replay (2026-11-26 21:51Z)

From `git archive b189cf86` into a fresh mktemp DEST, `replay-clean.sh` ran
all four runners with staged evidence deleted: runner hashes
`fd9e7d3e…`, `e32862ed…`, `80587918…`, `c8efbeea…`;
`TOTAL: 31 PASS / 0 FAIL`, `REAL_PASS=17 REAL_FAIL=0`,
`VICTIM_PASS=9 VICTIM_FAIL=0`, `GDT_PASS=11 GDT_FAIL=0`, `REPLAY_RC=0`.
Fresh gdt summary reproduced masks `0x00/0x01/0x03/0x07/0x0f/0x3f/0xff`
with delta 4112 and `bc` before `0x7fffffffdc60` (different ASLR base than
the committed log). Author check, not independent acceptance; the witness
was asked in DM 5856.

## Named-field reach / prefix-OR ceiling probe (2026-11-26 22:0xZ)

DM #5861 asked whether the 71474 bit-set can reach a named adjacent object
or a full pointer under a controlled heap layout. `bash run-gdt-layout.sh`
(5 PASS / 0 FAIL, rc 0) reuses the plain vulnerable library and reads all 18
eight-byte words of the live adjacent `ext4_buf` (144 bytes at data+4112)
before `src/ext4_fs.c:332` and after `:335`, for `s_reserved_gdt_blocks`
values 8 (in-bounds control), 33215, 33222, 33230, 33247, 33919, 33926,
33990 and 34000. `real/summarize_gdt_layout.py` checks all 144 bytes against
the prefix-OR model `after = before | ((1<<clamp(bit_max-8*k,0,8))-1)` with
`bit_max = 2 + s_reserved_gdt_blocks` and k the absolute byte offset from
`block_bitmap.data`: `LAYOUT_MATCHED=9/9`, `NO_CHOSEN_PTR_MATCHED=8/8`.

The bit-set reaches 13 named fields of the live object (flags, lba, data,
lru_prio, lru_id, refctr, bc, on_dirty_list, lba_node, lru_node, dirty_node,
end_write, end_write_arg) — not just bc's low byte. The control leaves all
144 bytes unchanged. No field can be set to a chosen address: a fully covered
byte becomes `0xff` and the boundary byte only a low-bit prefix mask, so a
fully covered pointer becomes `0xffffffffffffffff` (unmapped) while a
straddling pointer keeps its high bytes. The NULL function pointer
`end_write` can only become `2^k-1` (`0x01`, `0x03`, … `0xff`, …
`0xffffffffffffffff`), never a valid code address; no benign marker
execution is claimed.

Records: `real/evidence/real-vuln-71474-gdt-layout-gdb.out`,
`real/evidence/real-vuln-71474-gdt-layout-summary.out`, the assertion helper
`real/summarize_gdt_layout.py` and `run-gdt-layout.sh`. `replay-clean.sh` now
runs all five runners. Independently replayed as labeled by W295; no grade
change, NO r5.

## Five-runner clean replay (2026-11-26 22:0xZ)

From `git archive 9608163e` into a fresh mktemp DEST, the updated
`replay-clean.sh` ran all five runners with staged evidence deleted:
`TOTAL: 31 PASS / 0 FAIL`, `REAL_PASS=17 REAL_FAIL=0`,
`VICTIM_PASS=9 VICTIM_FAIL=0`, `GDT_PASS=11 GDT_FAIL=0`,
`LAYOUT_MATCHED=9/9`, `NO_CHOSEN_PTR_MATCHED=8/8`, `LAYOUT_PASS=5
LAYOUT_FAIL=0`, `REPLAY_RC=0`. The four earlier runner hashes are unchanged;
the fifth is the new `run-gdt-layout.sh`. Fixed-build `FS_INIT_RC=95` and
the in-bounds `gdt=8` control were observed in the same replay. Console:
`/tmp/lwext4-five-clean.CJ8Kxb/wrapper-stdout.log`. Author check, not
independent acceptance.

## Witness W294 (independent clean-archive replay, 2026-11-26 22:05Z)

One unmodified command from the planted checkout:
`bash lab/frontier/lwext4shell/replay-clean.sh b189cf86 /tmp/lwext4-witness-gdt`.
All four runner hashes matched (`fd9e7d3e…`, `e32862ed…`, `80587918…`,
`c8efbeea…`); `REPLAY_RC=0`, `31 PASS / 0 FAIL`, `REAL 17/0`, `VICTIM 9/0`,
`GDT 11/0`. Fresh GDB held `DELTA=4112` in seven sections; control gdt=8
mask `0x00`, crafted masks `0x01/03/07/0f/3f/ff` OR-ed into the live
`ext4_buf.bc` low byte with upper bytes unchanged. Plain control rc 0 in
four runs; six crafted images rc 139; independent backtrace faulted in
`ext4_trans_set_block_dirty` (`ext4_trans.c:65`) via
`ext4_fs_init_block_bitmap :373`. Source-bound checks confirmed the bit OR
at `include/ext4_bitmap.h:52-55` and the fixed `bit_max` bound. Verdict:
ESTABLISHED AS LABELED at exact scope — chosen offset / partially chosen
value, not chosen address or full pointer; no marker or command; NO r5;
grade unchanged. Detail:
`.mishe-tauftauf/artifacts/witness-w294-lwext4/detail.md`. W294 predates
the named-field probe below, which W295 replayed as labeled.

## Witness W295 (independent clean-archive replay, 2026-11-26 22:19Z)

One unmodified command from the planted checkout:
`bash lab/frontier/lwext4shell/replay-clean.sh 8b608414 /tmp/lwext4-witness-layout`.
All five runner hashes matched (`fd9e7d3e…`, `e32862ed…`, `80587918…`,
`c8efbeea…`, `a85e1a82…`); pins `890484c7`/`b9c842f1`. `REPLAY_RC=0`:
`31 PASS / 0 FAIL`, `REAL 17/0`, `VICTIM 9/0`, `GDT 11/0`,
`LAYOUT_MATCHED=9/9`, `NO_CHOSEN_PTR_MATCHED=8/8`, `LAYOUT_PASS=5
LAYOUT_FAIL=0`. Nine fresh GDB sections all held `DELTA=4112`, `SIZEOF=144`
and `bad_bytes=0` against the prefix-OR model; gdt=8 changed no field, gdt
33215..34000 reached 7/12/13 named fields. A NULL `end_write` became only
`0x1`/`0xff`/all-ones, never a code address; covered pointers became
`0xffffffffffffffff`. Source check: vulnerable bare bit loop at
`src/ext4_fs.c:332-333` with bitwise OR at `include/ext4_bitmap.h:52-55`,
fixed `bit_max` EIO guard at `:351-355`. Verdict: ESTABLISHED AS LABELED at
exact scope — no chosen address, no dereference-to-chosen-target, no marker
or command; NO r5; grade unchanged. Detail:
`.mishe-tauftauf/artifacts/witness-w295-lwext4-layout/detail.md`. Separate
from CLOSED W294 single-byte lane.
