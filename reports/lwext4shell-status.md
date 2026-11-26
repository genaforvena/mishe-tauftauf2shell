# lwext4shell — status (admitted 2026-11-26)

State: **ADMITTED 03:3xZ under standing #6 as the 159th declared target mind**;
window 167 adopted; witness W242 replay ESTABLISHED AS LABELED for the earlier
stand-in harness only, no grade change and NO r5. Real-library lane staged
2026-11-26 14:1xZ: `run-real.sh` 17 PASS / 0 FAIL; adjacent-object lane
`run-victim.sh` 9 PASS / 0 FAIL.
Grade: **rung 3 CONFIRMED on the real library / rung 4 DEMONSTRATED by the
author in the lab build (witness replay owed, no r5)**. Image-derived
`ipg=32777` gives ASan `WRITE of size 4098` past the real 4096-byte bcache
buffer; `ipg=65537` in a plain build zeroes the adjacent live `ext4_buf.bc`
pointer and faults its natural consumer; fixed rejects both crafted images
with `ENOTSUP=95`. No chosen-address pointer, no command.
Brief `reports/frontier-lwext4.md`, harness
`lab/frontier/lwext4shell/`, seed wall `.mishe-tauftauf/walls/lwext4shell.md`,
charter `.mishe-tauftauf/charters/lwext4shell.md`.

Claim: CVE-2025-71473 / CWE-787 (NVD 2026-11-20), lwext4 v1.0.0
`ext4_fs_init_inode_bitmap()` calls `memset(b.data, 0, (inodes_per_group + 7)/8)`
on a one-block buffer without checking the image-derived count against
`block_size`. Fix `b9c842f168e6044bd03fe34e1237eda33c299908`, parent
`a2dacdc14ea45745a3d65d2a1ea62d1b3681bfdc` (both pinned verbatim) rejects
`inodes_per_group > block_size * 8` with `EIO`. The sibling CVE-2025-71474
block-bitmap OOB is in the same fix and is now staged in the real lane.

`run-all.sh`: 31 PASS / 0 FAIL. GCC and Clang ASan report
`heap-buffer-overflow`, `WRITE of size 4098`, 0 bytes past a 4096-byte region;
ASan frame #0 is `memset`/`__asan_memset`, frame #1 is the pinned call site
`ext4_fs_init_inode_bitmap pins/lwext4-vulnerable.inc:23`. Fixed attack
returns `RC=5`; safe geometry is clean. Plain canary reads `0xfe` (ipg=32777)
or `0xfc` (ipg=32778) at `block+4097`, tracking the input; safe/fixed read
`0x4d`.

## Next

1. Witness replay of `run-real.sh` (tape 5602) and `run-victim.sh` (tape
   5605) is owed: these are author observations in the real library, not
   covered by W242's stand-in-harness verdict.
2. Only a chosen-address pointer primitive or a benign command side effect
   on a live loopback target could open rung 5; neither is measured here.
3. Do not relabel the adjacent-object byte write as remote execution.

## Receipts

- Provisioning 2026-11-26 03:1xZ: read-only NVD API, upstream issue/PR and raw
  GitHub source fetches. No probe of any external host.
- Author run 2026-11-26 03:15Z: `bash run-all.sh` returned
  `TOTAL: 31 PASS / 0 FAIL`, rc 0; raw logs in
  `lab/frontier/lwext4shell/out/`.
- In-tree `run-witness.sh` 2026-11-26 03:16Z: all five pins exact,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, `WITNESS REPLAY PASS`,
  `TOTAL: 31 PASS / 0 FAIL`, rc 0.
- Clean archive 2026-11-26 03:18Z: `git archive b4a7acd4
  lab/frontier/lwext4shell` into `/tmp/w242-lwext4-clean`; unmodified
  `run-witness.sh` (sha256
  `42d5b68df4e6c4d5ffc28011da2fd814fceeafeb636568f95a746d0bb30838f5`,
  identical in-tree) returned `WITNESS REPLAY PASS`, five pins exact,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, `TOTAL: 31 PASS / 0 FAIL`, rc 0.
- Window created 2026-11-26T03:21Z on the inner tmux socket: index 167,
  session `mishe-tauftauf2shell-current`, panes `%336`/`%337`, `dead=0`,
  captures 15/2 lines, both processes live (`tail -F` status above,
  `plant_view --role lwext4shell --output --log --follow` below). Registered
  in `.mishe-tauftauf/operator/window-registry.json` at 03:21:24Z (168
  windows / 168 unique names). No route, resolver key or wake unit added by
  frontier; no unit/sync edit (person-reserved).
- Operator DM 4767 at 03:21Z states the window already exists and the target
  is staged, not admitted. Witness DM 4768 at 03:21Z requests independent
  replay and verification of the labeled grade.

- Witness W242 independent replay (03:25Z): unmodified wrapper from worktree
  and a second clean `git archive b4a7acd4` tree at `/tmp/w242-clean`
  (sha256 `42d5b68df4e6c4d5ffc28011da2fd814fceeafeb636568f95a746d0bb30838f5`,
  identical in both), both `REPLAY_PASS=6/0`, `TOTAL: 31 PASS / 0 FAIL`, rc 0;
  raw upstream v1.0.0 / b9c842f1 full and excerpt hashes exact, EIO guard
  present; GCC+Clang ASan, fixed/safe controls and `0xfe`/`0xfc` vs `0x4d`
  readback reobserved. Verdict ESTABLISHED AS LABELED, no grade change,
  NO r5. Detail: `.mishe-tauftauf/artifacts/witness-w242-lwext4shell/detail.md`.

- Operator admission 2026-11-26 03:3xZ under standing #6: unmodified
  `run-witness.sh` re-run in-tree and from a second clean `git archive b4a7acd4`,
  both `REPLAY_PASS=6 REPLAY_FAIL=0`, rc 0, no grade change. Window 167 adopted;
  no route, resolver, unit or sync edit (person-reserved). hy4-flash route and
  three generated wake units remain missing; omp-only and doctor stay RED.

## Real mount lane receipt (2026-11-26 14:1xZ)

Public `git clone` of lwext4, detached worktrees at
`890484c72dbb321535127625c3686e51f1f424b9` (v1.0.0) and
`b9c842f168e6044bd03fe34e1237eda33c299908` (fix); both full libraries built
under GCC ASan `-O0`. `real/mount_driver.c` drives the library's own file
block device, real `ext4_fs_init()`, real bcache and real
`ext4_fs_get_block_group_ref()`. Base image comes from the library's
unmodified `ext4_mkfs()`; two patch scripts edit only superblock and group
descriptor bytes. `bash run-real.sh` returned `REAL_PASS=17 REAL_FAIL=0`,
rc 0: vulnerable attack ASan `WRITE of size 4098` at 0 bytes past the
4096-byte bcache buffer from `src/ext4_fs.c:404` via `:611`; fixed attack
`FS_INIT_RC=95` from mount-time geometry validation; vulnerable/fixed safe
`BG_REF_RC=0`; 71474 vulnerable ASan OOB bit-set from `src/ext4_fs.c:333`
via `:601`; fixed 71474 `FS_INIT_RC=95`. Logs:
`lab/frontier/lwext4shell/real/evidence/`; hashes and commands:
`lab/frontier/lwext4shell/PROVENANCE.md`. Grade change from this lane:
rung 3 harness → rung 3 real library; rung 4 advanced by the lane below.

## Adjacent-object receipt (2026-11-26 14:1xZ)

`bash run-victim.sh` returned `VICTIM_PASS=9 VICTIM_FAIL=0`, rc 0. Plain
vulnerable full library, image patched only at `s_inodes_per_group=65537`,
one-entry bcache; gdb at `src/ext4_fs.c:404` shows live `b.buf->bc =
0x7fffffffdc60` with `b.buf - b.data = 4112`, at `:416` shows `bc = 0x0`,
zeros at `b.data+4096` and `0xfe` at `b.data+8192`; an ungdb'd plain process
faults in `ext4_trans_set_block_dirty()` (rc=139). Logs:
`lab/frontier/lwext4shell/real/evidence/real-vuln-victim-{gdb,plain}.out`.
Grade advanced from rung 4 PARTIAL to rung 4 demonstrated by the author,
conditions as stated; ESTABLISHED needs witness replay (tape 5605). NO r5.
