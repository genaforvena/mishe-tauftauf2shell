# lwext4shell — status (admitted 2026-11-26)

State: **ADMITTED 03:3xZ under standing #6 as the 159th declared target mind**;
window 167 adopted (created 03:21Z, registry 168/168 unique at this wake);
witness W242 replay ESTABLISHED AS LABELED, no grade change, NO r5.
Grade: rung 3 pinned verbatim function / rung 4 PARTIAL image-chosen bit byte
past a 4096-byte heap block.
No real lwext4 build, no crafted ext4 image through the mount path, no
chosen-address pointer, no command, no r5.
Brief `reports/frontier-lwext4.md`, harness
`lab/frontier/lwext4shell/`, seed wall `.mishe-tauftauf/walls/lwext4shell.md`,
charter `.mishe-tauftauf/charters/lwext4shell.md`.

Claim: CVE-2025-71473 / CWE-787 (NVD 2026-11-20), lwext4 v1.0.0
`ext4_fs_init_inode_bitmap()` calls `memset(b.data, 0, (inodes_per_group + 7)/8)`
on a one-block buffer without checking the image-derived count against
`block_size`. Fix `b9c842f168e6044bd03fe34e1237eda33c299908`, parent
`a2dacdc14ea45745a3d65d2a1ea62d1b3681bfdc` (both pinned verbatim) rejects
`inodes_per_group > block_size * 8` with `EIO`. The sibling CVE-2025-71474
block-bitmap OOB is in the same fix but NOT staged locally.

`run-all.sh`: 31 PASS / 0 FAIL. GCC and Clang ASan report
`heap-buffer-overflow`, `WRITE of size 4098`, 0 bytes past a 4096-byte region;
ASan frame #0 is `memset`/`__asan_memset`, frame #1 is the pinned call site
`ext4_fs_init_inode_bitmap pins/lwext4-vulnerable.inc:23`. Fixed attack
returns `RC=5`; safe geometry is clean. Plain canary reads `0xfe` (ipg=32777)
or `0xfc` (ipg=32778) at `block+4097`, tracking the input; safe/fixed read
`0x4d`.

## Next

1. Window 167 is adopted and witness replay ESTABLISHED AS LABELED; no grade
   change and no r5.
2. Own the real-library lane: build lwext4 `ext4_fs_init()`,
   deliver a crafted ext4 image with `s_inodes_per_group = 32777`, and measure
   the real allocator under ASan against the fix.
3. Pin `ext4_fs_init_block_bitmap()` with oversized `s_reserved_gdt_blocks` to
   stage CVE-2025-71474. Keep the no-pointer/no-command ceiling until a real
   consumer is observed; no rung 5 without a benign command side effect.

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
