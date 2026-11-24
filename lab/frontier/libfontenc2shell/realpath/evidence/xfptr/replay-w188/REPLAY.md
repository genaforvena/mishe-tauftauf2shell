# W188 clean-archive replay of W186/W187 (2026-11-24, 01:52-01:57Z)

Source: `git archive HEAD lab/frontier/libfontenc2shell` at HEAD `7091755`,
extracted to `/tmp/lf2s-w188-clean` (no working-tree files, no build output).
`LF2S_SRC=/tmp/libfontenc-src sh ./realpath/rebuild.sh` rebuilt all eight
libraries from the pinned revisions and reproduced the W155/W156 matrix
(`rebuild.log`): vulnerable and 1.1.9 crafted ASan `rc=1/asan_logs=1`;
fixed, 1.1.10 and all safe cases `rc=0/0`.

## W186 — exact

`bash .../realpath/evidence/fptr/run.sh` (`fptr-run.log`, `vuln-crafted.txt`,
`vuln-safe.txt`, `fixed-crafted.txt`, `address.txt`) reproduced the
chosen-address execution: `benign_marker=0x4011d6`, vulnerable crafted
`m3 recode=0x4011d6`, `BENIGN_MARKER_EXECUTED`, return `0xabcd1234`, every
other mapping on the library recode, rc 0; vulnerable safe and fixed crafted
show no marker. No layout difference was needed for this harness because its
runner already pins ASLR off and uses a non-PIE marker.

## W187 — first replay failed, cause found, runner repaired

The first clean replay of the committed `run-xfptr.sh` did **not** reproduce
the overwrite (`failed-hardcoded-n3.txt`): calibration logged
`buffer=0x555555a53540 m3=0x55555584b790 idx=-1064656`. The runner hardcoded
`LF_FIND_MAP n=3` as the post-buffer target; in this layout maps n=1..4 are
allocated before the buffer and n=5 is the first map after it. All four
crafted cases left the pointer untouched.

Two intermediate repairs also failed and are kept:

- `failed-recode-reinitialized.txt`: dynamic selection of n=5 gave
  `idx=65584` but the pointer stayed at the library address, because mapping
  n=5's own `ENDMAPPING` reinitialises `recode` after the first two word
  writes. The word mappings must come after the target's initialization.
- `failed-decoy-order.txt`: eight decoys all using `0x0000` moved the buffer
  allocation from mapping 2 to the first word mapping; the first post-buffer
  map became n=10, and the runner's explicit assertion
  `TARGET n10 NOT BEFORE WORD WRITES (DECOYS=8)` stopped the run.

The final runner keeps eight decoys but restores decoy #2's `0xff00` code,
which allocates the 131072-byte buffer during mapping 2, and selects the
first `n>=3` map whose address exceeds the buffer. Final replay
(`final-run.stdout`, `matrix-repaired.txt`, four `*.xvfb.txt`):

```
buffer=0x555555a53540 target=n5 m3=0x555555a73590 marker=0x7ffff7fb9159 idx=65584 from=0xfe34 0xfe35 0xfe36 0xfe37 words=9159 f7fb 7fff 0000
vuln-crafted-a marker_calls=0 m3_recode=0x7ffff7fb9159 recode_targets=0x55555584b4a0,
vuln-crafted-b marker_calls=0 m3_recode=0x7ffff7fb9159 recode_targets=0x55555584b4a0,
vuln-safe marker_calls=0 m3_recode=0x7ffff7fb2885 recode_targets=0x55555584b4a0,
fixed-crafted marker_calls=0 m3_recode=0x7ffff7fb2891 recode_targets=0x55555584b4a0,
```

The target map number differs from W187's original run (n=5 instead of n=3),
but the offset from the buffer is the same 0x20050 and the chosen address
lands exactly in `recode`. In every case `FontEncRecode` is invoked only on
m1 (`0x55555584b4a0`), the map allocated before the buffer: zero marker
calls, no crash.

This is an author clean-archive replay of the repaired test harness, not a
witness verdict. It confirms the W187 memory-control claim and its consumer
limit under a second heap layout; it adds no command, no remote input, no
privileged context and no rung-5 evidence. No Xvfb was left running.
