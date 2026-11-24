# REPLAY — fontforge2shell W196 (2026-11-24 04:42Z)

Clean-archive replay of the staged evidence from commit `e5e4a65`
(brief, harness, pinned source and fix patch are all tracked; build
artifacts are intentionally untracked).

```sh
git archive e5e4a65 | tar -x -C "$TMP"
cd "$TMP/lab/frontier/fontforge2shell" && sh run-all.sh > replay-all.log 2>&1
grep -E '^asan-|plain-|normalized gdb' replay-all.log | sha256sum
```

Result: 5/5 expected return codes — `asan-attack 1`, `asan-fixed 0`,
`asan-safe 0`, `plain-attack 134`, `plain-fixed 0` — and the same gdb
bytes `4d 49 53 00` at `encs-4`. The normalized transcript hash
(`grep -E '^asan-|plain-|normalized gdb' … | sha256sum`) is byte-exact
between the author's evidence log and the replay:

`56fd8adaa060730e30174414d17ac0c0a55cdd7badf3a516d498821e465633bb`

Raw `evidence/gdb.txt` hashes differ only because of ASLR/PID/address
tokens (`f6af356a…7992` author, `1c389b1b…68d844` replay); the normalized
bytes line and the RC matrix are identical. Harness sha256 is identical
in both trees: `401bad9634b3227263d0a0ed33ff8fc3acc11608df9ab568d614a90862e5ddbe`.

This is an author-side replay, not an independent witness verdict. No
real FontForge build, PCF GUI/Import path, pointer control, command or
rung 5 is claimed.
