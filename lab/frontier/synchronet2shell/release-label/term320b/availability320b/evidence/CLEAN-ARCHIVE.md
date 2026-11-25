# W26 clean-archive receipt (2026-11-25 16:42:23Z–16:44:05Z)

Abstracted from commit `79f3710b` with
`git archive 79f3710b lab/frontier/synchronet2shell | tar x -C /tmp/sync-w26-clean`,
then a private copy of the gitignored, pinned `src-tree/320b` (HEAD verified
`db9c5d6fd37ef74b6e6ca647308d351e656de18d`) and `provision/` was placed inside
the copy. The live worktree was untouched. Unmodified
`release-label/term320b/availability320b/run-availability320b.sh` returned
**RESULT: PASS=13 FAIL=0**, rc 0, at 16:43:28Z–16:44:05Z; all 13 assertion
labels matched the live run at 16:40:18Z–16:40:58Z. The vulnerable phase again
died at `Node 1 destructor begin` with SIGSEGV and the fifth client again got
`Connection refused`; the fixed phase again served five sessions with four
completed teardowns and a live process.

Normalized key-line SHA-256 prefixes (timestamps, ports, PIDs, socket and
session numbers masked), live / clean:

```
vuln-server.log       353b588348063870 / 353b588348063870
vuln-client-5th.log   3ccc4792617210d7 / 3ccc4792617210d7
vuln-alive.txt        50e620887ae756b1 / 50e620887ae756b1
fixed-server.log      47f2018f0c9c9f09 / 47f2018f0c9c9f09
fixed-client-5th.log  e3b0c44298fc1c14 / e3b0c44298fc1c14  (no refusal line)
fixed-alive.txt       a70d371785791e26 / a70d371785791e26
pinned-hunk.log       853538e058f4d67a / 853538e058f4d67a
```

Both worktrees' `src-tree/320b/src/sbbs3/answer.cpp` were restored to pinned
state by the script's exit trap. This is an author clean-archive replay, not an
independent witness verdict; no grade change and no r5.
