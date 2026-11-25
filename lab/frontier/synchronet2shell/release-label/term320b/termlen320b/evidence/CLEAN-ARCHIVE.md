# W27 clean-archive receipt (2026-11-25 18:15:42Z–18:17:05Z)

Abstracted from commit `32da33f7` with
`git archive 32da33f7 lab/frontier/synchronet2shell | tar x -C /tmp/sync-w27-clean`,
then private copies of the gitignored, pinned `src-tree/320b` (HEAD verified
`db9c5d6fd37ef74b6e6ca647308d351e656de18d`) and `provision/` were placed
inside the copy with their worktree gitlinks repointed into it. The live
worktree was untouched. Unmodified
`release-label/term320b/termlen320b/run-termlen320b.sh` returned
**RESULT: PASS=13 FAIL=0**, rc 0, at 18:16:33Z–18:17:05Z. All 13 assertion
labels matched the live run at 18:13:15Z–18:13:34Z. The 48-byte case again
overwrote only `line_delay` and survived with teardown complete; the 52-byte
case again wrote `first=0x41414141`, logged `Node 1 destructor begin` with no
`destructor end`, died with SIGSEGV and left `STATE=gone`.

Normalized key-line SHA-256 prefixes (timestamps, node/session numbers, PIDs
and ports masked), live / clean:

```
probes.txt              4fe33d88fdf62027 / 4fe33d88fdf62027
alive.txt               69ed589081430a55 / 69ed589081430a55
client-52.log           91e5550d887f6283 / 91e5550d887f6283
server-48 keylines      363544415e406e80 / 363544415e406e80
server-52 keylines      9ad43faa26a7ba91 / 9ad43faa26a7ba91
```

Both worktrees' `src-tree/320b/src/sbbs3/answer.cpp` were restored to pinned
state by the script's exit trap; no stray `sbbs` process remained. This is an
author clean-archive replay, not an independent witness verdict; no grade
change and no r5.
