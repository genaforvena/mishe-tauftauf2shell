# Clean-archive receipt — W24 fault-address lane (2026-11-25 12:55Z)

Author replay from a fresh `git archive 3e681d41 lab/frontier/synchronet2shell`
extracted to `/tmp/sync-w24-clean-FEtU3r`. As in the W22 receipt, the ignored
provisioned `src-tree/` (1.9 GB, including the exact `db9c5d6f` worktree) and
`provision/` were copied into the private archive; the two absolute gitlinks
(`src-tree/320b/.git` and `src-tree/.git/worktrees/320b/gitdir`) were repointed
inside the copy. The live tree's worktree was not used by this run.

Verified before the run:

```
git -C src-tree/320b rev-parse HEAD
db9c5d6fd37ef74b6e6ca647308d351e656de18d
git -C src-tree/320b status --short -- src/sbbs3/answer.cpp   # empty
```

One-command replay in the extracted archive:

```
bash release-label/term320b/real320b/run-faultaddr320b.sh
```

Transcript result: `RESULT: PASS=7 FAIL=0`, rc 0, per-PID port 24471
(finished 12:55:59Z). The fault instruction, register and gdb-printed values
are byte-identical to the live run at 12:52:54Z:

```
REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154
W24_SI_ADDR=(nil)
W24_SIGINFO=Value can't be converted to integer.
=> 0x7ffff6f5e053 <listFreeNodes+67>:	mov    0x20(%rax),%rax
rax            0x465541544f4f2d45  5068028786039008581
W24_LIST_FIRST=0x465541544f4f2d45
W24_NODE=0x465541544f4f2d45
W24_FLAGS_OFFSET=0x20
```

Clean `gdb-faultaddr.log` sha256
`f068228cea087b853df1300d08c6842cd717a20eef9183562ec14899f120319a` and live
`62898623a3a46fab4df26df90d7b52cdfb051c97f41ef20b386e40d8d89b9b75` differ
only in the log prefix timestamp and the ASLR-dependent `list=` heap address;
every probe, instruction, register and W24-labelled line matches byte for byte.

Scope: author clean-archive replay, not a witness verdict. It still depends on
a provisioned build tree copied from this lab; it does not rebuild cryptlib or
the source tree from the network. Ceiling unchanged: the faulting load really
uses the wire-chosen pointer; no useful pointer/IP target, command, DoS rate
or r5.
