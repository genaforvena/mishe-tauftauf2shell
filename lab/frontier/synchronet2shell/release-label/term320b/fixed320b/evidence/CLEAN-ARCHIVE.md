# Clean-archive receipt — W22 fixed-form 3.20b control (2026-11-25 08:26Z)

Author replay from a fresh `git archive 7d3a0088 lab/frontier/synchronet2shell`,
extracted to `/tmp/w22-clean-20261125`. The ignored provisioned `src-tree/`
(1.9 GB, including the exact `db9c5d6f` worktree) and `provision/` were copied
into that private archive, and the two absolute gitlink files in the copy were
repointed to the copied clone. The live checkout's own worktree was never
patched by this run: the copied worktree has its own path, so the driver's
process cleanup cannot match live processes.

Verified before the run:

```
git -C src-tree/320b rev-parse HEAD
db9c5d6fd37ef74b6e6ca647308d351e656de18d
```

One-command replay in the extracted archive:

```
bash release-label/term320b/fixed320b/run-fixed320b.sh
```

Transcript (`/tmp/w22-clean-20261125/clean-replay.log`):

```
patching file src/sbbs3/answer.cpp
PASS vulnerable 3.20b: chosen pointer pair written by 64-byte TERM
PASS vulnerable 3.20b: node thread never reaches destructor end
PASS fixed copy statements are byte-exact pinned cb6d77dbca hunk
PASS fixed 3.20b: 64-byte wire TERM leaves adjacent fields clean
PASS fixed 3.20b: node thread completes teardown
RESULT: PASS=5 FAIL=0
```

rc 0. Probe lines in the clean archive's `evidence/server-vuln.log` and
`evidence/server-fixed.log` are the same bytes as in the live checkout after
removing only the `MM/DD HH:MM:SS term` prefix:

```
REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154
Node 1 destructor begin                                      (no destructor end)
FIXED_320B_PROBE sizeof=41 wire=64 len=40 off41=00 cv=00000000 first=(nil) last=(nil)
Node 1 destructor begin
Node 1 destructor end
```

Clean-archive hashes: `run.log`
`8825f5e07f8be4cbbfdb5e8f0c36eb525f93cf3369842d1b0e8d1e5c20004e54` and
`pinned-hunk.log` `0b8ac3b45f070e387342a558670135a5e6c6f9bb9a9644d8c0521e2258684f73`
are byte-identical to the live run. `server-vuln.log`
`4bfb5519a8a0b5099122cdbeb00fee2fc6f44b65328d43299c96efe637129228`
and `server-fixed.log`
`144b998107cc376720e807f7946ff9ad1b09065382b804004c7c34c3618c281c`
differ from the live artifacts only in timestamps, ports and PIDs.

Scope: this is an author clean-archive replay, not a witness verdict. It still
depends on a provisioned build tree copied from this lab; it does not rebuild
cryptlib or the source tree from the network. Ceiling unchanged: availability
only, no pointer/IP or command, no rung 5.
