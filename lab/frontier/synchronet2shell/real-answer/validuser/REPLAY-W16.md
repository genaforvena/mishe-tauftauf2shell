# W16 replay — default-config, valid-password node exhaustion

One command from an author tree that already has the gitignored lab
`src-tree/` (pinned parent `42f586d7`) and `provision/` present:

```
bash lab/frontier/synchronet2shell/real-answer/validuser/run-validuser-availability.sh
```

Expected: `VALIDAVAIL RESULT: PASS=10 FAIL=0`, four `REAL_ANSWER_PROBE
sizeof=41 l=64 off41=42 off44=4853494d off48=4f4f2d45 off52=TAUFTAUF`
lines in `availability-evidence/vuln-server.log`, four `SSH login: 'lab'`
lines, four `sbbs/termNode hrtimer_nanosleep` snapshots in
`vuln-threads.txt`, one `!No nodes available for login.` refusal on the fifth
connection; fixed form has four `REAL_FIXED_PROBE sizeof=41 len=64 off40=00
off44=00000000 off48=00000000` lines, five `Attaching to Node` lines, five
password successes and no refusal. Both configs have zero `SSH_ANYAUTH` lines.

The script provisions user `lab` offline with the pinned tree's `makeuser`
binary when needed, adds the `ctrl/data -> ../data` symlink, applies the same
instrumentation-only `answer.cpp` patches as W5/W6/W15, rebuilds `sbbs3`
serially and starts it only on 127.0.0.1:22230. Four stock OpenSSH clients
send a chosen 64-byte pty-req TERM with `sshpass` password auth, then a fifth
sends a clean 40-byte TERM. No traffic leaves loopback.

From a clean archive, link the two gitignored directories first:

```
git archive <HEAD> lab/frontier/synchronet2shell | tar x -C /tmp/sync-w16
cd /tmp/sync-w16/lab/frontier/synchronet2shell
ln -s /path/to/live/lab/frontier/synchronet2shell/src-tree ./src-tree
ln -s /path/to/live/lab/frontier/synchronet2shell/provision ./provision
bash real-answer/validuser/run-validuser-availability.sh
```

Do not run W15/W16 drivers concurrently: they share the gitignored `src-tree`
build and its `answer.cpp` is patched in place. Port 22230 must be free and
bindable; the driver checks with a real bind and waits for the four node
threads, because Synchronet prints `SSH Server listening` before a failed
bind (the second W16 author run hit that TIME_WAIT race and is preserved in
`availability-evidence/first-run-assert-negative.txt` along with the first
run's assertion defect; both are pre-repair negatives, not target behavior).

This is an author replay path, not a witness verdict. Timestamps, PIDs and
socket numbers are volatile; assertion lines, probe hexdumps, auth lines and
PASS/FAIL counts are compared verbatim.

## Author clean-archive replay (2026-11-25T01:30Z)

`git archive be7d19a2 lab/frontier/synchronet2shell` extracted to
`/tmp/sync-w16-replay`, with the gitignored `src-tree/` and `provision/`
symlinked from the live lab, gave rc 0 and `VALIDAVAIL RESULT: PASS=10
FAIL=0`. All ten client transcripts were byte-identical to the author run
(vulnerable sessions `c55002fcf22313c850bd824997e41e5337796be78490dbbb4e84fcaa2ad4c316`,
vulnerable fifth `5e8aadfe1bcbe0758bc0b839747f8c5db84991789f597c96509d126a00c3278f`,
fixed sessions `dcdcd9038e759341aac8047fee2e0e0df10e3eb173ca642e9d8d05292c3ef985`).
Both server logs' assertion lines match after removing only the volatile
`11/25 HH:MM:SS` prefix and four-digit
socket numbers: vulnerable normalized sha256
`f29f5e39dbbbd564ddc38a7b4bfea0fa8e03c4f974d78a22c53b8064a459070d`,
fixed `e0661bc5cbbe0b2d2527f8fd1d2f6b8a3ebbe15b8455e312c3da746c96e40ac1`,
identical in both runs. Each thread snapshot has four `hrtimer_nanosleep`
termNode threads. This is an author replay, not a witness verdict.
