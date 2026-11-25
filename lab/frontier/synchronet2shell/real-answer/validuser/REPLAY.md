# W15 replay — valid credentials under the default config

One command from an author tree that already has the gitignored lab
`src-tree/` (pinned parent `42f586d7`) and `provision/` present:

```
bash lab/frontier/synchronet2shell/real-answer/validuser/run-validuser.sh
```

Expected result: `VALIDUSER RESULT: PASS=4 FAIL=0`, `PROBE_COUNT=2`,
`ANYAUTH_LOG_COUNT=0`, and in `evidence/server.log` two
`SSH password authentication successful` lines followed by
`REAL_ANSWER_PROBE sizeof=41 l=64 off41=42 off44=4853494d off48=4f4f2d45
off52=TAUFTAUF` (chosen 64-byte TERM) and
`REAL_ANSWER_PROBE sizeof=41 l=40 off41=00 off44=00000000 off48=00000000`
(40-byte control). The config line must read
`Options = XTRN_MINIMIZED | ALLOW_SSH | NO_TELNET | NO_HOST_LOOKUP | NO_EVENTS`.

The script provisions user `lab` offline with the pinned tree's `makeuser`
binary when `data/user/user.tab` has no `LABPASS123` record, adds the
`ctrl/data -> ../data` symlink that binary needs, applies the same
instrumentation-only `answer.cpp` patch as W5/W7/W9, rebuilds `sbbs3` serially
and starts it only on 127.0.0.1:22229. `sshpass` and stock OpenSSH with
`PreferredAuthentications=password` perform a real password login; no traffic
leaves loopback. All traffic, probes and logs stay in the lab.

From a clean archive, link the two gitignored directories first:

```
git archive <HEAD> lab/frontier/synchronet2shell | tar x -C /tmp/sync-w15
cd /tmp/sync-w15/lab/frontier/synchronet2shell
ln -s /path/to/live/lab/frontier/synchronet2shell/src-tree ./src-tree
ln -s /path/to/live/lab/frontier/synchronet2shell/provision ./provision
bash real-answer/validuser/run-validuser.sh
```

This is an author replay path, not a witness verdict. Timestamps, PIDs, node
numbers and client-relative line ordering are volatile; the assertion lines,
probe hexdumps, auth lines and PASS/FAIL counts are compared verbatim.
