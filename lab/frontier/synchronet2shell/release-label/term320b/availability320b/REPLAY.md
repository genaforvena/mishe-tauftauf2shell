# W26 — replay and scope

One command from the repository root (loopback only, about 40 s):

```
bash lab/frontier/synchronet2shell/release-label/term320b/availability320b/run-availability320b.sh
```

Preconditions: the lab's gitignored `src-tree/320b` worktree is at exact detached
HEAD `db9c5d6fd37ef74b6e6ca647308d351e656de18d` and `provision/` holds the
lab-local `.deb` extracts. The script clones the pinned mirror if the tree is
absent, builds with `make -C 3rdp/build jslib` then `make -C src/sbbs3` (serial),
and restores `answer.cpp` on exit via a trap. Each phase uses a fresh loopback
port derived from the PID; both configs include `SSH_ANYAUTH`.

Expected on the shipped 3.20b build: `RESULT: PASS=13 FAIL=0`, rc 0. The four
64-byte chosen TERMs produce four `REAL_320B_PROBE` lines with
`cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154`. The server
then logs `Node 1 destructor begin`, no `destructor end`, the process is gone
or a zombie before the fifth connection, and that client records
`Connection refused`. There is deliberately **no** `!No nodes available for
login.` line on this release: the W6/W16 thread-park mechanism did not fire.
The fixed phase uses the byte-exact pinned `cb6d77dbca` hunk from
`harness/fixed.inc` (verified by `fixed320b/patch-fixed.py`); four 64-byte
probes are clamped to `len=40`, the fifth 40-byte wire control is also
`len=40`, five sessions attach to nodes, all teardowns complete and the
process stays alive.

Failed prediction: `evidence/FAILED-PREDICTION.md` preserves the first run's
7 PASS / 3 FAIL result and the verbatim failed assertions; raw transcripts of
that run are in `evidence/first-run/`. The second run had 12 PASS / 1 FAIL
solely because the fifth fixed-phase client sends a 40-byte wire TERM, so its
probe says `wire=40`, not `wire=64`; the assertion was corrected to the exact
control probe, not the input. Both negatives are preserved, not retried into
existence.

Scope: real shipped `db9c5d6f` `sbbs3` build, verbatim pinned copy statement
plus an instrumentation-only `lprintf`, unauthenticated loopback OpenSSH
pty-req TERM under `SSH_ANYAUTH`. The chosen-pointer fault attribution is W24's
gdb observation (`mov 0x20(%rax),%rax`, `rax == list->first`); W26 measures
concurrent-load impact and the fixed control, not a new fault model. No
pointer/IP target, command, useful control-flow impact, measured DoS rate,
ASLR defeat or r5. Author replay, not independent witness acceptance.
