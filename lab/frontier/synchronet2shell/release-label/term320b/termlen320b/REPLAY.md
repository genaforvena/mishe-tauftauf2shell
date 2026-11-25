# W27 — real-build TERM-length threshold

One command from the repository root (loopback only, about 31 s):

```
bash lab/frontier/synchronet2shell/release-label/term320b/termlen320b/run-termlen320b.sh
```

Preconditions: the lab's gitignored `src-tree/320b` worktree is at exact detached
HEAD `db9c5d6fd37ef74b6e6ca647308d351e656de18d` and `provision/` holds the
lab-local `.deb` extracts. The script clones the pinned mirror if the tree is
absent, reuses W26's provisioning/build/config helpers, builds with `make -C
3rdp/build jslib` then `make -C src/sbbs3` (serial), and restores
`answer.cpp` on exit via a trap. Each case uses a fresh loopback port derived
from the PID, `SSH_ANYAUTH`, and one unauthenticated OpenSSH pty-req TERM of
uniform `A` bytes.

Expected: `RESULT: PASS=13 FAIL=0`, rc 0. The four probes in
`evidence/probes.txt`:

```
l=40 off41=00 cv=00000000 first=(nil) last=(nil)
l=42 off41=41 cv=00000000 first=(nil) last=(nil)
l=48 off41=41 cv=41414141 first=(nil) last=(nil)
l=52 off41=41 cv=41414141 first=0x41414141 last=(nil)
```

For 40, 42 and 48 bytes the teardown completes and `evidence/alive.txt`
records `STATE=S`. At 52 bytes, `Node 1 destructor begin` is logged with no
`destructor end`, the process is gone, and the shell reports
`Segmentation fault (core dumped)`. The first crashing length is the one whose
wire bytes reach `savedlines.first` (sbbs_t+48); 48 bytes overwrites only
`line_delay` (sbbs_t+44) and the process survives.

First execution failed before any case: `sha256sum: ...run-termlen320b.sh: No
such file or directory`, because `$0` was relative to the repository root while
the script changes directory. The provenance path was made absolute; no input
or assertion was changed to force a pass. No negative about the target was
hidden — the failing run never started a server.

Scope: real shipped `db9c5d6f` `sbbs3`, verbatim pinned no-size copy statement
plus an instrumentation-only `lprintf`, uniform non-chosen TERM bytes, loopback
only. This measures the availability threshold, not pointer control: no chosen
bytes, no useful pointer/IP target, no command, no measured DoS rate, no ASLR
defeat and no r5. Author replay, not independent witness acceptance; the
consolidated witness offer #4421 and W26 note #4469 remain outstanding.
