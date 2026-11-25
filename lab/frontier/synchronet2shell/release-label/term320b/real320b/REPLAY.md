# Replay — shipped 3.20b real build, wire TERM, live chosen-pointer free (W21)

Time: 2026-11-25 07:29:32Z. Advisory CVE-2026-133646. All clients connect only
to 127.0.0.1; the source fetch from the public GitHub mirror is provisioning.

## Provisioning and build

The shipped release commit `db9c5d6fd37ef74b6e6ca647308d351e656de18d` was
fetched into the ignored `src-tree` clone and added as a detached worktree at
`src-tree/320b`. Its own headers say `VERSION "3.20"` and `REVISION 'b'`; the
no-size getter is at `answer.cpp:520` and the layout at `sbbs.h:644-646` is
`terminal[41]`, `cterm_version`, `savedlines`.

```
cd lab/frontier/synchronet2shell
git -C src-tree fetch --depth=1 origin db9c5d6f...
git -C src-tree worktree add --detach "$PWD/src-tree/320b" db9c5d6f...
# then the build in evidence/build-320b.log: jslib, then
# make -C src-tree/320b/src/sbbs3 FILE_LIBS="..."
```

Build rc 0. The dev-parent provisioning prefix (`provision/local`) supplies
zip, autoconf-2.13, libarchive and NSPR headers/libs; no host package changed.

## One-command live replay

```
bash lab/frontier/synchronet2shell/release-label/term320b/real320b/run-real320b.sh
```

Expect `RESULT: PASS=4 FAIL=0`, rc 0. The script patches `answer.cpp` with
`probe-320b.patch`, an instrumentation-only `lprintf` after the verbatim copy;
it restores `answer.cpp` at the end. Ports are derived per run to avoid
TIME_WAIT. Key live lines (`evidence/server-control40.log`,
`evidence/server-vuln.log`):

```
40-byte control: REAL_320B_PROBE sizeof=41 l=40 off41=00 cv=00000000 first=(nil) last=(nil)
64-byte chosen:  REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154
```

The chosen TERM is 41 x 'A', 3 x 'B', `MISHE-OOTAUFTAUF`, 4 x 'Z'. The clamp
writes index 40, so byte 41 stays 'B'. Bytes 44..47 = `MISH` land in
`cterm_version`, 48..55 in `savedlines.first`, 56..63 in `savedlines.last`.

The chosen session ends in `Node 1 destructor begin`, then SIGSEGV. A separate
gdb replay (`run-gdb320b.sh`, backtrace preserved in
`evidence/gdb-vuln-final.log`) identifies the faulting frame:

```
#0 listFreeNodes (list=...) at link_list.c:78      # node->flags read
#1 listFree (list=...) at link_list.c:107
#2 sbbs_t::~sbbs_t (...) at main.cpp:3922
#3 node_thread (...) at main.cpp:4625
```

## Honest ceiling

This is the first **live shipped-release** observation: an unauthenticated
loopback SSH pty-req TERM of 64 bytes writes chosen bytes into adjacent
`sbbs_t` fields and the chosen `savedlines.first` is dereferenced at teardown,
faulting the node thread. Availability impact only. No chosen instruction
pointer, no shell/command, no ASLR-conditioned execution, no fixed-form 3.20b
control, no witness verdict and no rung 5. Author replay, not independent
acceptance. Failed expectations, port collisions and the interrupted gdb retry
are in `evidence/negatives.txt`.
