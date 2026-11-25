# fceux2shell — staged status (W233, 2026-11-25 19:2xZ)

Brief: reports/frontier-fceux2shell.md
Evidence: lab/frontier/fceux2shell/PROVENANCE.md

Claim: CVE-2026-136918, FCEUX < 2.8.0, UNIF MAPR chunk with declared size
0xffffffff wraps the malloc argument; truncated board-name copy writes past
the allocation. Fix d9132c2 (parent 1e1de9b).

Local result: pinned verbatim SetBoardName, GCC+Clang ASan heap WRITE-19,
0 bytes after a 1-byte region; fixed and safe-input controls clean.
Plain chosen bytes: PAST_ALLOC=41552c66664d495348452d4643455558, rc 42.
run-all.sh: 14 PASS / 0 FAIL.

Grade: rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes at chosen
offsets. No adjacent object, pointer, wire, command or rung 5.

Next: operator admission/witness replay; then build a real ROM-loading
consumer to test the heap neighborhood and the AV:L caveat. Independent
next frontier candidate: nfdump GHSA-gpgq-hv9x-7mqj (network, fix
32b9cbe7, no tagged release).
