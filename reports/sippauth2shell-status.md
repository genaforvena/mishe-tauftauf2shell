# sippauth2shell — status (staged 2026-11-27 W334)

State: **STAGED, awaiting operator admission and independent witness replay.**
Brief `reports/frontier-sippauth2shell.md`, lab
`lab/frontier/sippauth2shell/`, provenance in that lab's `PROVENANCE.md`.
Author-side reproduction only; the witness has not replayed it.

Finding: CVE-2026-90779 (CWE-121, SIPp <= 3.7.7), pinned v3.7.7
`369b3c18…` → v3.7.8 `741ee230…`, exact fix `1d4a5622…` (not an ancestor of
v3.7.8; equivalent bounded call in that release). A challenge-controlled
`algorithm=` length feeds `strncpy(algo, start, end-start)` into `algo[32]`
at `src/auth.cpp:188`, with a NUL at `:190`.

Grade: R1/R2/R3 ✓ — ASan `WRITE of size 64` at `auth.cpp:189` into
`[32,64) 'algo'`; 32-byte boundary case is a `WRITE of size 1` at `:190`;
fixed and safe controls clean. R4 DEMONSTRATED **in-process**: read-only GDB
sees `algo+32..+43` as chosen `0x41` and saved RBP/RIP `0x4141414141414141`;
with 62 chosen bytes the six low saved-RIP bytes are chosen while the high
zero bytes survive, and a benign marker mapped at canonical
`0x0000414141414141` executes in the vulnerable plain O0 build. The marker
`mmap(MAP_FIXED)`, unprotected build and direct call are explicit lab
conditions. R5 NOT CLAIMED — no live SIPp process, socket request,
production mapping or command side effect was observed; the source-level
401/407 wire path is untested.

`./run-all.sh`: `TOTAL: 15 PASS / 0 FAIL`, stdout SHA-256
`8dd157952a776ea48083b9acd73c279e25a04142b4b808375fdfb3d4037fc802`
byte-identical across two runs; pin/harness hashes in
`lab/frontier/sippauth2shell/HARNESS_SHA256.txt`.

Next: operator admission under the standing mandate, witness replay of the
stage commit, then a loopback UAS/UAC 401 challenge with 62 chosen algorithm
bytes to test whether the sink and the control-flow diversion are reachable
from a real request. A wire no-result is a legitimate negative; no rung-5
claim without an observed request-driven command side effect.
