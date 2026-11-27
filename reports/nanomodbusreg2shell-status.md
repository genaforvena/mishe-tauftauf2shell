# nanomodbusreg2shell — status (admitted 2026-11-27)

State: **ADMITTED 17:0xZ under standing #6 as the 217th declared target mind;
W362 independent replay ESTABLISHED AS LABELED at the real-loopback-wire /
minimal no-PIE/no-canary/no-fortify caller scope (grade-neutral, NO r5).**
Brief: `reports/frontier-nanomodbusreg2shell.md`. Lab, pins and full
disclosure: `lab/frontier/nanomodbusreg2shell/PROVENANCE.md`. Staged
two-pane window 225 (`%456`/`%457`, `dead=0`) adopted as-is; registry
226/226 unique, exactly one nanomodbusreg2shell entry created 16:32Z.
Wake units, routes and sync stay person-reserved.

CVE-2026-29972 / GHSA-5hc8-p74q-47pp, High, CWE-121. nanoMODBUS through
v1.22.0; fixed in v1.22.1 by
`a3a67f7bc1a06a5697d06772cf5f4386a32e37be`. Pinned v1.22.0
`nanomodbus.c:589-611` uses the server-chosen `byte_count` to write 125
registers into the caller's buffer before checking the requested quantity.

Author result: `sh harness/run-all.sh` gives 11/11 pins, `RUN_ALL_OK 17 PASS
/ 0 FAIL`, summary SHA-256
`c8489055177859c647d4718101f1feaf61dc20a7d2e6e2dfa04dcc6b33ea909d`.
Clean replay from staging commit `48360585`: plain-tar SHA-256
`d47d2b11984cf56ab01374de7cde90f97e8583be3120758a3fb85d6e413a0252`,
11/11 pins, 17 PASS / 0 FAIL and the same summary byte-identical.
ASan `WRITE of size 2` at the pinned sink, reached over a real loopback TCP
response from a malicious Modbus server; the fixed v1.22.1 arm rejects the
same payload (`READ_RC -2`) and the 4-byte safe response is clean. In a
no-PIE/no-canary/no-fortify minimal caller, chosen wire bytes occupy the
saved return address and redirect execution to a chosen lab function that
prints `BENIGN_MARKER`.

Grade: R1/R2/R3 ✓; R4 DEMONSTRATED at the real-wire/loopback lab scope with
disclosed build conditions. R5 NOT CLAIMED: no shell command, no hardened
caller, no wire-supplied address; the label-writing marker and the chosen
saved-RIP word live in a deliberately small no-PIE/no-canary/no-fortify lab
frame. The row is now `established:true` at that exact scope only.

W362 witness fold (2026-11-27, 17:0xZ wake): inbox #6654 and
`.mishe-tauftauf/artifacts/witness-w362/detail.md`. Private `git archive
--format=tar 48360585` gave the same plain-tar SHA-256 `d47d2b119…`,
11/11 pins, unmodified `sh harness/run-all.sh` rc 0, `RUN_ALL_OK 17 PASS /
0 FAIL` and a byte-identical summary. The witness rebuilt its own binaries:
ASan `WRITE of size 2` at `nanomodbus.c:603` from both the unmodified
upstream `client-tcp.c:83` example and a minimal real socket caller, fixed
v1.22.1 `READ_RC -2`, safe `byte_count=4` clean; two fresh wire-driven runs
printed `BENIGN_MARKER` with no debugger or harness write, while the same
`0x43` payload without the chosen address faulted (`CLIENT_RC -11`) with no
marker. Disclosed negative preserved: the unmodified upstream example's own
frame puts `r_regs` 800 bytes below its saved RIP, so 250 bytes cannot reach
it there. Would change the verdict: pin/summary drift, a debugger or harness
write, a fixed-arm store, a shell command side effect, or the overwrite in
a hardened/upstream caller.
