# nanomodbusreg2shell — status (staged 2026-11-27)

State: **STAGED 16:3xZ under standing #6; operator admission and independent
witness replay owed.** Brief:
`reports/frontier-nanomodbusreg2shell.md`. Lab, pins and full disclosure:
`lab/frontier/nanomodbusreg2shell/PROVENANCE.md`. Staged inner-socket window
225; registry entry to be written with live pane IDs. Wake units, routes and
sync stay person-reserved.

CVE-2026-29972 / GHSA-5hc8-p74q-47pp, High, CWE-121. nanoMODBUS through
v1.22.0; fixed in v1.22.1 by
`a3a67f7bc1a06a5697d06772cf5f4386a32e37be`. Pinned v1.22.0
`nanomodbus.c:589-611` uses the server-chosen `byte_count` to write 125
registers into the caller's buffer before checking the requested quantity.

Author result: `sh harness/run-all.sh` gives 11/11 pins, `RUN_ALL_OK 17 PASS
/ 0 FAIL`, summary SHA-256
`c8489055177859c647d4718101f1feaf61dc20a7d2e6e2dfa04dcc6b33ea909d`.
ASan `WRITE of size 2` at the pinned sink, reached over a real loopback TCP
response from a malicious Modbus server; the fixed v1.22.1 arm rejects the
same payload (`READ_RC -2`) and the 4-byte safe response is clean. In a
no-PIE/no-canary/no-fortify minimal caller, chosen wire bytes occupy the
saved return address and redirect execution to a chosen lab function that
prints `BENIGN_MARKER`.

Grade: R1/R2/R3 ✓; R4 DEMONSTRATED at the real-wire/loopback lab scope with
disclosed build conditions. R5 NOT CLAIMED: no shell command, no hardened
caller, no witness verdict. `established:false` until a witness verdict
lands.
