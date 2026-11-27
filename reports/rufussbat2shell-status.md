# rufussbat2shell — status (admitted 2026-11-27 W369)

State: **ADMITTED 21:1xZ under standing #6 as the 221st declared target mind**;
W372 (stage `0415fa78`/receipt `7064369a`) and W373 (correction `553bfad5`)
graded ESTABLISHED AS LABELED. Inner-socket window 229 (two panes `%464`/
`%465`, dead=0) was created 21:01Z and adopted as-is; wake units, routes and
full-flag sync stay person-reserved. Brief: `reports/frontier-rufussbat2shell.md`.
Lab and pins: `lab/frontier/rufussbat2shell/PROVENANCE.md`. Charter and seed wall
are under `.mishe-tauftauf/{charters,walls}/rufussbat2shell.md`.

Operator clean replay at 21:07Z from `git archive --format=tar 0415fa78
lab/frontier/rufussbat2shell` (plain-tar SHA-256
`178726d9f94a0bbf2e249431fc00576dccbb610cb9c912d41ea10cab18a9c025`): 16/16
`SHA256SUMS` pins matched and unmodified `./harness/run-all.sh` reported
`RUN_ALL_OK 11 PASS / 0 FAIL`. Staging receipt commit `7064369a`.

Post-admission correction `553bfad5` fixes the witness citation nits, allocation
accounting and replay postconditions without changing the grade. Clean TAR
`d8ec9e29f7ffc0356faa85c5971f191bb7acb828fd6730ace4e01175b07e11b9`
replayed 16/16 pins and 11/0; a controlled stable-output mismatch failed the
post-regeneration pin check with rc 1. Witness #6864 ESTABLISHED AS LABELED,
grade-neutral, NO r5 on stage `0415fa78`/receipt `7064369a`.

GHSA-hcpc-vq8c-923h; affected Rufus `>=4.11, <=4.16_BETA`, patched `4.16`.
Fixed commit `842873017f289713a5d5009320c11f31cfee36ed`; pinned pre-fix parent
`de4cf676c2aedf73b0ddfc234e420d19c8969c2e`. Vulnerable `GetSbatEntries()`
counts LF before converting CR to LF, allocates 32 bytes for CR-only input, then
writes one 16-byte entry per line. Entry 2 writes an attacker-buffer product
pointer and chosen 32-bit version past the allocation. The fix converts CR
before counting.

Grade: R1 ✓, R2 ✓, R3 ✓ (ASan heap-buffer-overflow WRITE-8 and READ-8), R4
**LIMITED** (chosen low-32-bit callback transfer and `BENIGN_MARKER` only in a
synthetic adjacent-victim/no-PIE/no-canary build), R5 NOT CLAIMED.
`./harness/run-all.sh` = `RUN_ALL_OK 11 PASS / 0 FAIL` with GCC and Clang.
Witness verdicts are folded in docs and the register: W372 on the stage scope
and W373 on correction `553bfad5`, both ESTABLISHED AS LABELED and grade-neutral;
the register flag still names stage `0415fa78` and no replay is owed.

Cheapest follow-through: measure real x86_64 Windows heap adjacency after the
32-byte list allocation; test same-image pointer redirection under ASLR/CFG;
drive a lab-trusted loopback TLS response through unmodified
`CheckForFidoThread()`; only then test a benign command side effect. Do not
upgrade the grade without an observed transfer in the intended consumer.
