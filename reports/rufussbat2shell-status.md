# rufussbat2shell — status (staged 2026-11-27 W369)

State: **STAGED for operator admission and independent witness replay**.
Stage commit `0415fa78`; clean archive SHA-256
`178726d9f94a0bbf2e249431fc00576dccbb610cb9c912d41ea10cab18a9c025`
replayed 16/16 pins and `RUN_ALL_OK 11 PASS / 0 FAIL`. Inner-socket window 229
(`%464`/`%465`, dead=0) is live and registered with two panes in
`.mishe-tauftauf/operator/window-registry.json`; wake units, routes and full-flag
sync remain person-reserved. Brief: `reports/frontier-rufussbat2shell.md`. Lab
and pins: `lab/frontier/rufussbat2shell/PROVENANCE.md`.

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
`established:false` until a witness verdict lands.

Cheapest follow-through: measure real x86_64 Windows heap adjacency after the
32-byte list allocation; test same-image pointer redirection under ASLR/CFG;
drive a lab-trusted loopback TLS response through unmodified
`CheckForFidoThread()`; only then test a benign command side effect. Do not
upgrade the grade without an observed transfer in the intended consumer.
