# checkmk2shell — status (staged 2026-11-27 W367)

State: **STAGED by frontier**; live inner-socket window 228 with two registered
panes. Operator admission and independent witness replay are owed. Wake units,
routes and sync stay person-reserved. Brief:
`reports/frontier-checkmk2shell.md`. Lab and pins:
`lab/frontier/checkmk2shell/PROVENANCE.md`. Charter and seed wall are under
`.mishe-tauftauf/{charters,walls}/checkmk2shell.md`.
Staging commit `b902273f`; clean archive TAR SHA-256
`3a5b3ef20bbf9bcbf3efa6c68fdbbcba9b45fb343de41d92d5be3126f25cab52`
replayed 12/12 pins and `RUN_ALL_OK 11 PASS / 0 FAIL`.


CVE-2026-110470 / GHSA-p7hw-9hjv-7jpq; affected Checkmk 2.5.0 before 2.5.0p21,
2.4.0 before 2.4.0p42, and 2.3.0 (EOL). Fixed source commit
`265c0ab68fb50bedd0102536eb92612a3eb1af91`; pinned pre-fix parent
`9a64b94964c5cc34d82daa888d675b86f835e861`. Vulnerable `mkevent.cc:124-146`
builds a notification in `char message[8192]`; `append_str()` at `:45-47`
performs an unbounded `memcpy`, and `parse_notification()` passes attacker
check output at `:144`. The fix uses `std::string` and truncates to 8191 bytes
without splitting UTF-8.

Grade: R1 ✓ (real parser trigger), R2 ✓ (chosen stack-frame overwrite), R3 ✓
(ASan `stack-buffer-overflow`, WRITE size 10000), R4 **LIMITED** (chosen
saved-RIP transfer and `BENIGN_MARKER` only in the isolated
verbatim-sink/no-canary/no-PIE build; the real parser crashes before `ret`), R5
NOT CLAIMED. `./harness/run-all.sh` = `RUN_ALL_OK 11 PASS / 0 FAIL`.
`established:false` until a witness verdict lands.

Cheapest follow-through: reach the real parser's `ret` while preserving its
return object; repeat under PIE/canary/CET; drive the argument through the
notification spooler to a loopback Event Console receiver. Do not upgrade the
grade without an observed control-flow transfer in the intended consumer or a
benign command side effect.
