# netrekcow2shell — STAGED, WINDOW 178 LIVE (2026-11-26)

Brief: `reports/frontier-netrekcow2shell.md`. Lab:
`lab/frontier/netrekcow2shell/`. Claim: CVE-2026-121969, netrek-client-cow
through 3.3.3, `handleSMessage()` in `short.c:914-951` writes an unbounded
server-controlled message into a 100-byte stack buffer with
`sprintf(buf, "%-9s%s", addrbuf, &packet->mesg)` at `short.c:949`. Fixed in
released tag 3.3.4 and commit `fb322e74abee3b0b76a9c5a31df6aab5585d3127`
(length-derived `body_max`, `strnlen`, clamp, `snprintf`). State: **STAGED by
frontier; operator admission and independent witness replay owed**. Window 178
`netrekcow2shell` created on the inner tmux socket
(`mishe-tauftauf2shell-current`), panes %358/%359, both live (top: this status,
bottom: `plant_view --role netrekcow2shell --output --log --follow`);
registered in `operator/window-registry.json` (179/179 unique names).
Evidence: canonical `run-all.sh` sha256
`52078f004e10bc89c0faa96c8755287c7afd6adc92f1c123e7697b5ce1799288` pins
codeload archives for 3.3.3/3.3.4/fix commit, the patch, driver and three
verbatim source extracts, then rebuilds GCC+Clang ASan, recoverable ASan and
plain variants. **RESULT PASS=32 FAIL=0**, rc 0 (10:41:46Z): vulnerable ASan
`stack-buffer-overflow`, `WRITE of size 130`, frame `short.c:949`, `'buf'
(line 916)` at `[80,180)`; recoverable ASan reads back server-chosen `M`,
`A`, `R`, `K` at buffer offsets 100..103 in ASan poison; unprotected plain
attack faults `rc=139`; fixed 3.3.4 is clean (`outlen=99` attack, `outlen=14`
safe); vulnerable safe frame clean (`outlen=14`). Grade: rung 3 verbatim /
rung 4 PARTIAL — chosen bytes in poisoned redzone, no named adjacent object,
pointer, control flow, live wire, command or r5. Negatives are preserved in
`lab/frontier/netrekcow2shell/PROVENANCE.md`.

Next: operator admission; witness replay. Route and generated wake units are
person-reserved; do not add them here.
