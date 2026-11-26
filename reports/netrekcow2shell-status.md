# netrekcow2shell — ADMITTED (169th, 10:4xZ 2026-11-26), WINDOW 178 LIVE

Brief: `reports/frontier-netrekcow2shell.md`. Lab:
`lab/frontier/netrekcow2shell/`. Claim: CVE-2026-121969, netrek-client-cow
through 3.3.3, `handleSMessage()` in `short.c:914-951` writes an unbounded
server-controlled message into a 100-byte stack buffer with
`sprintf(buf, "%-9s%s", addrbuf, &packet->mesg)` at `short.c:949`. Fixed in
released tag 3.3.4 and commit `fb322e74abee3b0b76a9c5a31df6aab5585d3127`
(length-derived `body_max`, `strnlen`, clamp, `snprintf`). State: **ADMITTED
10:4xZ under standing #6 as the 169th declared target mind; independent witness
replay completed W262, ESTABLISHED AS LABELED**. Window 178
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
(line 916)` (GCC `[80,180)`, Clang `[32,132)`); recoverable ASan reads
back server-chosen `M`, `A`, `R`, `K` at buffer offsets 100..103 in ASan
poison; unprotected plain
attack faults `rc=139`; fixed 3.3.4 is clean (`outlen=99` attack, `outlen=14`
safe); vulnerable safe frame clean (`outlen=14`). Grade: rung 3 verbatim /
rung 4 PARTIAL — chosen bytes in poisoned redzone, no named adjacent object,
pointer, control flow, live wire, command or r5. Negatives are preserved in
`lab/frontier/netrekcow2shell/PROVENANCE.md`.

Author clean-archive replay of the unmodified runner from `git archive
f0672f0d` into `.mishe-tauftauf/replays/netrekcow2shell-w261/`: generated
includes and evidence deleted, three tarballs re-fetched by tag/commit SHA,
rc 0 and `RESULT PASS=32 FAIL=0` at 10:45:33Z with runner hash unchanged
(`replay-console.log` there). That was an author replay, not independent
acceptance.

Witness replay W262 (10:48:20Z–10:48:24Z, #5245): from a clean `git archive
f0672f0d` subtree with archived logs and generated `.inc` files removed and
all three tarballs re-fetched fresh, the unmodified runner returned rc 0,
`RESULT PASS=32 FAIL=0` in 4.58 s; all pins and controls held, GCC+Clang ASan
`WRITE of size 130` at `short.c:949`, chosen bytes at 100..103 in poison,
fixed/safe clean and plain attack rc=139. **ESTABLISHED AS LABELED** at rung 3
verbatim / rung 4 PARTIAL, no contradiction, no grade change, NO r5. Two
wording NITs (GCC-only `[80,180)` frame layout, 78 vs 79 padding bytes) were
corrected in the brief and PROVENANCE. Detail:
`.mishe-tauftauf/artifacts/witness-w262-netrekcow2shell/detail.md`.

Next: none for this replay. Route and wake units remain person-reserved;
do not add them here.
