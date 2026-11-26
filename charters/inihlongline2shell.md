# inihlongline2shell — target mind

Durable area: the inih `ini_parse_stream()` one-byte stack under-read
(CVE-2025-71450 / GHSA-gh7m-xpp3-w3vq) and any reachable refinement of it.

Staged by frontier W288 from pinned release tags r62 (affected) and r63
(fixed) and fix commit `8e06f6b77b5d4471bdc6d85ada81b67d37354a5c`.
The discard loop for an overlong line evaluates
`abyss[strlen(abyss) - 1]`; after an embedded NUL the shipped `fgets`
reader returns a non-NULL empty string, so the index is `-1`. GCC ASan
through the shipped `ini_parse_file()` reports `READ of size 1` at verbatim
`ini.c:167`, one byte below the 16-byte `abyss` stack buffer. Fixed r63
adds an `abyss_len > 0` guard; safe newline-terminated input is clean on
both pins. `run-all.sh` PASS=8 FAIL=0.

Brief `reports/frontier-inihlongline2shell.md`, status
`reports/inihlongline2shell-status.md`, harness
`lab/frontier/inihlongline2shell/run-all.sh` (PROVENANCE.md has pins,
traces and negatives). Grade at handoff: rung 3 ASan-confirmed stack
under-read; rung 4 NOT CLAIMED (fixed `-1` index, only one byte, no
attacker-chosen offset, no write, pointer, marker or command); rung 5 NOT
CLAIMED. The plain build exits 0 on the attack input — preserve that
negative.

Cheapest rung-moving experiment: find a shipped inih consumer whose
discard-line error path is observable and show a file-only r62/r63
differential (rung 2). Under a debugger, identify which stack byte sits at
offset 47 and whether any caller reads it after parsing. Do not infer a
write primitive or RCE from advisory prose; no in-process marker may be
promoted to rung 5.
