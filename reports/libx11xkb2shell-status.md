# libx11xkb2shell — ADMITTED (167th target mind, 2026-11-26)

Brief: `reports/frontier-libx11xkb2shell.md`. Lab:
`lab/frontier/libx11xkb2shell/`. Claim: CVE-2026-88806 / ZDI-CAN-32061,
libX11 before 1.8.14 lets a malicious XkbGetMap reply carry
`firstKeyAct + nKeyActs` beyond `max_key_code + 1`; `_XkbReadKeyActions()`
writes past the 9-entry `server->key_acts` array. Fixed in 1.8.14 by
`6d4432b13c0b3b6a644c13de9c793a14db48d545` (one bounds check before the
loop). State: **ADMITTED 08:5xZ under standing #6**; window 175 adopted from
frontier (panes %352/%353 live, no duplicate); operator clean-archive replay
passed 12/0; independent witness replay owed.

Evidence: canonical `run-all.sh` sha256
`2c7273f01d6a26b36c8aeecd94f1e9a9835d9ea81f7e3896072b9b9ee3532bc0`
verifies the pinned tarballs, raw fix patch, linkage-only `expose.patch` and
harness SHA-256s; rebuilds 1.8.13/1.8.14 under GCC+Clang ASan and GCC plain
and drives real `_XkbReadKeyActions()` with a synthetic reply
(`firstKeyAct=8`, `nKeyActs=2`, descriptors `[1,0]` against
`max_key_code=8`). `RESULT PASS=12 FAIL=0`: vulnerable 1.8.13 under both
compilers gives `WRITE of size 2` at verbatim
`src/xkb/XKBGetMap.c:277`, 0 bytes after an 18-byte `key_acts` allocation;
1.8.14 returns `BadLength` (status 1) in all builds; safe inputs succeed;
plain vulnerable build is silent. Author clean-archive replay of the unmodified
`run-all.sh` from staging commit `9b56c822` gave `RESULT PASS=12 FAIL=0`, rc 0;
the console is the git-tracked
`lab/frontier/libx11xkb2shell/evidence/run-all-console.log`. (An earlier draft
of this status cited a non-existent site-home path for that console; corrected
here — no evidence was lost.)
Operator admission replay: the unmodified `run-all.sh` (sha256 above) was run
from a clean `git archive 9b56c822` at
`.mishe-tauftauf/replays/libx11xkb2shell-op-20261126T0856Z/`, with both pinned
tarballs seeded from the lab cache and every SHA-256 re-verified by the runner.
Console `replay-console.log` (08:54:32Z–08:59:36Z) records 12 PASS lines,
`RESULT PASS=12 FAIL=0`, `RC=0`. This is a second author-side replay, not
independent witness acceptance.
Grade: rung 3 verbatim / rung 4 PARTIAL —
server-controlled index/length and a deterministic 2-byte zero write, but
no named adjacent object, pointer control, live X wire, command execution or
r5. The advisory's RCE framing remains a claim.

Negatives preserved in `PROVENANCE.md`: `firstKeyAct` is CARD8 (256 wraps to
0); eight nonzero actions hit a NULL `acts` array/read-before-write before the
intended sink; `key_sym_map` is deliberately over-allocated so the first ASan
report is the WRITE. Next: independent witness replay; only a measured
loopback mock-X-server path through public `XkbGetMap()` plus a named adjacent
field with chosen bytes could advance rung 4. Route and generated wake units
are person-reserved; do not add them here.
