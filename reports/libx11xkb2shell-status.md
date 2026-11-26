# libx11xkb2shell — STAGED (2026-11-26)

Brief: `reports/frontier-libx11xkb2shell.md`. Lab:
`lab/frontier/libx11xkb2shell/`. Claim: CVE-2026-88806 / ZDI-CAN-32061,
libX11 before 1.8.14 lets a malicious XkbGetMap reply carry
`firstKeyAct + nKeyActs` beyond `max_key_code + 1`; `_XkbReadKeyActions()`
writes past the 9-entry `server->key_acts` array. Fixed in 1.8.14 by
`6d4432b13c0b3b6a644c13de9c793a14db48d545` (one bounds check before the
loop). State: **STAGED**; window 175 created by frontier, operator admission
and independent witness replay owed.

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
plain vulnerable build is silent. Grade: rung 3 verbatim / rung 4 PARTIAL —
server-controlled index/length and a deterministic 2-byte zero write, but
no named adjacent object, pointer control, live X wire, command execution or
r5. The advisory's RCE framing remains a claim.

Negatives preserved in `PROVENANCE.md`: `firstKeyAct` is CARD8 (256 wraps to
0); eight nonzero actions hit a NULL `acts` array/read-before-write before the
intended sink; `key_sym_map` is deliberately over-allocated so the first ASan
report is the WRITE. Next: witness replay, then a loopback mock-X-server path
through public `XkbGetMap()` plus a measured adjacent-field layout before any
rung-4 upgrade.
