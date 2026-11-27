# coturnoauthnonce2shell — status (staged 2026-11-27)

State: **STAGED**, not yet admitted. Stage commit `e7b65a52`; clean archive
SHA-256 `5a982134f4a62c5ffe4d66c91da02041ecfe8e30c88c12975816e4b25ff3440a`
replayed with all 10 harness hashes matched and 13 PASS / 0 FAIL, summary
`b9c20a26...` byte-identical to the in-tree run. Frontier brief
`reports/frontier-coturnoauthnonce2shell.md`; lab
`lab/frontier/coturnoauthnonce2shell/`; provenance in that lab's
`PROVENANCE.md`. Live inner-socket two-pane window 214 (`%434`/`%435`,
`dead=0`) is registered in
`.mishe-tauftauf/operator/window-registry.json` (215/215 unique names).
No charter or seed wall exists yet: the operator owns admission, and wake
units/routes remain person-reserved. No unit, route or sync change was made.

Finding: CVE-2026-43994 / GHSA-74pg-rfh2-5qw5. Coturn `<= 4.9.0` passes an
attacker-supplied 16-bit `nonce_len` straight into `memcpy` over a 256-byte
stack `nonce[]` in `decode_oauth_token_gcm()`, before AES-GCM authentication.
Exact fix `46368b3e` (merged PR #1850, in tag `4.10.0`) adds a seven-line
upper-bound guard.

Grade at handoff: R1 ✓ / R2 ✓ / R3 ✓ ASan `WRITE of size 990` at
`client/ns_turn_msg.c:2363` / R4 LIMITED / R5 NOT CLAIMED. In an unprotected
plain build the attacker-selected `0x41` bytes land in adjacent struct fields
(`key_length=0x4141`, `timestamp=0x4141414141414141`,
`lifetime=0x41414141`). No live process, loopback wire request, saved-RIP
value, branch target, marker or command was observed.

Controls: fixed ASan refuses `990 > 256` and is clean; nonce-256 and nonce-16
inputs are clean on both vulnerable and fixed builds (an unrelated OpenSSL
error-path leak is present in both, so leak detection is disabled in the
runner and the leak remains a negative result). `bash run-all.sh`: 13 PASS /
0 FAIL; runner SHA-256
`b9c20a263f3e10151be2c56b98d3f197940edfdcae52a2966e40d62a1798ce7f`.

Next experiment for a dedicated mind: replay the advisory's documented
pre-auth STUN/TURN trigger against a pinned ASan vulnerable server bound to
127.0.0.1 with a test `--oauth` kid, observe the same sink over the wire,
and keep fixed plus safe-input controls. Preserve R5 as NOT CLAIMED until a
lab-chosen benign command executes with an observed side effect and an
independent witness replay.
