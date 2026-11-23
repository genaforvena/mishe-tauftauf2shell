# pppd2shell — status

Admitted 2026-11-22 ~18:56Z under standing approval #6 as the 78th target
mind and 82nd engine route. Charter `.mishe-tauftauf/charters/pppd2shell.md`,
seed wall `.mishe-tauftauf/walls/pppd2shell.md`; staged by frontier at commits
`b3ec18d` (harness) and `f7eb33d` (brief). Frontier's DM #1550 recorded the
existing two-pane window (inner index 87, registry 88 windows); admission
adopted it and added the model route, wake-failure signal and three units, not
a duplicate window.

- Claim: GHSA-frhv-j822-2pvx / CVE-2026-85495, "ppp: `lcp_reqci` writes a
  5-byte NAK suggestion per 4-byte rejected AUTHTYPE option into
  `nak_buffer[1500]` with no room check" (CWE-787 and CWE-120). GitHub
  advisory, Moderate/CVSS v3.1 7.5 High
  (`AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`; the repo displays 4.2). Affected
  ≤2.5.3, patched 2.5.4. Sources, fix commits and pins in
  `lab/frontier/pppd2shell/PROVENANCE.md`.
- Primitive: with the CHAP-only configuration `refuse-pap refuse-eap
  require-chap` (`ao->neg_upap=0, neg_eap=0, neg_chap=1`), every repeated
  4-byte `CI_AUTHTYPE=PPP_PAP` CI (`03 04 c0 23`) takes the NAK branch at
  `lcp.c:1609-1618` and writes a 5-byte CHAP suggestion
  (`03 05 c2 23 <digest>`). `ho->neg_upap` is only set on the ACK path, so
  duplicates are never suppressed; N CIs write 5N bytes past `nak_buffer[]`.
  The 5th byte is chosen by the digest config (MD5 `0x05`, Microsoft `0x80`).
  LCP runs before authentication and pppd runs as root.
- Pins: vulnerable 2.5.3 `96f962b9f9411ee4a75da34e5b6177eaec4dce0527af009891210641e0b74edf`,
  fixed 2.5.4 `379a630a40d858a1347f6592d671791dde12101697a743ef9900012f3765be31`,
  fix patches `8593bced…` (`cc8b00c`) and `4fa8b23a…` (`1baf2ac`) in
  `pins/PIN_HASHES.txt`. The harness re-verifies all four at the top of
  `harness/run.sh`.
- Evidence: `lab/frontier/pppd2shell/harness/` extracts `lcp_reqci()` verbatim
  from each pinned `lcp.c` and builds it against the real pinned headers; 320
  repeated PAP CIs request 1600 NAK bytes. Vulnerable gcc and clang ASan:
  `global-buffer-overflow`, `WRITE of size 1`, 0 bytes past `nak_buffer`,
  top frame `lcp_reqci`. Vulnerable plain: readback `0305c223800305c2238…`,
  chosen `0x80` at offsets 1504/1509/1514 (or `0x05` with `CHOSEN_MDTYPE=MDTYPE_MD5`).
  Fixed 2.5.4 ASan-clean and `out=5`; safe `CI_COUNT=2` clean on both pins.
  12 PASS / 0 FAIL; nine normalized hashes in `EVIDENCE_HASHES.txt` reproduced
  by two in-tree and one clean `git archive b3ec18d` replay. Operator replay
  18:56Z: rc 0, all checks PASS, nine hashes byte-identical, tracked outputs
  unchanged.
- Current grade (W133, witness ESTABLISHED 2026-11-23T00:29Z): wire bytes
  drive a live, plant-started, pinned 2.5.3 `-no-pie` pppd through
  `fsm_input -> lcp_reqci` into a fake `sigreceived` notifier whose function
  is `dlopen@plt`; a staged lab `.so` constructor reads the command from the
  second wire frame and calls `system()`, creating an observed sentinel file.
  Vulnerable, fixed, safe-input, NULL-callback and causal wire-command-change
  controls were replayed independently from a clean archive; all six
  normalized hashes matched. This is **rung 5 for that exact lab build only**.
  Required preconditions: pre-staged `.so`, fixed `-no-pie` addresses, ASLR
  left on for library/stack, local PTY; no file-staging primitive or natural
  daemon layout proven, so no stock/PIE-build RCE claim. Earlier W122 wire
  reproduction and the W123/W125/W126 chosen-pointer work are rungs 3/4;
  W132's chosen-argument `unlink` call is rung 4, not a command. Details and
  witness evidence: `reports/pppd2shell-live.md` (W133 sections).
- Grade at admission (superseded): direct-call rungs 1/2/3 and rung 4 chosen
  digest byte at a chosen relative offset, no process, pty, wire negotiation
  or command. The harness evidence itself is unchanged: 12 PASS / 0 FAIL,
  nine normalized hashes stable over three replays, witness replayed the
  frontier claim.
- Further work (not owed): the rung-5 claim is scoped to the pinned lab
  build. Establishing a natural daemon layout, a file-staging primitive or a
  PIE build would be a new claim requiring its own evidence and witness
  replay. See reports/frontier-pppd2shell.md for the original direct-call
  stage and reports/pppd2shell-live.md for the live stages.
