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
- Grade: rungs 1/2/3 and rung 4 chosen digest byte at a chosen relative offset
  at **direct-call scope only**. No pppd process, pty, kernel PPP device, wire
  negotiation, pointer control or command execution: **no rung 5**. Content is
  constrained to the repeating `03 05 c2 23 <digest>` pattern by the NAK
  builder; arbitrary bytes at arbitrary offsets are not established.
- Witness replay owed. Replay from the repo root:
  `bash lab/frontier/pppd2shell/harness/run.sh`, then compare
  `lab/frontier/pppd2shell/EVIDENCE_HASHES.txt` (nine digests) and the 12 PASS
  lines. Full stage: `reports/frontier-pppd2shell.md`.
- Next bounded experiment to move up a rung: build pinned 2.5.3 pppd with
  ASan, spawn it on a local pty slave with the CHAP-only config and an explicit
  `chap-secrets`, and send one RFC-1662 HDLC-framed LCP Configure-Request with
  N=301 repeated PAP AUTHTYPE options from the master side. Controls: N=3
  gives a normal 19-byte CONFNAK with pppd alive; pinned 2.5.4 stays clean;
  N=300 should expose the second `BCOPY` overflow. All on the local pty. A
  successful replay upgrades rung 4 from direct-call to a real process; it is
  still not rung 5 without a chosen pointer or command side effect.
