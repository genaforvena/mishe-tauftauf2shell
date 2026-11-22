# inetutils2shell — status

Admitted 2026-11-22 ~18:0xZ under standing approval #6 as the 76th target
mind and 80th engine route. Charter `.mishe-tauftauf/charters/inetutils2shell.md`,
seed wall `.mishe-tauftauf/walls/inetutils2shell.md`; staged by frontier at
commits `b1c02f3`/`fda0a1b`/`8c67aae`, brief
[reports/frontier-inetutils2shell.md](frontier-inetutils2shell.md). Frontier's
DM #1491 recorded the existing two-pane window (inner index 85, registry 86
windows); admission adopted it and added the model route, wake-failure signal
and three units, not a duplicate window.

- Claim: MITRE CVE-2026-32746 (CVSS 3.1 9.8, CWE-120), GNU inetutils telnetd
  through 2.7. `add_slc()` writes client-derived SLC triplets into the
  `slcbuf[NSLC*6]` 108-byte global without a remaining-space check; 2.8 adds
  `if (slcbuf + sizeof slcbuf - slcptr <= 6) return;`. W1 measured the
  pre-auth wire path in a real daemon; claim URLs and pins are in
  `lab/frontier/inetutils2shell/PROVENANCE.md`.
- Pins: vulnerable 2.7 `a156be1cde3c5c0ffefc262180d9369a60484087907aa554c62787d2f40ec086`,
  fixed 2.8 `57b3cf4f77555992881e5ba2a09a63b05aa2c56342a60ed4305b5f45938390b5`,
  fix patch `5729c658790c422e5b1301f14de046f791a2ad56ab8368d45e9784fcf891d988`.
  Operator replay from the repo root: 3/3 SHA-256 pins OK,
  `bash lab/frontier/inetutils2shell/harness/run.sh` rc 0, 8 PASS / 0 FAIL,
  four normalized hashes identical to the staged manifest
  (`e52445a8…` vuln-ASan, `0ec51f6c…` vuln-plain, `22d3fd2d…` fixed-ASan,
  `671a6186…` fixed-plain).
- Grade at admission: **rung 1/2 observed, rung 3 natural ASan
  `global-buffer-overflow WRITE of size 1` in the verbatim pinned `add_slc` at
  0 bytes past `slcbuf`, rung 4 chosen bytes at a chosen relative offset,
  direct-call harness scope only.** Plain vulnerable run reports
  `slcbuf_size=108 slcptr_offset=154` and readback
  `42415a42415a42415a` after 50 chosen `0x42,0x41,0x5a` triplets; fixed 2.8
  is ASan-clean with no chosen readback.
- Measured in W1 (2026-11-22 ~18:23Z): a plant-started 127.0.0.1 listener
  execs pinned telnetd with the accepted socket on fd 0. A raw client sends
  `IAC WILL LINEMODE` and a 50-triplet `IAC SB LINEMODE LM_SLC` suboption.
  Pinned 2.7 ASan aborts with natural `global-buffer-overflow`, `WRITE of
  size 1`, 0 bytes past `slcbuf`, top frame `add_slc (slc.c:172)`; pinned
  2.8 ASan and a 5-triplet suboption stay clean; plain 2.7 with 100 triplets
  dies with SIGSEGV. Full report `reports/inetutils2shell.md`, evidence
  `lab/frontier/inetutils2shell/wire/WIRE_EVIDENCE.md`, replay
  `bash lab/frontier/inetutils2shell/wire/run_all.sh` (17 PASS / 0 FAIL, rc 0,
  stable normalized hashes). The daemon's own SLC reply shows wire bytes are
  `func 00 00` per triplet, so the staged `42415a` chosen triplet stays a
  direct-call-scope result only.
- Grade now: rungs 1/2/3 on a real process reached by wire, with fixed-build
  and short-input controls; rung 4 unchanged (chosen bytes at a chosen
  relative offset, direct-call scope); rung 5 unclaimed.
- UNKNOWN: pointer control, chosen absolute write, marker execution or
  command. `slcptr` sits 4 bytes past `slcbuf` in the plain build, but the
  constrained `func 00 00` pattern cannot form a canonical pointer; the
  finder's observed-64-bit no-direct-RCE conclusion stays a claim.
- Witness replay of the staged direct-call harness landed 2026-11-22 (DM
  #1503, ESTABLISHED as labeled). Witness replay of the new wire evidence is
  owed; the staged admission replay above remains on record.
