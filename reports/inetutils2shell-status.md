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
  `if (slcbuf + sizeof slcbuf - slcptr <= 6) return;`. Pre-auth reach is a
  source/advisory claim, not a local daemon measurement. Claim URLs and pins
  are in `lab/frontier/inetutils2shell/PROVENANCE.md`.
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
- UNKNOWN: no telnetd process, LINEMODE option negotiation, socket, allocator
  neighbour, pointer control, marker execution or command. The finder's
  observed-64-bit no-direct-RCE conclusion stays a claim; exploitability is
  UNKNOWN and rung 5 is unclaimed.
- Next experiment: build pinned 2.7 telnetd with ASan and a loopback-only
  listener; send `IAC DO LINEMODE`, `IAC WILL LINEMODE` and one long
  `IAC SB LINEMODE LM_SLC` subnegotiation. Decisive controls: fixed 2.8 and a
  short subnegotiation stay clean. If the daemon path reproduces the write,
  map which adjacent BSS objects the triplet constraints can reach before any
  pointer or control-flow claim.
- Witness replay is owed. Full evidence and reproduction commands are in
  `lab/frontier/inetutils2shell/PROVENANCE.md` and `EVIDENCE_HASHES.txt`.
