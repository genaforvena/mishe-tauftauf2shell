# pnet2shell — status

Admitted 2026-11-22 ~17:2xZ under standing approval #6 as one of three
frontier-staged target minds (engine routes 77–79, inner windows 82–84).
Charter `.mishe-tauftauf/charters/pnet2shell.md`, seed wall
`.mishe-tauftauf/walls/pnet2shell.md`; staged at commit `df587c6`, brief
`reports/frontier-pnet2shell.md`. Frontier's window registry records the
two-pane inner window at index 84, verified live at 17:18Z (frontier's
registry correction); admission added the model route, wake-failure signal and
six units, not a duplicate window.

- Claim: CVE-2026-127122 / GHSA-9cfr-5cg8-55x5 / EUVD-2026-125302 (CNA
  RT-Labs AB, vendor advisory RRTL-261109-01 §3.6, upstream release v1.0.4
  issue 2692). CWE-787: a Connect request with more `PF_BT_MCR_REQ` blocks
  than `PNET_MAX_MC_CR` (default 1) writes request bytes past
  `pf_ar_t.mcr_request[]` with no established AR and no credentials;
  ADJACENT network access required, CVSS 4.0 7.2 HIGH. Affected before 1.0.4;
  builds with `PNET_OPTION_MC_CR=0` are not affected.
- Brief: [reports/frontier-pnet2shell.md](frontier-pnet2shell.md). Pins under
  `lab/frontier/pnet2shell/` (`PIN_HASHES.txt`, `PROVENANCE.md`): vulnerable
  tag public/v1.0.3 `19782d52c56640526156f8db04efe93317f9c530`, fixed tag
  public/v1.0.4 `1c3b0b435b2ee2c6cea86849c14ee98f6ee579f1`.
- Primitive: pinned `pf_cmrpc.c` passes the unbounded `p_ar->nbr_mcr` as `ix`
  to `pf_get_mcr_request()`; the real writer `pf_block_reader.c:785-817`
  stores eight attacker-chosen scalars and up to 240 chosen name bytes plus a
  NUL into `mcr_request[ix]`, advancing 252 bytes per block. The v1.0.4 fix
  adds `if (!(p_ar->nbr_mcr < PNET_MAX_MC_CR))` before the call; the writer is
  unchanged.
- Grade at admission: **rung 3 ASan-confirmed and rung 4 chosen bytes at a
  chosen relative index on the real pinned writer, at direct-call harness
  scope.** Vulnerable ASan gives `heap-buffer-overflow`, `WRITE of size 2`, 0
  bytes after a 49600-byte `calloc` at `pf_get_mcr_request
  (pf_block_reader.c:790)` after 40 blocks; fixed-caller ASan clean. Plain
  two-block readback shows `iocr=4142 protocol=43 resolution=44 timeout=4546
  namelen=16 name=5a…` through the real `pf_multicast_cr_t` fields at index 1
  (offset 252); fixed rejects at block 1 with WRONG_BLOCK_COUNT. `bash
  harness/run.sh` self-extracts hash-verified tarballs, builds all four cells,
  runs 11 asserts and produced byte-identical normalized hashes on two
  replays, including one after a clean-source delete.
- UNKNOWN: no daemon built and no PROFINET frame sent. The ADJACENT pre-auth
  surface is an advisory-plus-source claim; `PNET_OPTION_MC_CR=1` was chosen
  in the harness. No absolute-address write, pointer control, marker execution
  or command side effect. Rung 5 UNKNOWN.
- Next experiment: build the pinned v1.0.3 sample stack on loopback with the
  management UDP listener and replay a canned Connect frame with two appended
  `0x0106` MCR blocks under ASan; decisive observation is a WRITE in
  `pf_get_mcr_request` with `pf_cmrpc_rm_connect_interpret_ind` in the chain
  and a v1.0.4 WRONG_BLOCK_COUNT reject for the same frame.
- Witness replay is owed. No rung 5 claim.
