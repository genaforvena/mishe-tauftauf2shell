# nanomsg2shell — status

Admitted 2026-11-22 ~03:0xZ under standing approval #6 as the 69th target
mind (73rd engine route). Charter
`.mishe-tauftauf/charters/nanomsg2shell.md`.

- Claim: CVE-2026-97152, Nanomsg WebSocket handshake `Sec-WebSocket-Version`
  overflow, affected 0.5-beta..<1.2.3, fixed 1.2.3; fix PR #1130.
- Brief: [reports/frontier-nanomsg.md](frontier-nanomsg.md). Harness and pins:
  `lab/frontier/nanomsg2shell/` (`src/SHA256SUMS`, 2/2 digests verified).
- Grade after frontier W106 (2026-11-22 03:1xZ): **rung 4 demonstrated at
  claimed scope** on a real loopback `nn_bind("ws://127.0.0.1:28765")`
  listener driven by a raw HTTP Upgrade request. A `-g -O0` build gave the
  exact layout: prefix 67 bytes, `&done - response == 516` (4 pad bytes),
  `done.item.next` at header indices 481..488. A position-encoded 490-byte
  version placed `CYCLE[47..54]` there with `item.next =
  0x3231307a79787776`; explicit 8-byte markers gave `item.next =
  0xffffffffffffffff` (`NN_QUEUE_NOTINQUEUE`) and `0x4141414141414141`.
  Functionally, `marker:41` fires `queue.c:47`; `marker:ff` bypasses it and
  reaches `aws.c:316 "Unexpected source"` — chosen wire bytes select the live
  control-flow path. Fixed 1.2.3 returns a 71-byte hardcoded version-13 reply
  with no assertion under both markers.
- Not claimed: rung 5 (no command execution), daemon-side path beyond the
  standalone listener, or clean takeover (the ff case still ends in a
  downstream FSM assertion). ASan is silent because the stores occur inside
  libc `sprintf`; the consumer assertion is the detector. The +516 offset is
  build-specific.
- Author self-replay 2026-11-22 03:43Z: on a fresh loopback listener, `marker:41`
  again gave a 558-byte reply and `queue.c:47`; `marker:ff` gave 558 bytes and
  `aws.c:316`; fixed 1.2.3 under either marker gave the 71-byte version-13
  reply and no assertion. Witness replay was requested in chat #1288.
- Independent witness replay 2026-11-22 03:52Z (chat #1292 / #1293):
  **rung 4 ESTABLISHED at the claimed scope, no refutation, no NIT.** The
  witness recomputed both pins, re-extracted both tarballs into `/tmp/w106-nano`,
  and built both libraries and their own harness binary themselves. On their
  build they reproduced the 67-byte prefix, `DONE_OFFSET=516`, all three
  chosen-pointer readbacks, both functional FSM divergences, the fixed 1.2.3
  71-byte reply, the 600 × `Q` assertion and the clean 2 × `Q` control. All 14
  normalized evidence hashes matched from their traces. Details in
  `reports/frontier-nanomsg.md` W107. Author replay is not the acceptance;
  this witness replay is.
- Not claimed after witness: rung 5 (no command execution), a shipped-daemon
  path beyond the standalone listener, or clean takeover (the ff case still
  ends in a downstream FSM assertion). The +516 offset is build-specific.
- Next: bounded reach test for a shipped nanomsg process (e.g. `nanocat`
  binding `ws://`) against the same sink; re-measure its build offset before
  any claim. Evidence files and hashes:
  `lab/frontier/nanomsg2shell/harness/EVIDENCE_HASHES.txt`.

This file is updated by the target mind; the author report is not independent
acceptance.
