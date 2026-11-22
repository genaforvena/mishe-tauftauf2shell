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
- W108 (2026-11-22 04:16Z) — shipped-process reach: `nanocat` from both pinned
  trees binds `ws://127.0.0.1:28765` directly. On 1.2.2 the short control is
  clean, `marker:41` gives a 558-byte reply plus `queue.c:47`, `marker:ff` gives
  558 bytes plus `aws.c:316`; fixed 1.2.3 gives 71 bytes under both markers.
  Gdb inside `nanocat` reads `DONE_OFFSET=516` and `item.next` equal to the
  chosen 8 bytes for both markers. Reproduce with
  `bash harness/nanocat_reach.sh`; raw traces in `harness/nanocat/`.
- Not claimed after W108: rung 5 (no command execution), clean takeover (the
  ff case still ends in a downstream FSM assertion), or that every nanomsg
  application is reachable — nanocat is a shipped CLI tool. The +516 offset is
  build-specific and must be re-measured for a release-flag build.
- W109 (2026-11-22 04:49Z) — release-flag rebuild closes the build-specificity
  question. At `-O3` with FORTIFY disabled (`src/build-rel-nofort`,
  `CMAKE_C_FLAGS="-g -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0"`), the offset
  is still `+516` (type-based and live gdb), the 490-byte cycle still gives
  `item.next = 0x3231307a79787776`, and `marker:41`/`marker:ff` still give
  558-byte replies plus `queue.c:47`/`aws.c:316`. So `+516` is not an `-O0`
  artifact. But the default optimized build on this host gets
  `_FORTIFY_SOURCE=3` (Ubuntu GCC default at `-O3`) and imports
  `__sprintf_chk`: there `marker:41`/`marker:ff` abort inside the sprintf with
  `*** buffer overflow detected ***` (rc 134), `reply_len=0`, and no chosen
  byte reaches the FSM. Rung 4 therefore holds on non-fortified builds only;
  a default Release build yields a remote source-local abort, not chosen-byte
  control. Source also closes rung 5: `nn_assert` is not `NDEBUG`-gated,
  `nn_fsm_raise` overwrites the corrupted `fsm/src/srcptr/type` before
  `nn_queue_push` reads `item.next`, and `nn_queue_push` resets `next=NULL`
  and writes only to the legit queue tail — no write-what-where. Raw traces in
  `harness/release/`; details in `reports/frontier-nanomsg.md` W109.
- Original harness evidence files and hashes:
  `lab/frontier/nanomsg2shell/harness/EVIDENCE_HASHES.txt`.

This file is updated by the target mind; the author report is not independent
acceptance.
