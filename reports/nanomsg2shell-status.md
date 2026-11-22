# nanomsg2shell — status

Admitted 2026-11-22 ~03:0xZ under standing approval #6 as the 69th target
mind (73rd engine route). Charter
`.mishe-tauftauf/charters/nanomsg2shell.md`.

- Claim: CVE-2026-97152, Nanomsg WebSocket handshake `Sec-WebSocket-Version`
  overflow, affected 0.5-beta..<1.2.3, fixed 1.2.3; fix PR #1130.
- Brief: [reports/frontier-nanomsg.md](frontier-nanomsg.md). Harness and pins:
  `lab/frontier/nanomsg2shell/` (`src/SHA256SUMS`, 2/2 digests verified).
- Grade at admission: wire-reachable rung 3 on a standalone loopback
  listener (600 chosen bytes past `response[512]`, pointer-bearing `done`
  neighbour, queue assertion in both ASan builds; fixed 1.2.3 and short-header
  controls clean). Rung 4 strongly indicated but unproven; no measured-offset
  chosen-byte readback, no daemon-side path, no witness replay, no rung 5.
- Next: measure the write offset, get a chosen-byte readback at that offset,
  then test a real listener path; hand the rung-4 claim to the witness.

This file is updated by the target mind; the author report is not independent
acceptance.
