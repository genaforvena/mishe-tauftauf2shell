# Falkordb2Shell status

Handed off from frontier 2026-11-20 ~17:45Z and admitted under standing
approval #6 at ~18:12Z (charter `.mishe-tauftauf/charters/falkordb2shell.md`,
docs/task.md commit `6aa9dce`). Dedicated two-pane window and restorer registry
entry exist; wake trigger units and the presentation.json `active` entry are
owed from the person's full-flag sync. Everything below is inherited from
frontier, not yet re-run by this mind.

## Target

FalkorDB Bolt/WebSocket extended-length heap over-write, CVE-2026-107909 /
GHSA-x67x-q5pm-p9h7 (CWE-787, CVSS 4.0 8.8,
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H`). Advisory boundary: before 4.20.0;
Bolt endpoint (`BOLT_PORT`) disabled by default. Vulnerable parent
`40780e992ecc11f598ce3f4f65e04367f9abae2f`; fix
`0b11a00b34b25c4d4fdfe55f0a35c8a00593bd7d` removes the whole subsystem, so
there is no upstream fixed function to diff. Unowned at handoff; admitted
under standing approval #6 at ~18:12Z.

## Inherited, not yet re-run by this mind

- Rung 1 PASS: 14-byte masked frame with no payload, declared length 4144,
  produces 525 writes past the received bytes; in-bounds control (length 8,
  8 bytes supplied) produces zero OOB writes.
- Rung 2 PASS: zero canary at chunk offset 104 becomes
  `0x4242424242424242` with mask `0x42424242`, and
  `0x4141414141414141` with mask `0x41414141`.
- Rung 3 PASS: ASan heap-buffer-overflow in `buffer_apply_mask_single`
  (rc 1) with short 64-byte lab chunks; source-level counter observes all
  525 OOB writes with faithful 4096-byte chunks. Short-chunk layout is a lab
  artifact — upstream allocates 4096 bytes per chunk.
- Rung 4 NOT demonstrated: the mask repeats every 4 bytes, so the primitive
  writes `K:K`; no chosen address, pointer hijack or marker execution. Live
  service reachability and heap layout are UNKNOWN.
- `FIXED` build in the harness is a locally added length guard, not the
  upstream fix. Keep that distinction in every claim.

## Open

- Reproduce with `bash lab/frontier/falkordb2shell/run.sh` from clean HEAD;
  no off-loopback probe.
- Measure adjacent allocator metadata / first OOB `chunks[]` pointer on a
  real 4096-byte layout; decide whether `K:K` control advances rung 4.
- Preserve the in-bounds and alternate-mask controls and the short-chunk ASan
  caveat. File a witness claim with digests at cutoff.
- Evidence: `reports/frontier-falkordb2shell.md`,
  `lab/frontier/falkordb2shell/logs/digests.txt`.
