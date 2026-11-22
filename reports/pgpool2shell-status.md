# pgpool2shell — status

Admitted 2026-11-22 ~04:2xZ under standing approval #6 as the 70th target
mind (74th engine route). Charter
`.mishe-tauftauf/charters/pgpool2shell.md`. Frontier staged the find at
commit `da833f5` (brief `reports/frontier-pgpool2shell.md`); the operator
completed admission after re-verifying the pins and replaying the harness.

- Claim: CVE-2026-92867 (JVN#22475874, JPCERT/CC CNA 2026-09-29; NVD Awaiting
  Analysis), CWE-787, CNA CVSS 4.0 8.7 / CVSS 3.0 8.8, PR:L authenticated
  watchdog peer. Affected 4.3.0–4.3.20 / 4.4.0–4.4.17 / 4.5.0–4.5.12 /
  4.6.0–4.6.7 / 4.7.0–4.7.2 (and EOL 3.5.x–4.2.x), fixed 4.3.21 / 4.4.18 /
  4.5.13 / 4.6.8 / 4.7.3 (2026-09-29).
- Brief: [reports/frontier-pgpool2shell.md](frontier-pgpool2shell.md). Pins,
  fix patch and harness: `lab/frontier/pgpool2shell/` (`PROVENANCE.md`,
  `src/SHA256SUMS`, 2/2 digests re-verified OK by the operator at admission).
- Primitive: `parse_wd_node_function_json()` (`src/watchdog/wd_json_data.c`)
  allocates `*node_id_set` but writes `*(node_id_set[i])` instead of
  `(*node_id_set)[i]` — a one-character C-precedence error fixed upstream at
  commit `0388652d` (V4_7_STABLE backport `a58fe0c7`). At `i == 0` the write
  lands in the palloc'd buffer, which is why the single-node failover path
  stayed latent; at `i >= 1` the code reads the pointer-sized slot adjacent
  to the caller's `int **node_id_set` argument, dereferences it and stores the
  peer-chosen 32-bit `NodeIdList` value through it. Trigger needs
  `NodeCount >= 2`. Two real callers in `watchdog.c` pass `&node_id_list`
  (failover command over watchdog IPC, online recovery from a peer packet).
- Grade at admission: **rung 3 ASan-confirmed and rung 4 chosen-value write
  at direct-call harness scope**, on the real pinned 4.7.2 parser object.
  `NodeCount=1` is clean on both versions. `NodeCount=2` on 4.7.2 gives
  `AddressSanitizer: stack-buffer-overflow`, READ of size 8 at
  `wd_json_data.c:858` (ASan aborts in the bad-index redzone). On the plain
  4.7.2 build under gdb, `node_id_set[1]` is `0x555555564060` (the JSON
  buffer) and chosen `0x42424242` is written as bytes `42 42 42 42` there;
  the destination's second element stays zero, proving the store went through
  the bad index. Pinned 4.7.3 under the same payload is clean and stores both
  values in the intended buffer. `bash lab/frontier/pgpool2shell/harness/run.sh`
  replays all cases from a clean tree (operator rc 0 at admission); normalized
  hashes are in `harness/EVIDENCE_HASHES.txt`.
- Not claimed: wire reach, address steering, daemon-side layout, command
  execution or rung 5. The write **address** in the harness is whatever
  pointer the caller's adjacent slot holds (here the JSON buffer), not shown
  attacker-steerable; a real caller's adjacent slot must be re-measured per
  build. No wire packet was sent and no `pgpool` process was started. The
  vendor's "arbitrary memory address / arbitrary code execution" wording is
  not established by these observations. PR:L caps the claimed reach.
- Operator replay 2026-11-22 04:25Z: `sha256sum -c src/SHA256SUMS` 2/2 OK from
  `lab/frontier/pgpool2shell/src`, then `bash harness/run.sh` reproduced all
  four cases including the gdb byte readback (rc 0). The pinned full-flag
  `--no-observe` doctor returned `PASS local plant out of Git` / `GREEN`, rc 0.
- First target-mind steps: re-verify the inherited state, then bound one lane —
  either emulate a watchdog peer packet to reach the sink on the wire, or map
  the caller's adjacent stack slot under a real daemon build and test whether
  a second peer-controlled JSON field steers the write address. Witness replay
  is owed at the claimed direct-call scope; none has been requested yet.

- **W1 wire result (2026-11-22 ~05:18Z):** a synthetic loopback watchdog peer
  reaches `process_remote_online_recovery_command()` in a real, plant-built
  `pgpool` watchdog child and crashes it with the vulnerable parser. A/B/C:
  4.7.2 `NodeCount=2` → SIGSEGV; 4.7.2 `NodeCount=1` → clean; 4.7.3
  `NodeCount=2` → clean. gdb on the live child caught the fault at
  `wd_json_data.c:858` with `node_id_set[1] = 0x1`, confirming the adjacent
  slot is not a peer-steerable pointer on this build. Full report:
  [reports/pgpool2shell-wire-w1.md](pgpool2shell-wire-w1.md); replay assets in
  `lab/pgpool2shell/wire/`. Grade: rung 3 now wire-confirmed on a real daemon;
  rung 4 remains at direct-call harness scope; address steering and rung 5
  remain UNKNOWN. Wire-scope witness replay is owed.

This file is updated by the target mind; the author report is not independent
acceptance.
