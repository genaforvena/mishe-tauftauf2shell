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
- **W2 -O2 build (2026-11-22 ~05:42–05:48Z):** rebuilt pinned 4.7.2 at
  `-g -O2 -fno-omit-frame-pointer` and replayed the loopback wire. A/B still
  holds (NodeCount=2 → SIGSEGV, NodeCount=1 → clean), so wire reach is not
  an O0-layout artifact. gdb on the live O2 watchdog child finds
  `node_id_set[1] = 0x55555562d742 <read_packet_of_type+402>` — a stale code
  pointer, unchanged by a safe-N=1 warm-up packet; the chosen value writes
  into read-only text and faults. Second measured negative for address
  steering, independent of W1's O0 disassembly/gdb/sweep negatives. Full
  report: [reports/pgpool2shell-o2-w2.md](pgpool2shell-o2-w2.md). Grade
  unchanged: rung 3 wire-confirmed on a real daemon in two build layouts;
  rung 4 only at direct-call harness scope; no chosen-address write, no
  command, no rung 5. Witness replay of W1 still owed.
- **Independent verdict (witness W113, closed 08:09Z; folded 2026-11-22
  11:2xZ):** the witness's own wall records ESTABLISHED at the claimed rung-3
  wire scope — it verified 2/2 pins, built 4.7.2/4.7.3 itself at `-g -O0`,
  ran A/B/C on its own ports 29003–29005 with its own config (counters 1/1,
  1/0, 1/0), and captured a live gdb fault at `wd_json_data.c:858` reached
  from `process_remote_online_recovery_command()` (`watchdog.c:7558`) with
  `node_id_set[1]=0x1`. Its verdict explicitly excludes a chosen-address
  write, command execution and rung 5. The optional warm-up steering negative
  was **not** independently replayed (its gdb fork-follow stalled and left
  stale IPC state); it remains author evidence only, not a contradiction.
  Caveat on delivery: the witness wall says a verdict DM was sent, but no
  witness chat event follows #1327 (05:31Z) until #1376 (10:14Z), and no DM
  reached this role's dossier. The verdict above is cited from the witness
  wall and its recorded artifacts, not from a delivered message. Grade stays
  rung 3 wire-confirmed with independent replay; rung 4 only at direct-call
  harness scope; rung 5 UNKNOWN.

- **W6 cross-command grooming negative (2026-11-22 ~16:57Z):** at low host
  load gdb was responsive, so the previously stalled lane was replayed. The
  local node was allowed to reach LEADER state; one benign type-`f` failover
  packet (`NodeCount=1`, matching one-element list) executed the parser in the
  failover caller's frame (`0x7fffffff0f90`), then a type-`r` `NodeCount=2`
  trigger still read `node_id_set[1]=0x1` in the recovery caller's frame
  (`0x7fffffff0fd0`, 0x40 away) and SIGSEGV'd at `wd_json_data.c:858`. The
  last open address-steering lane is closed by measurement; all six attempted
  lanes are now negatives. Full report:
  [reports/pgpool2shell-groom-w6.md](pgpool2shell-groom-w6.md); replay assets
  in `lab/pgpool2shell/wire/groom-w6/`. Grade unchanged: rung 3 wire-confirmed
  with independent replay; rung 4 only at direct-call harness scope; no
  chosen-address write on a real daemon, no command, no rung 5.

This file is updated by the target mind; the author report is not independent
acceptance.
