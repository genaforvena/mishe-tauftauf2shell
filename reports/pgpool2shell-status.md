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

- **W7 adjacent lane — CVE-2026-92869 (2026-11-22 ~17:26–17:3xZ):** under
  operator DM #1462 ("do NOT retire; mine an adjacent same-target lane"),
  the 4.7.2→4.7.3 fix series was checked against upstream release notes and
  the pinned parser diff. A genuinely different primitive was measured:
  unbounded peer-controlled `backend_desc` array length in
  `get_pool_config_from_json()` (`wd_json_data.c:130-142`), fixed by
  `parse_peer_count()` in 4.7.3. Direct call on the real 4.7.2 parser: ASan
  heap-buffer-overflow **WRITE of size 4** 256 bytes past the palloc'd
  `BackendDesc`; gdb readback at `i=128` shows chosen `0x42424242` written at
  the OOB slot; safe N=128 and fixed 4.7.3 N=129 are clean. On a real daemon,
  one loopback type-`Z` `WD_POOL_CONFIG_DATA` packet with N=129 crashes the
  4.7.2 watchdog child while N=128 and fixed 4.7.3 do not; live gdb caught
  the chosen value at `0x55555591dbe0` from `standard_packet_processor`
  (`watchdog.c:4472`) and a following SIGSEGV in `json_value_free_ex` with
  pointer `0x555542424242` (low 32 bits equal the chosen value).
  Full report: [reports/pgpool2shell-config-w7.md](pgpool2shell-config-w7.md);
  assets in `lab/pgpool2shell/config/`. Grade for this lane: rung 3 ASan
  corruption and wire crash, rung 4 chosen-value write at a layout-fixed
  offset including on a live daemon via wire input; **no arbitrary-address
  steering, no command, no rung 5**, and no witness replay of this new lane.
  W6's closed 92867 steering lanes were not retried.

- **W8 alias analysis (2026-11-22 ~18:02–18:06Z):** operator #1488 handed
  this mind new evidence on the W7 lane with a no-rung-5/no-steering-claim
  boundary. On the unchanged direct-call harness the OOB store lands in a
  live `json_value` node (type field `0x3` → `0x42424242`), not in the
  `backend_desc` array's `values[]`; the harness abort is value-independent
  (chosen `0` and `0x11111111` both give `free(): invalid size`, rc 134).
  On the live 4.7.2 watchdog child, a second wire replay with chosen
  `0x11111111` gives OOB slot `0x11111111` and fault pointer
  `0x555511111111`, matching W7's `0x42424242` → `0x555542424242`:
  low 32 bits track the peer value, high 16 are inherited. Before/after
  enumeration identifies the slot as `json_object_entry.value` of
  `backend_hostname` in a peer backend object (name_length `0x10`);
  `json_value_free_ex` walks object entries in reverse and faults on that
  child pointer first. Full report:
  [reports/pgpool2shell-alias-w8.md](pgpool2shell-alias-w8.md); replay assets
  in `lab/pgpool2shell/config/`. Grade unchanged: rung 3 + rung 4 at a
  layout-fixed offset, no address steering, no command, no rung 5. Witness
  replay was outstanding at measurement time; its verdict is recorded below.

- **Independent witness replay W118 (DM #1531, 2026-11-22 ~18:25–18:5xZ):**
  the witness returned ESTABLISHED **as labeled** for W7/W8. From a clean
  git-archive replay with its own pinned plain/ASan builds (SHA256SUMS 2/2
  OK): harness A–G as claimed; ASan WRITE of size 4 at `utils/json.c:1189`
  from `wd_json_data.c:136`, 256 bytes past the 113672-byte `BackendDesc`;
  9/10 normalized hashes identical (the ASan-file difference is only its
  build paths/BuildId/PC, same fault address and frames). Harness alias idx
  `-2767`, word `0x3` → `0x42424242`; abort value-independent at chosen
  `0`, `0x11111111`, `0x33333333`. On its own live 4.7.2 build, wire
  `0x11111111` at `0x55555591dbc0` → SIGSEGV at `0x555511111111`,
  `0x33333333` → `0x555533333333` at the same slot; backtrace
  `get_pool_config_from_json` ← `standard_packet_processor:4472` ←
  `watchdog_main`. `run.sh` A/B/C: safe N=128 clean, vulnerable N=129
  faults, fixed 4.7.3 rejects with `invalid watchdog JSON payload`. Ports
  19003–19006 free before and after; only its own children killed; no repo
  edits. Counter-observation, no grade change: its absolute slot
  `...dbc0` differs from the author's `...dbe0` by `0x20`, but both are
  `+0x1bd08` from `backend_desc` — relative offset is layout-fixed,
  absolute base is build-dependent. Its two NITs were checked against the
  pinned 4.7.2 tarball and fixed in
  [reports/pgpool2shell-alias-w8.md](pgpool2shell-alias-w8.md): reverse
  object walk is `utils/json.c:1100`, `value->parent = 0` is `:1075`, and
  `:1079` is the `switch (value->type)` PC gdb reports. Grade unchanged:
  no address steering, no command, no rung 5. W9 was not replayed.

- **W9 `wd_nodes` branch (2026-11-22 ~18:3xZ):** a distinct unchecked array
  in the same peer config parser — 4.7.2 `wd_json_data.c:189-202` copies the
  peer-set `wd_nodes` length into the 128-entry `WdNodesConfig.wd_node_info`
  with no cap; 4.7.3 adds an explicit `MAX_WATCHDOG_NUM` rejection at
  `:215-219`. On the real pinned 4.7.2 parser object at N=129, chosen
  32-bit ports land at `wd_node_info[128]` offsets +256/+260 and a 12-byte
  peer hostname sets the adjacent `trusted_servers` pointer field to
  `0x5555555555555555` or `0x4141414141414141`; N=128 and fixed 4.7.3 are
  clean. ASan is clean because the write stays inside the `POOL_CONFIG`
  allocation, so no rung 3 is claimed for this branch. Full report:
  [reports/pgpool2shell-wdnodes-w9.md](pgpool2shell-wdnodes-w9.md); replay
  `bash lab/pgpool2shell/wdnodes/run-harness.sh` (A–G, hashes in
  `EVIDENCE_HASHES.txt`). Grade: rung 4 at direct-call scope only, on a
  layout-fixed adjacent field; no wire, no chosen address, no command, no
  rung 5. Harness-only: no ports used during witness W118's window.

This file is updated by the target mind; the author report is not independent
acceptance.
