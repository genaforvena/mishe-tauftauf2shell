# Xrdp2Shell status

Admitted under standing approval #6 ~20:3xZ on frontier's #306 handoff. The
site charter (`.mishe-tauftauf/charters/xrdp2shell.md`) and docs/task.md entry
are live; the dedicated two-pane window 19 (inner socket) and restorer
registry entry were already live from frontier. Wake trigger units and the
presentation.json `active` entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`) — never a bare `mishe sync`. The operator re-ran
frontier's extracted harness from clean committed sources at ~20:25Z:
`bash lab/frontier/xrdp2shell/run.sh` prints `ALL CHECKS PASS`, rc 0; digests
`46735a43…` / `2da4d3ea…` match the brief.

## Target

xrdp server-side virtual channel forwarding to chansrv: fixed 8192-byte
`chan_trans` out stream plus client-controlled reassembled DYNVC payload,
GHSA-hh7r-2rmq-q4g4 / CVE-2026-44178 (CWE-122, CVSS 3.1 8.8 High,
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`). Affected `< 0.10.6.1`; fixed in
`0.10.6.1`. Fix commit `43dc9c3b71e5e46733d70ec0239c482ee264cd9f`. Default
posture is post-authentication (PR:L) with a dynamic channel open.

## Mechanism and reproduction

- `xrdp_mm_drdynvc_data_first()` (raw `xrdp_mm.c:2318-2346`, v0.10.6) asks
  `trans_get_out_s(trans, 8192)` (:2330), writes a 28-byte header and then
  `out_uint8a(s, data, bytes)` (:2343); `data()` (:2351-2377) uses a 24-byte
  header; `xrdp_mm_process_channel_data()` (:2763-2809) uses 26. `init_stream`
  keeps the 8192 buffer (`common/parse.h:248-259`) and `out_uint8a` is a plain
  `g_memcpy` unless `USE_DEVEL_STREAMCHECK` is compiled in (`:563-572`, `:82-90`).
- `drdynvc_process_data_first()` (`libxrdp/xrdp_channel.c:425-498`) checks only
  `total_bytes >= 1590 && bytes <= total_bytes` (:472); the DYNVC reassembly
  path (`:547-658`) stages a client-sized `total_length` stream (:586), so a
  multi-chunk message can drive `bytes` far past the 8164-byte threshold.
- The 0.10.6.1 fix allocates the exact `pdu_size` in all three writers and
  rejects `length > 65535`.
- Harness (pinned digests above): rung 1 28+20000 bytes gives
  `oob_writes=11836 first_oob=8192 last_oob=20027`; static 26-byte path gives
  `oob_writes=11834`; rung 2 chosen `ab`/`cd` land at OOB offsets 8228/12028;
  rung 3 ASan `heap-buffer-overflow`, `WRITE of size 20000`, 0 bytes after the
  8192-byte region; rung 4 `de`/`ad` across two messages at OOB offsets
  8228/12024; exact-size and benign controls `oob_writes=0`; 5/5 traces
  byte-identical.

## Evidence boundary

Rungs 1/2/3 established, rung 4 PASS in the extracted harness with
client-chosen bytes at client-chosen offsets. Live xrdp process, real
DRDYNVC PDU parse/reassembly, dynamic-channel open, stock allocator layout,
network reachability and the auth gate remain UNKNOWN. No off-loopback probe.

Brief: `reports/frontier-xrdp2shell.md`; harness:
`lab/frontier/xrdp2shell/{xrdp_overflow.c,run.sh}`. Witness replay requested;
author report is not acceptance.
