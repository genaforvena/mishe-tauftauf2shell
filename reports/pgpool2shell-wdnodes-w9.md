# pgpool2shell W9 — `wd_nodes` array overflow in the same peer config parser

2026-11-22 ~18:3xZ. Author-measured, harness-only. This is a **different
branch** of the CVE-2026-92869 fix, not a retry of W7/W8's `backend_desc`
array. No daemon was started, no packet sent, no loopback port used, and the
witness's W118 replay window was left alone.

## Primitive

`get_pool_config_from_json()` reads the peer-controlled `wd_nodes` array
length into `config->wd_nodes.num_wd` and writes `wd_port`, `pgpool_port` and
`hostname` into `wd_node_info[i]` for every element:

- 4.7.2 `src/watchdog/wd_json_data.c:184-203`: no upper bound on
  `value->u.array.length` (`wd_json_data.c:189`).
- `include/pool_config.h:153-157`: `WdNodesConfig` holds
  `wd_node_info[MAX_WATCHDOG_NUM]`, `MAX_WATCHDOG_NUM = 128`
  (`pool_config.h:39`); `WdNodeInfo` is 264 bytes
  (`hostname[256]`, `pgpool_port` at +256, `wd_port` at +260).
- 4.7.3 `wd_json_data.c:215-219` rejects `wd_nodes` length above
  `MAX_WATCHDOG_NUM` before the loop. This is the same fix series as W7's
  `parse_peer_count()` cap on `backend_desc`.

At `i >= 128` the two integer stores land 256/260 bytes past the last
`wd_node_info` element, still inside the same palloc'd `POOL_CONFIG`, and the
`strncpy(..., hostname, 255)` (`wd_json_data.c:202`) writes up to 255 bytes
from the OOB slot. The following `trusted_servers` field starts 4 bytes after
that slot, so peer hostname bytes 4..11 land in its pointer.

## Measurement

Replay from `lab/pgpool2shell/wdnodes/`: `bash run-harness.sh` builds or
reuses the hash-pinned 4.7.2/4.7.3 parser objects (ASan and plain trees),
links the direct-call harness and runs A–G. Normalized hashes are in
`EVIDENCE_HASHES.txt`; raw outputs are `evidence-*.txt`.

| Case | Build / input | Observed |
| --- | --- | --- |
| A | 4.7.2 plain, N=128 | `num_wd=128`, OOB slot and `trusted_servers` zero/NULL (rc 0) |
| B | 4.7.2 plain, N=129, port `0x42424242`, host `PEERHOST` | `port_slot=4242424242424242`, `hostname_slot=50454552484f5354...`, `trusted_servers=0x54534f48` |
| C | 4.7.2 plain, N=129, port `0x11111111` | `port_slot=1111111111111111`; `trusted_servers` unchanged from B |
| D | 4.7.3 plain, N=129 | `ERROR: invalid watchdog configuration JSON`, no config returned |
| E | 4.7.2 ASan, N=129 | **clean** — the write stays inside the `POOL_CONFIG` allocation (intra-object overflow) |
| F | 4.7.2 plain, N=129, host `wxyzUUUUUUUU` | `trusted_servers=0x5555555555555555` |
| G | 4.7.2 plain, N=129, host `wxyzAAAAAAAA` | `trusted_servers=0x4141414141414141` |

B/C show peer-chosen 32-bit port values; F/G show peer-chosen hostname bytes
setting all eight bytes of the adjacent pointer field. The destination is a
layout-fixed field of the config object; this is **not** an attacker-selected
write address. ASan does not flag this branch, so rung 3 is **not** claimed
for it. No follow-on dereference of the corrupted `trusted_servers` pointer
was attempted and no wire reach was measured on this branch.

## Grade

Rung 4 at direct-call scope only: chosen-value and chosen-byte writes to an
adjacent struct field on the real pinned 4.7.2 parser object, with N=128 and
fixed-4.7.3 controls. No rung 3 by ASan on this branch, no wire, no chosen
address, no command execution, no rung 5. Independent replay not requested;
W118 is replaying W7/W8 only.
