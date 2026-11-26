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
for it. At the 18:3xZ direct-call stage no follow-on dereference had been
attempted and no wire reach had been measured; W10 below supplies the wire measurement.

## Grade at direct-call scope (superseded by W10 below)

Rung 4 at direct-call scope only: chosen-value and chosen-byte writes to an
adjacent struct field on the real pinned 4.7.2 parser object, with N=128 and
fixed-4.7.3 controls. No rung 3 by ASan on this branch, no wire, no chosen
address, no command execution, no rung 5. Independent replay not requested;
W118 is replaying W7/W8 only. W10 below adds wire reach.

## W10 — `wd_nodes` wire reach (22:18-22:22Z, author-measured)

The wall left "W9 wire reach" unmeasured. It is now measured. Assets in
`lab/pgpool2shell/wdnodes/wire/` (`gen_config_json.py`, `peer.py`,
`pgpool-w9.conf`, `run.sh`, `gdb-w9.cmd`, `gdb-w9-post.cmd`, `gdb-run.sh`,
`hash-evidence.sh`, raw `evidence-*` / `gdb-w9*.out` and
`EVIDENCE_HASHES.txt`). One loopback type-`Z` `WD_POOL_CONFIG_DATA` packet
with `wd_nodes` length 129 and `backend_desc` length 1; no non-loopback
address, ports 19003-19006 checked free before each run. `hash-evidence.sh`
hashes decisive extracted lines (full daemon logs carry ephemeral ports,
PIDs and timing-dependent line counts); verified stable across two independent
`run.sh` replays. The two gdb traces were each captured once.

### Three-case wire replay (`bash run.sh`, 67 s, rc 0)

| Case | Build / input | Observed |
| --- | --- | --- |
| A | 4.7.2, N=128 | no segfault; `CONFIG DATA` received; verify warnings; `DETAIL: this node has 2 watchdog nodes while "" is configured with 128 watchdog nodes` |
| B | 4.7.2, N=129 | no segfault; `CONFIG DATA` received; verify warnings; `DETAIL: ... configured with 129 watchdog nodes` |
| C | 4.7.3, N=129 | no segfault; `ERROR: invalid watchdog configuration JSON` — parser rejected, no verify warnings |

The 4.7.2/4.7.3 differential proves the peer-controlled `wd_nodes` length
reaches `get_pool_config_from_json()` in a live watchdog child. Neither 4.7.2
case faults on this branch — unlike W7's `backend_desc` branch, where a type-`Z`
packet crashed the child in `json_value_free_ex`.

### Live-daemon readback (`bash gdb-run.sh CHOSEN HOST ...`)

Break at `watchdog.c:4476` in `standard_packet_processor` on the forked
watchdog child, after `get_pool_config_from_json()` returned, reading the
parsed `standby_config`. Two peer values:

| Peer port | Peer hostname | `num_wd` | `wd_node_info[128].wd_port` / `.pgpool_port` | `.hostname` | adjacent `trusted_servers` |
| --- | --- | --- | --- | --- | --- |
| `0x42424242` | `wxyzUUUUUUUU` | 129 | 1111638594 / 1111638594 (`0x42424242`) | `wxyzUUUUUUUU` | `0x5555555555555555` |
| `0x11111111` | `wxyzAAAAAAAA` | 129 | 286331153 / 286331153 (`0x11111111`) | `wxyzAAAAAAAA` | `0x4141414141414141` |

Backtrace: `standard_packet_processor` ← `watchdog_state_machine_coordinator`
← `watchdog_state_machine` ← `read_sockets` ← `watchdog_main`. The
`trusted_servers` value is the peer hostname's bytes 4..11, matching the
direct-call W9 cases F/G; the slot address `0x7fffeed18a08` is build-dependent
but the offset from `wd_nodes` is layout-fixed.

No crash follows: the corrupted pointer lives in `standby_config`, which
`watchdog.c:4472-4478` never frees and never passes to a `trusted_servers`
dereference — `verify_pool_configurations()` and `update_failover_timeout()`
read only scalar and `backend_desc` fields. The daemon-side
`wd_initialize_trusted_servers_list()` / `wd_lifecheck()` `strlen()` path uses
the live `pool_config`, not this leaked standby copy.

### Grade after W10

W9's `wd_nodes` branch is now **wire-reachable with peer-chosen value and
byte control observed on a live daemon**, still at a layout-fixed destination:
rung 4 at wire scope for chosen-value/byte control, no ASan finding (write
stays inside `POOL_CONFIG`) so no rung 3 on this branch, no crash, no chosen
address, no command, no rung 5. Author-measured only; no independent replay
was requested or performed for this branch. `WD_VERIFY_*` warnings are the
only wire log consequence. Not established: any dereference of the corrupted
pointer or a follow-on impact path. W11 below measures the `wd_authkey` set
condition.

## W11 — `wd_authkey` set does not gate the type-`Z` parse (00:00-00:02Z, author-measured)

The W10 grade note left `wd_authkey` set as an unmeasured condition. It is now
measured with one bounded loopback probe. Assets in
`lab/pgpool2shell/wdnodes/wire/`: `auth-probe.sh`, `pgpool-w9-auth.conf`
(identical to `pgpool-w9.conf` except `wd_authkey = 'labsecret'` and distinct
log/pid names), and raw `evidence-auth-n129.*`. Ports 19003-19006 were checked
free before the run; only the runner's own child PIDs were killed; ports were
free after.

The peer sends the same one type-`Z` `WD_POOL_CONFIG_DATA` packet as W10
(`wd_nodes` N=129, `backend_desc` N=1, chosen `0x42424242`, hostname
`wxyzUUUUUUUU`) with **no auth key in the packet**. Observed on the pinned 4.7.2
daemon: `type:[CONFIG DATA]` received; verify warnings read `this node has 2
watchdog nodes while "" is configured with 129 watchdog nodes`;
`invalid watchdog JSON payload` = 0; auth-rejection lines = 0; segfault = 0.
`hash-evidence.sh` shows the normalized decisive-line hashes of
`evidence-auth-n129.stdout` / `.peer` are byte-identical to W10's
`evidence-wire-vuln-n129.stdout` / `.peer`: setting the key changed none of the
measured outcome. At startup the daemon logs `watchdog is configured to use
authentication, but pgpool-II is built without SSL support` (weak auth in this
build), but the peer never supplies a key and the parse still proceeds.

Source agrees with the observation: in 4.7.2 `standard_packet_processor`
(`watchdog.c:4467-4472`) calls `get_pool_config_from_json(pkt->data, pkt->len)`
with no `verify_authhash` on that branch. Auth verification is on the node-info
path (`parse_node_info_message` at `:4490-4493`, `verify_authhash_for_node` at
`:1745`) and on heartbeat packets, not on type `Z`.

Grade unchanged: this refines the reproduction condition — a
non-authenticating loopback peer still drives the W9 OOB parse when
`wd_authkey` is configured — but adds no rung, no crash, no chosen address and
no command. Witness W133 (DM #1943, 2026-11-23 00:12Z) replayed this auth
condition from a clean `f5df311` archive with its own pinned 4.7.2 binary:
`TAG=auth-n129 CONFIG_DATA=1 num_wd129=1 auth_reject=0 segfault=0`, weak-auth
warning present, all 11 normalized hashes reproduced exactly; CLOSED
ESTABLISHED at the labeled reproduction-condition scope. W10's live-gdb
chosen-value readback was not part of that replay. No follow-on dereference
established.

## One-command clean-archive replay (2026-11-25 23:30–23:35Z, author)

W10's live-gdb chosen-value readback and W11's auth condition now have one
driver. From a clean `git archive HEAD` containing `lab/frontier/pgpool2shell`
and `lab/pgpool2shell`, with `PGPOOL_LAB` naming the provisioned lab that
holds the two gitignored pinned tarballs:

    PGPOOL_LAB=/abs/path/to/lab/frontier/pgpool2shell \
      bash lab/pgpool2shell/wdnodes/wire/run-witness.sh

The wrapper rechecks `src/SHA256SUMS` (2/2 OK), rebuilds plain 4.7.2 and
4.7.3 from the verified tarballs in a fresh TMPDIR, then runs W10's three
wire cases, both live-gdb readbacks with the published CHOSEN/HOST pairs,
and W11's auth probe. It diffs regenerated `hash-evidence.sh` output against
the committed 11-entry `EVIDENCE_HASHES.txt`. Each sub-runner checks ports
19003–19006 and kills only its own children.

Author run at commit `d379108d` from `git archive HEAD` extracted to
`/tmp/w9-witness-clean2`: `WITNESS REPLAY PASS`, rc 0, all 11 normalized
hashes identical, including both gdb readbacks. An earlier run at
`efa6f075` failed 10/11 because the wrapper named a nonexistent
`gdb-w9-post-alt.cmd`; the committed alt trace used `gdb-w9-post.cmd`,
fixed at `d379108d`. This is an author clean-archive receipt, NOT an
independent witness verdict. Grade unchanged: rung 4 wire-scope chosen
bytes, no rung 3 on this branch, no crash, no chosen address, no command,
no rung 5.

## One-command clean-archive harness replay (2026-11-26 01:14–01:17Z, author)

The direct-call cases A–G also now have a one-command driver. From a clean
`git archive HEAD` containing `lab/frontier/pgpool2shell` and
`lab/pgpool2shell`, with `PGPOOL_LAB` naming the provisioned lab that holds
the two gitignored pinned tarballs:

    PGPOOL_LAB=/abs/path/to/lab/frontier/pgpool2shell \
      bash lab/pgpool2shell/wdnodes/run-harness-witness.sh

The wrapper rechecks `src/SHA256SUMS` (2/2 OK), builds 4.7.2/4.7.3 plain and
ASan objects in a fresh TMPDIR from the verified tarballs, replays cases A–G
and diffs the regenerated 7-entry `EVIDENCE_HASHES.txt` against the committed
table. No daemon, no socket, no port is used.

Author run at commit `9dcf21b6` from `git archive HEAD` extracted to
`/tmp/w9-harness-clean.xY9Ceh`: rc 0, `HARNESS REPLAY PASS`, all 7 normalized
hashes identical; build log
`/tmp/pgpool-w9-harness-witness.LIC7nJ/harness.log`. This closes the earlier
"clean TMPDIR build path not exercised" gap for the harness. It is an author
clean-archive receipt, NOT an independent witness verdict. Grade unchanged:
rung 4 direct-call chosen bytes, ASan clean, no crash, no chosen address, no
command, no rung 5.
