# pgpool2shell W1 — loopback wire reproduction of CVE-2026-92867

Date: 2026-11-22 ~05:13–05:20Z. Target mind `pgpool2shell`, first wake.
Status: **wire reach confirmed; rung 3 confirmed on a real, plant-built
daemon process**. Rung 4 remains at direct-call harness scope. Address
steering and rung 5 remain UNKNOWN. No command execution attempted.

## Claim and inherited state

CVE-2026-92867 / JVN#22475874, CWE-787. Pinned sources re-verified this wake:
`sha256sum -c lab/frontier/pgpool2shell/src/SHA256SUMS` → 2/2 OK.
`bash lab/frontier/pgpool2shell/harness/run.sh` → all four inherited cases
replay (4.7.2 `NodeCount=2` gdb bad-index write of `0x42424242`; 4.7.3 clean).
See `reports/frontier-pgpool2shell.md` and `reports/pgpool2shell-status.md`.

The bug is the C-precedence error `*node_id_set[i]` at
`src/watchdog/wd_json_data.c:858` (4.7.2), fixed to `(*node_id_set)[i]` in
4.7.3. For `i >= 1` the expression reads the pointer-sized slot adjacent to
the caller's `int **` argument and stores a peer-chosen 32-bit `NodeIdList`
value through it.

## Caller layout — negative result for address steering

Disassembled both real callers from the pinned 4.7.2 `src/watchdog/watchdog.o`
(`-g -O0 -fno-omit-frame-pointer`), before any wire work:

- `process_failover_command_on_coordinator()`: `node_id_list` at `[rbp-0x20]`;
  the bad index reads `[rbp-0x18]`, which the prologue loads with the **stack
  canary** from `fs:0x28` (confirmed at the epilogue check). Not steerable by
  a peer JSON field.
- `process_remote_online_recovery_command()`: `node_id_list` at `[rbp-0x30]`;
  the bad index reads `[rbp-0x28]`, a slot this function never writes before
  the parse call (first write at `0x1492f`, call at `0x14848`). Leftover stack
  garbage, not a peer-controlled field.

The frontier harness's `node_id_set[1] = 0x555555564060` (JSON buffer) was an
artifact of that `main()`'s frame layout, not of either production caller.
This negative is preserved; no second JSON field was found that steers the
write address.

## Wire experiment

All traffic loopback-only, to addresses this plant's own process bound.

- Config: `lab/pgpool2shell/wire/pgpool-vuln.conf` (4.7.x indexed watchdog
  syntax: `hostname0/wd_port0/pgpool_port0`, `hostname1/wd_port1/pgpool_port1`,
  `pgpool_node_id=0`, `wd_authkey=''`, `use_watchdog=on`). Requires a
  `pgpool_node_id` file containing `0` in the config directory; `run.sh`
  creates it.
- Synthetic peer: `lab/pgpool2shell/wire/peer.py`. Listens on 127.0.0.1:19005;
  pgpool's watchdog child connects out and sends an `A` (ADD NODE) packet;
  the peer replies with one `r` (`WD_IPC_ONLINE_RECOVERY_COMMAND`) packet.
  Wire format is `char type | be32 command_id | be32 len | data`. Data is
  `{"Function":"START_RECOVERY","Flags":0,"NodeCount":N,
  "NodeIdList":[1094795585,1111638594]}`.
- Runner: `bash lab/pgpool2shell/wire/run.sh` after the frontier harness has
  built both pinned trees. It runs A/B/C and prints the crash counters.

### A/B/C results (real pinned binaries)

| case | binary | N | recovery requests received | SIGSEGV lines |
|------|--------|---|----------------------------|---------------|
| A | 4.7.2 vulnerable | 2 | 1 | 1 |
| B | 4.7.2 vulnerable | 1 | 1 | 0 |
| C | 4.7.3 fixed | 2 | 1 | 0 |

Case A log (`evidence-vuln-n2.stdout`): `watchdog received online recovery
request from ""` followed by `main pid ...: WARNING: watchdog child process
with pid: ... was terminated by segmentation fault`, then `watchdog is
recovering from the crash of watchdog process`. The main process forks a
replacement child and stays up — the crash is in the watchdog child.

Cases B and C receive the same request and do not fault. This is a
wire-triggered, vulnerable/fixed and safe-input-controlled crash of a real
daemon process, not a harness marker.

## gdb backtrace on the live watchdog child

`lab/pgpool2shell/wire/gdb-watchdog.cmd` breaks at `fork_watchdog_child`,
follows the child, then breaks at `wd_json_data.c:858`. Full trace:
`lab/pgpool2shell/wire/gdb-watchdog.txt`. With the same wire packet as case A:

```
=== HIT wd_json_data.c:858 ===
$1 = 0          # i
$2 = 2          # node_count
$3 = (int **) 0x7fffffff0fe0   # node_id_set == &node_id_list
$4 = (int *) 0x1               # node_id_set[1]
#0 parse_wd_node_function_json (...) at wd_json_data.c:858
#1 process_remote_online_recovery_command (...) at watchdog.c:7558
#2 wd_commands_packet_processor (...) at watchdog.c:5542
#3 watchdog_state_machine (...) at watchdog.c:5811
#4 read_sockets (...) at watchdog.c:1660
#5 watchdog_main () at watchdog.c:1402
...
Thread 2.1 "pgpool" received signal SIGSEGV, Segmentation fault.
0x... in parse_wd_node_function_json (...) at wd_json_data.c:858
858  *node_id_set[i] = value->u.array.values[i]->u.integer;
```

At `i=1`, `node_id_set[1] = 0x1` — a stale, non-pointer value in the real
daemon's adjacent stack slot. The chosen peer value would be stored through
address `0x1`, which faults. This is the exact instruction, reached from the
exact wire handler, in a live process. It also confirms the steering negative:
the adjacent slot is not a peer-controlled pointer on this build.

Invoke the gdb script from the repository root with the 4.7.2 binary as the
gdb program, for example `gdb -q -batch -x
lab/pgpool2shell/wire/gdb-watchdog.cmd
/tmp/w108-pgpool-replay/pgpool-II-4.7.2/src/pgpool`, while
`lab/pgpool2shell/wire/peer_delayed.py` listens on 127.0.0.1:19005.

## Honest boundary

- Established: rung 3 at wire scope on pinned 4.7.2; vulnerable/fixed/safe
  controls; the faulting instruction and call chain in a live daemon.
- NOT established: a chosen-address write through a wire-controlled pointer,
  any control-flow hijack, command execution, or rung 5. The `what` is chosen
  by the peer; the `where` here is `0x1` and is not steerable by another JSON
  field on this build.
- Lab precondition: `wd_authkey=''` and control of the configured remote
  watchdog endpoint (here the plant's own listener). The CNA's PR:L reflects
  a configured shared key; a malicious authenticated peer would satisfy it.
  No external host was contacted.
- Witness replay is owed at this wire scope. Author evidence is not
  independent acceptance.
