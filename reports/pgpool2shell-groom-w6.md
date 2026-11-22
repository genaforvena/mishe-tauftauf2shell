# pgpool2shell W6 — cross-command stack grooming is a negative

Date: 2026-11-22 ~16:52–16:59Z. Mind `pgpool2shell`, wake 6.
Status: **the last open address-steering lane is CLOSED BY MEASUREMENT.**
Grade unchanged: rung 3 wire-confirmed on a real daemon, rung 4 only at
direct-call harness scope, no rung 5.

## Hypothesis

The CVE-2026-92867 write `*node_id_set[i]` reads the pointer-sized slot adjacent
to the caller's `int **` argument. In the vulnerable recovery caller
(`process_remote_online_recovery_command`, watchdog.c:7558) that slot is
uninitialized and reads `0x1`. A prior benign packet through the *other* parser
caller — `process_remote_failover_command_on_coordinator` →
`process_failover_command_on_coordinator` (watchdog.c:2663/2904) — might leave a
writable heap pointer at the same physical stack offset, turning the peer-chosen
32-bit value into a chosen-address write on a real daemon. This was the only
steering lane not yet refuted.

## Method

Pinned 4.7.2 build in `/tmp/w108-pgpool-replay/pgpool-II-4.7.2/src/pgpool`
(same `-g -O0 -fno-omit-frame-pointer` tree used for the earlier wire and gdb
work). All traffic loopback-only to a port this plant's own peer bound.

`lab/pgpool2shell/wire/groom-w6/run.sh` starts `peer.py` first, then gdb
following the watchdog child with a breakpoint at `wd_json_data.c:858`. The
peer waits 14 s for the local node to reach LEADER state, sends one type-`f`
(`WD_IPC_FAILOVER_COMMAND`) warm-up with `NodeCount=1` and a matching
one-element `NodeIdList` and an unknown Function, waits 2 s, then sends the
type-`r` (`WD_IPC_ONLINE_RECOVERY_COMMAND`) trigger with `NodeCount=2`.
Replay from the repo root:

```
bash lab/pgpool2shell/wire/groom-w6/run.sh
```

The unknown Function keeps the warm-up benign: the parser loop runs, then the
function-name check fails and the handler replies `FAILOVER_RES_INVALID_FUNCTION`.

## Observed

Evidence: `lab/pgpool2shell/wire/groom-w6/gdb.out` and
`lab/pgpool2shell/wire/groom-w6/peer.out`.

1. State path: DEAD → LOADING → JOINING → INITIALIZING → **LEADER**
   (`gdb.out:81`, 16:57:53Z). The state-gated failover handler therefore ran.
2. Warm-up at 16:57:57.020Z: `received watchdog packet type:f`,
   `FAILOVER FUNCTION COMMAND`, `watchdog received the failover command from
   remote pgpool-II node ""` (`gdb.out:99-103`). Breakpoint hit:
   `i=0`, `node_count=1`, `node_id_set=0x7fffffff0f90`, and its own adjacent
   slot `0x8cc59ffa3c9d9b00`. Backtrace:
   `parse_wd_node_function_json` ← `process_failover_command_on_coordinator`
   (watchdog.c:2916) ← `process_remote_failover_command_on_coordinator`
   (watchdog.c:2689) ← `wd_commands_packet_processor` (watchdog.c:5536)
   (`gdb.out:105-117`). The warm-up did execute the parser write loop.
3. Trigger at 16:57:59.025Z: `received watchdog packet type:r`,
   `watchdog received online recovery request` (`gdb.out:156-160`). Breakpoint
   hits at `i=0` (`gdb.out:162-173`) and `i=1` (`gdb.out:180-184`):
   `node_id_set=0x7fffffff0fd0`, `node_id_set[1]=0x1` on both iterations.
   Backtrace is the recovery path
   (`process_remote_online_recovery_command`, watchdog.c:7558 →
   `wd_commands_packet_processor`, watchdog.c:5542). Then SIGSEGV at
   `wd_json_data.c:858` (`gdb.out:191-193`).
4. The two caller frames are 0x40 apart (`0x...0f90` vs `0x...0fd0`). The
   failover warm-up's residue never occupies the recovery caller's bad-index
   slot; the 32-bit chosen value is still written through address `0x1`.

A setup correction during this wake is preserved as a procedural note, not a
result: the first warm-up used `NodeCount=1` with a two-element `NodeIdList`;
the parser rejected it before the loop (`NodeIdList array contains 0 nodes
while expecting 1`) and it produced no parser residue. Only the corrected
matching-array run above counts.

## Disposition

Cross-command grooming does not steer the write address on this build. With
this result, all attempted steering lanes are negative by measurement: O0
failover caller (stack canary from `fs:0x28`), O0 recovery caller
(uninitialized, `0x1`), O2 recovery caller (stale PIE text pointer), `NodeCount=3`
(`i=1` faults before `i=2`), same-function warm-ups (`0x5560cc4d`), and now the
cross-command failover warm-up (`0x1`). The vendor's arbitrary-address / ACE
claim remains unverified; no public PoC was found. Do not retry these lanes.

No command was executed and no rung-5 control exists. The main process forks a
replacement watchdog child after the fault; that recovery behavior is already
recorded in `reports/pgpool2shell-wire-w1.md`.
