# pgpool2shell W3 — `NodeCount >= 3` multi-slot hypothesis: refuted

Date: 2026-11-22 ~06:57Z. Scope: pinned 4.7.2 (`e72b9d0f…`, verified by
`lab/frontier/pgpool2shell/src/SHA256SUMS`), plant build at `-g -O0
-fno-omit-frame-pointer` (`/tmp/w108-pgpool-replay`), real `pgpool` watchdog
child reached over loopback 19005. No external traffic.

## Hypothesis

`parse_wd_node_function_json()` has no upper bound on `NodeCount`: it only
checks `node_count > 0` and that `NodeIdList`'s array length equals it. The
bad-index loop `*node_id_set[i]` therefore reads `node_id_set[0]` (the
palloc'd buffer), `node_id_set[1]` (the caller's adjacent stack slot), then
`node_id_set[2]`, `node_id_set[3]`, … — progressively farther caller stack
slots. W1/W2 measured only `i = 1`. If a farther slot held a writable pointer,
a peer packet storing a chosen 32-bit value through it would be a rung-4
write on a real daemon at a second address.

## Observation

`peer_delayed.py`-equivalent with `NodeCount=3` and three distinct
`NodeIdList` values (`0x41414141, 0x42424242, 0x000f423f`), type `r`
(`WD_IPC_ONLINE_RECOVERY_COMMAND`), gdb following the watchdog child with a
breakpoint at `wd_json_data.c:858`:

```
=== HIT wd_json_data.c:858 ===
$1 = 0                       # i
$2 = 3                       # node_count
$3 = (int **) 0x7fffffff1010 # node_id_set
$4 = (int *) 0x5555558c3fa8  # node_id_set[0] — palloc'd buffer
$5 = 1094795585              # chosen value[0]
=== HIT wd_json_data.c:858 ===
$6 = 1                       # i
$9 = (int *) 0x5560cc4d      # node_id_set[1] — unmapped low-half address
$10 = 1111638594             # chosen value[1]
Thread 2.1 "pgpool" received signal SIGSEGV, Segmentation fault.
0x… in parse_wd_node_function_json (…) at wd_json_data.c:858
858   *node_id_set[i] = value->u.array.values[i]->u.integer;
```

The loop faults at `i = 1`; iteration `i = 2` is never executed. Peer-chosen
`NodeIdList` values cannot affect the address read from `node_id_set[1]`,
which is stale stack data (W1/W2: `0x1` at O0 without warm-up, code pointer
`0x55555562d742 <read_packet_of_type+402>` at O2; here `0x5560cc4d`, also
unmapped). No farther stack slot is reachable through this loop on these
builds.

## Disposition

Keep as a negative result. Combined with W1 (O0 disassembly, warm-up sweep)
and W2 (O2 gdb), address steering through the bad index is now refuted for
`i = 1` on both layouts and for `i >= 2` by short-circuit at `i = 1` on the
O0 layout. Grade unchanged: rung 3 wire-confirmed on a real daemon in two
build layouts; rung 4 only at direct-call harness scope; no chosen-address
write on a real daemon, no command execution, no rung 5. No public PoC or
vendor ACE evidence was found. Witness replay of W1 remains owed (#1322,
#1323).

Raw evidence: `lab/pgpool2shell/wire/w3-n3-{peer.out,gdb-trace.out}` plus the
throwaway scripts `w3-n3-peer.py`/`w3-n3-gdb.cmd` in the same directory.
