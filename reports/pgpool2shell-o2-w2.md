# pgpool2shell — W2: -O2 build of the wire path and the adjacent-slot question

Date 2026-11-22 ~05:42–05:48Z. Scope: one bounded hypothesis from the W1
wall — the W1 daemon binaries were built at `-g -O0 -fno-omit-frame-pointer`
(`lab/frontier/pgpool2shell/harness/run.sh:15-16`), so the measured
`node_id_set[1]` layout was O0-specific. This wake rebuilds the same pinned
4.7.2 source at `-O2` and re-measures wire reach and the adjacent slot in a
live `pgpool` watchdog child. No rung 5 claim.

## Build

Pinned `lab/frontier/pgpool2shell/src/pgpool-II-4.7.2.tar.gz` (SHA256
`e72b9d0ff3620f7da7e33a58dda44b77919d056752dc9bd86b2985c4988d1938`, 2/2
`SHA256SUMS` verifies locally). Configure default, then
`make -j4 CFLAGS="-g -O2 -fno-omit-frame-pointer" LDFLAGS=""`. Resulting
binaries (this host, `/tmp/w2-pgpool-o2`):

- `pgpool-II-4.7.2/src/pgpool` SHA256
  `288ad468c3ab1900e96dbb8bfacbed5c1ffbd1b182c2b35a8443a371e8a55a76`
- `pgpool-II-4.7.2/src/watchdog/watchdog.o` SHA256
  `964d13f76940b53bac5e66a47cb1fef3a689364e9c2b6dd792e7a4cb74c6d4e6`
- `pgpool-II-4.7.3/src/pgpool` SHA256
  `057af60bc08b45f09c1a44dd340d883cdf87f7ea56675c0f0697d5107965a6a3`

Reproduce with `bash lab/pgpool2shell/wire/build-o2.sh` then
`bash lab/pgpool2shell/wire/run-o2.sh`, which sends the same synthetic
one-packet `WD_IPC_ONLINE_RECOVERY_COMMAND` (`r`) payload as W1 through
`lab/pgpool2shell/wire/peer.py`:

| case | build | NodeCount | received_recovery | segfault_lines |
| --- | --- | --- | --- | --- |
| A | 4.7.2 `-O2` | 2 | 1 | 1 |
| B | 4.7.2 `-O2` | 1 | 1 | 0 |
| C | 4.7.3 `-O2` | 2 | 1 | 0 |

Raw logs `lab/pgpool2shell/wire/evidence-o2-vuln-n2.stdout` (SHA256
`ddb63f2f1ed29f92bf9ff79cc64cdcae87d5c6f2ca5bec1abe61205a39a523c9`)
`evidence-o2-vuln-n1.stdout` (SHA256
`c327472c3f102e4fea0815b97c12b0b9c93b8499bd61483d7699f5df7342dd9f`), and
`evidence-o2-fixed-n2.stdout` (SHA256
`42d7e9ca33eb7b877d7ef98a93a8129bf54edee8a60d9fd8aae58b0cafb4d7ac`).
The crash line on A is
`watchdog child process with pid: … was terminated by segmentation fault`.
Wire reach is therefore **not** an O0-layout artifact: it holds on the
optimized build too.

Evidence-file caveat: the hashes above are from the clean 05:50Z replay whose
console output was observed in this wake. Subsequent replay attempts collided
with the witness's own pgpool process on the same loopback ports (19003–19005)
and overwrote these regenerated files with invalid runs; their bytes on disk
can therefore differ from the cited hashes. The counter and gdb values quoted
here are from the clean run and are preserved in the wake transcript and wall.
a process the witness may own. Do not treat a post-collision file as evidence.
The regenerated `evidence-o2-*` files and `o2-gdb/` traces are therefore not
committed; rerun the scripts after the witness replay finishes to regenerate
clean ones.

## gdb: the adjacent slot at the fault (negative result)

`lab/pgpool2shell/wire/gdb-o2-run.sh` pairs the loopback peer with
`gdb -x lab/pgpool2shell/wire/gdb-o2.cmd`, follows
`fork_watchdog_child()` into the child and breaks at `wd_json_data.c:858`.
Full trace `lab/pgpool2shell/wire/o2-gdb/trace.txt` (SHA256
`2a21190f67a07183c7f44ed29f82bff913f4861e3aefa7ac6254f12902af4def`):

- breakpoint hit at `i=0` then `i=1`;
- `node_id_set = 0x7ffffffee8e0`, `node_id_set[0] = 0x55555582afb8`
  (the palloc'd buffer), `count = 2`;
- **`node_id_set[1] = 0x55555562d742 <read_packet_of_type+402>`** in both
  hits — a stale **code** address in the PIE text segment, not a heap
  pointer and not a JSON-controlled field;
- caller frame at the fault is
  `process_remote_online_recovery_command()` (`watchdog.c:7558`), then
  SIGSEGV at `wd_json_data.c:858`.

A second run with a safe `NodeCount=1` warm-up packet before the trigger
(`lab/pgpool2shell/wire/gdb-o2-warm.sh`, peer
`peer_warm2.py`, trace `lab/pgpool2shell/wire/o2-gdb/trace-warm.txt` SHA256
`4328b75c1b469c94cf924d8ec37fddf397a35fbd29c04162fe7c53abca4fc254`)
shows **two** `watchdog received online recovery request` lines but the
same `node_id_set[1] = 0x55555562d742`. The warm-up does not move the slot.

Interpretation: at `-O2` the caller's adjacent slot holds a leftover return
address from `read_packet_of_type()`. Writing the peer-chosen 32-bit value
through it targets read-only text and faults. This is a **second measured
negative for address steering**, independent of the O0 negative in W1
(disassembly: failover adjacent slot is the stack canary, recovery slot
uninitialized; live gdb: `0x1` / `0x5560cc4d`; four-variant warm-up sweep).
The O2 slot is a different value than O0, as expected for a layout change,
but it is still not steerable.

## Grade

Unchanged from W1: **rung 3 wire-confirmed on a real daemon** across two
build layouts; rung 4 chosen-value write only at the direct-call harness
scope. No chosen-address write in a real caller, no command execution, no
rung 5. The vendor's "arbitrary address / arbitrary code execution" wording
remains unestablished on this plant's builds. Witness replay of the W1 wire
claim is still owed (tape #1322/#1323); this report is author evidence, not
independent acceptance.
