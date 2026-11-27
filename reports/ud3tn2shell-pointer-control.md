# ud3tn2shell W26 — groomed pointer control over the BPv6 admin-record overwrite

Status: **rung 3 and rung 4 confirmed on this plant's pinned builds; rung 5
DEMONSTRATED on the pinned plain build under the labeled ASLR-off conditions
and independently replayed as ESTABLISHED AS LABELED by witness W317**. This
is not a register-ESTABLISHED flag; the operator folds grades. Earlier
sections record author-only states at their time; the final two sections
carry the current chain and verdict. All work stays loopback-only on
plant-started daemons under `lab/frontier/ud3tn2shell/`.

## Replay of the inherited harness (2026-11-26 12:27Z)

```
cd lab/frontier/ud3tn2shell
python3 harness/wire_trigger.py --src "$PWD/src" --outdir "$PWD/replay-w26" \
    --vuln-port 22224 --fixed-port 22230
python3 harness/gdb_readback.py \
    --binary "$PWD/src/ud3tn-v0.15.1-plain/build/posix/ud3tn" \
    --outdir "$PWD/replay-w26-gdb" --port 22234 --marker 90
```

`replay-w26/results.txt`: vulnerable 0x41 and 0x5a `rc=-6 asan=True`, ASan
`WRITE of size 1` at `components/bundle6/reports.c:439` via
`bundle6_parse_administrative_record`; vulnerable source-EID length 8 and fixed
v0.15.2 trigger both `rc=0 asan=False` with "administrative record we cannot
parse, discarding." `replay-w26-gdb/gdb-readback.log`: 20 stored 0x5a bytes at
offsets 0..19 of `p=0x7ffff0001120`, `index=20`, `remaining=65516`. Inherited
grade reproduces.

## Heap grooming: the sequential write reaches live pointers

`harness/gdb_probe.py`, `harness/heap_map.gdb`, `harness/gdb_readback.py`'s
`make_bundle` and a malloc/free logger (`harness/malloc_log.c`) were used to
map the neighbourhood. The vendor bundle's BPv6 creation-sequence SDNV at
prefix offset 17 must be varied per bundle or the BPA drops duplicates as
"already delivered". Changing the payload-length SDNV at prefix offset 84
permits arbitrary overwrite lengths.

- **No pre-bundle** (`probe-w26/logged/map-*.log`): allocation order is
  `malloc(0x58)` admin record at 0x...1080 (`init_administrative_record`),
  `malloc(0x38)` status report at 0x...10e0 (`init_status_report`),
  `malloc(1)` source EID at `p=0x...1120`. The forward memory is virgin arena
  space; the one-byte chunk and the two live objects behind it hold no pointer
  in the write direction. This is the case frontier measured.
- **One benign BPv6 admin bundle first** (`source-EID length 8`, sequence 1;
  `probe-w26/pre1b/map-*.log`): the trigger's `malloc(1)` reuses a freed 0x20
  tcache chunk at `p=0x7ffff0001040`, while the trigger's admin record lands
  **ahead** of it at `record=0x7ffff0001140` (`p+0x100`). A 280-byte chosen
  stream (`probe-w26/n320/map-*.log`, marker 0x5a) covers `p..p+0x15f`,
  including `record->status_report` (`p+0x110`), `record->bpdu` (`p+0x118`)
  and `record->bundle_source_eid` (`p+0x140`). Grooming, not address steering,
  produces the useful ordering.

Plain-build survival matrix with the same grooming
(`probe-w26/plain-survival/daemon.log`): count 64 and 100 -> `rc=-6`,
`munmap_chunk(): invalid pointer` from the corrupted next-chunk size; count
280, 320, 1024 -> `rc=-11` SIGSEGV in the post-parse free path.

## Measured pointer control (rung 4)

`probe-w26/postparse2/map-*.log`, plain v0.15.1 under gdb, one benign bundle,
320 marker-0x5a bytes:

```
POSTPARSE record=0x7ffff0001140 type=1515870810 \
  status_report=0x5a5a5a5a5a5a5a5a bpdu=0x5a5a5a5a5a5a5a5a ...
#0 __GI___libc_free (mem=0x5a5a5a5a5a5a5a5a5a)  rdi=0x5a5a5a5a5a5a5a5a
#1 free_administrative_record (record=0x7ffff0001140) report_manager.c:128
#2 bundle6_parse_administrative_record reports.c:477
#4 bundle_deliver_adu bundle_processor.c:1370
```

`free()` is called with exactly the bytes chosen in the wire input, at a live
pointer field dereferenced after parsing. This is pointer control in the lab
build, not a crash-only result. It is still rung 4: no indirect call, no
command, no witness replay.

## One bounded command attempt and its controls (negative)

Prediction: turn the controlled `free()` into tcache poisoning by forging a
chunk inside the attacker-written region, then get a later `malloc` to return
the forged address — the prerequisite for an arbitrary write toward a command
side effect. Crafted stream (`probe-w26/tcache/gdb.log`, 480 bytes) set
`record->status_report` to `F=0x7ffff0001200 = p+0x1c0`, left `bpdu` and the
EID scheme NULL/invalid, and wrote a 0x25 size field at `F-8`.

Observed: `free_administrative_record` called `free(0x7ffff0001200)` with the
chosen pointer and a valid-looking header at `F-8` (`x/4gx` at the free entry:
size `0x25`), but glibc 2.39 aborted at `_int_free` (`malloc.c:4507`,
`free(): invalid pointer`) before tcache insertion. The follow-up bundle was
never sent; no arbitrary write, no command, no side effect. Controls on the
same wire: fixed v0.15.2 ASan `rc=0` clean discard
(`probe-w26/tcache-controls/fixed-121510/daemon.log`) and vulnerable v0.15.1
with source-EID length 8 `rc=0` clean discard
(`probe-w26/tcache-controls/safe-eid8/daemon.log`). No rung 5.

The daemon has no command-execution sink reachable from this parse path:
`grep -rn 'system(\|popen(\|execv\|execl' components --include='*.c'` on v0.15.1
returns nothing. `struct bundle_administrative_record`
(`include/ud3tn/bundle.h:340-357`) contains only data pointers and
`eid_free` (`components/ud3tn/eid.c:186`) only calls `free()`, so a command
path would need a further heap-metadata or use-after-free chain. Not attempted
in this wake; it stays UNKNOWN, not established or refuted in general.

## Transport reach

`lab/frontier/ud3tn2shell/transport-w26/RESULTS.md` (runner `transport_probe.py`,
raw logs and per-case JSON with exact commands): with correct framing, the same
BPv6 `eid_len=0` bundle gives ASan `heap-buffer-overflow` at `reports.c:439`
on v0.15.1 over CBOR-framed MTCP (baseline), passive SMTCP, TCPCLv3 (contact
handshake then `0x13` DATA_SEGMENT with the raw bundle), and SPP-framed
TCPSPP (APID 1). Each hit has a fixed v0.15.2 control and an `eid_len=8`
safe-input control with `rc=0` and no ASan. Spot-checked directly:
`smtcp-vuln-eid0.log`, `tcpclv3-vuln-eid0b.log` and `spp-vuln-eid0.log` carry
the exact SUMMARY line; all three fixed controls are clean. Raw unframed
bytes on the MTCP listener and a 4-byte ION-STCP prefix did not reach the
parser (negatives preserved). BPv7 zero-length subject-EID status reports did
reach admin dispatch on MTCP, TCPCLv3 and SPP ("administrative record we
cannot parse, discarding") with no ASan on either build;
`components/bundle7/reports.c` and `components/bundle7/eid.c` contain no
analogous malloc-and-decrement sink. BIBE and sqlite CLAs were not exercised.

## Evidence and next step

Harness additions: `harness/gdb_probe.py` (variable-length wire, pre-bundles,
optional LD_PRELOAD), `harness/heap_map.gdb`, `harness/postparse.gdb`,
`harness/free_inspect.gdb`, `harness/malloc_log.c`. Raw logs live in the
gitignored lab directories named above. What would change the grade: an
observed arbitrary write followed by a lab-chosen benign command with a
side effect, on a live plant-started target reached by wire input, with
vulnerable/fixed/safe-input controls and independent witness replay. A
fixed-build fault under the same wire input would refute the inherited
control and must be preserved.

## W-2026-11-27: fresh heap-metadata chain — chosen-address allocation and write

The W26 `free()` abort was misattributed. `probe-w26/tcache-inspect/gdb.log`
shows the sequence `free(p=...1040)`, `free(F=...1200)`, `free(record=...1140)`;
the invalid-pointer abort was on **record**, whose own size word at
`record-8 = p+0xf8` had been zeroed by the chosen stream. The forged `free(F)`
completed and entered tcache. That gives a fresh chain, not a retry of the
aborted route.

Prediction: preserve the collateral chunk headers, move the forged chunk past
the natural allocation frontier, and a later wire request should be served
from tcache at the chosen address. `harness/tcache_chain.py` and
`harness/tcache_chain.gdb` send, on 127.0.0.1 MTCP under a plant-started
pinned daemon: one benign BPv6 admin pre-bundle (source-EID length 8), one
768-byte crafted trigger (source-EID length 0), then a benign follow-up with
source-EID length `0x27` (a 40-byte, 0x30-chunk allocation). The crafted stream
sets `record->status_report = F = p+0x300`, a 0x31 size word at `F-8` (tcache
bin 1), a 0x41 size word at `record-8` (bin 2, so freeing the record cannot
displace F), EID scheme 2 so `eid_free` is a no-op, and preserves the size
words at `p+0x18`, `p+0x38`, `p+0x98`, `p+0xd8` and the top-chunk size at
`p+0x158`. gdb disables ASLR, so `p=0x7ffff0001040` and `F=0x7ffff0001340`.

Observed (`chain-far-vuln/chain.log`, plain v0.15.1): all four intended frees
complete with no invalid-pointer abort; the follow-up parse reports
`STORE_BEGIN p=0x7ffff0001340 record=0x7ffff00011a0 rem=38` — the EID buffer
is the chosen address F, and `x/40bx` at that moment shows the first chosen
wire byte `0x43` there. An earlier variant with `F=p+0x1c0`
(`chain-final-vuln/chain.log`) also showed `p=F`, but that address coincides
with the natural next allocation, so it is not proof; moving F past the
frontier makes the poisoning distinguishable.

Controls on the same three-bundle wire: vulnerable v0.15.1 with the trigger's
source-EID length 8 (`chain-far-safe/chain.log`) gives no chosen allocation —
the follow-up lands at the natural `0x7ffff0001200`; fixed v0.15.2 ASan
(`chain-far-fixed/chain.log`) reports zero AddressSanitizer hits and follows
the natural ASan layout. Both are clean of the faulting free chain.

Grade: rung 4 now includes a tcache-poisoned, chosen-address allocation whose
first bytes are attacker-chosen from a live wire request, on a plant-started
loopback daemon, with vulnerable / fixed / safe-input controls. This is still
not rung 5: no callable pointer was overwritten, no indirect call, no
benign-command side effect and no witness replay. R5 remains UNKNOWN. The
attempt stops here as scoped; the several intermediate `chain-w*` runs are
preserved as negative iterations (each abort was a collateral header that had
to be preserved, never a change to the underlying primitive).

## W-2026-11-27 second wake: wire-driven benign command on the live daemon

Grade: **rung 5 demonstrated on the pinned v0.15.1 plain build under the
explicit lab conditions below, independently replayed by witness W317 and
ESTABLISHED AS LABELED at that scope (2026-11-27, #6122)** — not a
register-ESTABLISHED flag or an ASLR-on claim, and no grade beyond a lab
`touch` marker. Rung 3/4 evidence above is unchanged.

The earlier chosen-address write was aimed at the wrong heap. A live
`struct agent` node with `trx_callback` is in the PIE brk heap
(`0x5555555b8...`), while the admin-record parser's one-byte chunk and tcache
are in a second thread arena (`0x7ffff0001040`). `arena-probe/mainheap.bin`
and `arena-probe2/chain.log` show the live `"config"` agent node at
`0x5555555b8bf0`/`0x5555555b8bd0` with a `0x61` chunk header at `F-8`;
`arena-probe/heap.bin` shows only *copies* of agent structs in the parser
arena. gdb's `agent_forward` breakpoint proves the callback is invoked from
the brk-heap node, not the parser-arena copy.

New harness `harness/call_chain.{py,gdb}` discovers the live node and header
at startup (`agent_manager.c:560`) without extra wire, then sends four
CBOR-framed MTCP bundles over 127.0.0.1 to the plant-started daemon:

1. benign admin pre-bundle (source-EID length 8, seq 1);
2. 768-byte crafted trigger (EID length 0, seq 2) whose
   `record->status_report` is the discovered agent node `F`; its collateral
   headers are preserved and the `record` size word at `p+0xf8` is `0x61`;
3. follow-up admin bundle (EID length `0x48`, seq 3) whose 0x60-chunk EID
   allocation is served from the poisoned tcache bin at `F`, writing 0x48
   chosen bytes over the agent's `trx_callback`, `param`, sink and flags;
4. non-admin bundle addressed to `dtn://ud3tn.dtn/config` (seq 4), whose
   ADU delivery reaches `agent_forward`.

`agent_manager.c:414` compiles the indirect call as `mov 0x38(%rax),%rdx;
mov %rdx,%rdi; call *%r8`; the MEMORY-class `struct bundle_adu` first argument
leaves `rdi` for `param`. The overwritten callback is `system` and `param`
points at a `touch <lab marker path>` command embedded at `p+0x200` in the
crafted stream.

Observed in `call-rce4/chain.log` (plain v0.15.1, ASLR disabled by gdb, PIE
base `0x555555554000`, libc base `0x7ffff7c00000`, `system=0x7ffff7c58750`,
thread arena `0x7ffff0000000`): discovered `F=0x5555555b8bd0`, header `0x61`;
`FREE_REC status=0x5555555b8bd0`; follow-up `STORE p=0x5555555b8bd0 rem=71`;
`CALL_SITE ag=0x5555555b8bd0 trx=0x7ffff7c58750 param=0x7ffff0001240`;
`SYSTEM_HIT rdi=0x7ffff0001240` with `x/s` showing the exact `touch` command;
`Detaching after vfork` followed by the marker file
`call-rce4/marker.txt` being created by the daemon. gdb observes only; the
call and the vfork are the daemon's own, not debugger-forced.

Controls with the identical wire: `call-safe/chain.log` (trigger EID length 8)
has no chosen allocation, `CALL_SITE trx=0x55555558356a` (original
`rx_callback`) and no marker; `call-fixed/chain.log` (v0.15.2 ASan, hash
`5653296d…`) has zero `AddressSanitizer` reports, original callback and no
marker. Vulnerable binary hash `36d77768…`; `reports.c` hashes
`e722cddc…`/`ea68a68d…` match `src/PINS.txt`. Debug-build daemon (`-L 4`, no
AAP2 secret) binds only 127.0.0.1; no credential, off-loopback target or
external action. Earlier negatives (raw TCP, 4-byte STCP, BPv7, aborted
record-free route) stay preserved.

This is deliberately labeled: ASLR is off, addresses are discovered live by
gdb, and the command is a filesystem marker inside the lab. ESTABLISHED rung 5
requires an independent witness replay of this exact wire and build. The
earlier `call-vuln*` and `call-rce2`/`call-rce3` logs are preserved as negative
iterations (wrong heap, shifted layout and a breakpoint that stopped before
`system()` executed), not erased or folded into the positive.

### W317 independent witness replay (2026-11-27 05:35–05:36Z)

Witness #6122 replayed commit `9ca46a2d` from a clean `git archive` (28 files),
with unmodified harness hashes `7b0de51a…` / `38abeb22…` / `de71c556…` and
pinned `reports.c` and binary hashes matching `src/PINS.txt`. On a fresh port
the vulnerable lane re-discovered `F=0x5555555b8bd0` (header `0x61`), logged
`STORE p=F rem=71`, `CALL_SITE trx=0x7ffff7c58750 param=0x7ffff0001240`,
`SYSTEM_HIT rdi=0x7ffff0001240`, `x/s` of the exact lab `touch` command and a
vfork detach; the daemon created the marker at 05:35:48Z. The safe EID-length-8
lane landed at the natural `0x7ffff0001200` with the original callback
`0x55555558356a` and no marker; the fixed v0.15.2 ASan lane had zero ASan /
ERROR / SUMMARY / invalid-pointer hits, original callback and no marker.

Verdict: **ESTABLISHED AS LABELED**, rung 5 DEMONSTRATED at the stated scope;
no register flag, count or grade fold is claimed here. NITs preserved:
prebuilt pinned binaries rather than a fresh rebuild, harness `rc=-9` from a
12 s timeout after all four sends were acknowledged, gdb-discovered addresses
with ASLR off, same host/glibc. Detail artifact
`.mishe-tauftauf/artifacts/witness-w317-ud3tn-r5/detail.md`; raw logs
`vuln.chain.log`, `safe.chain.log`, `fixed.chain.log` there with sha256
`4f72fc1f…`, `3780a0df…`, `dd5d32c6…`. No counterexample was found; no new
rung is claimed.
