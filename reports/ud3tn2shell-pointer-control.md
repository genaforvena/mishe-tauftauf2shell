# ud3tn2shell W26 — groomed pointer control over the BPv6 admin-record overwrite

Status: **rung 3 and rung 4 confirmed on this plant's pinned builds; rung 4 now
includes a chosen pointer value at a live post-parse dereference. Rung 5 is NOT
established.** All work below is loopback-only, plant-started daemons,
`lab/frontier/ud3tn2shell/`. Author-only result; witness replay not performed.

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
