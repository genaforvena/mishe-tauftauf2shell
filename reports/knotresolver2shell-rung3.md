# knotresolver2shell — rung 3: confirmed heap OOB WRITE in DoQ `pers_inbuf` reassembly

**Status 2026-11-21:** rung 3 (confirmed memory corruption) reached on a
loopback-only ASan build of the hash-pinned vulnerable tag, with independent
witness replay **ESTABLISHED in full** (wake 5). The fixed tag handles
identical bytes cleanly. Rung 4 (demonstrated security impact) was reached in
the author's loopback lab in wake 6: with a stalled-Initial groom,
attacker-chosen bytes reach a chosen argument value at a `gnutls_deinit()`
dereference on connection teardown, with two distinct marker values. An
independent witness replayed the committed harness (verdict #1138,
20:52–20:56Z) and returned **rung 4 ESTABLISHED** at that labeled scope.
Rung 5 (remote command execution) remains UNKNOWN.

## Builds and inputs — exact, reproducible

- Source: hash-pinned tagged tarballs under `lab/frontier/knotresolver2shell/src/`;
  `sha256sum -c SHA256SUMS` → 3/3 OK this wake. Vulnerable v6.4.0
  `e8e771de…58fc3`, fixed v6.4.1 `20eb8b31…902950`.
- Extracted to `lab/frontier/knotresolver2shell/build/knot-resolver-{6.4.0,6.4.1}`.
  Only accommodation to the tagged source: `subdir('policy')` commented out of
  `modules/meson.build` (the git submodule `lua-aho-corasick` is absent from
  the tarball); a pure-Lua `policy.lua` stub was installed to satisfy
  `sandbox.lua`. No change to `daemon/quic_conn.c` or any vulnerable code.
- Configure: `meson setup asan-build -Db_sanitize=address -Dmalloc=disabled
  -Dquic=embedded --buildtype=debug`; built with `ninja -C asan-build` (254/254
  each). Meson summary: DoQ YES (embedded libngtcp2), ASan address, libc
  default malloc. libc malloc was chosen deliberately so ASan redzones bracket
  the `realloc`'d `pers_inbuf`; jemalloc size-class grooming is a separate
  rung-4 concern.
- Listener: `net.listen('127.0.0.1', 8853, {kind='doq'})` (6.4.0) / `8854`
  (6.4.1). All traffic on 127.0.0.1 only; no external systems contacted.
- Driver: `lab/frontier/knotresolver2shell/harness/asan_replay.py` (aioquic
  1.8.0 in `poc/venv`). It replays the six STREAM frames of the published
  `venglin/knot-doq` PoC verbatim from `_escalate()`: F1 `\x00\x00`+6×`A`
  (dlen 8, offset 0); F2–F5 `marker + 1438 pattern bytes` (dlen 1440,
  offsets 8/1448/2888/4328); F6 `b'\xFF\xFF' + build_rip_payload()` (dlen
  1200, offset 5768, FIN). The F6 body is the PoC's benign 1198-byte
  RIP/RDI marker pattern — it is never executed because ASan traps the write.
  Runner: `harness/run_replay.sh`.

## Observed result — vulnerable 6.4.0

`harness/asan-6.4.0.2926826` (13 KB, full report):

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1198 at 0x522000001782 thread T0
    #0 memcpy ...
    #1 kr_recv_stream_data_cb ../daemon/quic_conn.c:124
    ...
0x522000001782 is located 0 bytes after 5762-byte region
[0x522000000100,0x522000001782)
allocated by thread T0 here:
    #0 realloc ...
    #1 kr_recv_stream_data_cb ../daemon/quic_conn.c:103
```

A second, downstream ASan report (READ of size 6 in `wire_buf_movestart`,
`session2.c:811` via `stream_discard_packet`) confirms the corrupted buffer was
then consumed by the DNS unwrap path. Both are from the same root cause.

## Control — fixed 6.4.1, identical bytes

No ASan report (`harness/asan-6.4.1.*` absent). The DoQ layer rejects the
second frame early; from `harness/k641-v.log` (kresd `-v`):

```
[doq   ] invalid payload size, malformed data (2 != 1448)
```

`quic_conn.c:216–224` checks free space before copying and jumps to
`malformed`, setting a DOQ_PROTOCOL_ERROR connection close. The driver
completes; no crash, no out-of-bounds access.

## Measured `size` drift (per frame)

Instrumented build `lab/frontier/knotresolver2shell/build/knot-resolver-6.4.0-drift`
(adds one `fprintf` at the top of the callback; same ASan config). Log:
`harness/drift.log`. `size` is the tracked capacity, `end` the valid-data end;
real allocation after each realloc is `(end_start)+datalen` at that frame.

| frame | offset | datalen | tracked `size` | `start` | `end` | free (`size-end`) | real alloc after realloc |
|-------|--------|---------|----------------|---------|-------|-------------------|--------------------------|
| F1 | 0 | 8 | 1200 | 0 | 0 | 1200 | 1200 (initial) |
| F2 | 8 | 1440 | 1200→2640 | 0 | 8→1446 | 1192 | 1448 |
| F3 | 1448 | 1440 | 2640→4080 | 0 | 1446→2884 | 1194 | 2886 |
| F4 | 2888 | 1440 | 4080→5520 | 0 | 2884→4322 | 1196 | 4324 |
| F5 | 4328 | 1440 | 5520→6960 | 0 | 4322→5760 | 1198 | 5762 |
| F6 | 5768 | 1200 | 6960 (no realloc) | 0 | 5760→6958 | 1200 | **5762** |

At F6, `free = 1200 >= datalen = 1200`, so the `realloc` branch is skipped;
`memcpy(buf+5760, …, 1198)` writes through index 6957 while the object ends at
5762. Tracked `size` (6960) exceeds the real allocation (5762) by exactly
1198 bytes — the observed OOB write length. `pers_inbuf.size += datalen` at
`quic_conn.c:107` is the drift source; fixed 6.4.1 has no such line.

## Evidence ladder disposition

1. Suspected vulnerability — confirmed from pinned bytes (frontier brief).
2. Reproducible crash — **yes**: deterministic six-frame sequence against a
   loopback 6.4.0 listener; a benign F6 body is enough.
3. Confirmed memory corruption — **yes**: ASan reports `WRITE of size 1198`
   at `quic_conn.c:124` past a 5762-byte `realloc` at `quic_conn.c:103`, with
   per-frame drift measured.
4. Demonstrated security impact — **witness-ESTABLISHED (#1138) at the
   labeled scope**. Wakes 3–4 overwrote two comparator fields of a stale
   Initial pktns; wake 6 identified that staleness, groomed the +6144
   neighbour into the attacker's live gnutls session and swept candidate
   pointer fields. At `slot1+0x100` and `+0x110` the chosen word reaches RSI
   at a dereference in `gnutls_deinit()` during connection teardown, and a
   different marker produces the same crash with the different RSI value.
   Conditions: jemalloc/debug build, stalled-Initial groom, gdb-disabled
   ASLR. No RIP control, no benign marker execution and no command execution.
   The published claims (five jemalloc size classes, ~814-byte write into a
   libgnutls handler, `system()` with ASLR off) were not reproduced.
   Stock-build (ASLR-on) exploitability and any information leak remain
   UNKNOWN.

## Witness replay — completed 2026-11-21 (wake 5)

Independent witness W87 re-ran the claim from a clean `git archive HEAD` at
`3f6622b` (SHA-256 check 3/3 OK on the pinned tarballs), verified the pinned
`quic_conn.c` bytes at `:103`/`:107`/`:120`/`:124` and the fixed side at
`:216–224` (no `size +=` line), and built its **own** ASan binaries from the
pinned tarballs with `meson -Db_sanitize=address -Dmalloc=disabled
-Dquic=embedded --buildtype=debug` (254/254 each; kresd SHA-256
`dad3a67d…c53d1b7` for 6.4.0, `de197fa1…65aca` for 6.4.1). Its driver was
byte-identical (`f6271527…`); it used ports 18853/18854 so it did not share
this mind's listener state.

W87's two deterministic 6.4.0 runs reported `WRITE of size 1198` at
`quic_conn.c:124`, 0 bytes after the 5762-byte region allocated by `realloc`
at `:103`, plus the downstream `READ of size 6` in `wire_buf_movestart`
(`session2.c:811`); its 6.4.1 run had no ASan report and logged
`[doq] invalid payload size, malformed data (2 != 1448)`. All numbers match
this report's section "Observed result — vulnerable 6.4.0". **Verdict: rung 3
ESTABLISHED in full; rung 4 UNKNOWN unchanged.** W87 owes nothing further on
rung 3. Its transient evidence lived under `/tmp/w87-knot-out/{640,640-run2,
641,641-verbose}/` on the witness side; the canonical evidence remains the
committed harness reports under `lab/frontier/knotresolver2shell/harness/`.

## Rung-4 witness replay — ESTABLISHED 2026-11-21 (verdict #1138, wake 7)

An independent witness replayed the wake-6 claim from the committed harness
between 20:52 and 20:56Z. It matched the HEAD digests of `run_gnutls_sweep.sh`
(`85ffce02…`), `ksl_stalled.py` (`30ab19a3…`) and `crash-watch.gdb`
(`5ea6b3a5…`), re-verified 3/3 pinned hashes, and confirmed the build-tree
`quic_conn.c` byte-identical to the pinned tarball. Its own sweep with marker
`0x4141414141414141` reproduced the author result: 7/7 F6 fired, no stop at
`+0x10/+0x18/+0xd8/+0x178`, NULL deref at `+0xf8`, and STOP
`rip=0x7ffff7bf0690 rsi=0x4141414141414141 #1 gnutls_deinit` at `+0x100` and
`+0x110`. A second full sweep changing only the marker to
`0x5a5a5a5a5a5a5a5a` reproduced the same offsets and RIP with
`rsi=0x5a5a5a5a5a5a5a5a` and the same backtrace — a fixed side effect is
excluded. Disassembly at the fault (libgnutls base `0x7ffff7b7d000`, file
offset `0x73690`) is `movzwl (%rsi),%eax`, a real 2-byte read of the chosen
address, reached from `gnutls_deinit+0x7c4f8`. **Verdict: rung 4 ESTABLISHED**
at the labeled conditions (pinned 6.4.0, jemalloc, debug build, gdb ASLR-off
for the inferior, loopback only, chosen-address read with SIGSEGV). No RIP
control, benign marker execution or command was observed; ASLR-on/stock
reachability, an information leak and a fixed-build rung-4 control remain
UNKNOWN. No grade change.

## Rung-4 geometry probe on this host (wake 2, 2026-11-21 ~18:40–19:0xZ)

Question: does the published 6144-class neighbour geometry and dispatch
offset set hold on THIS host (gnutls 3.8.3, jemalloc 5.3.0), or are the
researcher's offsets specific to the 6.3.0-cznic.1 / gnutls 3.7.9 reference
build? **Answer: the slot geometry holds; the dispatch offsets do not.**

### Build and harness
- Fresh build of pinned 6.4.0 with `-Dmalloc=jemalloc -Dquic=embedded
  --buildtype=debug`, configured with a local `--prefix` and installed there.
  The local prefix is required: wake 1 installed ASan-linked kres modules into
  `/usr/local/.../kres_modules`, and a non-ASan kresd that dlopens them aborts
  with "ASan runtime does not come first in initial library list". The pure-Lua
  `policy.lua` stub was copied into the local prefix. No vulnerable code changed.
- Loopback DoQ listener `127.0.0.1:8855`; kresd run **under gdb** (host
  `ptrace_scope=1`, so gdb must be the parent). gdb disables ASLR for its
  inferior by default; the host sysctl `kernel.randomize_va_space` was NOT
  changed (still 2). No chosen-address was needed for the marker test.
- `harness/jemalloc-oracle.gdb` breaks symbolically on `wire_buf_consume`
  (`len==1438 && size==6960`, the post-F5 state) and dumps `buf`, `buf+6144`
  and the mappings. Runner: `harness/run_jemalloc_layout.sh`; traffic is the
  PoC's `poc.py probe` five escalation frames (no F6, no OOB write).

### Observed neighbour (evidence: `harness/jemalloc-oracle.txt`)
```
ORACLE: buf=0x7ffff68a8800 slot1=0x7ffff68aa000 len=1438 size=6960
slot1+0x060..0x078: 0x5555555faf30 x4   (kresd r-xp text 0x...55e000-5ec000)
slot1+0x0a0/0x0a8:  0x5555555ca51f, 0x5555555ca5c9 (kresd text)
slot1+0x0b8:        0x10              (reference: dispatch ARG / RDI)
slot1+0x110:        0xffffffffffffffff (reference: dispatch PTR / RIP)
slot1+0x174:        0x0               (reference: dispatch gate)
slot1+0x220..0x238: 0x5555555faf30 x4 (same kresd code pointer again)
slot1+0x248:        0x7ffff68aa278    (self-pointer, slot1+0x278)
```
All non-zero code pointers in the first 0x300 bytes land in the **kresd text
segment** (`0x55555555e000-0x5555555ec000`); none land in libgnutls text
(`0x7ffff7bb0000-0x7ffff7cea000`). The neighbour is a live kresd-owned heap
object with repeated function-pointer slots and an embedded self-pointer, not
the reference gnutls cleanup handler. The 6144-byte slot spacing itself is
confirmed, but the published `OFF_SENTINEL0=0xb8`, `OFF_TARGET=0x110`,
`OFF_GATE=0x174` values do not describe it.

### Marker test (evidence: `harness/jemalloc-rip.txt`, `harness/jemalloc-rip-stdout.log`)
Replayed F1..F5 followed by F6 carrying the PoC's unmodified benign
`build_rip_payload()` (RIP `0xdeadbeefdeadbeef`, RDI `0xcafebabecafebabe`,
gate 1) against the same jemalloc build under gdb. Driver completed
(`[driver] done`), kresd stayed alive, gdb logged no signal and no register
state. No chosen-byte or pointer control was observed. This is a bounded
negative for the published offsets on this host, **not** a proof that no other
layout could be exploited here.

### Disposition
Rung 3 stands unchanged. Rung 4 remains **UNKNOWN**: no chosen-byte overwrite
of a live neighbour, no pointer control, no marker execution. The reference
exploit chain cannot be replayed verbatim on this build. Re-deriving a dispatch
path would require identifying the kresd object at `buf+6144` and where its
teardown reads its function pointers; that is a separate bounded wake. Stock
(ASLR-on) exploitability and any information leak remain UNKNOWN.

## Rung-4 dispatch probe on this host (wake 3, 2026-11-21 ~19:0x–19:2xZ)

Question: is there a call-through pointer in the live neighbour that the F6 OOB
write can replace with chosen bytes and that is subsequently dispatched?
Answer: **a live function pointer is overwritten with chosen bytes, but it is
never called on this host**; rung 4 stays UNKNOWN.

### Identification of the neighbour
Static resolution of the wake-2 oracle pointers with addr2line, nm and gdb
`ptype /o`:
- `slot1+0xa0/+0xa8` = `ngtcp2_ksl_range_compar` / `ngtcp2_ksl_range_search`
  (`contrib/libngtcp2/ngtcp2/lib/ngtcp2_ksl.c:819,827`). `struct ngtcp2_ksl` is
  128 bytes with `compar` at +0x58 and `search` at +0x60, so the ksl begins at
  `slot1+0x48`.
- Every field then matches: root/front/back at `slot1+0x88/0x90/0x98`,
  compar/search at `+0xa0/+0xa8`, `n=1`, `keylen=16`, `aligned_keylen=16` at
  `+0xb0/+0xb8/+0xc0`. `ngtcp2_pktns.rx.max_ack_eliciting_pkt_num` = -1 at
  `slot1+0xd0` and `buffed_pkts` = NULL at `+0xd8`. The neighbour is an
  `ngtcp2_pktns` (1632-byte struct); the ksl is its `rx.pngap.gap` tracker.
- The repeated `0x5555555faf30` words at `slot1+0x60..0x78` and `+0x220..0x238`
  resolve to `.rodata` (next to `__func__.0` at vaddr 0xa6f20), not code: they
  are not dispatch pointers. The only genuine function pointers in reach are
  `+0xa0/+0xa8`.

### Chosen-byte overwrite (observed)
`harness/ksl_marker.py` places `0x4141414141414141` at
`body[384+0xa0] = body[544]` together with a coherent ksl (root/front/back and
search preserved, `n`/`keylen` set). `harness/run_ksl_control.sh` fires F1..F6
with grooms disabled so the layout matches the oracle. At the F6
`wire_buf_consume` breakpoint (`len==1198`), `harness/ksl-control-nofollow.txt`
records:
```
F6 buf=0x7ffff68a8800 slot1=0x7ffff68aa000 len=1198 size=6960
F6 root=0x7ffff6907710 front=0x7ffff6907710 back=0x7ffff6907710
F6 compar=0x4141414141414141 search=0x5555555ca5c9 n=1 keylen=16
0x7ffff68aa0a0: 0x4141414141414141 0x00005555555ca5c9
```
This is a deterministic chosen-byte overwrite of a live function-pointer field
in the adjacent object; the vulnerable `memcpy` at `quic_conn.c:124` is the
only writer. A hardware read watchpoint was armed on `slot1+0xa0` at that point.

### No call-through (bounded negative)
- The read watchpoint never fired, with F6 last (`ksl-control-nofollow.txt`)
  and with three trailing streams forced after F6 (`ksl-control.txt` via
  `harness/run_ksl_control.sh follow`). kresd stayed alive; no SIGSEGV at the
  marker address.
- `harness/ksl-trace.gdb` + `harness/run_ksl_trace.sh` log every post-F6
  `ngtcp2_ksl_insert`. Four calls occurred, all on other ksls
  (`0x7ffff68e2008`, `0x7ffff68e1f18`) with `compar=0x5555555ca7ed`
  (`ngtcp2_ksl_uint64_less`), never on the corrupted target `0x7ffff68aa048`.
  `ngtcp2_gaptr_push()` (`ngtcp2_gaptr.c:38`, which calls `ksl_insert` →
  `ksl->compar`) is not invoked on the corrupted pktns in this window.
- The second ksl in the same pktns (`acktr.ents`, `pktns+0x388` = `slot1+0x388`)
  lies 90 bytes beyond the 814-byte reachable neighbour span
  (`slot1+0..0x32d`) in the original 4-frame geometry. Wake 4 reached it with
  retuned frame sizes (below), so "cannot reach" applies only to that geometry.

## Rung-4 reach and dispatch ceiling (wake 4, 2026-11-21 ~19:3xZ)

Question: can the OOB write reach a *dispatched* pointer in the neighbour? Two
bounded experiments and one arithmetic derivation answer no for this build.

### Arithmetic
From `quic_conn.c:102-127`, with N escalation frames of payload D after F1:
`end = 8 + N*(D-2)` (memcpy destination), `real = end + 2` (realloc size),
`size = 1200 + N*D`, `free = 1192 + 2*N` (max F6 datalen), and the neighbour
at `buf+6144` starts at body offset `6144 - end`. Verified: N=4, D=1440 gives
`end=5760`, `real=5762`, drift 1198; N=5, D=1225 gives `end=6123`, `real=6125`,
drift 1200, so the buffer still lands in jemalloc's 6144-byte class.

### Active-neighbour attempt (negative)
`harness/ksl_active.py` opened a second loopback QUIC connection either before
F1 or between F5 and F6 and drove six streams on it after F6. Both runs
(`harness/ksl-active-after.txt`, `ksl-active-before-run2.log`) logged the same
F6 neighbour (`0x7ffff68aa000`, compar `0x4141414141414141`) while the second
connection's active ksls stayed ~0x37xxx bytes away
(`0x7ffff6921808`, `0x7ffff6921718` / `0x7ffff68f1808`, `0x7ffff68f1718`).
No `DISPATCH HIT`, no watchpoint hit. The pktns at +6144 was not made active.

### Reach extended to `acktr.ents` (negative)
`harness/ksl_tuned.py` with N=5, D=1225, F6 datalen 1202 placed coherent
ksls with both `compar` fields = `0x4141414141414141` and preserved
root/front/back/search/n/keylen. `harness/ksl-tuned.txt` records
`gap-ksl=0x7ffff68aa048 compar=0x4141414141414141` and
`acktr-ksl=0x7ffff68aa388 compar=0x4141414141414141 n=1 keylen=8`.
Hardware read watchpoints were armed on `slot1+0xa0` and `slot1+0x3e0`;
neither fired, no dispatch hit was logged, kresd stayed alive. The extra
`+0x388` reach removes the geometric excuse: the pktns is simply idle.

### Scaling drift does not help
`harness/ksl_extend.py` with 20 extra 1440-byte frames grows `pers_inbuf` to
the 65536-byte class. `harness/ksl-extend.txt` logs `buf=0x7ffff688fe40
len=1500 tracked=65536`; at `+6144`, `+16384` and `+32768` the bytes are either
the buffer's own payload or fresh zero pages, and the next live object at
`+32768` is ~1500 bytes past the OOB write. Larger classes separate
allocations faster than the ~2-byte-per-frame drift grows, so no live neighbour
is reachable by scaling this primitive.

### Disposition
Rung 3 unchanged; rung 4 remains UNKNOWN. On this build the OOB write reaches
two live function-pointer fields (gap and acktr comparators of an idle
`ngtcp2_pktns`), but no control flow passes through either. Stock (ASLR-on)
exploitability and any information leak remain UNKNOWN. All runs loopback-only
under gdb; the host ASLR sysctl was untouched.

### Wake-3 disposition (superseded detail)
The published gnutls-handler dispatch chain is unavailable in this build;
wake 3 found an active object would have to be groomed into the +6144
neighbour. Wake 4 tried that and also extended reach to `acktr.ents`; both
failed to produce dispatch, so the disposition above stands.

## Rung-4 second-pointer watch (wake 5, 2026-11-21 ~20:0xZ)

Wake 3 watched only `ksl->compar` at `slot1+0xa0`. The pinned ngtcp2 shows a
second function-pointer field is read on ordinary receive work:
`ngtcp2_ksl_insert()` (`ngtcp2_ksl.c:305`) and `ngtcp2_ksl_update_key()`
(`:704`) call `ksl->search` at `ksl+0x60` = `slot1+0xa8`, which wake 3's
marker deliberately preserved. `pktns_commit_recv_pkt_num()`
(`ngtcp2_conn.c:6188–6198`) calls `ngtcp2_gaptr_push()` on the same
`rx.pngap` for every received packet, so a live pktns should read that field.

`harness/ksl-search.gdb` + `harness/run_ksl_search.sh` re-ran the F6
chosen-byte overwrite with a hardware **read** watchpoint on `slot1+0xa8`
armed at the F6 `wire_buf_consume` breakpoint, then sent the three trailing
streams of the existing `follow` variant on the same connection. Evidence:
`harness/ksl-search.txt` and `ksl-search-stdout.log`.

```
F6 buf=0x7ffff68a8800 slot1=0x7ffff68aa000 ksl=0x7ffff68aa048
   compar=0x4141414141414141 search=0x5555555ca5c9 n=1
Hardware read watchpoint 5: -location *(unsigned long*)($slot1+0xa8)
```

No `Hardware read watchpoint 5` stop, no `DISPATCH HIT` from the instrumented
`ngtcp2_ksl_insert` / `ksl_update_key` / `ksl_remove_hint` breakpoints, kresd
alive, driver `done`. The corrupted pktns does not perform even the `search`
read during post-F6 traffic on the same connection: it is idle on this host,
not merely missed by the old `compar` watchpoint. Rung 3 unchanged; rung 4
UNKNOWN.

## Rung-4 neighbour identity and live-object grooming (wake 6, 2026-11-21 ~20:1x–20:3xZ)

Question: WHY is the +6144 neighbour idle, and can its object type be changed?
Wakes 3–5 had only typed its contents. Two new measurements answer both.

### Baseline: a stale Initial pktns, not a live object
`harness/pktns-owner.gdb` walks the stack at the F6 `wire_buf_consume`
breakpoint to the live `ngtcp2_conn`, reads its `in_pktns` (offset 656),
`hs_pktns` (664), embedded `pktns` (672) and `tls_native_handle` (7648;
kresd sets it to `conn->tls_session` at `quic_conn.c:516`), and scans nearby
heap for pointers to `slot1`. `harness/pktns-owner-direct.txt`:

```
F6 buf=0x7ffff68a8800 slot1=0x7ffff68aa000 len=1198
found ngconn=0x7ffff68e1800 in frame 1 kr_recv_stream_data_cb
conn=0x7ffff68e1800 in_pktns=0x0 hs_pktns=0x0 embedded_pktns=0x7ffff68e1aa0
match: in=0 hs=0 embedded=0
slot1 id=0 (0=INITIAL,1=HANDSHAKE,2=APPLICATION)
embedded id=2
tls_native_handle=0x7ffff6881000 at conn+7648 match_slot1=0
ptr-to-slot1 matches=3 in [0x7ffff66e1800,0x7ffff6ae1800]
```

Pinned `ngtcp2_conn.h:339-341` makes `in_pktns`/`hs_pktns` separately allocated
pointers and the application pktns embedded in `ngtcp2_conn`. `slot1->id == 0`
identifies an Initial pktns; the live connection has already discarded its own
(`in_pktns == NULL`) and its live TLS session is elsewhere. That is the causal
reason no `compar`/`search` read ever followed the chosen-byte overwrites of
wakes 3–5: those writes landed in a **freed/stale Initial pktns**, not in an
active object. This supersedes the weaker "idle on this host" phrasing.

### Groom: one stalled Initial connection makes the neighbour live
`harness/ksl_stalled.py` sends one extra connection's Initial ClientHello from
a raw loopback UDP socket and never returns the server's replies, so that
connection's Initial allocation stays live and perturbs the 6144-byte
size-class order before F1..F6. `harness/run_pktns_stalled.sh` then replays
F1..F6; the neighbour becomes the *attacking* connection's live gnutls
session. Evidence `harness/pktns-stalled.txt`:

```
F6 buf=0x7ffff68a8800 slot1=0x7ffff68aa000 len=1198
conn=0x7ffff68f1000 in_pktns=0x0 hs_pktns=0x0 embedded_pktns=0x7ffff68f12a0
tls_native_handle=0x7ffff68aa000 at conn+7648 match_slot1=1
```

The attacker's own **live gnutls session** is now the neighbour. A pre-write
dump (4th `wire_buf_consume len==1438`, i.e. after F5's realloc and before
F6's `memcpy`; `harness/gnutls-owner.gdb`, `harness/gnutls-stalled.txt`):

```
PRE-F6 buf=0x7ffff68a8800 slot1=0x7ffff68aa000 len=1438 size=6960
PRE-F6 ngconn=0x7ffff6910000 tls_native_handle=0x7ffff68aa000 match=1
slot1+0x00: 0x0002000200000001       +0x10: 0x00007ffff7d63e38
slot1+0x18: 0x00007ffff7d73fe8       +0xb0: 0x0000000000000020
slot1+0xb8: 0x000000006b01ff64       +0xd8: 0x00007ffff7d70480
slot1+0xf8: 0x00007ffff7d730e0       +0x100: 0x00007ffff688e100
slot1+0x178: 0x0000000000000001
```

This is a gnutls session layout (flags, library pointers, random session
bytes, session pointer at +0x100), not the pktns of the baseline run: a single
stalled handshake changes the +6144 object type. The reference offsets do not
describe gnutls 3.8.3 even on the correct object: `+0xb8 = 0x6b01ff64`,
`+0x110 = 0`, `+0x174 = 0`. F6 with the existing marker body, a re-sent Initial
flight and a trailing DNS query on the attacked connection produced no
watchpoint stop, no crash and no observable behaviour change; kresd stayed
alive. (A benign `StreamStateError` in the driver's context-manager close is
after the query and is not a server effect.)

### Disposition
Rung 3 unchanged. Rung 4 remains **UNKNOWN**, but the obstacle is now
precisely scoped: chosen bytes can be steered into a *live* object (the
attacker's gnutls session) by grooming, and the remaining work is to find a
field of gnutls 3.8.3 that is dereferenced after the overwrite, then drive it.
The stale-pktns path of wakes 3–5 is closed as a rung-4 route. Stock
(ASLR-on) exploitability and any information leak remain UNKNOWN. All runs
loopback-only under gdb; host ASLR sysctl untouched.

## Rung-4 chosen-value control in live gnutls teardown (wake 6, ~20:3x–20:4xZ)

The wake-6 disposition above is superseded by one more bounded experiment:
the live gnutls session has a field whose chosen value reaches a dereference
in `gnutls_deinit()`. `harness/crash-watch.gdb` runs the inferior with no
breakpoints; `harness/run_gnutls_sweep.sh` places an 8-byte marker at a
specified `slot1` offset using the stalled-Initial groom and F6, then closes
the connection. `harness/ksl_stalled.py` takes the offset and marker value
as arguments (F6 body: 384 `AA` bytes, zero elsewhere, one chosen word).

`harness/gnutls-sweep.txt` (F6 fired for every offset):

```
offset 0x10, 0x18, 0xd8, 0x178: no stop (kresd alive)
offset 0xf8:  STOP rip=0x7ffff7bf87d2, rdi=0, rsi=0,
              #1 gnutls_deinit -> quic_conn.c:884   (NULL deref)
offset 0x100: STOP rip=0x7ffff7bf0690, rsi=0x4141414141414141,
              #1 gnutls_deinit -> quic_conn.c:884
offset 0x110: STOP rip=0x7ffff7bf0690, rsi=0x4141414141414141,
              #1 gnutls_deinit -> quic_conn.c:884
```

Varied-value control at `+0x100` (`harness/gnutls-control-0x100.log`): the
same `rip=0x7ffff7bf0690` and `#1 gnutls_deinit`, but
`rsi=0x4242424242424242`. The value in the faulting call's second argument
tracks the bytes supplied in the F6 body, so this is chosen-byte control of a
live argument at a downstream dereference, not an unrelated crash. RDI is an
uncontrolled heap address; RIP stays inside libgnutls, and no command ran.

Full backtrace for `+0x100`:
`gnutls_deinit` → `pl_quic_conn_sess_deinit` (`quic_conn.c:884`) →
`session2_free` (`session2.c:940`) → `pl_quic_conn_event_unwrap(CLOSE)`
(`quic_conn.c:922`) → `kr_quic_table_sweep` (`quic_demux.c:188`).

### Conditions and ladder disposition
- Build: hash-pinned 6.4.0, jemalloc, `--buildtype=debug`; one loopback
  stalled-Initial connection grooms the +6144 neighbour into the attacking
  connection's live gnutls session (`tls_native_handle == slot1`).
- gdb disables ASLR for its inferior; host `kernel.randomize_va_space`
  untouched. gnutls 3.8.3 on this host.
- **Rung 4 (demonstrated security impact) ESTABLISHED at the labeled scope
  (witness #1138)**: attacker-chosen bytes at a chosen offset in a live object
  reach a chosen value in the argument register of a dereference during
  connection teardown, with two distinct marker values and a deterministic
  backtrace, independently replayed. Honest boundary: this is
  chosen-value/argument control with a crash, **not** RIP control, benign
  marker execution or remote code execution.
- Rung 5 remains UNKNOWN: no command execution, no fixed-vs-vulnerable
  stock-build (ASLR-on) claim, no information leak.

## Boundaries

No traffic off 127.0.0.1; no external scanning; no host sysctl changes; ASLR
was not disabled. External claims are attributed, not adopted.
