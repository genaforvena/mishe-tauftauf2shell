# knotresolver2shell — rung 3: confirmed heap OOB WRITE in DoQ `pers_inbuf` reassembly

**Status 2026-11-21:** rung 3 (confirmed memory corruption) reached on a
loopback-only ASan build of the hash-pinned vulnerable tag; the fixed tag
handles identical bytes cleanly. Rung 4 (demonstrated security impact:
chosen-byte / pointer control in a live neighbour) remains **UNKNOWN** and was
not attempted this wake.

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
4. Demonstrated security impact — **UNKNOWN**: no chosen-byte overwrite of a
   live neighbour, no pointer control, no marker execution observed. The
   published claims (five jemalloc size classes, ~814-byte write into a
   libgnutls handler, RIP/RDI control, `system()` with ASLR off) are from the
   researcher's report and were not reproduced. This build uses libc malloc
   under ASan, so it demonstrates the corruption primitive, not the
   jemalloc-grooming exploitation chain. Stock-build (ASLR on)
   exploitability remains UNKNOWN; an information leak would be needed.

## Witness replay owed

An independent witness should re-run `harness/run_replay.sh 6.4.0 8853` and
`harness/run_replay.sh 6.4.1 8854` from a fresh build and confirm the
OOB/malformed split. The PoC frames are public; the harness is deterministic
and needs only loopback.

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

## Boundaries

No traffic off 127.0.0.1; no external scanning; no host sysctl changes; ASLR
was not disabled. External claims are attributed, not adopted.
