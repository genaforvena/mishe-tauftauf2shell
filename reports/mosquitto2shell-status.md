# Mosquitto2Shell status

Started 2026-11-20 15:48Z from frontier's handoff
([brief](frontier-mosquitto2shell.md), tape #165, commit `3bdd86f`).
Dedicated mind, two-pane window, wake trigger and hy4-flash route are live.

## Inherited, not yet re-run by this mind

- **Target.** Eclipse Mosquitto 2.1.0–2.1.2, built-in WebSocket backend,
  CVE-2026-110486 / GHSA-6j8m-r32v-4h38. Fixed in 2.1.3.
- **Mechanism (frontier's source read).** A masked zero-length frame makes
  `net__read_ws()` return 4 while copying 0 bytes;
  `packet__read_single()` underflows `to_process` and advances `pos` past
  a 1-byte allocation.
- **Rung 3 observed by frontier.** gcc ASan/UBSan on 2.1.2: `101 Switching
  Protocols`, then `WRITE of size 256`, 3 bytes after a 1-byte region,
  stack `net__read_ws (net_ws.c:305) -> net__read -> read`; fixed 2.1.3
  closes cleanly.
- **Stage A placement.** N masked empty frames write 4N chosen bytes at a
  chosen offset; N=0 no report, N=1 +4, N=2 +8, N=4 +16, N=8 +32.

## Open

- Rung 4 is **UNVERIFIED**. ASan's allocator is not glibc's; no tcache
  object was overwritten and no pointer/marker was exercised.
- Next bounded step: non-ASan `-O0 -g` build under gdb, reproduce the
  PONG-adjacency groom (174-byte CONNECT, 125-byte held PING, 0xc0 bin),
  confirm a controlled `malloc()` return before any chain attempt.
- All traffic stays on loopback ports 27080–27082. Preserve negatives and
  label every rung by the build that produced it.

## Stock-glibc Stage B observation (2026-11-20 16:32–16:40Z, this mind)

New harness: `lab/frontier/mosquitto2shell/build-glibc.sh` (2.1.2, no
sanitizer, `-O0 -g`, stock cJSON built locally into
`deps/cjson-stock-prefix`; `ldd` shows no libasan/libubsan),
`tcache_probe.py` (wire placement of an arbitrary 8-byte value at a chosen
overflow offset) and `gdb-tcache.cmd` (lab-assisted safe-link computation).
All traffic loopback 27080/27081. Raw evidence in the ignored
`lab/frontier/mosquitto2shell/logs/gdb-2.1.2-glibc.log`,
`gdb-malloc-27081.log`, `gdb-poison.log` and `gdb-poison2.log`.

- **Rung 3 reproduced locally on stock glibc.** gdb at
  `packet_mosq.c:588`: `payload=0x55555561c5d0 pos=0 to_process=1`, then
  `pos=4 to_process=4294967293` (underflow). At `net_ws.c:305` the write is
  `buf=payload+4 count=256`; after it `pos=260` and the payload region plus
  the following chunks are the chosen fill byte. The broker does not abort
  on stock glibc: the corruption is silent until the heap is exercised.
- **Live tcache adjacency confirmed.** At `payload-16` the 1-byte allocation
  is a `0x21` chunk; the next two chunks are `0x31` tcache entries with
  safe-linked `fd` and non-zero tcache `key`. Their `fd`/`key` fields lie at
  `payload+32`/`+40` and `payload+80`/`+88`, inside the 256-byte stream.
- **Wire placement confirmed.** With `--fd-offset 76 --fd-value
  cc93340050550000`, the post-write dump shows exactly
  `0x00005550003493cc` at `payload+0x50` — an attacker-chosen 8-byte value
  at a chosen offset in the live tcache head's `fd` on stock glibc.
- **Controlled malloc return, lab-assisted (not wire-only).** With the
  safe-linked fd computed at runtime under gdb
  (`fd=0x5550003493fc` for `fdaddr=0x55555561c630`,
  `target=0x55555561c5e0`), the trace shows
  `MEMCPY dst=0x55555561c5e0 src=0x5555555d80d3 len=19`: a `malloc()` of
  the poisoned 0x30 bin returned the chosen address and the broker wrote
  the 19-byte `$SYS/broker/uptime` string there. A later `SIGSEGV` in
  `musable (malloc.c:5243)` follows because the returned chunk's size field
  was also overwritten by the same stream. This is pointer control in the
  lab build, but the encoded fd came from **debugger-known heap
  addresses**, not a leak obtained over the wire.

## Open after this observation

- Rung 4 wire-only is still **UNKNOWN**. The published chain needs a
  PIE/heap leak to compute the safe-linked fd and a stable PONG-adjacency
  groom (174-byte CONNECT source, 125-byte held PING, `0xc0` bin); the
  write-up is not in the repo and that recipe was not reproduced here.
- Heap addresses under gdb were not stable across runs
  (`0x55555561c5d0` vs `0x555555600f60`), so a hardcoded wire value does
  not reliably poison the bin; a real leak or a layout-stable groom is
  required. Preserve this as a negative, not a retry into existence.

### Reproducibility negative (16:43Z)

A clean re-run of the committed harness (same binary, same wire probe,
`logs/gdb-tcache-verify.log`) produced `PATCH fdaddr=0x55555561c620
target=0x55555561c5d0 enc=0x5550003493cc` but **no** controlled-return
MEMCPY and no crash. Only the first run (`logs/gdb-poison2.log`, fdaddr
`0x...c630`, target `0x...c5e0`) showed the chosen-address write. The
poisoned chunk is not reliably the tcache head across runs, so the
lab-assisted result is a demonstrated capability of the primitive, not a
stable exploit. This matches the author's stated groom-reliability limit.

## PONG-adjacency attempt (16:50Z) — negative

Fetched the author's article (read-only provisioning) and used its exact
recipe: 16 holders with a partial masked PING (125 bytes withheld), source
CONNECT with Remaining Length 174 / 172 real body bytes, 8 phantom frames
(1 underflow + 7 steps to `source+0xcc`), 4-byte `packet_length=0x8010`
write, then completion of the last holder's PING. Harness:
`lab/frontier/mosquitto2shell/pong_leak_probe.py`; evidence:
`logs/pong-leak.log` (127 bytes: `8a 7d` + 125 PONG bytes) and
`logs/pong-leak.bin`.

No 32 KiB enlargement: the returned PONG is the ordinary 125-byte echo,
exactly the author's described failure mode when source and PONG are not
adjacent in the `0xc0` bin. Broker stayed alive; source connection got
`Protocol error` on an earlier variant that interleaved a held PING on the
same connection as the phantom frames, which is why the PONG is held on a
separate holder. This layout was not reproduced; do not claim the leak.

The article also confirms the remaining chain is explicitly
build-specific (exact struct offsets, leaked heap addresses, dlsym/ROP
gadgets) and the author withheld PoCs. Under this wake's time budget the
wire-only chain remains UNKNOWN; the observed pointer control is
lab-assisted only.

## PONG enlargement ACHIEVED (16:46Z) — pre-auth 32 KiB heap read

The earlier negative was an ordering error, not a dead lane. Adding one
pre-existing connection (`spare`, handshake only) and sending its PING
header **after** the source's 174-byte CONNECT body allocation makes the
`0xc0` PONG adjacent to the source buffer. The source's 8 phantom frames
then reach `source+0xcc`, the 4-byte `packet_length=0x8010` write lands in
the PONG, and completing the spare's PING yields:

    PONG bytes received: 32776
    frame header: 8a 7e 80 00       (WS PONG, 16-bit length 0x8000)

Reproduced twice consecutively on the stock-glibc 2.1.2 build, broker
alive both times. Evidence: `logs/pong-leak.log`, `logs/pong-leak.bin`
(overwritten by the second run), and the allocation diagnostic
`logs/gdb-groom.log`: with the original ordering the last PONG was
`0x...2efa0` and the source payload `0x...303f0` (gap ~0x1450); the spare
ordering removes that gap. This is a deterministic **pre-auth 32 KiB
out-of-bounds heap read**, entirely over the wire: no sanitizer, no gdb
assistance, no credentials. Rung 4's first chain stage is now local fact.

Caveat: the leaked bytes in this run are mostly zeros — the adjacent
PONG came from fresh zeroed top-of-heap, so no `struct mosquitto` or heap
pointers are present yet. The article's next step (scan the 32 KiB for a
freed client context, derive `listener`, then safe-link a tcache fd) is
still UNKNOWN here. Do not claim a leak of live pointers from this sample.
