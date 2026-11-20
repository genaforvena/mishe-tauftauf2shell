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

### Stale-window attempt (16:50Z) — negative

`pong_leak_probe.py --groom-close 8` (close eight holders before the
source/PONG pair) still produced the 32 KiB PONG (`8a 7e 80 00`, broker
alive), but the leaked window remains almost entirely zeros: 17 unique
byte values, zero aligned `0x55…` heap pointers, no readable strings.
Freeing holders did not place a `struct mosquitto` in the read window on
this build. Keep the enlargement; do not claim any leaked address from
this configuration.

## Wire-only heap pointer disclosure (17:05-17:12Z) — rung 4 impact DEMONSTRATED

New harness `lab/frontier/mosquitto2shell/groom_leak_probe.py` extends the
32 KiB PONG read: after the `packet_length=0x8010` overwrite but before
completing the spare PING, it opens 16 live filler connections (WS
handshake + partial PING). `context__init()` allocates a pointer-bearing
`struct mosquitto` (0x380) plus `in_packet.packet_buffer` and registers
`hh_sock.next/prev` heap links (context.c:56, 65-71); these land from top
inside the read window.

Fresh stock-glibc 2.1.2 broker, port 27081, no sanitizer, no gdb in the
probe: `PONG bytes received: 32776`, header `8a 7e 80 00`, broker alive,
34 connections. Leaked bytes are raw heap (the server does not mask its
WS frames; the `41 72 63 14` repeats at window +8 are the echoed PING
payload XORed with the client mask). Broad aligned scan found **64 aligned
heap pointers** with high half `0x5deb` (that run's ASLR heap base), plus
`127.0.0.1`, `Sec-WebSocket-Key`, `zzhZRbK+xOo=` strings at 0x460 spacing.
Concrete leaked pointer at window +0x1878: `0x00005deb6563b0c0`. Repeated
invariants: `0x...65601530` at +0x2f0/+0x1740/+0x1ba0/+0x40d0/+0x5520 and
`0x...65607d00` at +0x360/+0x17b0/+0x1c10/+0x4140/+0x5590.

Under a separate ASLR-on run (`logs/leak-freshL.bin`):

    window +0x2f0 = 0x5f95d2348530   (repeated invariant)
    window +0x368 = 0x5f95d237f3f0   (source struct mosquitto context)
    window +0x388 = 0x5f95d2380904   (PONG payload + 0xa8)

gdb observer runs (ASLR on and off; observer only, no memory patched)
validated the geometry: `PONG_payload = value(+0x388) - 0xa8`,
`source payload = PONG_payload - 0xdc`, window base = `payload + 12`,
and `PAYLOAD mosq=... ptr=... len=174` matches the leaked context exactly.
This is a wire-only, pre-auth, deterministic disclosure of live heap
addresses: ASLR is defeated and attacker-chosen heap bytes are read.
That is a demonstrated security impact (rung 4 information disclosure),
independent of the still-unproven code-execution chain.

## Wire-derived tcache poison — negative (17:22Z), do not claim

Attempted to turn the leak into a controlled malloc return without gdb
address patching. `C` read from window +0x368; predicted poison payload
`P = C - 0x11310` from one earlier same-process observation; safe-linked
`fd = (fdaddr>>12) ^ target` with `fdaddr = P+80`, `target = P`, placed at
stream offset 76 by `tcache_probe.py`. Observed:

    C = 0x5c9d712ac3f0   predicted P = 0x5c9d7129b0e0
    actual P (gdb observer) = 0x5c9d712a7b40   = C - 0x48b0

No `MEMCPY19 dst=predicted-P` and no crash; broker survived. The 1-byte
poison payload address depends on tcache state after the leak, not on a
fixed offset from the leaked context: it moved between runs (`+0x151b0`
fresh, `-0x11310` and `-0x48b0` after a leak). The earlier gdb-assisted
controlled return at `0x55555561c5e0` (`logs/gdb-poison2.log`) remains a
capability demonstration with a lab-supplied address only.

**Status.** Rung 4 information disclosure: demonstrated, wire-only.
Wire-derived controlled pointer / tcache-to-control chain: UNKNOWN, with
the concrete blocker recorded above. dlsym/setcontext: out of scope.
Evidence in gitignored `lab/frontier/mosquitto2shell/logs/`:
`groom-leak-f16.bin`, `groom-aslr.bin`, `leak-freshL.bin`, `wire-leak.bin`,
`wire-poison.log`, `gdb-wire-poison.log`, `gdb-aslr-calib.log`.
