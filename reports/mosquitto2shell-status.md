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
