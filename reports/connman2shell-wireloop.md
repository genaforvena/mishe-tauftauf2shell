# ConnMan `get_domains()` — loopback wire input (CVE-2026-115863)

Date 2026-11-23. This extends the W2 REPLY-parser report
(`reports/connman2shell-wirereply.md`) by removing its remaining input caveat:
the REPLY is no longer an in-process byte buffer. A separate sender process
writes it to a real 127.0.0.1 UDP socket; a receiver process reads it with
`recvfrom()` and feeds the received bytes to ConnMan's own option parser and
the three-function caller chain. No connmand daemon, external network or full
ConnMan build is used.

## Harness

`lab/connman2shell/wireloop/` uses the same four **verbatim** pinned tag-2.0
functions as W2, with SHA-256 asserted on every run:

| Source | Function | SHA-256 |
| --- | --- | --- |
| `gdhcp/common.c` | `dhcpv6_get_option` | `d4dd4372…ccfccd3` |
| `gdhcp/client.c` | `get_domains` | `090d8ea2…60a5c2` |
| `gdhcp/client.c` | `get_dhcpv6_option_value_list` | `0391d8e7…497414` |
| `gdhcp/client.c` | `get_dhcpv6_request` | `b38eb698…4f812` |

`driver.c` forks. The child binds an ephemeral UDP port on `INADDR_LOOPBACK`,
reports the port through a pipe, then blocks in `recvfrom()`. The parent crafts
the 2056-byte REPLY (message 7, option 24 `len=2048`, value `0xff` with
`value[1024]=K`, trailing zero) and `sendto()`s it to that port. The child casts
the **received** bytes to `struct dhcpv6_packet` and calls
`dhcpv6_get_option()` then `get_dhcpv6_request()`. The attacker-chosen K byte
therefore crosses the kernel loopback socket before reaching the parser.
GLib is stubbed; the fixed snapshot is tag `2.0` plus the Miu patch.

## Observed

`bash lab/connman2shell/wireloop/run.sh` → `30 PASS / 0 FAIL`, three
consecutive runs. Plain outcome counts are informational, not pass criteria.

- **Socket delivery**: `CLI SENT=2056 PKTLEN=2056 DST=127.0.0.1:<port>`,
  `SRV BOUND=127.0.0.1:<port> RECV=2056`, and
  `WIREPARSE OLEN=2048 COUNT=1 OFFSET=8` — all 2048 attacker bytes survive the
  UDP loopback path and are accepted by ConnMan's real option walker.
- **Reachability** (`K=0x80`, ASan): `stack-buffer-overflow`, `READ of size 1`,
  frames `get_domains` ← `get_dhcpv6_option_value_list` ←
  `get_dhcpv6_request` ← `run_chain` ← `server_body` ← `main`. ASan places
  `dns_name` at `[48, 1074)` and the access at offset 1201 — the same 127-byte
  delta as the direct call, the stubbed chain and W2's in-process wire buffer.
  The receiver child exits 1; the parent records `SRV EXIT=1 SIGNALED=0`.
- **Controls**: fixed snapshot gives `CHAIN DONE STATUS=0`, no ASan, exit 0 on
  the same socket-delivered 2056-byte packet. A well-formed 8-byte DOMAIN_LIST
  gives `WIREPARSE OLEN=8 COUNT=1 OFFSET=8`, `CHAIN DONE STATUS=0`, no ASan,
  exit 0 on the vulnerable pin.
- **Store landing** (plain, 12 runs, `K=0x80`): the OOB walk wrote `0x2E` into
  the immediate caller's 16 KiB canary in 5, 7 and 4 of three fresh samples;
  the rest wrote none. No faults in these samples. The mix is
  ASLR-dependent, as in W1/W2.

## Return-address steering over the socket

`bash lab/connman2shell/wireloop/retarget.sh` → exit 0,
`RETARGET_K=0x67 HITS=5/5`. gdb follows the forked receiver child. At the
`get_domains()` entry breakpoint it solves for K from the live frame chain:
`first OOB offset = 1025 + K`, target `caller_rbp + 8` (the saved return
address of `get_dhcpv6_option_value_list`). That K=103=0x67 travels in the
REPLY option value across the UDP socket. A hardware watchpoint on the target
byte reads `BEFORE=ae AFTER=2e` on all five ASLR-enabled runs, with the watch
hit confirmed in each `evidence/retarget-*.out`. The initial byte differs from
W1's `0x33` because the socket receiver adds a frame; the written byte is the
same fixed `.`. K is layout-specific and not universal.

## Grade

Rung 3 plus scoped rung 4, unchanged. The new fact is narrow: attacker-chosen
REPLY bytes delivered over a real loopback UDP socket reach the verbatim
caller chain, fault on the same delta, and the chosen K can steer the first OOB
write onto a live saved return-address byte in the receiver process. **Not
rung 5 and not broad rung 4**: there is no connmand daemon, no remote input,
no pointer/marker/command, the written byte is the fixed `.`, and the walk
after the first step reads ambient stack bytes. Root-service impact remains an
advisory claim.
