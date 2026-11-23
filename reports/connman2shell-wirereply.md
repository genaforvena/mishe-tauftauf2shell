# ConnMan `get_domains()` — REPLY parser evidence (CVE-2026-115863)

Date 2026-11-23. This extends the W1 caller-chain report
(`reports/connman2shell-callpath.md`) by removing its main caveat:
`dhcpv6_get_option()` is no longer a stub. A raw DHCPv6 REPLY-shaped packet is
parsed by ConnMan's own option walker, and the returned option-24 value reaches
`get_domains()` through the real three-function caller chain. No socket,
daemon, network or full ConnMan build is used; the attacker-controlled input
is a byte buffer inside this process.

## Harness

`lab/connman2shell/wirereply/` includes four functions **verbatim** from pinned
tag-2.0 sources (SHA-256 asserted on every run):

| Source | Function | SHA-256 |
| --- | --- | --- |
| `gdhcp/common.c` | `dhcpv6_get_option` | `d4dd4372…ccfccd3` |
| `gdhcp/client.c` | `get_domains` | `090d8ea2…60a5c2` |
| `gdhcp/client.c` | `get_dhcpv6_option_value_list` | `0391d8e7…497414` |
| `gdhcp/client.c` | `get_dhcpv6_request` | `b38eb698…4f812` |

The pinned `common.c` was fetched from
`https://git.kernel.org/pub/scm/network/connman/connman.git/plain/gdhcp/common.c?h=2.0`
and saved as `lab/frontier/connman2shell/src/common-2.0.c` (SHA-256
`2ff01d8b8d8347fad8876092035a3acfc38fb9048b2ea0da8be90c43af73eada`). The
verbatim parser computes `rem = pkt_len - 4` and returns a pointer into
`packet->options`, exactly as a received DHCPv6 REPLY would.

`driver.c` builds a 2056-byte packet: message type 7 (REPLY), a transaction
ID, one option header (`code=24`, `len=2048`), and a 2048-byte value filled
with `0xff` except `value[1024] = K` and a trailing zero. The safe control is
a 16-byte packet with option 24 `len=8` and two well-formed short labels.
GLib is stubbed; the fixed snapshot is tag `2.0` plus the Miu patch already
used by frontier.

## Observed

`bash lab/connman2shell/wirereply/run.sh` → `29 PASS / 0 FAIL`; repeated
three times with the same result. Plain outcome counts are informational.

- **Real parser delivery**: `WIREPARSE OLEN=2048 COUNT=1 OFFSET=8`, i.e. the
  verbatim `dhcpv6_get_option()` accepts the REPLY-shaped option and hands
  all 2048 attacker bytes to `get_dhcpv6_option_value_list()`.
- **Reachability** (`K=0x80`, ASan): `stack-buffer-overflow`, `READ of size 1`,
  frames `get_domains` ← `get_dhcpv6_option_value_list` ←
  `get_dhcpv6_request` ← `run_chain` ← `main`. ASan places `dns_name` at
  `[48, 1074)` and the access at offset 1201 — the same 127-byte delta as
  frontier's direct call and W1's stubbed chain.
- **Controls**: fixed snapshot gives `CHAIN DONE STATUS=0` with no ASan on
  the same 2048-byte packet. Well-formed short DOMAIN_LIST gives
  `WIREPARSE OLEN=8 COUNT=1 OFFSET=8` and `CHAIN DONE STATUS=0` on the
  vulnerable pin, also with no ASan.
- **Store landing** (plain, 12 runs, `K=0x80`): 6 runs wrote `0x2E` bytes
  into the caller-stack canary, 4 wrote none, 2 faulted. The continuation
  still reads ambient stack bytes after the first attacker-chosen step.

## Build feasibility (negative result, 2026-11-23)

A full build is not available on this host without installing development
packages, which is outside this lab's scope. The pinned snapshot
`https://git.kernel.org/pub/scm/network/connman/connman.git/snapshot/connman-2.0.tar.gz`
was fetched (SHA-256
`e0f879af3dfe6c1e4ec1cc31d71af34ee01ed87892be6c596ee42990a17bac53`) and
extracted under `lab/frontier/connman2shell/src/connman-2.0/`. `configure.ac`
requires `dbus-1 >= 1.4` unconditionally and `libmnl >= 1.0.0` for every
firewall mode except `none` with wireguard disabled. On this host
`pkg-config --exists dbus-1` and `pkg-config --exists libmnl` both return 1,
and `/usr/include/dbus-1.0/dbus/dbus.h` is absent; `gdhcp/client.c` includes
`../src/connman.h`, which includes `<connman/dbus.h>`. So neither a full
connmand build nor a minimal object build of the real client is reachable
here. No live daemon, socket or REPLY-from-wire experiment was attempted, and
none is claimed.

## Grade

Rung 3 plus scoped rung 4, unchanged. The new fact is that a DHCPv6
REPLY-shaped packet, parsed by ConnMan's actual option parser, delivers the
overflowing value on the natural caller layout — the prior "stubbed REPLY"
caveat is gone. **Not rung 5 and not broad rung 4**: there is no live
connmand process, no socket, no remote input, no pointer/marker/command, the
written byte is the fixed `.`, and the post-first-step walk is
ambient-stack-dependent. Root-service impact remains an advisory claim.
