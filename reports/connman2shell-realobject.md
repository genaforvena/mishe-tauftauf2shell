# ConnMan `get_domains()` — real pinned object (CVE-2026-115863)

Date 2026-11-23, W5 (canary boundary added W6). Earlier harnesses (frontier
direct call, W1 callpath, W2 verbatim parser, W4 loopback socket) compile
*extracted* pinned functions into a driver. W5 builds the whole pinned tag-2.0
tree, links a real `connmand`, and probes the overflow inside that binary. It
overturns W2's measured build blocker and removes the "copied function"
caveat. W6 adds a canary-boundary measurement. Neither adds a daemon run or
any rung-5 evidence.

## Build

`bash lab/connman2shell/realobj/build.sh` is reproducible and self-contained:

1. Assert SHA-256 of `client-2.0.c`, `client-2.0-fixed.c` and `common-2.0.c`
   under `lab/frontier/connman2shell/src/` (frontier's pinned bytes).
2. `apt-get download` eight dev/runtime `.deb`s (dbus-1, libmnl, xtables,
   libnftnl) into `lab/connman2shell/realobj/deps/` and `dpkg-deb -x` them into
   a lab-local prefix. **Nothing is installed on the host and no sudo is
   used.** `xtables.pc` hardcodes `prefix=/usr`, so an explicit
   `-I<prefix>/usr/include` is required at configure time.
3. Copy the pinned tree to `deps/connman-buildsrc/` and `autoreconf -fi` there;
   the SHA-asserted pinned tree is never modified. The fixed variant copies
   that tree and replaces `gdhcp/client.c` with frontier's saved Miu-patched
   file (SHA `d252cf01…5c0e`).
4. Configure and `make -j2` three out-of-tree builds. All linked:
   `src/connmand` plain 1,319,488 B (`5aee902c…fec1c`), ASan 7,309,184 B
   (`d5aeb7ee…2ec`), fixed ASan 7,309,848 B (`96521172…779e`). Configure found
   dbus-1 1.14.10, libmnl 1.0.5, xtables 1.8.10, libnftnl 1.2.6; internal DNS
   backend.

W2's statement that a ConnMan build is blocked by absent dbus-1/libmnl dev
packages was true of the unprovisioned host only. The dependencies are
provisionable inside the lab; `configure` and `make` then succeed.

## Production geometry

`evidence/geometry-summary.txt` from the plain `-O2` binary:

```
24c7a: sub    $0x428,%rsp
24c81: mov    %fs:0x28,%rax
24cce: call   <strncpy@plt>
24ce0: movb   $0x2e,(%rbx)
24d24: sub    %fs:0x28,%rdx
```

The production object has a stack canary and still calls `strncpy` with the
fixed 1025-byte copy, followed by the unbounded `movb $0x2e` label walk. The
canary sits at `rsp+0x418`, the copy destination at `rsp+0x10`. W6 below
measures where a given K lands relative to that canary; the store half of the
read-modify-write is still unobserved in the production object.

## Real-object probe

`bash lab/connman2shell/realobj/probe.sh` → `12 PASS / 0 FAIL`. gdb stops at
`main()`, allocates the crafted DOMAIN_LIST value in the inferior, and calls
the static `get_domains()` in the real `connmand` binary. This is a
debugger-forced call: it measures compiled-object geometry, not reachability
from a live REPLY.

- **Vulnerable ASan, attack** (`2048` bytes `0xff`, `value[1024]=0x80`):
  `AddressSanitizer: stack-buffer-overflow`, `READ of size 1`,
  top frame `get_domains ... gdhcp/client.c:2223`, object `dns_name` at
  `[48, 1074)` (line 2214), access at frame offset **1201** — the same 127-byte
  delta measured in every earlier harness, now in the real linked object.
  Inferior aborts.
- **Fixed ASan, same attack**: no ASan report, inferior exits normally. The
  Miu patch's `name_end` bound holds in compiled code.
- **Well-formed 8-byte DOMAIN_LIST**: no ASan report on either the vulnerable
  or the fixed binary.

## W6 — canary boundary (2026-11-23T02:34Z)

`bash lab/connman2shell/realobj/canary-boundary.sh` → `9 PASS / 0 FAIL`, with
SHA assertions on all three binaries. `dns_name` starts at `rsp+0x10` and the
compiler's canary is at `rsp+0x418`, i.e. `dns_name+1032`. For an all-`0xff`
value the walk writes at `dns_name+0, 256, 512, 768, 1024` and then reads at
`dns_name+1025+K`:

- **K=7** makes that first read land on the canary slot: ASan reports
  `READ of size 1` at frame offset **1080** (`dns_name` at 48, plus 1032).
  In the production `-O2` object the canary's low byte is `0x00` (glibc
  convention), so the loop reads zero and stops before writing there; the
  injected call returns (`CALL_RETURNED`, no `stack smashing`).
- **K=0x80** steps over that slot: ASan reads frame offset **1201**, 127 bytes
  past `dns_name`, the same delta as every earlier harness.

This is a structural negative for the W1 canary result. W1's "69 bytes changed
from `0xEE` to `0x2E`" used a synthetic `0xEE`-filled caller canary; the real
compiler canary's zero low byte terminates a walk that lands on it, so that
byte-run count does not transfer to the production object. A larger K can
still step over the canary into a caller-frame byte — that read is observed in
the real object, the store is not. Hardware watchpoints do not fire during
gdb's injected `call`, so a clean store readback there needs a natural caller,
not a debugger-forced one.

## Scope disposition — private-netns daemon

Not run. A network namespace plus veth pair needs CAP_SYS_ADMIN and is a
host-level network change, while `AGENTS.md` limits lab instances to
loopback-only processes under `lab/`. A natural connmand would also need a
private system D-Bus and would write filesystem service state. Even if all of
that were provisioned, the primitive writes only `.` at a layout-dependent
offset: it cannot place a pointer, a marker or a command, so no observation
from that daemon could earn rung 5. The lane is at its honest ceiling; another
harness variant would not change the grade.

## Grade

Rung 3 plus scoped rung 4, unchanged. The new fact is that the real pinned
`connmand` object, compiled with the project's own `-O2` and stack protector,
contains the same unbounded walk, that an ASan build of the same tree traps
the read at the same offset with mandatory fixed and safe controls clean, and
that a canary-aligned K is stopped by the real canary's zero low byte. Still
absent: a running daemon, a natural DHCPv6 REPLY call chain, an observed store
landing in the production object, pointer control, marker execution and any
command side effect. Root-service impact remains an advisory claim. The only
route to rung 5 would require a plant-started daemon on an isolated network
plus an observed benign command; a fixed `.` byte and a layout-dependent K do
not provide that.
