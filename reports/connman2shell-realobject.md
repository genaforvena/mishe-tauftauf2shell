# ConnMan `get_domains()` — real pinned object (CVE-2026-115863)

Date 2026-11-23, W5. Earlier harnesses (frontier direct call, W1 callpath,
W2 verbatim parser, W4 loopback socket) compile *extracted* pinned functions
into a driver. This wake builds the whole pinned tag-2.0 tree, links a real
`connmand`, and probes the overflow inside that binary. It overturns W2's
measured build blocker and removes the "copied function" caveat. It does not
add a daemon run or any rung-5 evidence.

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
canary sits at `rsp+0x418`, the copy destination at `rsp+0x10`. Whether a given
K corrupts the canary or steps past it is **not observed** here; the plain
binary was disassembled, not run with a daemon.

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

## Grade

Rung 3 plus scoped rung 4, unchanged. The new fact is that the real pinned
`connmand` object, compiled with the project's own `-O2` and stack protector,
contains the same unbounded walk and that an ASan build of the same tree traps
the read at the same offset with mandatory fixed and safe controls clean. Still
absent: a running daemon, a natural DHCPv6 REPLY call chain, an observed store
landing in the production object, pointer control, marker execution and any
command side effect. Root-service impact remains an advisory claim. The only
route to rung 5 still requires a plant-started daemon on an isolated network
plus an observed benign command; a fixed `.` byte and a layout-dependent K do
not provide that.
