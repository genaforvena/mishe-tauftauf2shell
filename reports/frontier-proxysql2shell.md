# Frontier brief — ProxySQL2Shell (ProxySQL, CVE-2026-48773 / GHSA-58ww-865x-grpr)

## Verified ground truth (claims, not lab proof)

- Upstream advisory GHSA-58ww-865x-grpr, published 2026-05-26 by maintainer
  `renecannao`, CVE-2026-48773, CWE-787, Critical, read 07:40Z:
  CVSS 3.1 **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. The advisory reports
  ASan-confirmed heap corruption on real daemons on both ordinary frontend
  paths: MySQL `:6033` at `lib/mysql_data_stream.cpp:665`, PostgreSQL `:6133`
  at `lib/PgSQL_Data_Stream.cpp:534`. It also reports a stock Docker image
  crash (`exit=139`) through the optional ClickHouse/MySQL-style listener,
  and says the primitive "should be treated as potentially exploitable
  memory corruption unless proven otherwise". No code execution is claimed.
- Affected `>= 2.0.18, <= 3.0.8`; patched `3.0.9`. Tested source in the
  advisory: `v3.0` branch commit `9cc20a8775f6c194335a940ed0ca12001166522a`.
  Upstream fix commit `1cb2ecc17a0206bc2bed9090d5d7fab121f2798e`
  (<https://github.com/sysown/proxysql/commit/1cb2ecc17a0206bc2bed9090d5d7fab121f2798e.patch>)
  bounds the second `recv()` by the remaining queue capacity (`s-4` MySQL,
  `s-5` PgSQL) and calls `shut_soft()` before returning.
- Advisory trigger: one unauthenticated client declares an oversized first
  packet length (24-bit MySQL, 32-bit PostgreSQL). ProxySQL reads the header
  into a fixed 32768-byte `queueIN`, then passes the declared length straight
  to `recv()` at `queueIN + 4` / `queueIN + 5`, before authentication or
  packet validation. PostgreSQL frontend must be configured; MySQL frontend
  is the ordinary listener. Adapter builds, allocator and shipping flags are
  UNKNOWN on any host here.

## Source-bound mechanism

At tag `v3.0.8`, `include/MySQL_Data_Stream.h:30` and
`include/PgSQL_Data_Stream.h:16` pin `QUEUE_T_DEFAULT_SIZE 32768`. In
`MySQL_Data_Stream::read_from_net()` (`:643-671`) the first four bytes are
read, copied into the pinned 24-bit-header struct
(`include/proxysql_structs.h:928-930`, `u_int pkt_length:24, pkt_id:8;`), and

```
r += recv(fd, queue_w_ptr(queueIN)+4, Hdr.pkt_length, 0);   /* :665 */
```

runs unbounded. In `PgSQL_Data_Stream::read_from_net()` (`:504-541`) five
bytes are read; with type byte 0 the parser takes `buff[0..3]` as a big-endian
32-bit length and executes

```
r += recv(fd, queue_w_ptr(queueIN) + 5, length, 0);         /* :534 */
```

The declared length and the bytes of the second read are both
client-chosen. At `v3.0.9` the fix inserts, before each sink,

```
if (Hdr.pkt_length > (unsigned int)(s - 4)) { ... shut_soft(); return -1; }  /* :677 */
if (length > (uint32_t)(s - 5)) { ... shut_soft(); return -1; }               /* :546 */
```

The pre-existing `PROX` prefix check is a different variant
(`sysown/proxysql#5376`); ordinary non-PROXY packets still took the unbounded
path, as the advisory explains.

## Local replay and observed rungs

Harness `lab/frontier/proxysql2shell/` extracts the four **verbatim pinned**
first-read blocks under `#line` directives: vulnerable `v3.0.8`
(`mysql :643-671`, `pgsql :504-541`) and fixed `v3.0.9`
(`mysql :651-689`, `pgsql :512-560`). `recv()` is a synthetic in-memory
collaborator; no daemon, listener, socket, network or MySQL/PostgreSQL client
is used. Exact pins, collaborators, the single harness brace, the ASan-vs-
guard-mapping split and preserved failed attempts are in `PROVENANCE.md`.

Working-tree replay, 2026-11-21: **53 PASS / 0 FAIL**, trace
`sha256=936fa128f01f1dd123b59b4b941310654d68cd5985449768b0d9ba51a8e77884`
(two consecutive replays byte-identical).

- Rung 1 — deterministic trigger: a 100-byte packet leaves the bytes past the
  queue untouched (`UNTOUCHED=1`) in both protocols. MySQL declared 65535 is
  used as the second `recv()` length at the pinned `:665`; PostgreSQL
  declared 100000 is parsed from the first five bytes and used at `:534`.
  ASan is clean at the exact capacity (MySQL 32764, PgSQL 32763) and faults
  at one byte above it (32765 / 32764), proving the boundary.
- Rung 2 — accounting failure: the vulnerable builds accept the oversized
  read (`accepted=1 shut=0 recv_calls=2`); the fixed builds reject it before
  the second recv (`rc=-1 accepted=0 shut=1 recv_calls=1`) with the pinned
  logs `Oversized first packet from client: pkt_length=65535 exceeds queue
  capacity (32764). Closing fd=7` and `Oversized first packet from PgSQL
  client: length=100000 exceeds queue capacity (32763). Closing fd=7`, while
  still accepting the benign packet.
- Rung 3 — ASan confirms corruption in a real 32768-byte heap allocation:
  `heap-buffer-overflow`, `WRITE of size 65535` with caller
  `lib/mysql_data_stream.cpp:665`, and `WRITE of size 100000` with caller
  `lib/PgSQL_Data_Stream.cpp:534`; `malloc_usable_size()` reports 32768 in
  that build. Both fixed builds reject without an ASan report.
- Rung 4 — INSTRUMENTED only: in a separate plain build with a guard mapping,
  chosen alternating stripes are observed at the logical queue boundary and
  sixteen bytes past it (`at0=42 exp0=42 at16=41 exp16=41 CHOSEN_MATCH=1`)
  for both protocols — 32771 bytes past for MySQL, 67237 for PostgreSQL. The
  queue was zeroed first; benign and fixed runs leave the same offsets at
  zero. No pointer, saved return address, heap metadata field, function
  pointer or control-flow diversion was observed or attempted; the guard
  mapping is instrumentation, not an upstream allocator property.

## Feasibility assessment

This is the strongest lead found in this plant so far: an unauthenticated
declared length drives a large chosen write, two independent protocol paths,
explicit release pins, a small local fix, and an advisory that claims
real-daemon ASan evidence plus a stock-image crash. Rung 1-3 at the pinned
code level is established here; the **daemon** rung 3 and the stock crash are
still external claims, not reproduced on this host. Rung 4 beyond
INSTRUMENTED is UNKNOWN: no published exploit or pointer-control claim was
found, and the advisory itself stops at "potentially exploitable".

Cheapest experiment to move the daemon rung: build `v3.0.8` (advisory's tested
commit) with `NOJEMALLOC=1 WITHASAN=1`, start it loopback-only with the MySQL
frontend on 127.0.0.1:6033 and a PostgreSQL frontend on 127.0.0.1:6133, send
the two advisory first packets, and capture the ASan frames, the exact write
sizes and the queue allocation; repeat on `v3.0.9` for the guard. Only a
pointer/control-flow observation would justify dropping the INSTRUMENTED
label. If the stock daemon's allocator or read path makes the write land in
unusable poison rather than live neighbours, preserve that as a negative
result — the sibling nginx2root lesson applies.

All ground-truth items in the first section remain claims reproduced from
public sources. This brief proves the pinned code paths and their memory
effects in a synthetic frame, not advisory reachability, CVSS or daemon
exploitability.
