# proxysql2shell — status

Admitted 2026-11-21 ~07:5xZ by the operator under standing approval #6 on
frontier's commit `3aea985` and brief
[frontier-proxysql2shell.md](frontier-proxysql2shell.md). Claim source:
maintainer advisory GHSA-58ww-865x-grpr, CVE-2026-48773, published
2026-05-26 by `renecannao`, CWE-787, Critical; CVSS 3.1 **9.8**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. The advisory reports ASan-confirmed
heap corruption on real daemons on both ordinary frontend paths — MySQL
`:6033` at `lib/mysql_data_stream.cpp:665`, PostgreSQL `:6133` at
`lib/PgSQL_Data_Stream.cpp:534` — and a stock Docker-image crash (`exit=139`)
through the optional ClickHouse/MySQL-style listener, but claims no code
execution and says the primitive "should be treated as potentially
exploitable memory corruption unless proven otherwise". Affected
`>= 2.0.18, <= 3.0.8`; patched `3.0.9`. Tested source in the advisory:
`v3.0` branch commit `9cc20a8775f6c194335a940ed0ca12001166522a`; upstream fix
`1cb2ecc17a0206bc2bed9090d5d7fab121f2798e` bounds the second `recv()` by the
remaining queue capacity (`s-4` MySQL, `s-5` PgSQL) and calls `shut_soft()`.

Claimed trigger: one unauthenticated client declares an oversized first-packet
length (24-bit MySQL, 32-bit PostgreSQL); ProxySQL reads the header into a
fixed 32768-byte `queueIN`, then passes the declared length straight to
`recv()` at `queueIN + 4` (MySQL) or `queueIN + 5` (PgSQL), before
authentication or packet validation. Both the declared length and the second
read's bytes are client-chosen. The PostgreSQL frontend must be configured;
the MySQL frontend is the ordinary listener. Adapter builds, allocator and
shipping flags are UNKNOWN on a stock host here. Pins, hashes, raw URLs and
preserved failed attempts: `lab/frontier/proxysql2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/proxysql2shell/run.sh` — 53 PASS / 0 FAIL,
  canonical raw trace SHA-256
  `936fa128f01f1dd123b59b4b941310654d68cd5985449768b0d9ba51a8e77884`.
- Operator replay ~07:5xZ from two clean `git archive HEAD` (`3aea985`)
  extractions into separate absolute directories: 53 PASS / 0 FAIL in both,
  raw trace
  `sha256=936fa128f01f1dd123b59b4b941310654d68cd5985449768b0d9ba51a8e77884`
  — byte-identical between directories, to the working-tree replay and to the
  brief.
- Rungs 1/2/3 on verbatim pinned first-read blocks from `v3.0.8`
  (`mysql_data_stream.cpp:643-671`, `PgSQL_Data_Stream.cpp:504-541`) and
  `v3.0.9` (`:651-689`, `:512-560`): a 100-byte packet leaves bytes past the
  queue untouched (`UNTOUCHED=1`); MySQL declared 65535 is used as the second
  `recv()` length at `:665`, PostgreSQL declared 100000 is parsed from the
  first five bytes and used at `:534`. ASan is clean at exact capacity
  (32764 MySQL / 32763 PgSQL) and faults one byte above (32765 / 32764).
  Vulnerable builds accept the read (`accepted=1 shut=0 recv_calls=2`); fixed
  builds reject before the second `recv()` (`rc=-1 accepted=0 shut=1
  recv_calls=1`) with the pinned `Oversized first packet ...` logs while still
  accepting the benign packet. ASan reports `heap-buffer-overflow`,
  `WRITE of size 65535` at pinned `mysql :665` and `WRITE of size 100000` at
  pinned `pgsql :534`; `malloc_usable_size()` reports 32768.
- Rung 4 INSTRUMENTED only: in a separate plain build with a guard mapping,
  chosen alternating stripes are read back byte-exact at the logical queue
  boundary and sixteen bytes past it (`at0=42 exp0=42 at16=41 exp16=41
  CHOSEN_MATCH=1`) for both protocols — 32771 bytes past for MySQL, 67237 for
  PostgreSQL. The queue was zeroed first; benign and fixed runs leave those
  offsets at zero. No pointer, saved return address, heap-metadata field,
  function pointer, control-flow diversion or marker execution was observed
  or attempted; the guard mapping is instrumentation, not an upstream
  allocator property.
- UNKNOWN: live daemon, listener reachability, shipping allocator and compile
  flags, the advisory's real-daemon ASan frames and stock Docker crash, the
  post-overflow caller-side pointer neighbourhood, and whether a PostgreSQL
  listener is configured on any stock host. All external claims — reachability,
  CVSS, severity, daemon ASan evidence, "potentially exploitable" — remain
  claims. No probe was sent off loopback. Witness replay was requested in the
  handoff (#657); no verdict at admission.

Cheapest next rung: build `v3.0.8` (the advisory's tested commit) with
`NOJEMALLOC=1 WITHASAN=1`, start it loopback-only with the MySQL frontend on
127.0.0.1:6033 and a PostgreSQL frontend on 127.0.0.1:6133, send the advisory's
two first packets, capture the real ASan frames, write sizes and queue
allocation, and repeat on `v3.0.9` for the guard. Only a pointer or
control-flow observation would justify dropping the INSTRUMENTED label. If the
stock daemon's allocator or read path makes the write land in unusable poison
rather than live neighbours, preserve that as a negative result — the sibling
nginx2root lesson applies.
