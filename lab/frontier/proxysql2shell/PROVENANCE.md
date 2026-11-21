# Provenance — proxysql2shell frontier harness (2026-11-21)

All external reads were read-only provisioning from public sources. No probe
was sent off loopback; no ProxySQL daemon, listener, socket, MySQL or
PostgreSQL client was created. The `recv()` collaborator is an in-memory
`memcpy` from a synthetic payload.

## Claim sources

- GitHub advisory GHSA-58ww-865x-grpr, "ProxySQL pre-auth heap overflow in
  MySQL and PostgreSQL first-packet handling", published 2026-05-26 by
  `renecannao`, CVE-2026-48773, CWE-787, Critical, read 07:40Z:
  <https://github.com/sysown/proxysql/security/advisories/GHSA-58ww-865x-grpr>.
  Affected `>= 2.0.18, <= 3.0.8`; patched `3.0.9`. CVSS 3.1 **9.8**
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. The advisory reports ASan
  heap-buffer-overflow on real daemons at MySQL frontend :6033
  (`lib/mysql_data_stream.cpp:665`) and PostgreSQL frontend :6133
  (`lib/PgSQL_Data_Stream.cpp:534`), plus a stock Docker ClickHouse-listener
  crash `exit=139`. Those daemon observations are **claims here**, not lab
  results of this harness.
- Upstream fix commit `1cb2ecc17a0206bc2bed9090d5d7fab121f2798e`
  ("fix(security): bound first-packet recv() in MySQL and PgSQL data streams",
  2026-05-14) patch pinned below. It adds an `s - 4` / `s - 5` bound and
  `shut_soft()` before the second `recv()`, plus a TAP regression test.

## Exact pins and fetch method

Fetched with `curl -fsSL` from `raw.githubusercontent.com/sysown/proxysql/<ref>/…`
and the GitHub commit `.patch` URL into `pins/`. `run.sh` verifies every hash
on each replay.

| ref | file | sha256 |
| --- | --- | --- |
| `v3.0.8` | `lib/mysql_data_stream.cpp` | `629ddd51c6c53ce8918721d5e6e1c8a280e4a9f73ef95614d18b67e08fa51526` |
| `v3.0.9` | `lib/mysql_data_stream.cpp` | `8ad8012fc01a1d47cea6ab97e40869d85d1a145d133a93b68a085913eaa75eb0` |
| `v3.0.8` | `lib/PgSQL_Data_Stream.cpp` | `7e3b3c9f7672f589f67fb27f1059498dd6cbf18a29330c5aa2b0038766956f7b` |
| `v3.0.9` | `lib/PgSQL_Data_Stream.cpp` | `40b11ca492e489ee83185c0e1956183a973e030aaf6e5cb8f179b44abf038b13` |
| `v3.0.8` / `v3.0.9` | `include/MySQL_Data_Stream.h` | `63edb94b0d081b7866c8bfb009e534070bd418122176f0b48759938cf0d3c79e` |
| `v3.0.8` / `v3.0.9` | `include/PgSQL_Data_Stream.h` | `5a08a66877830797ff422fae03f55bf093b0472af597679417cba58ea5fe3af0` |
| `v3.0.8` | `include/proxysql_structs.h` | `f6bd64312b576db3779e1ac7795e7217d4d430ffc9794c961cfda2cc2d5926c4` |
| fix `1cb2ecc…` | `.patch` | `e65110dda3c43b61e46ec41b4c71775119fd534c207ae1da7ce0e5ea05a1c5da` |

`include/proxysql_structs.h:928-930` gives the exact pinned
`struct _mysql_hdr { u_int pkt_length:24, pkt_id:8; };`.
`include/MySQL_Data_Stream.h:30` and `include/PgSQL_Data_Stream.h:16` give
`QUEUE_T_DEFAULT_SIZE 32768` verbatim.

## Harness boundary

- `run.sh` asserts the exact asserted lines (`v3.0.8 mysql :643/:665`,
  `v3.0.9 mysql :651/:677/:683`, `v3.0.8 pgsql :504/:534`,
  `v3.0.9 pgsql :512/:546/:553`) and extracts **verbatim** pinned blocks:
  - MySQL vulnerable `v3.0.8:643-671`, fixed `v3.0.9:651-689`;
  - PostgreSQL vulnerable `v3.0.8:504-541`, fixed `v3.0.9:512-560`.
  Each is emitted under a `#line <first> "lib/<file>"` directive so ASan
  caller frames name the pinned source and line.
- Exactly one harness brace closes the pinned `if (encrypted == false)` after
  the MySQL block (v3.0.8:671 / v3.0.9:689); no upstream line is changed,
  reordered or omitted. The extracted bytes are checked after generation.
- Collaborators, all harness stubs: `recv()` is a macro calling
  `lab_recv_at(__LINE__, …)`, which prints the pinned line and copies the
  synthetic payload; `proxy_error()` prints the fixed build's pinned
  diagnostic with a `FIXED_LOG` prefix; `shut_soft()` sets a flag. `queue_t`,
  `PtrSize_t`, `mysql_hdr`, `queue_available()` and `queue_w_ptr()` are
  reconstructed from the pinned headers named above. No other upstream
  function is used.
- ASan builds use a real `malloc(32768)` queue: ASan polices the exact
  boundary and reports the summary caller at the pinned sink. Plain builds
  use a zeroed 256 KiB anonymous `mmap` with the logical queue beginning
  65536 bytes into it, so a multi-kilobyte chosen write stays in mapped memory
  and the bytes past the logical 32768-byte queue can be read afterwards.
  This is an instrumentation choice, not an upstream allocator property;
  `usable=0` in plain traces means no malloc chunk was inspected.
- The payload carries a 3-byte little-endian MySQL length or a 4-byte
  big-endian PostgreSQL length and two alternating 16-byte chosen stripes
  (`41` / `42`), so offsets past the queue are identifiable.
- No pointer, saved return address, heap metadata target, function pointer or
  control-flow diversion was attempted or claimed. Rung 4 here is
  INSTRUMENTED: chosen bytes at chosen offsets past the logical queue, with
  the heap-boundary proof supplied by the separate ASan build. Advisory
  reachability, CVSS and daemon PoCs remain claims.
- Trace hashes exclude ASan PIDs, addresses, build paths and shadow bytes:
  only normalized `CASE`, `RECV_CALL`, `RESULT`, `BOUNDARY`, `FIXED_LOG`,
  `ASAN` and `PASS`/`FAIL` lines are hashed, and those lines contain no
  volatile text.

## Failed attempts preserved

- First generation omitted the brace closing the pinned MySQL outer branch,
  so four variants failed to compile; fixed with the single conditional
  harness brace documented above.
- First PostgreSQL payload put the length at `buff[1..4]`, but with type byte
  0 the pinned parser reads `buff[0..3]`; declared 100000 became 390, so no
  overflow was observed. Corrected to big-endian bytes at `buff[0..3]`.
- First plain build freed a heap corrupted by the chosen write and segfaulted
  before printing; the guard mapping above replaced it. Benign and fixed
  controls were re-run after each repair, not only the chosen case.
