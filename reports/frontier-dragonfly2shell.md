# Frontier brief — DragonflyDB memcached reply-builder "KeyEcho"

- **Advisory**: GHSA-9q98-cx72-pg45 (GitHub Security Advisory, published
  2026-09-20), "Unauthenticated remote code execution in DragonflyDB
  (memcached reply-builder heap overflow)". No CVE assigned.
- **Affected / fixed**: affected ≤ 1.40.1, fixed in **1.40.2** (released
  2026-09-03, fix PR `dragonflydb/dragonfly#8213`). Note an internal defect in
  the advisory metadata: it says "Affected versions `< 1.40.1`" and "Patched
  versions: None" while its own description claims the chain was "proven end
  to end on the stock `ghcr.io/dragonflydb/dragonfly:v1.40.1` image". The
  v1.40.2 release notes and the PR diff resolve this: the vulnerable versions
  include 1.40.1; 1.40.2 is the fix. Advisory severity field says "Moderate"
  while the description claims CVSS 3.1 base 9.8 (Critical). Both are claims.
- **Precondition**: operator must have enabled `--memcached_port` (off by
  default); that protocol has no authentication. A long key must first be
  created over the RESP port, which has no 250-byte key limit — this is the
  exact staging path in the fix's own regression test
  (`test_read_huge_redis_key_over_memcached`).
- **Claim sources (read-only provisioning, treated as claims)**: the GHSA
  advisory above; v1.40.2 release notes "Protocol" section; PR #8213 diff
  (`patch-diff.githubusercontent.com/raw/dragonflydb/dragonfly/pull/8213.diff`).

## Verified ground truth (this lab, 2026-11-20)

Pulled both stock images by digest (not rebuilt locally):

- `ghcr.io/dragonflydb/dragonfly:v1.40.1` →
  `sha256:ebf3c6c213e82fb51b4521660cca13f06f3421dc5b1ed14f2f474c50b5e29986`
- `ghcr.io/dragonflydb/dragonfly:v1.40.2` →
  `sha256:18afa43e911f1dff18c7d1eb452361876d9702bb1cdff5c5d75c69617a4065c9`

Harness `lab/frontier/dragonfly2shell/trigger.py` + `run.sh`: RESP `SET` of a
20000-byte key (`b"k"*20000`), then a raw memcached `get` of that key. Host
ports published on 127.0.0.1 only; all sockets loopback; no external probe.

Observed bytes:

| build | RESP `SET` | memcached `get` reply | key echoed? | listeners after |
|---|---|---|---|---|
| v1.40.1 | `+OK\r\n` | **20024 bytes**, `VALUE kkkk… 0 5\r\nvalue\r\nEND\r\n` | **yes, all 20000 bytes** | `+PONG`, `END` — both alive |
| v1.40.2 | `+OK\r\n` | 38 bytes, `CLIENT_ERROR bad data chunk\r\n` | no | `+PONG`, `END` — both alive |

Logs: `lab/frontier/dragonfly2shell/logs/trigger-v1.40.1.log`,
`trigger-v1.40.2.log` (plus `server-*.log`). Reproduce with `./run.sh v1.40.1`
and `./run.sh v1.40.2`.

**Important negative preserved:** v1.40.1 did **not** crash. The 20000-byte
key is echoed out through a reply path whose fixed buffer is 8192 bytes
(`kMaxBufferSize`), so roughly 11800 bytes were written beyond that block,
yet the process kept serving. This is consistent with an attacker-controlled
silent heap overflow (the primitive a poisoning exploit needs), not with a
faulting crash. No crash is claimed.

## Source-bound mechanism (read from the fix diff, not inferred)

`src/facade/memcache_parser.cc` `ParseValueless()` — serving `get`, `gets`,
`gat`, `gats`, `delete`, `incr`, `decr` — had **no** key-length check; the
store (`ParseInternal`, `> 250`) and meta (`ParseMeta`, `> 250`) paths did.
The fix introduces `constexpr size_t kMaxKeyLen = 250` and returns
`PARSE_ERROR` for over-long keys at three points in `ParseValueless`.

`src/facade/reply_builder.cc` `SinkReplyBuilder::WritePieces()` computes
`required = piece_size(pieces)+...`, calls `Flush(required)` only when
`buffer_.AppendLen() <= required`, then writes each piece with an unbounded
`write_piece` `memcpy`. The fix adds `CHECK_LE(required, kMaxBufferSize)`.
`MCReplyBuilder::SendValue()` builds `WritePieces("VALUE ", key, " ",
mc_flag, " ", value.size())`; the fix adds
`DCHECK_LE(key.size(), kMaxBufferSize)` with the comment "Memcached key bounds
to 250 by hard protocol". The `"VALUE "` prefix is 6 bytes, so a key of
`8192-6+N` bytes writes `N` bytes past the 8192-byte block.

The escalation beyond the overflow (mimalloc plaintext free-list `next`
poisoning with `MI_SECURE=0`, a later `make_unique<char[]>` landing at
attacker-chosen `T = 0x19ef560`, a precomputed GOT image changing
`__isoc99_sscanf@got` to `base::sh_exec`, and a RESP `RESTORE` zset driving
`FetchDouble` into `sscanf(score) == sh_exec(score)`) is the **advisory
author's claim**, built against the stock non-PIE image with fixed addresses.
It is not reproduced here.

## Rung ladder — honest grading

- **Rung 1 (reproducible trigger): PASS.** Deterministic, pre-auth once the
  memcached port is enabled, two stock images, clean version differential.
- **Rung 2 (observed state failure): PASS.** The 250-byte protocol key limit
  is bypassed on `ParseValueless`; the 20000-byte key reaches `SendValue` and
  is echoed in full. The fixed build rejects the same request.
- **Rung 3 (ASan/Valgrind-confirmed corruption): NOT DEMONSTRATED on the
  stock build; mechanics PASS on a labeled synthetic harness.** Two attempts
  to sanitize the real binary failed honestly: the extracted `v1.40.1`
  (`deps/dragonfly-v1.40.1`, unstripped) needs `--proactor_threads=2` on this
  host, and under Valgrind `--force_epoll` its custom fiber stacks generate
  hundreds of `Invalid write of size 8` reports in
  `FiberInterface::SwitchSetup` / `Scheduler::Attach` and the process dies
  before serving the reply — false positives from Valgrind's stack model,
  **not** evidence about this bug (`logs/valgrind-v1.40.1.log`,
  `logs/vg-run3.out`). No report names `WritePieces`, `SendValue` or `memcpy`.
  Separately, `lab/frontier/dragonfly2shell/synthetic_overflow.cc` mirrors the
  exact v1.40.1 source lines (`Flush` clamps the scratch to
  `kMaxBufferSize=8192`; `write_piece(string_view)` is a bare `memcpy`;
  `SendValue` builds `VALUE ` + key + ` ` + flag + ` ` + size). Compiled
  `-fsanitize=address -fno-builtin -O0 -g`, the 20000-byte key gives
  `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 20000`,
  "`0x525000002100 is located 0 bytes after 8192-byte region
  [0x525000000100,0x525000002100)`", allocation at `malloc(kMaxBufferSize)`
  (`logs/synthetic-asan-o0.out`). This is **SYNTHETIC mechanics evidence**
  only; per standing approval #2 no stock-build conclusion is drawn from it.
  The real-binary fact remains: 20024 bytes echoed through an 8192-byte
  reply path with no crash.
- **Rung 4 (demonstrated security impact): NOT DEMONSTRATED.** No free-list
  poison, no controlled allocation, no pointer/GOT control, no marker or
  command execution was exercised in this lab. The published chain stays a
  CLAIM.

## Feasibility and cheapest next step

Tractability **HIGH for rungs 1–3**, **MEDIUM for rung 4**: pure C++ `memcpy`
into a fixed 8192-byte block (no AVX/AVX-512 hardware blocker, unlike
Java4Shell), pre-auth on both ports once memcached is enabled, stock images
publicly pullable, binary non-PIE with symbols (useful for a dedicated mind).
Reachability is narrower than Mosquitto's default-on listener because
`--memcached_port` is off by default, and the staging path needs the RESP port
too.

Cheapest next rung: use gdb on the extracted unstripped binary (native,
`--proactor_threads=2 --force_epoll`) to break at the reply-path `memcpy`
during the trigger and name the destination allocation and write length —
Valgrind is exhausted here (fiber false positives above). Then, on the stock
image only, attempt the published mimalloc free-list poison with
`T = 0x19ef560` and confirm a controlled `malloc()` return before anyone
claims rung 4. Preserve the negative if the groom fails.

## Reproduce

```
cd lab/frontier/dragonfly2shell
./run.sh v1.40.1          # logs/trigger-v1.40.1.log
./run.sh v1.40.2          # logs/trigger-v1.40.2.log
g++ -std=c++17 -fsanitize=address -fno-builtin -O0 -g \
  -o synthetic_overflow_o0 synthetic_overflow.cc
./synthetic_overflow_o0   # logs/synthetic-asan-o0.out; SYNTHETIC only
```

All listeners bind/publish on 127.0.0.1 only (host ports 16379/16211).
Stock image digests are pinned above; no host package changes.
