# PROVENANCE — llamarpc2shell (CVE-2026-118375)

All work loopback/local only. No external probing; source fetches are provisioning.
Everything below is reproducible with the pinned blobs and files in this tree.

## Pins (fetched 2026-11-23, sha256 verified on every harness run)

| file | source | sha256 |
|---|---|---|
| `src/transport-vuln.cpp` | `https://raw.githubusercontent.com/ggml-org/llama.cpp/620d2225cc436ab0b001e3200e590e3b286ef9ab/ggml/src/ggml-rpc/transport.cpp` | `a5a6774d87398344a09da643de6ac175ad8188c91d8def25f6dad9c0e8957e34` |
| `src/transport-fixed.cpp` | same path at `9a0fde9967fa1a35b6e5dd1f47e1a3648b6fecc1` | `cd61f2ec3968d2cfc90eb2ea30f9a2762f5160b14a9bddfcd64b11361fc8da43` |
| `src/fix-9a0fde99.patch` | `https://github.com/ggml-org/llama.cpp/commit/9a0fde9967fa1a35b6e5dd1f47e1a3648b6fecc1.patch` | `28056890f2a24ffaaa7df4858588529f733cdd092e0f93b7014c68236b0f5736` |
| `src/ggml-rpc-vuln.cpp` | same vulnerable commit, `ggml/src/ggml-rpc/ggml-rpc.cpp` | `583cf1ee149c5b94c215eca07a293564d1b755427b57b1a7846f0328e724eacd` |

Claim source: <https://www.vulncheck.com/advisories/llama-cpp-b8841-before-b11865-stack-based-buffer-overflow-via-ggml-rpc-rdma-rdma-recv>.
Fix PR: <https://github.com/ggml-org/llama.cpp/pull/30399>. Release: b11865.

## Harness

`harness/run.sh` (executable) drives everything from this directory:

```
cd lab/frontier/llamarpc2shell && bash harness/run.sh
```

It extracts `bool socket_t::impl::rdma_recv(void*, size_t)` through its
column-0 closing brace from both pinned blobs on every run (`awk`), concatenates
each slice verbatim between `harness/driver_head.cpp` and
`harness/driver_main.cpp`, and builds five binaries with g++/clang++ at `-O0 -g`:
plain vulnerable, plain fixed, ASan vulnerable (gcc and clang), ASan fixed.
`ASAN_BUILD` selects the faithful 1-byte stack `cmd` sink; the plain build uses
a contiguous `{ uint8_t cmd; uint8_t tail[128]; }` probe so adjacent stack bytes
can be read deterministically. The fake verbs environment delivers exactly one
attacker-crafted completion (`wc.byte_len = got`, message bytes in a 256 KiB
rx slot), then drops, so the underflow loop terminates after the first write.
This stub is a documented model boundary, not a real verbs device.

Assertions (29): 4 pin hashes, caller 1-byte sink, 5 slice-shape checks, fix
hunk dry-run application, 5 builds, rung 1 arithmetic, rung 2 measured
overflow/post, 3 chosen-byte/canary checks, 3 ASan checks, 4 fixed/safe
controls, 2 ASan exit-code checks, and a clean `/tmp` replay check.

Raw evidence: `harness/evidence/run{5,6,7}.txt` (three full 29/0 runs),
`trace.txt`, `plain-attack.out`, `fixed-attack.out`, `plain-safe.out`,
`vuln-gcc-asan.out`, `vuln-clang-asan.out`, `fixed-asan.out`,
`vuln-asan-safe.out`, `fix-dryrun.txt`, `build-*.log`.
Normalized trace hash (identical in all three runs and the replay):
`d898482a39c65919916750bb28f6151d55e91efb3b56d88e315321c62b09c1b2`.

## Environment notes and negatives preserved

- Host: uid 1000, passwordless `sudo -n`; `/usr/include/infiniband/verbs.h`
  and `/usr/bin/rdma` present; `/sys/class/infiniband` initially empty.
  `sudo -n modprobe rdma_rxe`, `sudo -n rdma link add rxe0 type rxe netdev lo`
  and `rdma link show` succeeded (link ACTIVE / LINK_UP on `lo`). At staging no
  build or wire client was run; this wake built the server and drove a full
  HELLO/caps + RC SEND exchange over `rxe0`, so live reachability is now
  OBSERVED on loopback with `AT:P` still applying to real deployments.
- The advisory's `transport.cpp#L510-L528` and the fix hunk's `@@ -517` are
  consistent with the pinned blob's `rdma_recv` at 510–528 and `memcpy` at 520;
  the 6-line offset is recorded, not silently normalized.
- The slice harness still exercises only `got=43`; the live wire experiment
  exercised 1, 43 and 3593 bytes. The advisory's 256 KiB upper bound remains
  unmeasured. Saved-frame data was overwritten in the live non-ASan Debug
  build (see below); no pointer redirect, ROP, command or RCE was observed.

## Live wire experiment — 2026-11-23 (this wake)

Full report: `reports/llamarpc2shell.md`. Provisioned source trees are listed
in `lab/frontier/llamarpc2shell/.gitignore` and are not committed (304 MiB +
182 MiB upstream trees plus build output). Verified source-state hashes:
`transport.cpp` `a5a6774d…e8957e34` (vulnerable) and `cd61f2ec…da43` (upstream
fixed worktree at `9a0fde99…`). Built server hashes are in the report.

- `wire/rdma_attacker.cpp` (sha `5dbb9573…e14bb9e6`): raw TCP HELLO/caps
  ({qpn, psn, gid}, 24 bytes) then RC QP RTR/RTS and one SEND; GID index 1 on
  `rxe0` is `::ffff:127.0.0.1`, RoCEv2, MTU 4096.
- `wire/run.sh` (sha `1daa391a…54f35d3c46bc`): `safe` (1 byte), `attack`
  (43 bytes, ASan), `fixed` (43 bytes, upstream fixed ASan server via
  `SERVER_BIN`). Creates/deletes `rxe0` when it was absent.
- `wire/run-gdb.sh` (sha `6bdf0864…bc23de72dbb5`) plus `gdb-frame.cmd`,
  `gdb-rip.cmd`, `gdb-crash.cmd`: plain Debug server under gdb; break in
  `socket_t::impl::rdma_recv`, three `finish` commands, dump the live
  `rpc_serve_client` frame.
- Raw logs: `wire/evidence/{client,server}-{safe,attack,fixed}.log`,
  `gdb-attack.log`, `gdb-rip.log`, `gdb-crash.log` and matching client logs.

Observed: live ASan `WRITE of size 43` into `[48,49) 'cmd'` at
`transport.cpp:520` called from `ggml-rpc.cpp:2475`; gdb frame dump shows
payload byte `+0 = 0x0f`, `+11 = 0x5a`, `+18 = 0x44`, other bytes `0x41`
through `+42`; 3593-byte payload puts `0x4242424242424242` in the saved RIP
slot at `&cmd + 3585`, and the no-breakpoint run takes SIGSEGV with that value
in backtrace frame #2. Fixed server logs `RDMA recv overrun: got=43 rem=1` and
is ASan-clean; 1-byte input on the vulnerable server is ASan-clean.

## Rung-5 feasibility attempt — 2026-11-23 second wake (negative)

Replay: `bash wire/run.sh attack` reproduced the live ASan `WRITE of size 43`
(`transport.cpp:520` ← `ggml-rpc.cpp:2475`, `wc byte_len=43`) before any edits.

New lab-only artifacts (all under `wire/`; binaries/large logs are not evidence
of a working exploit):

- `rdma_attacker.cpp` gained optional `RDMA_PAYLOAD_FILE`, which SENDs the file
  bytes verbatim; the default marker behaviour is unchanged.
- `server-noaslr.sh`, `server-fixedenv.sh`, `run-dump-fixedenv.sh`,
  `run-rce-gdb.sh`, `gdb-dump-nocanary.cmd`, `gdb-earlyret-dump.cmd`,
  `gdb-rce-observe.cmd`, `gdb-rxaddr.cmd`: wrappers to hold the lab server
  environment fixed, disable ASLR with `setarch -R`, and dump stack/runtime
  addresses. `env -i PATH=/usr/bin:/bin HOME=/home/mesh-home TERM=dumb` is used
  for every fixed-environment dump and attack.
- `src/llama.cpp-pin-nocanary/` (gitignored) is the same pin configured with
  `-fno-stack-protector` for C/CXX/link; built server sha256
  `3fb0d4bff4ae699088cd20f81f575b0399f1fe797ae2ec87979c100ea7599959`,
  `libggml-rpc` has no `__stack_chk_fail` import. Build log:
  `wire/evidence/build-nocanary.log`.
- Measured layout in that build under `setarch -R` + fixed environment:
  `&cmd = 0x7fffffffe4bf`, `rpc rbp = 0x7fffffffe7b0`, saved RIP at
  `&cmd + 761`, libc base `0x7ffff7200000`, RDMA rx slot `0x7ffff6bff000`.
  libc offsets: `pop rdi; ret` `0x10f84b`, `system` `0x58750`, `_exit`
  `0xee2c0`. Deterministic dumps: `pristine-fixed2.bin` == `pristine-fixed3.bin`.
- Attempted inputs: `wire/evidence/rce-payload{,-fixed,-early}.bin`, including
  a complete `ret`/`pop rdi`/`system`/`_exit` chain and a command string at
  `&cmd + 1200`. Failure logs: `fxlen100.log`, `fxlen761.log`, `fxlen820.log`,
  `rce-fixed-gdb.log`, `rce-early.log`, `rce-diag3.log`.

Result: no command, side effect or valid pointer redirect. The oversized
completion underflows `rem` in `rdma_recv`, so `recv_data` returns false and
`rpc_serve_client` breaks at `ggml-rpc.cpp:2476`; `rpc_server::~rpc_server`
at `:2432` then aborts on the smashed `graphs` vector (`free(): invalid
pointer`, `__n = -11`) before the epilogue can return into the chain. A 4608-byte
SEND instead faults in a second `rdma_recv` memcpy. 1-byte control is clean.
Rung 5 remains UNKNOWN; no witness replay of these failed inputs is needed.

Witness W142 (DM #2193) independently replayed the live rung-3/rung-4 claim
from a clean archive of `37da4e6` and graded it ESTABLISHED at the labeled
build scope; the failed ROP inputs above are not part of that verdict. W143
(DM #2206) found that the 4608-byte ROP run had overwritten the canonical
43-byte ASan attack logs at `a76b986`; the canonical files are restored to
the witness-verified `37da4e6` bytes (client `f8491730…8798fa5`, server
`76bec3c7…86b6a30`) and the 4608-byte pair is kept as
`wire/evidence/{client,server}-rce-4608.log` (`d7a88a75…fbcab58`,
`a5151d09…bbb1fe`). No grade change.
