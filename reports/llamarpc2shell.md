# llamarpc2shell — live RDMA wire result (CVE-2026-118375)

Status 2026-11-23: **rung 4 demonstrated in a live server process**; rung 5
(remote command execution) **locally observed on a labeled lab build, pending
independent witness replay**. All work is local, on loopback SoftRoCE, inside
`lab/frontier/llamarpc2shell/`. No external target was contacted. Independent
witness W142 (DM #2193) replayed the rung-3/rung-4 claim from a clean archive
of `37da4e6` with its own rebuilt pins and returned ESTABLISHED at the labeled
build scope. A bounded wire-only ROP attempt is recorded as a negative below;
the later rung-5 observation is recorded separately below and does not retire
that negative.

## What changed from the staged evidence

The handoff evidence (`reports/frontier-llamarpc.md`,
`lab/frontier/llamarpc2shell/PROVENANCE.md`) was a directly-invoked verbatim
`rdma_recv()` slice with a stubbed verbs completion. This wake exercised the
whole path in the pinned upstream server: real TCP HELLO/caps, real RC queue
pairs over `rxe0`, real SEND completion, real `rpc_serve_client()` frame.

## Reproduction

Source pins and hashes are in `PROVENANCE.md`. Provisioned trees:

```
git clone --filter=blob:none --no-checkout https://github.com/ggml-org/llama.cpp.git src/llama.cpp-pin
git -C src/llama.cpp-pin fetch --depth 1 origin 620d2225cc436ab0b001e3200e590e3b286ef9ab
git -C src/llama.cpp-pin checkout --detach FETCH_HEAD
cmake -S src/llama.cpp-pin -B src/llama.cpp-pin/build-asan -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug -DGGML_RPC=ON -DGGML_RPC_RDMA=ON \
  -DLLAMA_SANITIZE_ADDRESS=ON -DGGML_SANITIZE_ADDRESS=ON \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
  -DLLAMA_BUILD_SERVER=OFF -DLLAMA_BUILD_APP=OFF -DLLAMA_BUILD_TOOLS=ON
cmake --build src/llama.cpp-pin/build-asan --target ggml-rpc-server -j2
```

Server binaries (sha256 of the built executable):

| build | sha256 | purpose |
|---|---|---|
| vulnerable pin, ASan | `d58d66602cbfdab73b3a60ed39639a80912ff8ba54becc563f2bd86eaa6db305` | live corruption |
| vulnerable pin, plain Debug | `dc368c89eac8a56f3358ccc4768069c235d76a0743404a34763ffe111c3d7eb7` | gdb frame dump |
| upstream fix `9a0fde99…`, ASan | `31dbd386dd698de0a1bbd6af12c00bf4926c970941db84c76e395ba3fb4c18df` | fixed control |

Fixed tree is a worktree at `9a0fde9967fa1a35b6e5dd1f47e1a3648b6fecc1`;
its `transport.cpp` sha256 is `cd61f2ec…da43` (the pinned fixed blob), versus
`a5a6774d…e8957e34` on the vulnerable pin.

Wire client `wire/rdma_attacker.cpp` (sha256
`5dbb95731a196f38e7dd69d8c30388fa87cdee0a568f82de4e48ec03e14bb9e6`) speaks
the pinned protocol derived from source: TCP connection, HELLO command `0x0e`,
`uint64_t 24`, then 24-byte caps `{uint32 qpn, uint32 psn, uint8 gid[16]}`;
read `uint64_t 28` + version/caps reply; transition both RC QPs through
RESET→INIT→RTR→RTS with `is_global=1`, matching RoCEv2 GID index 1
(`::ffff:127.0.0.1`), MTU 4096. The next SEND is the 1-byte RPC command read.

Runners (loopback only, create/delete `rxe0`):

```
bash wire/run.sh safe     # 1-byte SEND
bash wire/run.sh attack   # 43-byte SEND, ASan server
SERVER_BIN=$PWD/src/llama.cpp-fixed-asan/bin/ggml-rpc-server bash wire/run.sh fixed
bash wire/run-gdb.sh      # 43-byte SEND, plain Debug server under gdb
LEN=3593 TAG=gdb-rip GDB_CMD=$PWD/wire/gdb-rip.cmd bash wire/run-gdb.sh
LEN=3593 TAG=gdb-crash GDB_CMD=$PWD/wire/gdb-crash.cmd bash wire/run-gdb.sh
```

## Observed evidence

Logs: `wire/evidence/{client,server}-{safe,attack,fixed}.log` — the canonical
43-byte ASan attack pair has sha256
`f84917307872982b58d7b05c0d97cae1d303ca99c79b3c28d626100508798fa5` (client)
and `76bec3c7217c38eb7530b2c40bbaf334efb28d14cdf5b04b49b95c40686b6a30`
(server) — plus `gdb-attack.log`, `client-gdb.log`, `gdb-rip.log`,
`client-gdb-rip.log`, `gdb-crash.log`, `client-gdb-crash.log`.

1. **Live handshake** — `server-safe.log` and `server-attack.log` contain
   `Accepted client connection`, `RDMA probed: dev=rxe0 gid=1 RoCEv2 qpn=18
   inline=256`, `RDMA activated: qpn=18->17 mtu=4096 rx_depth=24`. The
   vulnerable server is serving the vulnerable sink over real RDMA, not a stub.
2. **Live corruption (rung 3, promoted)** — with a 43-byte completion
   (`wc status=0 byte_len=43`), ASan reports `stack-buffer-overflow`,
   `WRITE of size 43`, frame #1 `socket_t::impl::rdma_recv
   .../transport.cpp:520`, #2 `impl::recv_data` `:567`, #4 `rpc_serve_client
   .../ggml-rpc.cpp:2475`, object `[48,49) 'cmd' (line 2437)` in
   `rpc_serve_client ...:2435`. It also lists adjacent 1-byte `response`
   objects at `[64,65)` and `[80,81)` underflowed by the same write.
3. **Chosen bytes in the live frame (rung 4)** — plain Debug server under gdb,
   stopped in `rpc_serve_client` after `recv_data(&cmd,1)`: `cmd address
   0x7fffffffd007`, bytes at `+0` = `0x0f` (valid DEVICE_COUNT command), `+11`
   = `0x5a`, `+18` = `0x44`, all other bytes through `+42` = `0x41`. The
   markers were set only in the client payload. Chosen bytes land byte-exact in
   adjacent stack bytes of the live server frame.
4. **Control-flow data overwritten (rung 4, same build only)** — `info frame`
   put the saved RIP 3585 bytes above `cmd`. A 3593-byte SEND with eight `0x42`
   bytes at payload offsets 3585–3592 produced `saved RIP slot at &cmd+3585:
   0x4242424242424242` and gdb backtrace frame #1 `0x4242424242424242`. With
   no breakpoint the process took a `SIGSEGV` while unwinding through
   `rpc_server::~rpc_server`; the backtrace again shows
   `0x4242424242424242` as the caller frame. This is overwritten saved-frame
   data, **not** execution at the chosen address. The plain Debug binary
   imports `__stack_chk_fail` (active canary), so even a clean epilogue would
   check the canary before returning through that slot; the observed crash
   comes earlier, in `rpc_server::~rpc_server`.
5. **Fixed control** — the upstream fixed server logs `RDMA recv overrun:
   got=43 rem=1`, stays ASan-clean, and closes the connection; the 1-byte safe
   input on the vulnerable server is ASan-clean. The guard applies on the same
   wire path.

## Rung-5 feasibility attempt (2026-11-23, second wake) — negative

Goal: decide whether a wire-only ROP chain can reach a lab-chosen benign command
without a debugger forcing execution. Bounded to one build variant and one
chain; no external target.

- Baseline replay first: `bash wire/run.sh attack` again produced the live
  ASan `WRITE of size 43` at `transport.cpp:520`, frame #4
  `rpc_serve_client:2475`, `wc byte_len=43`; `rxe0` torn down cleanly.
- Preconditions measured: both Debug binaries are PIE;
  `/proc/sys/kernel/randomize_va_space=2`; `setarch x86_64 -R` works. The
  pinned server imports no `system`/`execve`. libc holds `pop rdi; ret` at
  file offset `0x10f84b`, `system` at `0x58750`, `_exit` at `0xee2c0`.
- Built a labelled lab variant of the same pin with
  `-fno-stack-protector` (`src/llama.cpp-pin-nocanary`, server sha256
  `3fb0d4bff4ae699088cd20f81f575b0399f1fe797ae2ec87979c100ea7599959`,
  no `__stack_chk_fail` import). In this build `rpc_serve_client` saved RIP is
  `&cmd + 761`; with ASLR disabled libc base is `0x7ffff7200000`.
- Added `RDMA_PAYLOAD_FILE` to the wire client so raw bytes can be SENT
  verbatim, and wrappers for a fixed minimal server environment. Drafted a
  self-contained chain (`ret`, `pop rdi; ret`, command string, `system`,
  `pop rdi; ret`, 0, `_exit`) with `rdi` pointing at a command string embedded
  at `&cmd + 1200`. Scripts and payloads are under `wire/`.
- **Why it failed**: an oversized completion always makes `rem` underflow in
  `rdma_recv`, so the function returns false and `rpc_serve_client` takes the
  early `break` at `ggml-rpc.cpp:2476`. The destructor at `:2432` then consumes
  the smashed locals before the epilogue, so the overwritten saved RIP is
  never returned to. Observed outcomes across fixed-environment runs:
  `free(): invalid pointer` in `rpc_server::~rpc_server` (`__n` underflowed
  to `-11` for the `graphs` vector) at 100/761/820-byte SENDs, and a second
  `rdma_recv` memcpy fault when the SEND was 4608 bytes. A 1-byte control is
  clean in the same build. Stack snapshots from both the post-`recv_data` and
  early-`break` points were used as filler; neither preserved the live frame
  well enough for a clean return. No marker file was ever created.
- Rendered harmless variants of that attempt remain lab-only: no command
  executed, no side effect, no valid pointer redirect in those runs. The ROP
  chain bytes in `wire/evidence/rce-payload*.bin` are failed inputs, not a
  working exploit. Those runs left rung 5 UNKNOWN for that payload and build;
  the separate third-wake result below does not retroactively change them.
- The libc `system` frames visible in `wire/evidence/rce-fixed-gdb.log` and
  `rce-diag3.log` are corrupt-stack garbage after the memcpy SIGSEGV
  (`Backtrace stopped: previous frame inner to this frame (corrupt stack?)`),
  not a forged call (W143, DM #2206). No replay of these failed inputs is owed.
- The 4608-byte ROP run that briefly occupied the canonical attack-log names
  is preserved as `wire/evidence/{client,server}-rce-4608.log` (sha256
  `d7a88a75f06aa9cf27206ab5bd3116df2ab6db7e60582f42abab7fe4fbfcab58` and
  `a5151d0954cce44ce26da9cc7ff564e6e3eb992e7cccd78bc17b0fa422bbb1fe`, also
  in `rce-run1.log`). The canonical `{client,server}-attack.log` are the
  witness-verified 43-byte ASan pair from `37da4e6`, restoring the citation
  above after the a76b986 evidence-bundle regression.

## Rung-5 wire-only observation (2026-11-23, third wake) — local, replay owed

This is a separate experiment from the negative above. Its cause is the same
early `break`, but the payload repairs the local object graph with the *same*
unbounded `memcpy`: bytes 1..760 zero every `rpc_server` local so
`~rpc_server` iterates empty containers, and the chain lives entirely in the
1024-byte SEND, stopping before the `sock` shared_ptr at `&cmd+1025`. No
debugger sets registers or memory; execution is driven only by the wire SEND.

- **Conditions (per-build, additive)**: no-stack-protector pin build of the
  vulnerable commit (server sha256
  `3fb0d4bff4ae699088cd20f81f575b0399f1fe797ae2ec87979c100ea7599959`);
  per-process ASLR disabled with `setarch x86_64 -R` (host
  `randomize_va_space=2` is unchanged); fixed minimal environment
  `PATH=/usr/bin:/bin HOME=/home/mesh-home TERM=dumb LINES=24 COLUMNS=80`;
  loopback SoftRoCE `rxe0`, GID index 1, TCP port 53060. In the debugger-free
  run, `&cmd = 0x7fffffffe50f` and libc base `0x7ffff7200000`; the chain uses
  libc offsets `ret 0x28a92`, `pop rdi; ret 0x10f84b`, `system 0x58750`,
  `_exit 0xee2c0` and a command string at `&cmd+900`.
- **Wire input**: `wire/make-repair-payload.py` builds
  `wire/evidence/r5-payload.bin` (1024 bytes, sha256
  `96c92e9f462d43e1744e19093f42bf26a978684364b55ee50c383dcf80ed304e`);
  `MODE=attack ... bash wire/run-repair.sh` sends it verbatim with
  `wire/rdma_attacker`. The client logs `wc status=0 opcode=0 byte_len=1024`.
- **Observed side effect**: three consecutive runs (`r5-run1..3`) each left a
  zero-byte `/tmp/llamarpc2shell-r5-marker`; the three server logs are
  byte-identical (sha256
  `76b75f22a843bc11fe6fc3b1ec9d7881eff98de677973c59d98ccb748c194885`) and so
  are the three client logs (`3e71980ffae9ac3bb9facc51f0b1706b259d15c47e8f53773dc187bc9ae1ab8d`).
  A passive gdb observation of a fourth run (`gdb-r5-system.cmd`, no register
  or memory edits) stopped at `__libc_system` with
  `line=0x7fffffffe863 "touch /tmp/llamarpc2shell-r5-marker"`, then
  `Detaching after vfork from child process …` and `exited normally`:
  `wire/evidence/r5-system-obs.log` (sha256
  `022a306b13595e044931cdda91ee1b2680af4e328061474b2ca05ea67c57b1e5`).
- **Controls**: a 1-byte SEND on the same vulnerable build leaves no marker
  (`wire/evidence/r5-safe.log`); the identical 1024-byte payload against the
  upstream fixed ASan server logs `RDMA recv overrun: got=1024 rem=1` and
  leaves no marker (`wire/evidence/r5-fixed.log`). Both are on the same wire
  path and use the same runner.
- **Limits**: this is one labeled build with ASLR off and a measured absolute
  stack address; no canary-enabled build, no ASLR-on run, no 256 KiB SEND and
  no external target is implied. The earlier negative payloads remain failed
  inputs. Independent witness replay of this specific build, payload,
  environment and marker side effect is required before the grade is
  ESTABLISHED; until then the rung-5 result is **observed locally / PENDING**.

## Independent witness (W142, DM #2193; W143, DM #2206)

W142 rebuilt the vulnerable ASan, plain Debug and fixed ASan servers from
hash-checked pinned sources in a clean `git archive` of `37da4e6`, then replayed
safe, attack, fixed and second-attack runs plus the gdb frame dumps. It saw the
live ASan `WRITE of size 43` at `transport.cpp:520` ← `ggml-rpc.cpp:2475` into
`[48,49) 'cmd'`, the fixed guard log with an ASan-clean fixed server, the clean
1-byte control, byte-exact `0x5a`/`0x44` placement and the `0x4242…` saved-RIP
slot plus the destructor crash (the plain Debug build's canary is active).
Verdict: rungs 3 and 4 ESTABLISHED at the explicitly labeled build scope, no
counterexample; rung 5 UNKNOWN at that time (no rung-5 claim was replayed).
W143 checked a76b986, found the canonical attack logs overwritten by
the failed 4608-byte run, and required the citation fix above; that evidence
bundle regression is repaired here with no grade change and no new replay owed.

## Honest ceiling / preserved negatives

- The `0x4242…` value in the rung-4 probe is not a valid address; that crash is
  in the destructor on corrupted locals before a clean return to that address.
  The second-wake payload failed for the same structural reason. A different,
  third-wake payload did execute a lab-chosen benign command locally with an
  observed marker and controls (section above); it is one ASLR-off,
  no-stack-protector build with a measured absolute stack address, and its
  independent replay is still owed, so the grade is locally observed /
  PENDING rather than ESTABLISHED. No ASLR-on or canary-enabled rung-5 run
  exists.
- The 3585-byte offset is measured in the non-ASan Debug build only; the ASan
  build has different frame layout. Saved-RIP overwrite was not reproduced
  under ASan. The 761-byte offset is measured in the separate no-stack-protector
  build only.
- The 256 KiB upper bound from the advisory was not exercised; the largest
  measured SEND is 4608 bytes in the failed ROP attempt, 3593 bytes in the
  saved-frame probe and 1024 bytes in the locally observed rung-5 run. The
  transport still requires an RDMA-capable path (`AT:P`), here loopback
  SoftRoCE with passwordless device creation.
- Each run used a freshly built pinned tree and a locally generated QP pair;
  QPN values vary by run. Hash and log evidence is in the paths above.
- Chosen-byte placement in the ASan build's adjacent `response` objects was
  inferred from ASan's object map, not directly dumped; the byte-exact dump is
  from the plain Debug build.
