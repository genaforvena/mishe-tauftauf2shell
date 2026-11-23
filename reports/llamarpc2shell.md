# llamarpc2shell — live RDMA wire result (CVE-2026-118375)

Status 2026-11-23: **rung 4 demonstrated in a live server process**; rung 5
(remote command execution) **witness-ESTABLISHED on a labeled lab build** —
one no-stack-protector pin, `setarch -R` ASLR off, fixed minimal environment,
measured absolute stack address, benign `touch` side effect; not a deployment
or ASLR-on result. All work is local, on loopback SoftRoCE, inside
`lab/frontier/llamarpc2shell/`. No external target was contacted. Independent
witness W142 (DM #2193) replayed the rung-3/rung-4 claim from a clean archive
of `37da4e6` with its own rebuilt pins and returned ESTABLISHED at the labeled
build scope; witness W148 (DM #2372) replayed the rung-5 claim from a clean
archive of `bc9cc09` with its own rebuilt pins and returned ESTABLISHED at the
same labeled scope. A bounded wire-only ROP attempt is recorded as a negative
below; it is not retired by the later rung-5 observation.

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

## Rung-5 wire-only observation (2026-11-23, third wake) — witness-ESTABLISHED at labeled build scope

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
  inputs. Independent witness W148 (DM #2372) replayed this exact claim from a
  clean archive and returned ESTABLISHED at this scope; see below. The absolute
  `cmd` address is build-path and environment specific — a new build must
  re-measure it and regenerate the payload before it can inherit this verdict.

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

## Independent witness W148 — rung-5 replay (DM #2372)

W148 replayed the rung-5 claim (DM #2315, commit `9947231`) from a clean
`git archive HEAD` (`bc9cc09`) into `/tmp/w148-llama`, re-hashing the pinned
`transport.cpp` to `a5a6774d…e8957e34`. It rebuilt the no-canary Debug server
(sha `f90e1b929…d388a`; differs from our `3fb0d4bf…7599959` only in
path-dependent debug strings, no `__stack_chk_fail` import) and the upstream
fixed ASan server from `9a0fde99` (transport `cd61f2ec…8da43`).

- In W148's build, gdb measured `cmd=0x7fffffffe55f`, `rbp=0x7fffffffe858`
  (saved-RIP delta +761), libc base `0x7ffff7200000`; under the same gdb
  environment our binary measured `e4cf`, and our debugger-free `e50f` is
  +0x40, so its build predicted a debugger-free `e59f`. A regenerated payload
  at `e59f` gave 3/3 attacks with `client_rc=0` and a fresh marker; logs differ
  only in QPN/psn.
- Exact-claim replay with our hash-matched binary and the committed payload
  `96c92e9f…304e` also made a fresh marker; server/client logs, normalized
  only for QPN/psn and payload path, are byte-identical to `r5-run1`
  (`a957ca3f…606f` server, `4985bf2f…f4c` client).
- Countercheck: changing only the wire string at offset 900 to
  `touch /tmp/w148-witness-marker` created that file and no default marker.
  Passive `break system` using our `gdb-r5-system.cmd` (no register or memory
  writes) stopped with `$rdi` = the wire string
  `touch /tmp/llamarpc2shell-r5-marker`, detached after vfork, exited normally,
  marker present.
- Controls: a 1-byte SEND left no marker; its fixed ASan build with the
  1024-byte SEND logged `RDMA recv overrun: got=1024 rem=1`, no marker; three
  ASLR-on runs left no marker; one extra server environment variable (stack
  shift) left no marker. Our committed `e50f` payload against its different-path
  build left no marker — expected absolute-address sensitivity, not a
  counterexample.

Verdict: rung 5 **ESTABLISHED** at the explicitly labeled lab-build scope
(no-stack-protector pin, `setarch -R` ASLR off, fixed minimal environment,
loopback `rxe0`, measured absolute stack address, benign `touch`). No repair
owed. Limits preserved: one build per replay, no wire-derived address or
image, no ASLR-on or canary-enabled command, no external target. Earlier
negatives untouched.

## Honest ceiling / preserved negatives

- The `0x4242…` value in the rung-4 probe is not a valid address; that crash is
  in the destructor on corrupted locals before a clean return to that address.
  The second-wake payload failed for the same structural reason. A different,
  third-wake payload did execute a lab-chosen benign command with an observed
  marker and controls (section above); W148 replayed it independently and
  rung 5 is ESTABLISHED at that explicitly labeled lab-build scope (ASLR off,
  no stack protector, measured absolute stack address, benign `touch`). A
  canary-enabled variant is a measured negative (fifth wake below); no ASLR-on
  rung-5 run exists.
- The 3585-byte offset is measured in the non-ASan Debug build only; the ASan
  build has different frame layout. Saved-RIP overwrite was not reproduced
  under ASan. The 761-byte offset is measured in the separate no-stack-protector
  build only.
- The advisory's 256 KiB upper bound was exercised on the wire in a fourth
  wake: a 262144-byte SEND gives `wc.byte_len=262144` and faults the vulnerable
  process (`Segmentation fault (core dumped)` from the runner), with no marker.
  The fixed server logs `RDMA recv overrun: got=262144 rem=1` and stays up.
  That is a process-fault observation on the lab build, not a larger control
  primitive: no chosen bytes, pointer control or command at that size. The
  transport still requires an RDMA-capable path (`AT:P`), here loopback
  SoftRoCE with passwordless device creation.
- Each run used a freshly built pinned tree and a locally generated QP pair;
  QPN values vary by run. Hash and log evidence is in the paths above.
- Chosen-byte placement in the ASan build's adjacent `response` objects was
  inferred from ASan's object map, not directly dumped; the byte-exact dump is
  from the plain Debug build.

## 256 KiB SEND upper bound (2026-11-23 fourth wake)

Bounded wire-only measurement of the advisory's largest claimed copy. The
existing runner was reused unchanged with a 262144-byte zero-filled payload
(first byte `0x0f`, same as the 1024-byte rung-5 payload) generated locally:
`wire/evidence/bulk256k-payload.bin` sha256
`cc717bb7492c6d96c060e42c9ca9149616981cfb0c5785568287c1d16446d164`.
Both runs used loopback `rxe0`, port 53060, `setarch x86_64 -R` and the fixed
minimal environment of the rung-5 run; the client reported
`send wc status=0 opcode=0 byte_len=262144 wr_id=0 inline=0` in each.

- Vulnerable no-stack-protector server (sha `3fb0d4bf…7599959`): the runner
  reported `Segmentation fault (core dumped)`; no marker. Server stdout ends at
  `RDMA activated`, so its hash
  (`wire/evidence/bulk256k.log`, `76b75f22…194885`) matches the earlier r5
  server logs. Client: `wire/evidence/client-bulk256k.log` (`74613168…36d813`).
- Upstream fixed ASan server (sha `31dbd386…4c18df`): no crash, no marker,
  `RDMA recv overrun: got=262144 rem=1`, `Client connection closed`.
  Server: `wire/evidence/bulk256k-fixed.log`
  (`a75b3cc9…247bfc3b`); client: `wire/evidence/client-bulk256k-fixed.log`
  (`d5cef9f8…45adffc7a52`).

Command shape (from the repo root):
`MODE=attack TAG=bulk256k RDMA_PAYLOAD_FILE=$PWD/lab/frontier/llamarpc2shell/wire/evidence/bulk256k-payload.bin bash lab/frontier/llamarpc2shell/wire/run-repair.sh`,
then the same with `SERVER=$PWD/lab/frontier/llamarpc2shell/src/llama.cpp-fixed-asan/bin/ggml-rpc-server` and `TAG=bulk256k-fixed`.
This closes the "largest SEND 4608 bytes" gap; it does not change any grade.
No core file was retained; no independent replay is owed for this observation
because it adds no new primitive.

## Canary-enabled build: measured negative (2026-11-23 fifth wake)

The open question from the third wake — does the wire-only r5 chain survive a
stack-protector build? — was tested with the same runner and the same
loopback `rxe0:53060`, `setarch x86_64 -R` and fixed minimal environment.
Server: vulnerable pin plain Debug build, sha256
`dc368c89eac8a56f3358ccc4768069c235d76a0743404a34763ffe111c3d7eb7`
(the build that imports `__stack_chk_fail`), not the no-canary build.

- `MODE=measure` with that server (43-byte SEND, `gdb-measure-noaslr.cmd`)
  reported `cmd address 0x7fffffffda97`, `saved rip slot 0x7fffffffe898`
  (`&cmd + 3585`, the same offset as the earlier plain Debug layout),
  `server.buffers &cmd + 105`, `sock &cmd + 3721`, libc base
  `0x7ffff7200000`: `wire/evidence/canary-layout1.log`
  (`3fcdbae9dc7b5919a02bd3377bc31c3f7931ce3c346432fe414ece13924c8ba4`).
- `wire/make-repair-payload.py` gained optional `--saved-rip`, `--string-off`,
  `--length` and `--command` flags; its default invocation still reproduces
  `wire/evidence/r5-payload.bin` byte-for-byte (sha256
  `96c92e9f462d43e1744e19093f42bf26a978684364b55ee50c383dcf80ed304e`).
  The variant payload `wire/evidence/r5-canary.bin` (3716 bytes, sha256
  `4e0943a748caf44ef19644992d11ceb9cf57517512f22ceec13fdf081fbd32df`)
  carries the chain at `&cmd + 3585`, a command string at `+3660`, and stops
  before `sock` at `+3721`. The debugger-free `&cmd` was taken as the gdb value
  plus the previously measured 48-byte debugger-environment delta; the canary
  result does not depend on that address being exact.
- `MODE=attack` with that payload: client `wc status=0 byte_len=3716`; server
  printed `*** stack smashing detected ***` and aborted; the benign
  `/tmp/llamarpc2shell-canary-marker` was absent. Logs:
  `wire/evidence/canary-attack1.log`
  (`92519f51622dd33fc8688c74ade657accc055268a771798cf72df841b485b28b`) and
  `client-canary-attack1.log`
  (`07c807484aec102c31b4200fa1211f6d13a4db923517e4616fa9035b03448251`).
- Control: a 1-byte SEND on the same canary build closed cleanly
  (`Client connection closed`, no abort, no marker):
  `wire/evidence/canary-safe.log`
  (`095e0e6adba7c8402c5c631b3c32b6144643bfc59139b493448b5980c2642329`).

Interpretation is bounded: on this build, ASLR-off, with a wire-only SEND that
reaches the saved-frame slot, the active canary aborts before any command runs.
The abort site was not source-bound by a debugger here. This does not negate
the no-canary marker observation, does not establish ASLR-on behavior, and
changes no grade. No independent replay is owed for a negative with no new
primitive.
