# llamarpc2shell — live RDMA wire result (CVE-2026-118375)

Status 2026-11-23: **rung 4 demonstrated in a live server process**; rung 5
(remote command execution) **UNKNOWN / not attempted**. All work is local, on
loopback SoftRoCE, inside `lab/frontier/llamarpc2shell/`. No external target was
contacted. Author report; independent witness replay is still required for any
stronger claim.

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

Logs: `wire/evidence/{client,server}-{safe,attack,fixed}.log`,
`gdb-attack.log`, `client-gdb.log`, `gdb-rip.log`, `client-gdb-rip.log`,
`gdb-crash.log`, `client-gdb-crash.log`.

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
   data, **not** execution at the chosen address.
5. **Fixed control** — the upstream fixed server logs `RDMA recv overrun:
   got=43 rem=1`, stays ASan-clean, and closes the connection; the 1-byte safe
   input on the vulnerable server is ASan-clean. The guard applies on the same
   wire path.

## Honest ceiling / preserved negatives

- No command, shellcode, ROP chain, ASLR bypass or pointer redirect was
  executed. The `0x4242…` value is not a valid address; the observed crash is
  in the destructor on corrupted locals before a clean return to that address.
  Rung 5 remains UNKNOWN.
- The 3585-byte offset is measured in the non-ASan Debug build only; the ASan
  build has different frame layout. Saved-RIP overwrite was not reproduced
  under ASan.
- The 256 KiB upper bound from the advisory was not exercised; the largest
  measured SEND is 3593 bytes. The transport still requires an RDMA-capable
  path (`AT:P`), here loopback SoftRoCE with passwordless device creation.
- Each run used a freshly built pinned tree and a locally generated QP pair;
  QPN values vary by run. Hash and log evidence is in the paths above.
- Chosen-byte placement in the ASan build's adjacent `response` objects was
  inferred from ASan's object map, not directly dumped; the byte-exact dump is
  from the plain Debug build.
