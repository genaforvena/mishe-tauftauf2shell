# PROVENANCE — llamarpc2shell lab (CVE-2026-118375)

Advisories (VulnCheck, GitHub Advisory Database), the upstream PR and the fix
commit were fetched read-only. No external system was probed. No RDMA device
was created or configured; the only socket traffic is a loopback TCP
negotiation inside the harness on 127.0.0.1:46000.

## Pins

- Vulnerable reference: `ggml-org/llama.cpp` commit
  `620d2225cc436ab0b001e3200e590e3b286ef9ab` (the commit linked by the
  advisory). Raw files fetched from that commit:
  - `ggml/src/ggml-rpc/transport.cpp` saved as `src/transport.cpp`, sha256
    `a5a6774d87398344a09da643de6ac175ad8188c91d8def25f6dad9c0e8957e34`.
  - `ggml/src/ggml-rpc/transport.h` saved as `src/transport.h`, sha256
    `5859ae198de5c8df1d7184eb7eca13adab5cf2d5548910052756ad6d0ef53cc7`.
  - `ggml/src/log.h` saved as `src/log.h`, sha256
    `a295b4ba734c10d036d10c733f7c785bfee6296184197e45cb9697045d8d8664`.
- Upstream fix: commit `9a0fde9967fa1a35b6e5dd1f47e1a3648b6fecc1`
  (`rpc : add bounds check in rdma_recv (#30399)`), adding a `got > rem`
  check before the `memcpy` in `rdma_recv`. Released in b11865. The local
  `fix-rdma-recv.patch` (sha256
  `9be2e8de23cb8c9aa1bed9d000a3e3ad59ccbe88b7b6d53fab676d8ceab94987`)
  is that exact upstream hunk with only the path prefixes shortened;
  `patch -p1` applies it to the pinned file.
- Advisory: CVE-2026-118375 / GHSA-pmf8-m38j-h768, VulnCheck 2026-10-27,
  NVD/GHSA 2026-10-28. CWE-787; CVSS 4.0 9.2
  `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`. Affects llama.cpp >= b8841,
  < b11865. Reporter: Sohaib Harraoui (Ostorlab).
- All local file hashes, including the harness and shims, are in
  `pins.sha256` and checked by `sh bootstrap.sh`.

## Harness and exact build commands

`harness.cpp` compiles the **unmodified** pinned `transport.cpp` and drives
its public `socket_t` API: create a loopback server and client, exchange the
24-byte RDMA capability blobs via `get_caps()`/`update_caps()` (which makes
the real transport report `transport=RDMA`), then call
`recv_data(&frame.cmd, 1)` — the same 1-byte stack read that
`rpc_serve_client()` performs for the command byte. A stubbed ibverbs layer
(`shim/infiniband/verbs.h` + the `extern "C"` stubs in `harness.cpp`)
supplies one fake device and one receive completion whose `byte_len` the
harness chooses. The data in the posted receive slot is harness-chosen.

`sh bootstrap.sh` checks pins, copies the pinned source into `vuln-src/` and
`fixed-src/`, applies the upstream fix hunk to `fixed-src/`, then runs
exactly (with `CXX=${CXX:-g++}`):

```
g++ -std=c++17 -DGGML_RPC_RDMA -I shim -I src -O0 -g -fno-omit-frame-pointer -fsanitize=address harness.cpp vuln-src/transport.cpp -o vuln-asan
g++ -std=c++17 -DGGML_RPC_RDMA -I shim -I src -O0 -g -fno-omit-frame-pointer -fsanitize=address harness.cpp fixed-src/transport.cpp -o fixed-asan
g++ -std=c++17 -DGGML_RPC_RDMA -I shim -I src -O0 -g -fno-omit-frame-pointer harness.cpp vuln-src/transport.cpp -o vuln-plain
g++ -std=c++17 -DGGML_RPC_RDMA -I shim -I src -O0 -g -fno-omit-frame-pointer harness.cpp fixed-src/transport.cpp -o fixed-plain
```

`sh run-all.sh` runs all variants with attack (`byte_len=64`), safe
(`byte_len=1`) and steering fill-byte arguments; raw output is in the
gitignored `evidence/` directory and the summary in `replay.log`.

## Observed bytes (2026-11-24T12:49Z)

- `./vuln-asan attack`: ASan `stack-buffer-overflow`, `WRITE of size 64`,
  0 bytes past the local 49-byte `frame` in `main`. Frames:
  `memcpy` -> `socket_t::impl::rdma_recv()` `transport.cpp:520` ->
  `recv_data()` `:567` -> `recv_data()` `:671` -> harness. rc 1.
- `./vuln-plain attack`: `cmd=0x41 after0=0x42 after1=0x43 after7=0x49`:
  chosen bytes land at chosen stack offsets past the 1-byte command byte.
- Steering: `./vuln-plain attack 48` writes `0x48` at `cmd`, `after0`,
  `after1`, `after7`; `./vuln-plain attack 5a` writes `0x5a` at the same
  offsets. Fixed builds with the same inputs leave `cmd=0x00` and
  `after*=0xcc` and return `recv_data=0`.
- `./vuln-asan safe`, `./vuln-plain safe`, both fixed variants with attack
  and safe inputs: no ASan report, canaries intact, safe `recv_data=1`.
- `sh run-all.sh` -> 17 PASS / 0 FAIL, log `replay.log`.

## Known limits / negatives

- No real RDMA device, SoftRoCE link, HELLO capability advertisement,
  CQ event from a peer, or live `rpc-server` process. The `wc.byte_len`
  value is supplied by a harness stub, not by a wire peer. The vulnerable
  `memcpy`, the bounds-free loop, the capability exchange and the public
  `recv_data()` call path are the real pinned upstream code.
- The oversized completion is followed by a harness-generated error
  completion so `rem -= got` underflow cannot spin the real `rdma_poll()`
  loop; that is a lab control, not a claim about a real peer's behaviour.
- No pointer/IP/command control, no allocator-metadata corruption, no rung 5.
  The fixed control is the real upstream fix commit, not a reconstruction.
- No independent witness verdict yet.
