# frontier brief — llamarpc2shell (CVE-2026-118375)

## Ground truth

- Claim: llama.cpp from b8841 up to (excluding) b11865 lets an unauthenticated
  RPC peer overflow the server stack through the ggml-rpc RDMA transport.
  A peer advertising RDMA in its HELLO caps can make `rdma_recv()` copy up to
  256 KiB into the 1-byte command variable used by `rpc_serve_client()`.
- Sources (read-only): VulnCheck 2026-10-27 (CVE-2026-118375, CWE-787, CVSS
  4.0 9.2 `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`), GHSA-pmf8-m38j-h768,
  upstream PR `ggml-org/llama.cpp#30399`, fix commit `9a0fde9`, release
  b11865. Reporter: Sohaib Harraoui (Ostorlab).
- Affected: >= b8841, < b11865. Fixed in b11865 by a five-line upstream
  commit — an unusually clean vendor fix to use as a control.
- Primitive claimed: chosen bytes at chosen offsets past a 1-byte stack
  variable, reached from a network-facing server handshake.

## Source-bound mechanism

In pinned `ggml/src/ggml-rpc/transport.cpp` (commit `620d222`),
`socket_t::impl::rdma_recv(void * data, size_t size)` polls a completion and
does `memcpy(dst, c->rx_slot(slot), got)` where `got = wc.byte_len` comes from
the peer's RDMA send, while `rem` is the caller's requested size. There is no
`got > rem` check. `rpc_serve_client()` calls `sock->recv_data(&cmd, 1)` for
the command byte; through `recv_data()` that reaches `rdma_recv(data, 1)`, so
any completion with `byte_len > 1` writes past `cmd`. The loop then does
`rem -= got`, underflowing `size_t`.

The upstream fix adds, before the copy:

```c
if (got > rem) {
    LOG_ERROR("RDMA recv overrun: got=%zu rem=%zu\n", got, rem);
    c->post_rx(slot);
    return false;
}
```

The fixed control here is that exact upstream hunk, not a reconstruction.

## Local experiment

`lab/frontier/llamarpc2shell/` pins the upstream transport source and drives
the **unmodified** `transport.cpp` through its public `socket_t` API on a
loopback negotiation socket. A stubbed ibverbs layer supplies the fake device
and the completion; no RDMA device or host network change is used.

- Rung 1: deterministic; a 64-byte completion for a 1-byte read.
- Rung 2: `rem=1`, `got=64` -> 63 bytes past the destination; `rem` underflows.
- Rung 3: ASan `stack-buffer-overflow`, `WRITE of size 64`, 0 bytes past the
  local frame, frames `rdma_recv()` `transport.cpp:520` -> `recv_data()`
  `:567` -> `recv_data()` `:671`; rc 1.
- Byte control: chosen `0x41, 0x42, ...` land at `cmd`, `after0`, `after1`,
  `after7`; steering fills `0x48` and `0x5a` land at the same offsets. Upstream
  fixed build rejects the overrun (`recv_data=0`) with canaries intact; safe
  `byte_len=1` is clean in both. `sh run-all.sh` -> 17 PASS / 0 FAIL.
- Exact pins, commands, limits: `lab/frontier/llamarpc2shell/PROVENANCE.md`.

## Rung-4 feasibility and ceiling

Rung 3 is confirmed in the real pinned upstream transport with the real
bounds-free `memcpy` and real public call path; rung 4 is PARTIAL: chosen bytes
at chosen stack offsets, with the completion and receive data synthesized by
a harness stub. No real RDMA device or HELLO advertisement, no live
`rpc-server` process, no peer-generated wire completion, no pointer/IP/command
control, no allocator metadata, no rung 5. The advisory's unauthenticated
remote path remains UNKNOWN here, not a pass.

## Cheapest next experiment

Bring up a lab-local SoftRoCE (`rxe`) device bound to loopback — this needs an
explicit host-network change, so it was NOT performed under this lab's
isolation rules — build the pinned rpc-server with `GGML_RPC_RDMA`, and drive
the HELLO/caps negotiation plus an oversized RDMA SEND from a second local
process. Observe the same ASan `rdma_recv` frame and canary bytes across the
real verbs path, with the b11865 build and a safe 1-byte send as controls.
Then request independent witness replay before any stronger claim.
