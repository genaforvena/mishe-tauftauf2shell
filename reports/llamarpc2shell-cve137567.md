# llamarpc2shell — CVE-2026-137567, TCP `RPC_CMD_COPY_TENSOR` heap write

Distinct lane. This is **not** CVE-2026-118375 (`rdma_recv` stack write) and does
not change that lane's witness verdicts. All tests were loopback-only. W314
independent witness replay (04:18–04:21Z) returned **ESTABLISHED AS LABELED
at the labeled lab-build scope**, no grade change, NO r5; detail
`.mishe-tauftauf/artifacts/witness-w314-llamarpc137567/detail.md`.

## Claim (not acceptance)

NVD published 2026-11-26 (status Awaiting Analysis):
<https://nvd.nist.gov/vuln/detail/CVE-2026-137567>. llama.cpp `b11450` before
`b12658`, CWE-787, CVSS 3.1 9.8
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Claimed path: an unauthenticated peer
learns buffer bases with `BUFFER_GET_BASE`, then sends `RPC_CMD_COPY_TENSOR`
with a destination pointer below the buffer base and a zero-element destination
tensor, writing to an arbitrary heap address. Fix: commit
`03813c56e47f6cd7a9b9bc2ad8edcebed88ce342` / release b12658
(<https://github.com/ggml-org/llama.cpp/pull/32651>). Unlike the RDMA lane,
this path is plain TCP: no InfiniBand/RoCE peer or `AT:P` condition.

## Source-bound mechanism (pinned bytes, not advisory prose)

- Vulnerable `ggml-rpc.cpp` at b11450 (sha256
  `c599171b0df40a3ecb2759b3a8d0ed1c8890b0c5694be993156dd6dd07f62181`):
  `rpc_server::deserialize_tensor()` (lines 1554–1607) applies the destination
  bounds check only when `ggml_nelements(result) > 0` (line 1584), then
  unconditionally installs the wire-supplied `tensor->data` (line 1605).
  A tensor with all `ne[] = 0` therefore skips the lower-bound check while
  retaining an arbitrary `data` pointer and a valid `buffer` handle.
- `rpc_server::copy_tensor()` (lines 1911–1950) checks only the upper bound
  `dst_data + src_size > dst_base + dst_buf_sz` (line 1934). A `dst_data`
  **below** `dst_base` passes whenever `src_size` is small enough. The write at
  line 1949 reaches `ggml_backend_cpu_buffer_cpy_tensor()`
  (`ggml-backend.cpp:2488–2492`), which calls
  `memcpy(dst->data, src->data, ggml_nbytes(src))` with no layout assertion.
- Fixed b12658 `ggml-rpc.cpp` (sha256
  `7b4f1a834eee8d34030e7af0c3c5245c60e7a2cfc57ef45cf6549155c91685a7`)
  replaces the check with `rpc_check_region(__func__, dst, 0, ggml_nbytes(src))`
  in `copy_tensor()` (lines 2094–2116), which rejects the same request.
  Fix patch sha256
  `ebe53f862f7ea3a619b18db091cf00654bbecf5251d727fc125afc05adfcb3a6`.

## Live loopback experiment

Raw TCP client `lab/frontier/llamarpc2shell/heapwrite/tcp_client.cpp` (sha256
`a6b076debbcb16be9d12bc94db00c16877a4c0ed2297ffa588f9548d5d44f1f6`) performs
the real wire protocol, with no RDMA and no synthetic stubs:

1. `RPC_CMD_HELLO` (14) with 24 zero capability bytes; response is version 8.0.0.
2. `RPC_CMD_ALLOC_BUFFER` (0) twice, device 0, size 4096: buffer **B** first,
   then buffer **A**. `RPC_CMD_BUFFER_GET_BASE` (3) on each handle returns the
   live addresses; in the plain runs `B_base < A_base` with a 0x1040 gap.
3. `RPC_CMD_SET_TENSOR` (6) loads 16 chosen bytes
   `414243445a5a444411223344eeeeff00` into `A_base + 64` via a 4-element F32
   source tensor.
4. `RPC_CMD_COPY_TENSOR` (9) sends a source tensor on A and a **zero-element**
   destination tensor whose `buffer` is A's handle but whose `data` is
   `B_base + 64` = `A_base - 0x1000`, i.e. 4096 bytes below A's base and inside
   live buffer B. The vulnerable server replies `result=1`.
5. `RPC_CMD_GET_TENSOR` (8) on B's own handle at the same address reads the
   16 bytes back over the wire.

Servers: vulnerable plain Debug sha
`ed9972c82e7ed23443fcec431b83c8a0b8214c5d22bc2263b685afa7c510cc50`;
vulnerable ASan sha
`3c5b77fce00cb30ac9f0ae8ac3ca915e9100a56241e3da23c0b33cb165781180`;
fixed plain Debug sha
`29d6e4236fb57b5e2ff3ef2aa3f7dc6c42b85577cce0814ebd521ec9616367bd`.
Client binary sha `bb785b25e7185f3eebf694259a823536a4d65583bbda73825c81bba41c12cc76`;
runner sha `d8ac0d409fa0139996d8623f657def390b03ca0a3b3b41a81ba3510c504de597`.
Build recipe, source tarball hashes and all log hashes are in
`lab/frontier/llamarpc2shell/heapwrite/PROVENANCE.md`.

| Observation | Evidence (under `heapwrite/evidence/`) |
|---|---|
| 3/3 plain runs: `copy result=1`, `readback=414243445a5a444411223344eeeeff00`, `MATCH chosen bytes`; target measured 0x1000 below A's base | `rb3-client.log`, `rb4-client.log`, `rb5-client.log` (sha `bb911111…`, `288bb8d2…`, `25b36a00…`) |
| Vuln ASan, target `A_base - 16`: `heap-buffer-overflow`, `WRITE of size 16`, “16 bytes before 4096-byte region”, frames `memcpy` ← `ggml_backend_cpu_buffer_cpy_tensor` ← `ggml_backend_buffer_copy_tensor` ← `rpc_server::copy_tensor` (`ggml-rpc.cpp:1949`) ← `rpc_serve_client` (`:2569`) | `asan1-server.log` (sha `3b619aead806d83fbd100719b6bfe10c7dfefd953384ac1650c566e174d2c887`) |
| Fixed b12658, same wire request: `[copy_tensor] region (offset=0, span=16) out of tensor '' bounds (0)` then `[copy_tensor] invalid tensors`; no copy, no readback, connection closed | `fixed1-server.log` (sha `cf0f2f22…`) and `fixed1-client.log` |
| Safe input on vulnerable build: in-bounds target `A_base + 128`, copy and wire readback both succeed with the same chosen bytes | `safe2-client.log` (sha `6a234a76…`) |

Earliest two attempts (`rb1`, `rb2`) failed because the client used opcodes 8/7
for COPY/GET; the pinned enum assigns `GET_TENSOR=8`, `COPY_TENSOR=9`. Those
logs are preserved locally as a negative/debugging record, not as evidence.

## Grade and limits

- **Witness W314 ESTABLISHED AS LABELED at the labeled lab-build scope**:
  rung 3 (live ASan heap out-of-bounds write in the real server) and rung 4
  (attacker-chosen bytes land byte-exact in a live adjacent ggml buffer and
  are read back through a second wire command), for this distinct CVE.
  Fresh builds (3/3 wire readbacks matched) and fixed/safe controls were
  replayed; binary hashes differ by path-dependent debug info, so the author
  layout is not claimed as an invariant. No grade change, NO r5.
- No pointer word, saved frame, vtable or control-flow data was overwritten;
  no command, side effect or RCE was attempted or observed. No arbitrary
  address was read: readback used a genuine second buffer handle owning the
  target. `BUFFER_GET_BASE` supplies real server addresses; no address leak
  beyond the protocol's ordinary response was measured.
- The below-base write's success depends on allocation order (B allocated
  before A) and on the 4096-byte handle sizes used here. Addresses change per
  process and per build; the target is recomputed from the two wire-returned
  bases on every run. No external or deployment target was contacted.

## Reproduction

```bash
R=lab/frontier/llamarpc2shell/heapwrite
PORT=53082 MODE=readback TAG=rb4 bash $R/run.sh          # plain vulnerable
PORT=53083 MODE=asan TAG=asan1 SERVER=$R/build-vuln-asan/bin/ggml-rpc-server bash $R/run.sh
PORT=53084 MODE=readback TAG=fixed1 SERVER=$R/build-fixed/bin/ggml-rpc-server bash $R/run.sh
PORT=53085 MODE=safe TAG=safe2 bash $R/run.sh
```

The runner starts the server on 127.0.0.1 only, captures both logs under
`heapwrite/evidence/`, and kills the server on exit. Exact cmake flags and
source hashes: `heapwrite/PROVENANCE.md`.
