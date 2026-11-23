# frontier brief — llama.cpp ggml-rpc `rdma_recv()` stack overflow (CVE-2026-118375)

Status: **STAGED** by frontier 2026-11-23 under the standing similar-things mandate;
operator admission pending. Brief + live two-pane window are both present.
Target mind: `llamarpc2shell`. Evidence: `lab/frontier/llamarpc2shell/PROVENANCE.md`.

## Verified ground truth (claim, not acceptance)

- Claim source: VulnCheck advisory
  <https://www.vulncheck.com/advisories/llama-cpp-b8841-before-b11865-stack-based-buffer-overflow-via-ggml-rpc-rdma-rdma-recv>,
  published 2026-10-27; CVE **CVE-2026-118375**; credit Sohaib Harraoui (Ostorlab).
- Severity: CRITICAL **9.2**, `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`;
  CWE-787 (out-of-bounds write). The `AV:N` is qualified by `AT:P`: the attack
  needs an RDMA-capable peer/path, not plain HTTP/TCP.
- Affected: llama.cpp `>= b8841, < b11865`. Fixed in **b11865** by upstream commit
  `9a0fde9967fa1a35b6e5dd1f47e1a3648b6fecc1` (PR #30399, "rpc : add bounds check
  in rdma_recv", merged 2026-10-24).
- Claimed primitive: an unauthenticated peer that advertises RDMA capabilities in
  the HELLO message can make `wc.byte_len` up to `RDMA_CHUNK` (256 KiB) be copied
  into the 1-byte stack variable `cmd` in `rpc_serve_client()` — crash or
  "potentially execute code". The advisory's reproduction used SoftRoCE (`rxe0`)
  and ASan.

## Source-bound mechanism (pinned bytes, not advisory prose)

- Vulnerable pin: `620d2225cc436ab0b001e3200e590e3b286ef9ab/ggml/src/ggml-rpc/transport.cpp`,
  sha256 `a5a6774d87398344a09da643de6ac175ad8188c91d8def25f6dad9c0e8957e34`.
  `socket_t::impl::rdma_recv()` at lines 510–528: `size_t got = wc.byte_len;`
  then `memcpy(dst, c->rx_slot(slot), got);` with **no** `got <= rem` check,
  followed by `dst += got; rem -= got;` (unsigned underflow for `got > size`).
- Caller pin: same commit's `ggml/src/ggml-rpc/ggml-rpc.cpp`,
  sha256 `583cf1ee149c5b94c215eca07a293564d1b755427b57b1a7846f0328e724eacd`.
  `rpc_serve_client()` reads the initial command byte with
  `sock->recv_data(&cmd, 1)` at lines **2434** and **2475**.
- Fix pin: `9a0fde99…/ggml/src/ggml-rpc/transport.cpp`,
  sha256 `cd61f2ec3968d2cfc90eb2ea30f9a2762f5160b14a9bddfcd64b11361fc8da43`.
  Patch sha256 `28056890f2a24ffaaa7df4858588529f733cdd092e0f93b7014c68236b0f5736`
  inserts exactly:
  `if (got > rem) { LOG_ERROR("RDMA recv overrun: got=%zu rem=%zu\n", got, rem); c->post_rx(slot); return false; }`
  before the `memcpy`. The published hunk applies to the pinned vulnerable blob
  (verified with `patch --dry-run -F3` on every run).
- Line-number caveat: the advisory links `transport.cpp#L510-L528` and the fix
  hunk header says `@@ -517,6 +517,11 @@`; in the pinned vulnerable blob the
  `memcpy` is at line 520. Raw pinned bytes and the hunk are authoritative.

## Local evidence (harness, rung by rung)

`lab/frontier/llamarpc2shell/harness/run.sh` re-extracts the `rdma_recv` body
verbatim from both pinned blobs on every run, asserts four source hashes, builds
vulnerable/fixed × plain/ASan, and checks 29 assertions. Result: **29 PASS / 0 FAIL**
three consecutive times (`harness/evidence/run5.txt`, `run6.txt`, `run7.txt`)
plus a clean minimal `/tmp` replay with the same trace hash
`d898482a39c65919916750bb28f6151d55e91efb3b56d88e315321c62b09c1b2`.

| Rung | Observed | Evidence |
|---|---|---|
| 1 — trigger | `got=43` into `size=1`: `OOB=42`, `REM_UNDERFLOW=18446744073709551574` (= 1−43 mod 2⁶⁴) | `plain-attack.out` |
| 2 — state failure | `TAIL0=41` (adjacent stack byte overwritten), `POSTED=1`, `RC=0` | `plain-attack.out` |
| 3 — corruption | gcc and clang ASan: `stack-buffer-overflow`, `WRITE of size 43`, frame #1 `socket_t::impl::rdma_recv`, frame object `[32,33) 'cmd'` overflowed at offset 33 | `vuln-gcc-asan.out`, `vuln-clang-asan.out` |
| 4 — scoped impact | attacker-chosen `0x5a` at message offset 11 lands byte-exact at adjacent-stack offset 10; `0x44` at offset 18 lands at offset 17; canary beyond the 43-byte write intact | `plain-attack.out` (`TAIL10`, `TAIL17`, `TAIL43`) |

Controls: fixed slice with the same 43-byte message logs
`RDMA recv overrun: got=43 rem=1`, reposts the receive slot, returns false,
leaves every adjacent byte at the `0xc7` canary, and is ASan-clean; safe input
(`got=1`) on the vulnerable slice returns true with no adjacent-byte overwrite
and is ASan-clean.

## Honest ceiling / preserved negatives

- Rung 4 is **scoped**: chosen bytes land byte-exact in an adjacent synthetic
  stack probe. No saved frame pointer, canary, return address or vtable was
  overwritten in a live process; no pointer control, no ROP, no ASLR bypass,
  no command execution, no remote command execution.
- The staged evidence is a directly-invoked verbatim slice with a stubbed verbs
  environment delivering one crafted completion. No real `rpc_serve_client`
  process, no HELLO handshake, no wire/RDMA packet and no llama.cpp build were
  exercised. The advisory's "up to 256 KiB" and "potentially execute code"
  remain claims at these sizes — only 43 bytes were measured locally.
- `AV:N` is from the advisory vector but the transport is InfiniBand/RoCE,
  gated by `GGML_RPC_RDMA` at build time and `AT:P` at attack time. Whether this
  host's loopback SoftRoCE can carry a crafted completion into a live server is
  **UNKNOWN**: `sudo -n modprobe rdma_rxe` and `sudo -n rdma link add rxe0 type
  rxe netdev lo` both succeeded and showed the link ACTIVE, and the device was
  deleted immediately afterward; no server build or wire client was attempted.
- No prior brief, charter, window or registry entry existed for llama.cpp; the
  candidate is not on the plant's do-not-duplicate or screened-out lists.

## Cheapest experiment to move this up a rung

Build `llama-rpc-server` from pin `620d2225…` with `-DGGML_RPC=ON
-DGGML_RPC_RDMA=ON` and ASan, recreate loopback `rxe0`, connect a raw verbs
client that completes the HELLO/caps exchange, then send a 43-byte RDMA message
for the 1-byte `cmd` read. An ASan `stack-buffer-overflow` in the real server
would promote rung 3 from slice to live process; a benign marker landing in the
observed adjacent frame would make rung 4 unscoped. Only if both hold should a
mind look at control-flow data — never relabel this as RCE without observation.
