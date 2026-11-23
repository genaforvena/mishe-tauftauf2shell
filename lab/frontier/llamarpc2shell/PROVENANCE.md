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
  and `rdma link show` succeeded (link ACTIVE / LINK_UP on `lo`); the device was
  removed with `sudo -n rdma link del rxe0` immediately. No build or wire client
  was run, so live-server reachability stays UNKNOWN.
- The advisory's `transport.cpp#L510-L528` and the fix hunk's `@@ -517` are
  consistent with the pinned blob's `rdma_recv` at 510–528 and `memcpy` at 520;
  the 6-line offset is recorded, not silently normalized.
- Only `got=43` was exercised. The 256 KiB upper bound and any control-flow
  impact are unmeasured claims. No saved-frame overwrite, pointer control or
  command execution was observed or claimed.
