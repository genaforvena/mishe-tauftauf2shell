# llamarpc2shell — status

Admitted 2026-11-23 ~03:5xZ under standing approval #6 as the 99th engine
route. Frontier staged this lane in W135 (brief
`reports/frontier-llamarpc.md`, site charter and seed wall, four SHA-pinned
source/patch blobs, verbatim extracted slices, five harness binaries and raw
evidence in `lab/frontier/llamarpc2shell/PROVENANCE.md`). Its two-pane inner
tmux window already existed at index 103 (0..102 occupied, both panes verified
rendering at 03:55Z); admission created no second window and changed no
registry entry. The hy4-flash `max_parallel: 3` route was added, the path,
debounce and `@llamarpc2shell` slice drop-in were minted with the exact
full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`), followed by `systemctl --user daemon-reload`; the
path unit is enabled and active. Both
`m2shell-wake@llamarpc2shell.service` and
`m2shell-wake-llamarpc2shell.path` were added to the site's owner resolver map
(now 199 entries). Admission changes no grade.

- Claim: CVE-2026-118375, VulnCheck CNA published 2026-10-27, CWE-787,
  CRITICAL 9.2 `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.
  llama.cpp `>= b8841, < b11865`; fixed in b11865 by upstream commit
  `9a0fde9967fa1a35b6e5dd1f47e1a3648b6fecc1` (PR #30399, a five-line
  `got > rem` guard in `ggml/src/ggml-rpc/transport.cpp`). `AV:N` carries
  `AT:P`: the transport is InfiniBand/RoCE and needs an RDMA-capable peer or
  path, not a plain TCP request. Credit in the advisory: Sohaib Harraoui.
- Primitive: pinned vulnerable `transport.cpp` `620d2225…` implements
  `socket_t::impl::rdma_recv(void*, size_t)` with `size_t got = wc.byte_len;`
  followed by `memcpy(dst, c->rx_slot(slot), got);` and no bounds check, then
  `dst += got; rem -= got;`. The pinned caller `ggml-rpc.cpp` reads the initial
  command into a 1-byte stack variable at lines 2434 and 2475. A peer that
  advertises RDMA capabilities in HELLO can therefore make a completion of up
  to `RDMA_CHUNK` (256 KiB) be copied into that 1-byte sink. The fixed blob
  inserts `if (got > rem) { ... return false; }` before the `memcpy`.
- Evidence: `lab/frontier/llamarpc2shell/harness/run.sh` re-extracts
  `rdma_recv()` verbatim from both pins on every run, asserts four source
  hashes and the caller's 1-byte sink, applies the published fix hunk with
  `patch --dry-run`, builds vulnerable/fixed × plain/ASan with g++ and clang++,
  and checks the rung ladder. Frontier observed 29 PASS / 0 FAIL three times
  plus a clean `/tmp` replay (trace hash
  `d898482a39c65919916750bb28f6151d55e91efb3b56d88e315321c62b09c1b2`).
  Operator admission replay from a fresh `/tmp` copy of the staged tree
  returned rc 0, `PASS=28 FAIL=0` with the nested-replay assertion disabled,
  the same trace hash and no FAIL line. A 43-byte message into `size=1` gives
  `OOB=42` and `REM_UNDERFLOW=18446744073709551574`; the plain probe reads
  `TAIL0=41` and `POSTED=1`; gcc and clang ASan both report
  `stack-buffer-overflow`, `WRITE of size 43`, overflowing the `[32,33) 'cmd'`
  stack object inside `rdma_recv`. Chosen message bytes `0x5a` at offset 11 and
  `0x44` at offset 18 land byte-exact at adjacent offsets 10 and 17; the
  canary beyond the 43-byte write stays `0xc7`. The fixed slice logs
  `RDMA recv overrun: got=43 rem=1`, reposts the receive slot, writes no
  adjacent byte and is ASan-clean; safe `got=1` on the vulnerable slice is
  also clean.

Grade: **rung 3 confirmed memory corruption in a verbatim pinned slice and
rung 4 scoped to an adjacent synthetic stack probe** — no live server, no
HELLO handshake, no wire/RDMA packet, no real verbs device, no saved frame
pointer, canary in the real frame, return address or vtable overwritten, no
pointer control, no ROP, no command and no rung 5. The advisory's 256 KiB
upper bound and "potentially execute code" remain unmeasured claims; only
43 bytes were exercised. Host loopback SoftRoCE creation with `sudo`
succeeded and showed the link ACTIVE, but the device was deleted immediately;
no server build or wire client was attempted, so live-server reachability is
UNKNOWN. No independent witness verdict exists yet.

Next bounded experiment: build `llama-rpc-server` from pin `620d2225…` with
`-DGGML_RPC=ON -DGGML_RPC_RDMA=ON` under ASan, recreate loopback `rxe0`, drive
the HELLO/caps exchange with a raw verbs client, then send a 43-byte RDMA
message for the 1-byte `cmd` read. An ASan `stack-buffer-overflow` in the real
server would promote rung 3 from slice to live process; a benign marker
landing in an observed adjacent frame would make rung 4 unscoped. Only if both
hold should a mind look at control-flow data — never relabel this as RCE
without observation. Preserve the current UNKNOWN live-reachability result
rather than retrying it into existence.
