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

## Current grade — 04:2xZ (author-only, witness replay owed)

Rung 3 is confirmed both in the verbatim pinned slice and in a live
plant-started `ggml-rpc-server` over loopback SoftRoCE: a 43-byte SEND gives
ASan `stack-buffer-overflow`, `WRITE of size 43`, at `transport.cpp:520` ←
`ggml-rpc.cpp:2475` into the 1-byte `cmd`. Rung 4 is demonstrated in that live
server's frame: chosen `0x5a` at +11 and `0x44` at +18 land byte-exact, and a
3593-byte SEND with eight `0x42` bytes at offsets 3585–3592 puts
`0x4242424242424242` in the saved RIP slot at `&cmd+3585`, shown as backtrace
frame #1 before a `SIGSEGV` during destructor unwinding. That is overwritten
saved-frame data, not execution at the chosen address. The fixed server logs
`RDMA recv overrun: got=43 rem=1`, stays ASan-clean and closes; the 1-byte
safe SEND is clean on the vulnerable server.

No command, shellcode, ROP, ASLR bypass or pointer redirect was executed;
rung 5 is UNKNOWN. The +3585 offset is measured only in the non-ASan plain
Debug build (ASan frame layout differs); the largest SEND is 3593 bytes, so
the advisory's 256 KiB bound stays unmeasured. Each run used a freshly built
pin and its own QP pair (QPNs vary), and `AT:P` still qualifies the advisory's
`AV:N`: this needs an RDMA-capable peer, here loopback SoftRoCE with
passwordless device creation. Exact build hashes, runner commands and raw
logs are in `reports/llamarpc2shell.md`; `wire/evidence/*.log` are tracked,
the provisioned source trees and wire client binary are gitignored.

This is an author report: independent witness replay is still required before
any stronger claim. The staged slice grade above is kept as the historical
baseline, not as the current ceiling. Next useful work: a clean-checkout
witness rebuild of both pins that reruns `wire/run.sh safe|attack|fixed` and
the `wire/run-gdb.sh` frame dump, varying an attacker byte and checking the
saved-frame value. A rung-5 attempt still needs a command, a request-bound
observed side effect, controls and a witness; none was attempted.
