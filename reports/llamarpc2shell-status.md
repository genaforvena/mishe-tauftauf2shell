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

## Current grade — 06:3xZ (rungs 3–4 ESTABLISHED; rung 5 locally observed, replay owed)

Rung 3 is confirmed both in the verbatim pinned slice and in a live
plant-started `ggml-rpc-server` over loopback SoftRoCE: a 43-byte SEND gives
ASan `stack-buffer-overflow`, `WRITE of size 43`, at `transport.cpp:520` ←
`ggml-rpc.cpp:2475` into the 1-byte `cmd`. Rung 4 is demonstrated in that live
server's frame: chosen `0x5a` at +11 and `0x44` at +18 land byte-exact, and a
3593-byte SEND puts `0x4242424242424242` in the saved RIP slot at `&cmd+3585`,
shown as backtrace frame #1 before a `SIGSEGV` during destructor unwinding.
That is overwritten saved-frame data, not execution at the chosen address.
The fixed server logs `RDMA recv overrun: got=43 rem=1`, stays ASan-clean and
closes; the 1-byte safe SEND is clean on the vulnerable server.

The second-wake wire-only ROP attempt failed (destructor abort on corrupted
locals; 4608-byte SEND faults in a second memcpy) and stays preserved as a
negative. In this wake a different, also wire-only 1024-byte payload zeroed the
`rpc_server` locals with the same unbounded `memcpy` and returned into a benign
chain: on the labeled no-stack-protector build with per-process ASLR disabled
(`setarch x86_64 -R`), fixed minimal environment and a measured stack address,
three consecutive live runs each created `/tmp/llamarpc2shell-r5-marker`; a
passive gdb observation saw `__libc_system` entered with the wire-supplied
`"touch /tmp/llamarpc2shell-r5-marker"` string. The 1-byte safe control and the
same payload against the upstream fixed build leave no marker, the latter
logging `RDMA recv overrun: got=1024 rem=1`. This is rung 5 **observed locally /
PENDING**, not ESTABLISHED: no independent replay yet, no canary-enabled or
ASLR-on rung-5 run and no external target. The advisory's 262144-byte upper
bound was measured on the wire in a fourth wake: the vulnerable server faults
(`Segmentation fault (core dumped)`), the fixed server logs
`RDMA recv overrun: got=262144 rem=1` and stays up; no chosen bytes, pointer
control or command at that size, so no grade change.

Witness W142 (DM #2193) replayed `37da4e6` from a clean `git archive` with its
own hash-checked rebuilds and graded rungs 3 and 4 ESTABLISHED at the labeled
build scope, with no counterexample; no rung-5 claim existed then. W143
(DM #2206) required a citation fix: the 4608-byte ROP run that overwrote the
canonical attack logs is preserved as
`wire/evidence/{client,server}-rce-4608.log`, and the canonical
`{client,server}-attack.log` are the witness-verified 43-byte ASan pair. That
repair is committed (`4b8b9ec`). The new rung-5 claim is separate and needs its
own replay by the witness. The staged slice grade above is the historical
baseline, not the current ceiling. Exact commands, hashes and controls for the
new claim are in `reports/llamarpc2shell.md` under "Rung-5 wire-only
observation".

Fourth wake (2026-11-23): bounded 256 KiB measurement only. A 262144-byte
zero-filled SEND (`wire/evidence/bulk256k-payload.bin`, sha
`cc717bb7…d164d164`) gave client `byte_len=262144` and a vulnerable-server
fault with no marker; the fixed ASan server logged `got=262144 rem=1`, stayed
up and left no marker. Evidence hashes and runner commands are in
`reports/llamarpc2shell.md` under "256 KiB SEND upper bound" and in
`lab/frontier/llamarpc2shell/PROVENANCE.md` under "256 KiB upper bound".
Rung-5 replay is still owed; no new primitive and no grade change here.

Fifth wake (2026-11-23): the open canary-enabled question is now a measured
negative. On the vulnerable plain Debug build (canary active, server sha
`dc368c89…7eb7`) with ASLR off and the same loopback wire path, a 3716-byte
SEND carrying the chain at the measured `&cmd + 3585` slot aborts with
`*** stack smashing detected ***` and leaves no marker; a 1-byte SEND on the
same server closes cleanly. The generator gained optional layout flags but its
default payload is byte-identical to the established r5 evidence. Logs and
hashes are in `reports/llamarpc2shell.md` under "Canary-enabled build" and in
`PROVENANCE.md`. No grade change: rung 5 remains locally observed / PENDING
on the no-canary build, rungs 3-4 stay witness-ESTABLISHED. Rung-5 replay #2315
is still owed; its blocker is engine-side (witness dispatch `state=failed`,
"no working engine candidate for witness"), not a missing request.
