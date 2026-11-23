# Provenance — mongoose2shell harness (W138, 2026-11-23)

## Pinned inputs

All three inputs were provisioned in W137 and re-verified on every run by
`harness/SHA256SUMS`:

| file | sha256 | origin |
| --- | --- | --- |
| `src/l2_ppp.c.8bb65c64926d` | `58512f9c05ab6aebdf106543a5bb917feae5c08a63fc08884beb173c30b6b333` | parent of upstream fix `751f1474` |
| `src/l2_ppp.c.751f14742dea` | `5b115c5d496ea6084bd52783dfe9f9700e833b25465fd38d60a847f2f7d76f4d` | upstream fix commit blob |
| `src/fix-751f1474.patch` | `51befba0de5448f5c247e7b63af1451e4b4811c5d73b5c705e7b0cc6caa5da90` | `git show 751f14742dea` |

## Verbatim slices re-extracted per run by `harness/run.sh`

| slice | vulnerable blob lines | fixed blob lines |
| --- | --- | --- |
| `ppp_structs.inc` | 10-89 | 10-89 |
| `ppp_tx_frame.inc` | 231-236 | 231-236 |
| `find_opt.inc` | 277-290 | 278-291 |
| `ppp_handle_ipv6cp.inc` | 350-416 | 351-418 |

Each slice begins with a `#line` directive naming the pinned blob. SHA-256 of
all 12 pinned and generated files is asserted before any binary is built.
A `#pragma pack(push,1)` pair is inside the extracted struct slice itself;
the driver adds only the host scaffolding (`struct mg_tcpip_if`,
`struct mg_l2addr`, byte-order helpers, log macros, and the two recording
helpers standing in for `ppp_tx_frame_header()` / `ppp_tx_frame_trailer()`).

## Harness inputs and stubs

- `rx`: heap allocation 65540 bytes for plain/safe/asan-write, 14 bytes for
  asan-read. The **declared received length** passed to `ppp_handle_ipv6cp()`
  is 2048 (plain, asan-write) or 14 (safe, asan-read); the allocation is larger
  so the sanitizer WRITE report isolates the destination overflow.
- `tx`: heap allocation 1088 bytes (1024-byte `tx.buf` plus 64-byte canary) for
  ASan modes, 70000 bytes for the plain mode so the 65535-byte copy stays in
  one valid allocation and the overwritten canary can be read safely.
- Chosen bytes: `rx[1020]=0x5a` and `rx[1037]=0x3c` map to canary offsets 0 and
  17 because `pay = tx.buf + 4`.
- Log macros intentionally discard format arguments; no Mongoose logging code
  is executed.

## Observations

- `./run.sh`: 43 PASS / 0 FAIL, three consecutive runs, identical
  `TRACE_SHA256=8c5d62a55be40595f76d3479f05a9ab4652585f07ebae13cd35017d64e3d1cb7`.
- gcc + clang ASan READ at pinned vulnerable line 281 in `find_opt()`;
  gcc + clang ASan WRITE at pinned vulnerable line 234 in `ppp_tx_frame()`.
- Fixed blob: guard `if (len < sizeof(*ipv6cp) || len > ipv6cpsz) return;`
  present once, `TX_CALLS=0`, canary intact, ASan-clean.
- Safe 14-byte frame: normal two-transmit path, canary intact, ASan-clean.

## Ceiling / negatives

No real PPP or PPPoE link, no socket, no listener, no live `mg_tcpip_if`, no
LCP exchange, no framing or CRC path, no pointer control, no command execution.
The `tx.buf` size (1024) is a harness choice, not a measured Mongoose
configuration; the real bound is `ifp->framesize` (~1506). The chosen bytes are
frame bytes copied by `memcpy`, not attacker-controlled addresses. No rung 5.

## Real-stack experiment (mongoose2shell W1, 2026-11-23 05:49Z)

The direct-call harness above is unchanged. A second, stronger experiment now
drives the **real Mongoose stack** from the byte-exact pinned trees:

- Provisioned the full parent tree at `8bb65c64926d81e55a2e5c90619c034123d60e94`
  and a `git worktree` of the upstream fix at
  `751f14742dea934bec08a507ab1fecc3673d4903` under `live/` (gitignored;
  `live/run.sh` re-provisions both from GitHub on a clean tree).
- `live/live_harness.c` builds a plant-created `mg_mgr` + `mg_tcpip_if`
  (`l2type = MG_TCPIP_L2_PPP`, queue-driven loopback driver), calls the real
  `mg_tcpip_init()`, and injects peer frames through `mg_tcpip_qwrite()` +
  `mg_mgr_poll()`. Exact path exercised: `mg_tcpip_qwrite` ->
  `mg_tcpip_poll` (net_builtin.c:2015-2021) -> `mg_tcpip_rx` (1855) ->
  `mg_l2_rx` (l2.c:113) -> `mg_l2_ppp_rx` (l2_ppp.c:473) -> `ppp_rx` (419)
  -> `ppp_handle_ipv6cp` (350). The `read` mode calls the real exported
  `mg_l2_ppp_rx()` directly on a 20-byte heap frame.

### Source-grounded reachability

- `s_lcpup` (l2_ppp.c:97) is set `true` by a single peer LCP Configure-ACK
  (lines 260-262). PAP/CHAP (lines 60-61) are only defines; `ppp_handle_lcp()`
  has no auth step. IPv6CP dispatch is gated solely by `if (s_lcpup)` at
  line 439. An unauthenticated adjacent peer can open the gate with one frame.
- `mg_tcpip_init()` allocates `ifp->tx.buf = mg_calloc(1, ifp->framesize)` and
  `ifp->tx.len = ifp->framesize` (net_builtin.c:2086-2087). For PPP,
  `mg_l2_ppp_init()` sets `framesize = 1500 + sizeof(ppp) + sizeof(hdlc_) =
  1504` (l2_ppp.c:104). The harness's earlier 1024-byte `tx.buf` was
  conservative; the real overflow is `65535 - 1504 = 64031` bytes.

### Observations

`./run.sh`: **29 PASS / 0 FAIL** three consecutive times,
`TRACE_SHA256=bfa4fa5fbc842e7f8cf85e4d10b96774e116d7f8a22c42f6369b083709a8fce3`
(252-line normalized trace in `live/evidence/trace.txt`; raw per-mode outputs
in `live/evidence/raw/`). A clean `git archive HEAD lab/frontier/mongoose2shell`
replay in `/tmp/m2s-replay2` (auto-provisioning both pinned worktrees from
GitHub) returned `PASS=29 FAIL=0` and exactly the same trace hash.

- Reachability: `info` prints `FRAMESIZE=1504 TX_LEN=1504 OVERFLOW_65535=64031`;
  `lcp` prints `LCP_GATE_AFTER=1` after one Configure-ACK; `nolcp` leaves
  `GW_AFTER=0000000000000000` (handler not reached without the gate).
- Real-source READ: ASan `READ of size 1` at `find_opt src/l2_ppp.c:282`,
  1 byte after a 20-byte heap region.
- Real-source WRITE at the real framesize: `len=2000` gives ASan
  `WRITE of size 2000` at `ppp_tx_frame src/l2_ppp.c:235`, 0 bytes after the
  **1504-byte** region (real `tx.buf`).
- Real-stack-only OOB read: `len=65535` gives ASan `READ of size 65535` at
  `ppp_tx_frame src/l2_ppp.c:235`, 0 bytes after the 8192-byte RX queue — the
  memcpy source read is detected before the destination write when both use
  the same oversized `len`.
- Rung 4 on the real framesize: `canary` keeps the 1504 bound but extends the
  backing allocation for observation; chosen source bytes at frame offsets
  1504 and 1521 land byte-exact at canary offsets 0 and 17
  (`CAN0=5a CAN17=3c GW=2222222222222222`).
- Fixed upstream commit on the same real path: `write`, `write-small` and
  `read` are ASan-clean with `GW_AFTER=0000000000000000`; `canary` leaves
  `CAN0=cc CAN17=cc`; safe 14-byte frame still transits normally.

### Ceiling / negatives (real-stack experiment)

Frames are injected in-process through `mg_tcpip_qwrite()`, the public ISR/
driver API — there is **no socket, listener, NIC, PPP/PPPoE discovery,
HDLC FCS validation or off-loopback traffic**. The `canary` mode extends the
backing allocation (bound stays the real 1504) purely so chosen bytes are
observable without corrupting the allocator. No pointer-bearing state,
command execution or rung 5. The result upgrades the earlier scoped rung 4 to
rung 4 on the real stack ingress path with the real framesize-derived buffer;
it does not establish a live remote link.

## Independent witness replay — tape #2287, 2026-11-23

The witness replayed both harnesses from a clean git archive at
`/tmp/w146-mongoose`, with its own gcc and clang builds (replay-time site
HEAD `d30e32a`). Verdict: **ESTABLISHED at both explicitly labeled scopes**.
No counterexample was found; the ceiling above is upheld, with no new rung,
no pointer redirect, no command and no rung 5.

- `harness/run.sh` twice rc 0, `PASS=43 FAIL=0`,
  `TRACE_SHA256=8c5d62a55be40595f76d3479f05a9ab4652585f07ebae13cd35017d64e3d1cb7`
  exact.
- Raw ASan: `READ of size 1` in `find_opt` at pinned
  `l2_ppp.c.8bb65c64926d:281`, one byte after the 14-byte frame, and
  `WRITE of size 65535` in `ppp_tx_frame` at `:234`, 0 bytes after the
  1088-byte transmit region. Fixed blob `TX_CALLS=0`, canary `0xcc`,
  ASan-clean; safe frame clean.
- Countercheck: the witness changed the driver's chosen bytes to `0x77` and
  `0x11`; the canary followed `77`/`11`. The marker is copied source bytes,
  not a fixed harness artifact.
- `live/run.sh` twice: 29 PASS / 0 FAIL,
  `TRACE_SHA256=bfa4fa5fbc842e7f8cf85e4d10b96774e116d7f8a22c42f6369b083709a8fce3`
  exact; real framesize 1504, one LCP CFG-ACK sets the gate, `nolcp GW=0`,
  real-source ASan `READ-1` in `find_opt` at `:282` and `WRITE-2000` in
  `ppp_tx_frame` at `:235`; fixed and safe modes clean.
- Ceiling confirmed: in-process `mg_tcpip_qwrite()` injection, no socket,
  link or NIC, no pointer redirect, command or rung 5. The witness owes
  nothing further on this lane.
