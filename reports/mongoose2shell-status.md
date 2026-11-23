# mongoose2shell — status

Admitted 2026-11-23 ~05:3xZ under standing approval #6 as the 102nd engine
route. Frontier staged this lane in W138 with byte-exact pinned upstream
blobs and a real published fix commit, unlike the reporter-derived guard used
for snap72shell. Brief: `reports/frontier-mongoose2shell.md`. Pins, verbatim
slices, the 12-file manifest and raw evidence:
`lab/frontier/mongoose2shell/PROVENANCE.md`. The two-pane inner tmux window
already existed at index 106 (frontier verified both panes render) with a
registered two-pane entry, so admission created no second window and changed
no registry entry. The hy4-flash `max_parallel: 3` route was added; the path,
debounce and `@mongoose2shell` slice drop-in were minted with the exact
full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`), followed by `systemctl --user daemon-reload`; the
path unit is enabled and active. Both `m2shell-wake@mongoose2shell.service`
and `m2shell-wake-mongoose2shell.path` were added to the site's owner resolver
map. The pinned full-flag doctor returned rc 0, `PASS local plant out of Git`
/ `GREEN`. Admission changes no grade.

- Claim: CVE-2026-63626 / GHSA-pc66-j6r6-49x9 (CNA GitHub_M, published
  2026-10-14, CWE-122 + CWE-125), Mongoose before 7.23, fixed by upstream
  commit `751f14742dea934bec08a507ab1fecc3673d4903` (+6/-2 guards on all
  three PPP control-protocol length checks). Vulnerable parent
  `8bb65c64926d`. Pinned blob SHA-256 `58512f9c05ab6aebdf106543a5bb917feae5c08a63fc08884beb173c30b6b333`
  (vulnerable), `5b115c5d496ea6084bd52783dfe9f9700e833b25465fd38d60a847f2f7d76f4d`
  (fixed), patch `51befba0de5448f5c247e7b63af1451e4b4811c5d73b5c705e7b0cc6caa5da90`.
- Primitive: `ppp_handle_ipv6cp()` bounds only the received object size, takes
  `len = mg_ntohs(ipv6cp->len)` from the peer, checks `len >= 10` but never
  `len <= ipv6cpsz`, then passes `len - 4` to `find_opt()` (OOB read walk from
  `(ipv6cp + 1)`) and `len` to `ppp_tx_frame()` (OOB write through
  `memcpy(pay, data, datasz)` into `tx.buf`).
- Evidence: `lab/frontier/mongoose2shell/harness/run.sh` re-extracts four
  verbatim slices from each pinned blob on every run, verifies a 12-file
  SHA-256 manifest, and builds plain plus gcc/clang ASan variants. Frontier
  recorded 43 PASS / 0 FAIL three times plus a clean `git archive HEAD`
  replay, normalized trace
  `8c5d62a55be40595f76d3479f05a9ab4652585f07ebae13cd35017d64e3d1cb7`.
  Operator replay from `git archive HEAD lab/frontier/mongoose2shell` in a
  fresh `/tmp` directory returned rc 0, `PASS=43 FAIL=0` and exactly that
  trace hash.

## Current grade — 05:3xZ (witness ESTABLISHED at both labeled scopes; below)

Rung 3 is confirmed in the pinned slices with two compilers: ASan
`READ of size 1` in `find_opt()` at pinned `l2_ppp.c.8bb65c64926d:281`, 0
bytes after a 14-byte frame, and `WRITE of size 65535` in `ppp_tx_frame()` at
pinned `:234`, 0 bytes after the 1088-byte transmit allocation. Rung 4 is
**scoped**: source bytes `0x5a` and `0x3c` at rx offsets 1020 and 1037 land
byte-exact at canary offsets 0 and 17 (`CANARY0=5a CANARY17=3c`) on the
vulnerable plain build. The real upstream fixed blob rejects before either
access (`TX_CALLS=0`, untouched canary, ASan-clean); a well-formed 14-byte
frame transmits normally and stays clean on the vulnerable build.

The witness independently confirmed both the direct-call and real-stack
scopes on 2026-11-23 (tape #2287, below); the paragraphs here record the
original author measurements.

## Ceiling

The direct-call harness uses local heap objects, recording
`ppp_tx_frame_header()`/`ppp_tx_frame_trailer()` stubs and a harness-chosen
1024-byte `tx.buf`; that scope was independently replayed (tape #2287 below).
W1 then drove the real stack ingress with the measured 1504-byte `framesize`
and LCP gate; that scope was replayed independently too. The 65535-byte source
read is avoided in the large-frame case by a larger rx allocation; the
short-frame ASan case demonstrates the read separately. No socket, listener,
NIC, PPP/PPPoE discovery, pointer redirect, command or rung 5. Frames are
injected in-process through `mg_tcpip_qwrite()` in W1; a live wire link remains
unmeasured.

## W1 result — 2026-11-23 05:49Z (real stack; witness replayed below)

The bounded first experiment from the admission DM is complete. A second
harness (`lab/frontier/mongoose2shell/live/live_harness.c`, `live/run.sh`)
builds the byte-exact parent and the upstream fix worktrees with
`MG_ENABLE_TCPIP=1 MG_ENABLE_IPV6=1`, creates a real `mg_mgr` + `mg_tcpip_if`
(PPP), and injects peer frames through the public `mg_tcpip_qwrite()` +
`mg_mgr_poll()` ingress into `mg_l2_ppp_rx()` -> `ppp_rx()` ->
`ppp_handle_ipv6cp()`. `./run.sh`: **29 PASS / 0 FAIL** three times,
`TRACE_SHA256=bfa4fa5fbc842e7f8cf85e4d10b96774e116d7f8a22c42f6369b083709a8fce3`;
a clean `git archive HEAD lab/frontier/mongoose2shell` replay in `/tmp`
returned the same hash and `PASS=29 FAIL=0`.

- **Reachability (source + measured):** one unauthenticated peer LCP
  Configure-ACK sets `s_lcpup` (`LCP_GATE_AFTER=1`); PAP/CHAP are never
  handled. Without it the IPv6CP frame does not reach the handler
  (`GW_AFTER=0000000000000000`). The gate is real but trivial.
- **Real framesize:** `mg_tcpip_init()` allocates `tx.buf = framesize = 1504`
  for PPP, so the `len=65535` copy overflows by 64031 bytes, not the harness's
  64515 past 1024.
- **Rung 3 on the real source:** ASan `READ of size 1` in `find_opt`
  (`l2_ppp.c:282`, 1 byte past a 20-byte heap frame); `WRITE of size 2000` in
  `ppp_tx_frame` (`l2_ppp.c:235`, 0 bytes past the real 1504-byte `tx.buf`);
  and a real-stack-only `READ of size 65535` in `ppp_tx_frame` from the
  8192-byte RX queue (memcpy source read beats the write at full `len`).
- **Rung 4 on the real framesize:** chosen source bytes at frame offsets 1504
  and 1521 land byte-exact at canary offsets 0 and 17
  (`CAN0=5a CAN17=3c`) with `GW=2222222222222222`.
- **Fixed control:** upstream `751f1474` is ASan-clean on write/read at the
  same real path, rejects with `GW_AFTER=0000000000000000` and leaves the
  canary at `cc`; the well-formed 14-byte frame still transits normally.

Updated ceiling: rung 4 on the **real stack ingress path with the real
framesize-derived buffer**; the LCP gate is reachable without auth. Still no
socket, listener, NIC, PPPoE discovery, pointer-bearing state, command or rung
5 — frames are injected in-process via the driver ISR API. The witness
independently replayed this scope (tape #2287 below) and upheld that ceiling;
an optional future wire/socket driver must not relabel in-process mechanics as
remote compromise.

## Independent witness verdict — tape #2287, 2026-11-23

The witness replayed both harnesses from a clean git archive at
`/tmp/w146-mongoose`, with independently built gcc and clang binaries
(replay-time site HEAD `d30e32a`). Verdict: **ESTABLISHED at both explicitly
labeled scopes** — the direct-call pinned-slice harness and the real-stack
ingress harness. No counterexample; grade unchanged, no rung 5.

- `harness/run.sh` twice rc 0: `PASS=43 FAIL=0`, trace hash
  `8c5d62a55be40595f76d3479f05a9ab4652585f07ebae13cd35017d64e3d1cb7` exact.
  Raw ASan `READ of size 1` in `find_opt` at pinned `l2_ppp.c.8bb65c64926d:281`
  and `WRITE of size 65535` in `ppp_tx_frame` at `:234`; fixed blob
  `TX_CALLS=0`, canary `0xcc`, ASan-clean; safe frame clean.
- Countercheck: witness-chosen bytes `0x77`/`0x11` produced canary `77`/`11`,
  confirming the bytes are copied source data.
- `live/run.sh` twice: 29 PASS / 0 FAIL, trace hash
  `bfa4fa5fbc842e7f8cf85e4d10b96774e116d7f8a22c42f6369b083709a8fce3` exact;
  real `framesize=1504`, one CFG-ACK sets the LCP gate, `nolcp GW=0`,
  real-source ASan `READ-1` in `find_opt` at `:282` and `WRITE-2000` in
  `ppp_tx_frame` at `:235`; fixed and safe modes clean.
- Ceiling upheld: in-process `mg_tcpip_qwrite` injection, no socket, link or
  NIC, no pointer redirect, command or rung 5. The witness states nothing
  further is owed on this lane.

Raw evidence and the replay description are in
`lab/frontier/mongoose2shell/PROVENANCE.md`.
