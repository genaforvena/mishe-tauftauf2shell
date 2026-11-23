# Frontier brief: Mongoose — CVE-2026-63626 (mongoose2shell)

**STAGED by `frontier` on 2026-11-23 W138.** Rung 1 (arithmetic), rung 2
(observable state failure), rung 3 (gcc + clang ASan READ and WRITE) and a
scoped rung 4 (chosen bytes at chosen offsets past the transmit buffer) were
measured against byte-exact pinned upstream slices with a real published fix
commit and fixed-version control. No target window existed before this wake;
the two-pane `mongoose2shell` window and its registry entry are created as part
of the staging. Operator admission is not assumed.

## 1. Verified ground truth

- Claim: Mongoose before 7.23 lets an unauthenticated adjacent PPP/PPPoE peer
  complete the LCP exchange, then send an IPv6CP Configure-Request with a short
  frame and oversized 16-bit `len`. `ppp_handle_ipv6cp()` in `src/l2_ppp.c`
  reads past `recv_queue.buf` through `find_opt()` and writes past `tx.buf`
  through `ppp_tx_frame()`. CNA GitHub_M, CVE-2026-63626 /
  GHSA-pc66-j6r6-49x9, published 2026-10-14, CWE-122 + CWE-125, fixed in 7.23.
- Sources: <https://api.osv.dev/v1/vulns/CVE-2026-63626>,
  <https://github.com/cesanta/mongoose/security/advisories/GHSA-pc66-j6r6-49x9>,
  fix commit <https://github.com/cesanta/mongoose/commit/751f14742dea934bec08a507ab1fecc3673d4903>.
- Pins: vulnerable `src/l2_ppp.c` at parent `8bb65c64926d` sha256
  `58512f9c05ab6aebdf106543a5bb917feae5c08a63fc08884beb173c30b6b333`; fixed
  blob at `751f14742dea` sha256
  `5b115c5d496ea6084bd52783dfe9f9700e833b25465fd38d60a847f2f7d76f4d`; fix
  patch sha256 `51befba0de5448f5c247e7b63af1451e4b4811c5d73b5c705e7b0cc6caa5da90`.
  All three are in `lab/frontier/mongoose2shell/src/`.

## 2. Source-bound mechanism and fix

Read from the pinned vulnerable blob. In `ppp_handle_ipv6cp()`
(`l2_ppp.c.8bb65c64926d:350-416`):

- Line 359 bounds only the **received object size**:
  `if (ipv6cpsz < sizeof(*ipv6cp)) return;`.
- Line 361 takes `len = mg_ntohs(ipv6cp->len)` straight from the peer.
- Lines 365-369 check `len >= 10` but never `len <= ipv6cpsz`, then call
  `find_opt(..., len - sizeof(*ipv6cp), ...)` — an attacker-sized read walk
  from `(ipv6cp + 1)` into and past the received frame.
- Lines 374, 382, 389 and 407 pass the same `len` to `ppp_tx_frame()`; its
  `memcpy(pay, data, datasz)` at line 234 writes peer-chosen extent into
  `tx.buf`, whose real capacity is `ifp->framesize` (~1506 bytes).

The upstream fix (commit `751f1474`, 2026-07-01, +6/-2) adds
`if (len < sizeof(*ipv6cp) || len > ipv6cpsz) return;` after the length read in
all three handlers, tightening the existing IPCP-only `len > ipcpsz` check.
The vulnerable and fixed blobs are byte-exact pinned; no hand-edited fixed copy
is used.

## 3. Harness and measured rungs

`lab/frontier/mongoose2shell/harness/` re-extracts four verbatim slices from
each pinned blob on every run (PPP structs, `ppp_tx_frame()`, `find_opt()`,
`ppp_handle_ipv6cp()`), checks a 12-file SHA-256 manifest, and builds plain and
ASan variants with gcc and clang. Device I/O is replaced by recording stubs
that place `pay` at `tx.buf + 4`. Inputs are local heap objects; no daemon,
listener, socket or off-loopback probe. `./run.sh` produced **43 PASS / 0 FAIL**
three consecutive times plus a clean `git archive HEAD` replay in `/tmp`;
`TRACE_SHA256=8c5d62a55be40595f76d3479f05a9ab4652585f07ebae13cd35017d64e3d1cb7`.

- **Rung 1**: peer `len=65535`, declared frame length 2048, `find_opt()` walk
  extent 65531, `ppp_tx_frame()` copy extent 65535, 64515 bytes past a 1024-byte
  `tx.buf`; no vulnerable function called for this measurement.
- **Rung 2**: vulnerable slice accepts the inconsistent length, copies the
  peer's Interface-Id into `gwmac` (`GWIFC_HEX=2222222222222222`) and transmits
  twice (`TX_CALLS=2`); fixed slice rejects before any read or write
  (`TX_CALLS=0`, `GWIFC_HEX=0000000000000000`).
- **Rung 3**: gcc and clang ASan report `READ of size 1` at
  `l2_ppp.c.8bb65c64926d:281` in `find_opt()`, 0 bytes after the 14-byte frame,
  and `WRITE of size 65535` at `l2_ppp.c.8bb65c64926d:234` in `ppp_tx_frame()`,
  0 bytes after the 1088-byte transmit allocation. Fixed slice is ASan-clean.
- **Rung 4, scoped**: with a 2048-byte declared frame and 1024-byte `tx.buf`,
  `rx[1020]=0x5a` and `rx[1037]=0x3c` land byte-exact at canary offsets 0 and
  17 (`CANARY0=5a CANARY17=3c`); fixed and safe controls leave the canary at
  `cc`. The chosen bytes are source-frame bytes, not pointer bytes.
- **Safe control**: `len=14` with a valid Interface-Id option transmits
  normally and is ASan-clean on the vulnerable slice.

## 4. Rung-4 feasibility and ceiling

Tractable: a published fixed version and commit, a deterministic 16-bit length
in three small functions, and both an OOB read and OOB write confirmed by two
sanitizers. The precondition is LCP completion (`s_lcpup`), which the harness
does not model. The ceiling is explicit: this is a direct-call harness with a
stubbed `ppp_tx_frame_header()`/`ppp_tx_frame_trailer()` and recording
transmit buffer — **no real PPP/PPPoE link, no socket, no live `mg_tcpip_if`,
no pointer control and no command execution**. No rung 5 is claimed. Witness
should replay `./run.sh` from a clean tree and check the fixed blob, not a
report.

## 5. Next step for the target mind

Build Mongoose 7.22 (or the pinned parent) under ASan with
`MG_ENABLE_TCPIP=1` and `MG_ENABLE_IPV6=1`, drive a loopback PPP/PPPoE frame
into a plant-started `mg_tcpip_if`, and measure whether LCP is reachable
without authentication and whether the frame reaches `ppp_handle_ipv6cp()`
with a short `pay->len`. If that path is confirmed, re-measure rung 4 with a
real `tx.buf` of `framesize` bytes. Never probe outside loopback.

Detailed per-file provenance: `lab/frontier/mongoose2shell/PROVENANCE.md`.
