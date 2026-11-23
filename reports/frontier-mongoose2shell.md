# Frontier brief: Mongoose — CVE-2026-63626 (mongoose2shell)

**PROVISIONED, NOT STAGED — no target window exists.** Prepared by `frontier` on
2026-11-23 W137 as the next candidate with a real upstream fix commit. No
harness has been built, no rung has been measured, and no charter, seed wall or
two-pane window has been created. Operator admission is not requested.

## 1. Verified ground truth

- Claim: Mongoose before 7.23 lets an unauthenticated adjacent peer on a PPP or
  PPPoE link (`MG_ENABLE_TCPIP` and `MG_ENABLE_IPV6`) complete the LCP exchange,
  then send a short IPv6CP Configure-Request with an oversized 16-bit `len`.
  `ppp_handle_ipv6cp()` in `src/l2_ppp.c` reads past `recv_queue.buf` through
  `find_opt()` and writes past `tx.buf` through `ppp_tx_frame()`. CNA GitHub_M,
  CVE-2026-63626 / GHSA-pc66-j6r6-49x9, published 2026-10-14, CWE-122 + CWE-125,
  fixed in 7.23.
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
  `find_opt(..., len - sizeof(*ipv6cp), ...)` — an attacker-sized read walk from
  `(ipv6cp + 1)` into and past the received frame.
- Lines 374, 382, 389 and 407 pass the same `len` to `ppp_tx_frame()`, whose
  header/trailer helpers write into `tx.buf` at peer-chosen extent.

The upstream fix (commit `751f1474`, 2026-07-01, +6/-2) adds
`if (len < sizeof(*ipv6cp) || len > ipv6cpsz) return;` after the length read in
all three handlers (`ppp_handle_lcp`, `ppp_handle_ipcp`, `ppp_handle_ipv6cp`),
tightening the existing IPCP-only `len > ipcpsz` check. The vulnerable and fixed
blobs are byte-exact pinned; no hand-edited fixed copy is used.

## 3. Cheapest next experiment

Write a verbatim-slice harness that extracts `ppp_handle_ipv6cp()` and
`find_opt()` from both pinned blobs, stubs `ppp_tx_frame()` with a fixed-size
local `tx.buf` and `MG_*` logging, then drives a 10-byte Configure-Request with
`len = 0xFFFF`. Expect an ASan OOB READ in `find_opt()` and an ASan WRITE past
`tx.buf` in the vulnerable slice, both clean on the fixed slice; a well-formed
short frame is the safe control. That would be rungs 1-4 with a published
upstream fix — stronger than the Snap7 handoff, whose fixed control is only a
reporter's proposal.

If the slice works, the next step up is a real loopback PPP/PPPoE-style frame
into a plant-started Mongoose `mg_tcpip_if` under ASan; the LCP precondition
must be measured, not assumed. No external host is ever probed.

## 4. Why it ranked second this wake

Mongoose has a real fixed version (7.23), a real upstream commit, and a
deterministic 16-bit length in a small C function — all present in W137's
candidate set. mod_auth_openidc CVE-2026-54789 (three-line parser loop, fix
`8017478`) is the close third. Snap7 was staged instead because its harness was
already built and its loopback PoC recipe was fully specified, but its lack of
an upstream fix is the main weakness a witness could cite. No duplicate lane is
opened by this provisioned brief; do not create a window for it until it is
driven to a rung and formally staged.
