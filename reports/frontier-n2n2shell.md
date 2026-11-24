# Frontier brief — n2n2shell (CVE-2026-136404)

Status 2026-11-24 21:2xZ: STAGED and handed off, witness UNKNOWN, operator
admission pending. This is a research artifact, not independent acceptance.

## Ground truth (claim, not verified remotely)

- CVE-2026-136404, CWE-121/CWE-787, CNA VulDB, published 2026-11-24.
  Advisory title: "ntop n2n 3.0 through 3.1.1 Stack Buffer Overflow via
  REGISTER_SUPER_NAK token_size".
- Claim: a remote unauthenticated supernode can be crashed or worse by an
  oversized 16-bit `auth.token_size` in a `REGISTER_SUPER_NAK` datagram.
- Fix: ntop/n2n commit `854fbbe01bbf131bf4cb88f8450d7084267668e1`, PR #1243,
  "wire: bound decoded auth.token_size and num_sn to destination sizes".
  Parent (vulnerable) commit `dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff`.
  Advisory source links point at `src/sn_utils.c` L2309-2344 and
  `src/wire.c` decoders; no external system was probed.
- Affected: n2n 3.0 through 3.1.1. Fixed: commit `854fbbe0`; no numeric
  release version asserted here.

## Source-bound mechanism

`decode_REGISTER_SUPER_NAK()` (pinned vulnerable `src/wire.c:637-654`) reads
`auth.scheme` and `auth.token_size` straight from the packet with
`decode_uint16()`, then calls `decode_buf(nak->auth.token,
nak->auth.token_size, ...)`. The pinned `decode_buf()` (`wire.c:169-184`)
checks only that the *source* packet has `bufsize` bytes and then calls
`memcpy(out, base + idx, bufsize)`. `auth.token` is exactly
`N2N_AUTH_MAX_TOKEN_SIZE` (48) bytes in the pinned `n2n_typedefs.h:334`.
A conforming 16-bit `token_size` above 48 therefore copies attacker-chosen
wire bytes past the decoded structure. The fix adds the missing bound:
`if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE) return -1;`.

## Local experiment and observed bytes

`lab/frontier/n2n2shell/` pins both source archives and both `wire.c`
copies with SHA-256 (`pins.sha256`). `generated/handlers_vuln.c` and
`generated/handlers_fixed.c` extract the five decoder helpers and the whole
NAK decoder verbatim from the pinned files; only the surrounding types are
stand-ins reproducing the pinned layout. `harness/harness.c` builds a
wire-format packet (cookie, MAC, scheme, token_size, token bytes), passes it
to the verbatim decoder, and checks a canary.

- Vulnerable ASan build, `token_size=96`: heap-buffer-overflow, `WRITE of
  size 96`, 0 bytes after a 64-byte region, frames
  `decode_buf generated/handlers_vuln.c:47` and
  `decode_REGISTER_SUPER_NAK generated/handlers_vuln.c:81`; rc 1.
- Vulnerable plain build, same input: chosen wire bytes `48 5a 4d 49`
  appear at `canary[0..3]` (token offset 50..53); safe 48-byte input leaves
  `ab ab ab ab`.
- `sh harness/run.sh`: 15 PASS / 0 FAIL, rc 0, in-tree and from a clean
  `git archive 2907b7e4` replay (receipt commit follows).

## Rung-4 feasibility and ceiling

Rung 1 (deterministic trigger), rung 2 (state failure: bound omitted) and
rung 3 (ASan-confirmed heap corruption) are established on the verbatim
pinned decoder. Rung 4 is PARTIAL: chosen wire bytes observed in a live
adjacent object in the plain stand-in. Not established: a built n2n
supernode, a UDP datagram to a live process, stack canary/return-address
control, pointer or IP control, command execution, or rung 5. The advisory
calls this a stack overflow in `sn_utils.c`; the harness demonstrates the
root-cause heap/struct overflow in the decoder, so that attribution remains
a claim until a real supernode build is exercised. Witness replay UNKNOWN.

## Cheapest next experiment

Build the pinned vulnerable supernode (`cmake` from `provision/n2n-vuln.tar.gz`)
with ASan, configure a loopback community, and send one crafted
`REGISTER_SUPER_NAK` datagram; observe whether the overflow lands in the
stack NAK buffer at `sn_utils.c` and whether chosen bytes reach an adjacent
object. Keep fixed-commit and safe-input controls.
