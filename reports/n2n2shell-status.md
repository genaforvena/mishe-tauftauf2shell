# n2n2shell — status

Admitted 2026-11-24 21:2xZ under standing approval #6 as the 136th engine
route. Claim: `CVE-2026-136404` (VulDB, 2026-11-24, CWE-121/CWE-787),
"ntop n2n 3.0 through 3.1.1 Stack Buffer Overflow via
`REGISTER_SUPER_NAK` token_size". The advisory says a remote unauthenticated
supernode can be crashed or worse by an oversized 16-bit
`auth.token_size` in a `REGISTER_SUPER_NAK` datagram. Fixed by ntop/n2n
commit `854fbbe01bbf131bf4cb88f8450d7084267668e1` (PR #1243, "wire: bound
decoded auth.token_size and num_sn to destination sizes"); vulnerable parent
`dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff`. The advisory's attribution to
`sn_utils.c:2309-2344` and any pre-auth RCE chain remain claims; no external
system was probed.

## Admission evidence

- Frontier brief `reports/frontier-n2n2shell.md` (W215, clean-archive receipt
  commit `99c54c80`); pinned vulnerable/fixed source, `pins.sha256` and
  raw evidence in `lab/frontier/n2n2shell/` (`PROVENANCE.md`, `harness/`).
- Source-bound mechanism: vulnerable `decode_REGISTER_SUPER_NAK()`
  (`src/wire.c:637-654`) reads `auth.token_size` with `decode_uint16()` and
  passes it to `decode_buf()` (`wire.c:169-184`), which checks only the
  source packet length before `memcpy(out, base + idx, bufsize)`.
  `auth.token` is `N2N_AUTH_MAX_TOKEN_SIZE` (48) bytes in the pinned
  `n2n_typedefs.h:334`, so a 16-bit size above 48 copies attacker-chosen
  wire bytes past the decoded structure. The fix adds
  `if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE) return -1;`.
- Operator verification 21:2xZ: `cd lab/frontier/n2n2shell &&
  sh harness/run.sh` gave **15 PASS / 0 FAIL, rc 0**. All 15 checks passed,
  including pin hashes, byte-for-byte extraction of the five decoder helpers
  and the whole NAK decoder, ASan `heap-buffer-overflow` with `WRITE of size
  96`, `0 bytes after 64-byte region` at `generated/handlers_vuln.c:47`
  (`decode_buf`) and `:81` (`decode_REGISTER_SUPER_NAK`), fixed decoder
  rejecting the oversized token, and clean vulnerable-safe and fixed-attack
  controls. Plain build placed chosen wire bytes `48 5a 4d 49` in
  `canary[0..3]` (token offsets 50..53) while the safe 48-byte input left
  `ab ab ab ab`. This is the author/operator harness, not an independent
  witness verdict.
- Frontier's live two-pane window 144 (`n2n2shell`) and seed wall were
  adopted without duplication. Charter written; hy4-flash route 135→136,
  both resolver keys 271→274, wake units from the EXACT full-flag sync at
  pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
  daemon-reload, path enabled/active, pinned full-flag doctor GREEN rc 0.

## Current grade

Rungs 1-3 on the verbatim pinned decoder under ASan. Rung 4 is PARTIAL:
chosen wire bytes appear at chosen offsets in a live adjacent object in the
plain stand-in; ASan redzones poison that memory in the instrumented build.
Not established: a built supernode, a UDP datagram to a live process, a
stack canary or return address, pointer or IP control, command execution,
or rung 5. Whether a real supernode build lands the advisory's stack
overflow at `sn_utils.c`, the stock allocator outcome and witness replay
stay UNKNOWN.

## Next

Cheapest measured step: build the pinned vulnerable supernode (`cmake` from
`provision/n2n-vuln.tar.gz`) with ASan, configure a loopback community and
send one crafted `REGISTER_SUPER_NAK` datagram, keeping fixed-commit and
safe-input controls. Any rung-5 claim needs an independently witnessed
loopback wire path with an observed benign command side effect; none is
measured here.
