# srs2shell — status

Admitted 2026-11-21 ~09:2xZ by the operator under standing approval #6 on
frontier's handoff #716 and commits `24db73a` / `770669f`, brief
[frontier-srs2shell.md](frontier-srs2shell.md). Claim source: GitHub Advisory
`GHSA-qr8h-p53p-x564` (no CVE assigned at fetch), published
2026-10-30T14:14:41Z, HIGH 8.2, "RTC: Crash and heap overflow from a
malformed RTCP packet". Affected `srs >=4.0,<6.0.194`, `>=7.0,<7.0.214`,
`>=8.0,<8.0.73`; patched `6.0.194`, `7.0.214`, `8.0.73`. Only WebRTC-enabled
servers are affected and no authentication is needed without `on_play` /
`on_publish` callbacks — that reachability is a claim, not reproduced here.
Fix `ab03c94b0744ab392320253ad1767b21b6c82a59`, parent `f7968893…`; advisory
API, commit JSON, patch and vulnerable/fixed source pins are in
`lab/frontier/srs2shell/PROVENANCE.md`. External claims remain claims.

- Harness: `cd lab/frontier/srs2shell && ./run.sh` — 14 PASS / 0 FAIL, raw
  trace
  `sha256=77b6d5500dea19d3c3a8de713d7a37834a3241a62e6a7239d398661e5fea1965`.
- Operator replay ~09:1xZ from two clean `git archive 24db73a
  lab/frontier/srs2shell` extractions into separate absolute directories:
  14 PASS / 0 FAIL in both, raw trace
  `sha256=77b6d5500dea19d3c3a8de713d7a37834a3241a62e6a7239d398661e5fea1965`
  — byte-identical between directories, to the working-tree replay and to the
  brief. Harness uses no socket, daemon, ICE/DTLS/SRTP or network; the RTCP
  datagram is a local byte array. Witness replay requested separately on the
  tape; no verdict in hand at admission.
- Rungs 1/2/3 on verbatim pinned upstream ranges under `#line`: parent
  `length = 0` aborts with `srs_assert failed: require(size)` in pinned
  `srs_kernel_buffer.cpp:244`; a 1604-byte datagram declaring `length = 400`
  passes the parent's `length * 4 <= buffer->left()` check while declaring a
  1596-byte payload into `payload_[1500]`; ASan reports
  `heap-buffer-overflow`, `WRITE of size 1596` at pinned
  `srs_kernel_buffer.cpp:246`, decode frame `srs_kernel_rtc_rtcp.cpp:95`, 0
  bytes after a 1536-byte region. TWCC reproduces the write. Fixed BYE/TWCC
  and benign `length = 2` are clean.
- Rung 4 INSTRUMENTED only, with preserved negatives. In a 64 KiB zeroed
  collaborator chosen `0x5a` appears at 96 offsets from the payload-array end
  (20 in the object tail, 76 past the object), `0x41` reproduces the same
  count, the benign run writes none, and a guard-mapped object faults on the
  byte past the object (exit 77). The collaborator and guard page are
  instrumentation, not stock allocator properties. No pointer, return
  address, heap-metadata field, function pointer, control-flow diversion or
  marker execution was observed or attempted.
- UNKNOWN: WebRTC/daemon reachability, ICE/DTLS/SRTP session setup, full SRS
  daemon ASan frames, real heap layout around `payload_` under the shipping
  allocator, and any valid-address retargeting or post-write control. The
  advisory itself says no working code-execution exploit was shown.

Cheapest next rung: build pinned parent SRS with ASan, enable WebRTC on
loopback, open a WHEP/WHIP session, send one SRTP-protected BYE/TWCC packet
with `length = 400` and a chosen fill byte, and capture the daemon ASan frame
plus the real heap layout; repeat on the fixed version. Only an observed
pointer or control-flow result would drop INSTRUMENTED. If the real allocator
faults before chosen bytes persist, preserve that negative and cap at rung 3
in practice. All probes bind 127.0.0.1 only.
