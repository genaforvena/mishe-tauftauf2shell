# janus2shell — status

Admitted 2026-11-21 ~07:1xZ by the operator under standing approval #6 on
frontier's handoff #632 (commits `500db0e`, `8e754c0`; brief
`reports/frontier-janus2shell.md`). Claim source: maintainer advisory
GHSA-8qwr-6p52-4vj9 (2026-10-12, "No known CVE"), CVSS 3.1 7.5
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, availability-only as claimed, CWE-121
stack buffer overflow. Affected `<=1.4.2` and `<=0.16.2`; fixed `1.4.3` and
`0.16.3`; fix commits `e55e2915a2801f18495c7f0d049af9274dd70065` and
`c31cad9768368b996aa68753df1656fe4f30af7e`. Claim: an unauthenticated
client records an ~1900-byte `a=fmtp`, producing a 1986-byte `.mjr` info
header; a later play or startup rescan reads that length into the
1500-byte stack `prebuffer` at pinned
`src/plugins/janus_recordplay.c:707` (and `:2610`), then writes
`prebuffer[len] = '\0'`. Advisory reachability and the HTTP-to-`.mjr`
recording chain are claims, not reproduced. Brief:
[frontier-janus2shell.md](frontier-janus2shell.md). Pins and raw URLs:
`lab/frontier/janus2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/janus2shell/run.sh <outdir>` — 29 PASS /
  0 FAIL, `ALL CHECKS PASSED rc 0`, canonical trace SHA-256
  `c8568d26b07cac408da640b7e6d8347d1c43db3119274fafbfb73f3e41f9a21f`.
- Operator replay ~07:09Z from two clean `git archive HEAD` (dc1a4e1)
  extractions into separate absolute output directories: 29 PASS / 0 FAIL
  and `ALL CHECKS PASSED rc 0` in both, trace
  `sha256=c8568d26b07cac408da640b7e6d8347d1c43db3119274fafbfb73f3e41f9a21f`
  — byte-identical between directories and to the brief.
- Rungs 1/2/3 on verbatim pinned upstream blocks from tag `v1.4.2`
  (`:669-670`, `:701-714`): a 1986-byte info header writes 1986 bytes into
  `prebuffer[1500]` (`overflow=486`) and the vulnerable build accepts it;
  the `v1.4.3` guard rejects the same bytes with
  `Info header too big (1986 bytes)` while still accepting a benign
  100-byte header. ASan reports `stack-buffer-overflow`, `WRITE of size
  1986` at pinned `janus_recordplay.c:707`; a host-default-stack-protector
  control aborts with `stack smashing detected`. The vulnerable harness
  builds use `-fno-stack-protector`; shipping flags are UNKNOWN.
- Rung 4 INSTRUMENTED only: 16 chosen bytes read back byte-exact past the
  array in the no-canary lab frame (`CHOSEN_MATCH=1`,
  `53 54 55 56 57 58 59 5a 41 42 43 44 45 46 47 48`) with the adjacent
  local `len` overwritten; a second build aborts on canary corruption. No
  pointer value, saved return address, control-flow diversion or marker
  execution was observed or attempted; the canary abort proves only
  control-data adjacency in that compiled frame.
- UNKNOWN: live Janus process, HTTP/SDP path, real `.mjr` bytes, shipping
  compiler/canary flags, real stack layout and any impact beyond the
  advisory's crash-loop claim. No probe was sent off loopback. Witness
  replay was requested in parallel; no verdict at admission.

Cheapest next rung: build stock `v1.4.2` Janus on 127.0.0.1 with Record&Play
enabled, create the recording through the documented HTTP API with an
~1900-byte `a=fmtp`, request playback under ASan (and separately under a
debugger watching the saved return address), and capture the wire bytes,
`.mjr` header, real ASan frame and post-write stack state. Repeat with
`v1.4.3`. Only a pointer or control-flow observation would justify dropping
the INSTRUMENTED label; otherwise preserve the availability-only
characterization.
