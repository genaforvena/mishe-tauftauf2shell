# unbound2shell — status

Admitted 2026-11-21 ~06:5xZ by the operator under standing approval #6 on
frontier's handoff #620 (commits `f9295a0`, `34fd212`, `e76e23d`; brief
`reports/frontier-unbound2shell.md`). Claim source: CVE-2026-81642 (CNA NLnet
Labs), CWE-122 heap buffer overflow, CNA CVSS 4.0 9.1 Critical /
NVD CVSS 3.1 9.8 (Ubuntu priority Medium — vendor variance, kept as a
claim). Affected: all versions through `1.26.0`, fixed `1.26.1`; upstream fix
`8c2e0fd6cc5b6eaa618ac72227808824b4edee7c`. Claim: a DNSKEY owner-name
compression pointer to its own RDATA inflates the write in
`ds_create_dnskey_digest()` at pinned `validator/val_sigcrypt.c:293-317`
(tag `release-1.26.0`) past the per-worker scratch buffer allocated at
`daemon/worker.c:2436` with default size 65552 (`util/config_file.c:176`).
Advisory asserts possible RCE; DNSSEC configuration gate and the
compression-pointer route are UNKNOWN, not asserted. Brief:
[frontier-unbound2shell.md](frontier-unbound2shell.md). Pins and raw URLs:
`lab/frontier/unbound2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/unbound2shell/run.sh <outdir>` — 29 PASS /
  0 FAIL, `ALL CHECKS PASSED rc 0`, canonical trace SHA-256
  `05bf4ace988fc4fdc4d213674e1f30e85c739c170b47c5319cbfc2cd7f24f795`.
- Operator replay ~06:43Z from two clean `git archive HEAD` (1718991)
  extractions into separate absolute output directories: 29 PASS / 0 FAIL
  and `ALL CHECKS PASSED rc 0` in both, trace
  `sha256=05bf4ace988fc4fdc4d213674e1f30e85c739c170b47c5319cbfc2cd7f24f795`
  — byte-identical between directories and to the brief.
- Rungs 1/2/3 on verbatim pinned upstream lines: `dname_len=255` and
  `rdata_len=65535` write `65788` bytes into the 65552-byte scratch buffer
  (`overflow=236`) while the vulnerable build returns success with
  `GUARD_REJECTED=0`; ASan reports `heap-buffer-overflow`, `WRITE of size
  65533` at pinned `sldns/sbuffer.h:436`, called from `val_sigcrypt.c:311`.
  Both fixed pins (`8c2e0fd6cc5b`, `release-1.26.1`) return 0 and set
  `GUARD_REJECTED=1` on the same input; the benign case is unchanged.
  The harness defines `NDEBUG` so the capacity `assert()` is compiled out;
  shipping compile flags are UNKNOWN.
- Rung 4 INSTRUMENTED only: 16 RDATA bytes read back byte-exact at
  `data + 65552` in the non-ASan lab frame (`CHOSEN_MATCH=1`,
  `44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 41 42 43`). No pointer, saved
  return address, control-flow diversion or marker execution was observed.
- UNKNOWN: live resolver process, DNSKEY wire bytes, the advisory's
  compression-pointer inflation path, DNSSEC configuration, real allocator
  adjacency, shipping compile flags and any impact beyond the claimed
  crash/RCE. No probe was sent off loopback.

Cheapest next rung: build stock `release-1.26.0` under ASan with DNSSEC
validation enabled, bind only 127.0.0.1, serve a local malicious zone whose
DNSKEY owner name uses a self-referential compression pointer, query it from
the lab resolver, and record the real ASan frame, wire bytes and post-write
heap state. If chosen RDATA bytes reach a pointer or saved control-flow
datum, attempt a benign marker before claiming rung 4; otherwise keep the
INSTRUMENTED label. Repeat with `release-1.26.1` as the control.
