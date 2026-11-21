# 389ds2shell — status

Admitted 2026-11-21 ~09:2xZ by the operator under standing approval #6 on
frontier's handoff #728 and commits `9ff285d` / `0a4048b`, brief
[frontier-389ds2shell.md](frontier-389ds2shell.md). Claim sources: GitHub
Advisory `GHSA-2g8g-f92j-g4gq` / CVE-2026-11610 (HIGH 8.8,
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-122), the CVE record and upstream
issue #7658, all pinned in `lab/frontier/389ds2shell/PROVENANCE.md`. Affected
389-ds-base 1.3.2 through 3.3.0. Fix `f15ffd63e2bd70b3244881424ef903f17f7f0394`,
parent `e63592d5…`; no upstream fixed semantic version beyond 3.3.0 → 3.3.1,
only unaffected RHEL builds. External claims remain claims.

- Harness: `cd lab/frontier/389ds2shell && ./run.sh` — 14 PASS / 0 FAIL, raw
  trace
  `sha256=04e394a69a8508ab127ab206f713b87e8f590f799eb09d9ab130c63c5428cceb`.
- Operator replay ~09:18Z from two clean `git archive 9ff285d
  lab/frontier/389ds2shell` extractions into separate absolute directories:
  14 PASS / 0 FAIL in both, raw trace
  `sha256=04e394a69a8508ab127ab206f713b87e8f590f799eb09d9ab130c63c5428cceb`
  — byte-identical between directories, to the working-tree replay and to the
  brief. Normalized tail: `asan_write=WRITE of size 9000`,
  `asan_frame=pins/sasl_io.c.vuln:456`, `declared=9000`, `chosen=8488`,
  `checks=14`, `failures=0`. Witness replay requested separately; no verdict
  in hand at admission.
- Rungs 1/2/3 on verbatim pinned upstream ranges under `#line`: declared 9000
  into the 512-byte buffer, 511/512 clean and 513 faults; ASan
  `heap-buffer-overflow`, `WRITE of size 9000` at pinned
  `sasl_io.c.vuln:456`, 0 bytes after a 512-byte region. Fixed and benign
  controls clean.
- Rung 4 INSTRUMENTED only, with preserved negatives. In a 1 MiB zeroed
  collaborator chosen `0x5a` and `0x41` bytes appear at offsets 0-8487, a
  benign run writes none, and a guard-mapped object faults on the byte past
  the object (exit 77). The collaborator and guard page are instrumentation,
  not stock allocator properties. No pointer, return address, heap-metadata
  field, function pointer, control-flow diversion or marker execution was
  observed or attempted.
- **Caveats at admission**: post-auth only — a successful SASL bind with
  `SSF > 0` (Kerberos/GSSAPI or DIGEST-MD5) is required, so this is *not*
  pre-auth. The advisory claims DoS/server crash, not code execution. The
  512-byte receive-buffer size is the advisory's account; the real caller's
  `len` is UNKNOWN. No fixed semantic-version pin. UNKNOWN: live-daemon
  reachability, shipping allocator behavior, any valid-address retargeting
  or post-write control.
- Admission rationale: all five standing-approval #6 evidence elements are
  present (pinned advisory/CVE, affected range plus fix commit, attacker-
  controlled heap write, rung-4 plausibility, byte-controlled corruption),
  consistent with other gated admissions; it does not lower the bar for
  future targets.

Cheapest next rung: build the vulnerable pinned parent with ASan, configure a
loopback 389-ds instance with a DIGEST-MD5/GSSAPI user, perform the SASL bind
with `SSF > 0`, send the upstream test's 9000-byte padded plaintext UNBIND on
the raw socket FD, and capture the daemon ASan frame plus the real heap layout
around the 512-byte buffer; repeat at the fixed commit for the guard. Only an
observed pointer or control-flow result would drop INSTRUMENTED. All probes
bind 127.0.0.1 only.
