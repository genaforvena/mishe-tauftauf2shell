# kermit2shell — status

Admitted 2026-11-21 ~10:0xZ by the operator under standing approval #6 on
frontier handoff #758 and commits `96c03bb`, `ddbcb5e`, `59cfe1f`, `782fb64`;
brief [frontier-kermit2shell.md](frontier-kermit2shell.md). Claim sources:
CVE record `CVE-2026-129126` (CNA VulnCheck, published 2026-11-13, updated
2026-11-16, CVSS 4.0 9.2, CWE-122, pin `6c43f2b7…`) and GitHub Advisory
`GHSA-c5px-7h4c-gj8p` (pin `96477695…`). Affected: C-Kermit before 11.1.515;
pinned vulnerable tag `v11.0.514`, fixed tag `v11.1.515`, fix commit
`37e54720779237897bc6887efac42fe138817897` (pin `2f25c8d7…`). Every URL and
digest is in `lab/frontier/kermit2shell/PROVENANCE.md`. External claims stay
claims; the lab evidence below is what is graded.

- Harness: `cd lab/frontier/kermit2shell && ./run.sh out`. `gen_driver.py`
  verifies all eight pin hashes, extracts both `putsrv()` bodies verbatim
  under `#line` and aborts on drift; gcc `-O0 -g -std=c99`, ASan and plain
  variants. Latest: **18 PASS / 0 FAIL**, trace
  `sha256=f74a088605aba49a48108705fafe151d61d283c04e248836a81f6ca8e4978cc5`.
- Operator admission replay at ~09:56Z: two clean `git archive HEAD
  lab/frontier/kermit2shell` extractions at `782fb64` into separate absolute
  directories (`/tmp/kermit-replay-a`, `/tmp/kermit-replay-b`), each
  18 PASS / 0 FAIL with trace
  `sha256=f74a088605aba49a48108705fafe151d61d283c04e248836a81f6ca8e4978cc5`
  — byte-identical between directories, to the working-tree `out/trace.txt`,
  to the brief and to PROVENANCE. Handoff #758 quoted `0de1067b…`, the
  pre-normalization value superseded by peer commit `59cfe1f`; not a replay
  contradiction.
- Rungs 1/2/3 on verbatim pinned bytes in a synthetic frame: 98 repeat
  triplets × 94 = 9212 decoded characters into an exact `MAXRP+1 = 9025`-byte
  `srvcmd` faults; exactly 9024 is clean and 9118 faults. `emitted=9212
  srvcmdlen=9024 oob=188` with `decode_rc=0` while the fixed build returns
  `decode_rc=-1 first_reject=9024 oob=0`. ASan reports
  `heap-buffer-overflow`, `WRITE of size 1` at `pins/ckcfns.c.vuln:461` in
  `putsrv()`, 0 bytes after a 9025-byte region. Fixed and benign controls
  are clean.
- Rung 4 INSTRUMENTED only, with preserved negatives. In a 1 MiB zeroed
  collaborator, chosen `0x5a` and `0x41` read back identically at offsets
  9024–9151 (128 bytes); bytes at 9152–9211 are inferred from
  `emitted=9212`, not read back (witness nit #763). Benign decode writes 128
  zeros and a guard page faults (139). No pointer, return address, function
  pointer, allocator metadata, control-flow diversion or execution was
  observed or attempted; the collaborator and guard page are instrumentation.
- Witness #763 (09:52Z): rungs 1/2/3 ESTABLISHED AS CLAIMED and rung 4
  ESTABLISHED AS CLAIMED at INSTRUMENTED chosen-byte control, replayed from a
  clean `git archive` of `96c03bb`; all eight pins verified. Grade-affecting
  conditions: extracted verbatim-pin driver in a synthetic frame, no built
  `wermit` daemon, no real packet path, no pointer or control-flow claim.
  Two nits, grade unaffected: the generic repeat-call branch is
  `ckcfns.c.vuln:1479` with `(*fn)(a)` at `:1486` (the brief cites the
  putfil-only fast path at `:1420`), and the observed chosen-byte readback is
  128 bytes, not the full 188 inferred from `emitted`. No replay owed.

Caveats recorded at admission: no `wermit` build or live server; real
packet-length limits, `xunchar()` encoding constraints, DYNAMIC vs static
`srvcmd` allocation and live-daemon reachability are UNKNOWN; the handoff's
hand-built harness proves pinned C logic, not a shipping daemon. Admission
rests on the five #6 elements (pinned claim, affected/fixed version pins,
attacker-chosen heap write, rung-4 plausibility, byte-controlled corruption);
it does not lower the bar for future targets. Window 44 is pre-created and
registered; wake trigger units and presentation stay owed from the person's
full-flag sync (`docs/runtime-pin.md`), never a bare `mishe sync`.

Cheapest next rung: build vulnerable `v11.0.514` `wermit` with ASan, start a
loopback Kermit server, send a repeat-compressed server-command packet with
`set send packet-length 4000`, capture the daemon ASan frame at `putsrv`,
then repeat against `v11.1.515`. If the packet path, repeat decoder or
allocator blocks chosen bytes from persisting, preserve the negative and cap
at rung 3. Evidence: [the brief](frontier-kermit2shell.md) and
`lab/frontier/kermit2shell/PROVENANCE.md`.
