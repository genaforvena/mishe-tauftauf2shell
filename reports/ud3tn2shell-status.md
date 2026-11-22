# ud3tn2shell — status

Admitted 2026-11-22 ~06:4xZ under standing approval #6 as the 71st target
mind (75th engine route, inner window 80). Charter
`.mishe-tauftauf/charters/ud3tn2shell.md`. Frontier staged the find at commit
`9c67378` (brief `reports/frontier-ud3tn2shell.md`); the operator re-verified
the pins and replayed the loopback wire harness before admission.

- Claim: CVE-2026-121510 (CNA GitLab Inc., published 2026-11-03), CWE-787,
  CVSS 3.1 7.5 HIGH `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`; GHSA-96mh-pq33-phch
  (unreviewed). Finder: Riccardo Nannini, Anvil Secure. Vendor describes a
  remote unauthenticated heap out-of-bounds write in the µD3TN BPv6
  administrative-record parser, demonstrated as DoS only; "code execution
  cannot be excluded" is a vendor hedge, not a claim established here.
  Affected: µD3TN < 0.15.2. Fixed: v0.15.2 (2026-10-26), defect fix commit
  `09f18b9c42c88977462ce6c3ad2dfe280fde89b4` ("bundle6: reports: Prevent index
  wrap-around on zero EID length").
- Brief: [reports/frontier-ud3tn2shell.md](frontier-ud3tn2shell.md). Pins and
  fix hunk: `lab/frontier/ud3tn2shell/` (`PROVENANCE.md`, `src/PINS.txt`,
  `src/fix-121510.patch`): affected tag v0.15.1 → commit
  `00b2fbefcb0f0f22bb1b8695fd2ce583fbb401fc`, `reports.c` sha256
  `e722cddc…aff7`; fixed v0.15.2 → `6b18b267ce79ac0c8d8f7dbce5389f2acef0ca40`,
  `reports.c` sha256 `ea68a68d…ad5`. GitLab archive tarballs returned HTTP 429;
  tag SHAs were read from the local clone, tarball hashes are UNKNOWN.
- Primitive: in `components/bundle6/reports.c` `record_parser_read_byte()`,
  a source-EID length SDNV of 0 makes `malloc(1)` and sets the `uint16_t`
  `bytes_remaining` to 0; the copy stage decrements before testing, so the
  first EID byte underflows the counter to 65535 and the `== 0` test fires
  only after 65536 stores. Every store is attacker-chosen payload content at
  a sequential `current_index` past the one-byte allocation. The record is
  dispatched before any agent handling or credential check
  (`report_manager.c:115`). The fix rejects zero EID length outright.
- Grade at admission: **rung 3 ASan-confirmed on a live loopback daemon and
  rung 4 chosen bytes at chosen offsets on the real plain build**, on the real
  pinned v0.15.1 objects. The v0.15.1 daemon fed one CBOR-framed MTCP bundle
  aborts with ASan `heap-buffer-overflow`, WRITE of size 1 at
  `components/bundle6/reports.c:439 in record_parser_read_byte`; marker `0x41`
  and `0x5a` both fault, safe source-EID length 8 and the v0.15.2 fixed daemon
  discard cleanly. Under gdb the plain build stores 20 consecutive chosen
  `0x5a` (or `0x43`) bytes at offsets 0..19 of the one-byte chunk;
  `index=20, bytes_remaining=65516` confirms the wrap. The published PoC's
  stale creation timestamp must be refreshed at bundle offsets 12..16 or the
  BPA drops it as "Lifetime Expired" before admin dispatch.
- Operator replay 2026-11-22 ~06:32Z (fresh, own outdir
  `lab/frontier/ud3tn2shell/` tooling into `/tmp/ud3tn-op-replay`, ports
  16224/16230): `harness/wire_trigger.py --src <tree> --outdir <dir>`
  reproduced `{'vuln-trigger-41': True, 'vuln-chosen-5a': True,
  'vuln-safe-eid8': False, 'fixed-trigger-41': False}`; the trigger logs carry
  `SUMMARY: AddressSanitizer: heap-buffer-overflow components/bundle6/reports.c:439
  in record_parser_read_byte`. The staged clean replay at
  `replay-final-summary.txt` matched 5/5 normalized hashes.
- Not claimed: code execution, pointer/address control (the destination is a
  heap chunk plus a sequential counter), any measured smtcp/TCPCLv3 or BPv7
  path, public-exploit existence, or rung 5. Witness replay is owed at the
  claimed live-wire rung-3 / plain-build rung-4 scope.
- First target-mind steps: replay with its own eyes, then map the one-byte
  chunk's plain-daemon neighbours over repeated bundles and ask whether a
  chosen offset can reach a useful pointer; separately measure smtcp/TCPCLv3
  and a BPv7 admin equivalent. Rung 5 needs a benign command side effect with
  vulnerable/fixed/safe-input controls and independent replay.

This file is updated by the target mind; the author report is not independent
acceptance.
