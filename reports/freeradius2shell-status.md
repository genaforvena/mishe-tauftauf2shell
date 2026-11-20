# Freeradius2Shell status

Handed off from frontier 2026-11-20 ~17:20Z (DM to operator pending at
handoff). Dedicated two-pane window and two-pane restorer registry entry
exist; hy4-flash route is set. Charter and wake trigger unit are owed from
the operator/person. Everything below is inherited from frontier, not yet
re-run by this mind.

## Target

FreeRADIUS EAP-FAST SessionTicket stack overflow, CVE-2026-127030
(CWE-787, CVSS 3.1 7.5, `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). Red Hat marks
RHEL 10/9/8/7 affected; upstream vulnerable at master `3f802d74`, fixed by
commit `064567a08f3b9d9b4863fab6060fafe296ac7de9` (2026-10-14). Exact fixed
release number is UNKNOWN from the sources read — use the commit as the
boundary. EAP-FAST is optional and not enabled by default. Unowned at
handoff (no charter or target mind existed).

## Inherited, not yet re-run by this mind

- Rung 1 PASS: crafted local ticket `hdr.length=256`, `dlen=208` vs a 152-byte
  stack destination; deterministic. Digests and upstream commits in
  `reports/frontier-freeradius2shell.md`.
- Rung 2 PASS: chosen `0x4242...` observed at the saved-RIP slot
  (`orig → now`), plus `*** stack smashing detected ***` under the canary build.
- Rung 3 PASS: 208-byte write into the 152-byte stack structure observed by
  compiler canary and byte-exact state comparison; ASan blind because the
  write is in un-instrumented libcrypto (documented negative).
- Rung 4 PASS **in the standalone harness**: chosen address of
  `verify_marker()` at the chosen stack offset executes (rc 42), fixed build
  rejects the same ticket (rc 0). Conditions: faithful extracted function and
  struct, lab knows PAC-Opaque key. Real `radiusd`, network reachability,
  EAP-FAST config and key-unknown byte control are UNKNOWN, not lab facts.

## Open

- Reproduce with `bash lab/frontier/freeradius2shell/run.sh` from clean HEAD;
  no off-loopback probe.
- Replay against a loopback `radiusd` with EAP-FAST enabled; capture actual
  crash evidence and measure key-known vs key-unknown byte control.
- Preserve the fixed-build `PAC is too long (cap=148)` differential and the
  ASan-blind negative. File a witness claim with digests at cutoff.
- Evidence: `reports/frontier-freeradius2shell.md` (handoff commit pending).
