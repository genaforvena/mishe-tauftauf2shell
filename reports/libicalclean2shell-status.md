# libicalclean2shell — staged status (W300, 2026-11-27)

Staged by frontier from CVE-2026-134761 / GHSA-p95w-9p65-m226 (CNA VulnCheck,
CWE-415, CVSS 5.8 v4.0/v3.1, affected `< 4.0.7`). Vulnerable representative
v4.0.6 is `9cfca65c122fa23b9680a28e0c9225a2fd015fc5`; fixed v4.0.7 is
`cb58c3cb287bee48aa50cc60753155116a8f9081`; ownership fix is `6c48980a`.
The dedicated two-pane window 202 is live on the inner socket (panes
%410/%411, dead=0) and registered as one of 203 unique window names.

Truncated iCalendar leaves an open component. Vulnerable `icalparser_clean()`
returns `parser->root_component` without clearing it; the documented caller
frees the return value, then `icalparser_free()` frees the same pointer again.
Fixed v4.0.7 saves the result locally and clears the parser field.

Registered grade at handoff: **R1 ✓ / R2 ✓ / R3 ✓ / R4 LIMITED / R5 —**.
R4 is limited to a local public-API mechanics harness: a chosen nonzero
`parent` at offset 48 of a reclaimed 72-byte component selects a benign
early-return branch. No arbitrary code execution, pointer dereference, wire
path or command was observed. Operator admission and independent witness replay
are owed; author evidence is not self-acceptance.

## Measured evidence

- Unmodified public reproducer; clang 18.1.3 static v4.0.6/v4.0.7 builds.
- Eight vulnerable interrupted-input mode/shape combinations: ASan
  `heap-use-after-free`, `READ of size 8` at `icalcomponent.c:197` via
  `icalparser.c:117`; 72-byte component allocation.
- Fixed v4.0.7: all ten mode/shape combinations clean. Vulnerable complete
  input: clean.
- Plain vulnerable attack: rc 139, repeated three times. Plain safe input: rc 0.
- `rung4_reclaim.c`: exact tcache reuse (`REUSE=1`); zero offset 48 crashes,
  chosen `0x4141414141414141` survives; GDB observes the chosen `parent` in the
  stale consumer. Fixed zero/chosen controls survive and do not call the sink.
- `sh run-all.sh`: **PASS=57 FAIL=0**, rc 0; runner SHA-256
  `91869a1a6081679fde87b195abef85d6c02c044ff415685d91ffedf63e29b300`.

Brief: `reports/frontier-libicalclean2shell.md`. Harness and pin provenance:
`lab/frontier/libicalclean2shell/PROVENANCE.md`. The 3.0-series fixed release is
UNKNOWN; no remote or live-consumer claim exists.
