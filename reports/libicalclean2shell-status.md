# libicalclean2shell — admitted status (W301, 2026-11-27)

Admitted by the operator at 00:5xZ under standing #6 as the 194th declared
target mind: claim sources CVE-2026-134761 (CNA VulnCheck, published
2026-11-22) and GHSA-p95w-9p65-m226, CWE-415, CVSS 5.8 v4.0/v3.1, affected
`< 4.0.7`. Vulnerable representative v4.0.6 is
`9cfca65c122fa23b9680a28e0c9225a2fd015fc5`; fixed v4.0.7 is
`cb58c3cb287bee48aa50cc60753155116a8f9081`; ownership fix is `6c48980a`.
No duplicate CVE, GHSA or sink lane existed at staging. The dedicated
two-pane window 202 was adopted as-is (panes %410/%411, dead=0, one registry
entry, 204/204 unique names). Author evidence is not self-acceptance; the
independent witness replay is now closed (W301, below).

Truncated iCalendar leaves an open component. Vulnerable `icalparser_clean()`
returns `parser->root_component` without clearing it; the documented caller
frees the return value, then `icalparser_free()` frees it again.
Fixed v4.0.7 saves the result locally and clears the parser field.

Registered grade: **R1 ✓ / R2 ✓ / R3 ✓ / R4 LIMITED / R5 —**.
R4 is limited to a local public-API mechanics harness: a chosen nonzero
`parent` at offset 48 of a reclaimed 72-byte component selects a benign
early-return branch. No arbitrary code execution, pointer dereference, wire
path or command was observed.

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
- `sh run-all.sh`: **PASS=57 FAIL=0**, rc 0; clean-archive replay from
  `1c6f8cf1` with runs/sources/builds removed also PASS=57 FAIL=0. Runner SHA-256
  `91869a1a6081679fde87b195abef85d6c02c044ff415685d91ffedf63e29b300`.

Brief: `reports/frontier-libicalclean2shell.md`. Harness and pin provenance:
`lab/frontier/libicalclean2shell/PROVENANCE.md`. The 3.0-series fixed release is
UNKNOWN; no remote or live-consumer claim exists.

## Operator clean-archive admission replay (00:5xZ)

From `git archive e7bd221e lab/frontier/libicalclean2shell` with `runs/` and
source/build directories removed: runner SHA-256
`91869a1a6081679fde87b195abef85d6c02c044ff415685d91ffedf63e29b300`,
14/14 file pins verified, unmodified `sh run-all.sh` rc 0, **PASS=57 FAIL=0**.
Fresh ASan observations match the brief: `READ of size 8` at verbatim raw
`icalcomponent.c:197` via `icalparser.c:117`, 48 bytes into a 72-byte
component; plain vulnerable `clean-free-destroy` rc 139; fixed v4.0.7 and
complete-input controls clean. The R4 harness reproduced `REUSE=1`, zero
rc 139 and chosen `0x4141414141414141` rc 0 with GDB observing the chosen
parent in the stale free.

## Witness replay (W301, 00:31–00:4xZ)

The witness closed #5934 ESTABLISHED AS LABELED at the exact labeled scope
(detail `.mishe-tauftauf/artifacts/witness-w301-libical/detail.md`): clean
archive at `e7bd221e`, runner sha256 `91869a1a…`, 14/14 pins, unmodified
`sh run-all.sh` rc 0 `PASS=57 FAIL=0` against freshly built pinned
v4.0.6/v4.0.7 static libical. R1/R2/R3 confirmed and R4 LIMITED reproduced,
including tcache reuse, the GDB-observed chosen parent word and the zero-case
fault inside the stale free path; fixed and complete controls clean, no
counterexample. No wire, arbitrary pointer dereference, code pointer,
command or grade change. R5 NOT ACHIEVED.

## Named next experiment (standing #7)

Find or build a real loopback consumer that parses attacker-supplied
iCalendar and follows the documented `icalparser_clean()` ownership contract.
Measure the vulnerable/fixed differential with attacker-influenced same-size
allocations between the caller's free and `icalparser_free()`; keep all
traffic on 127.0.0.1. A fixed 3.0-series release, if one appears, needs its
own pin. Do not promote the harness branch control to RCE without a live
vulnerable/fixed/safe command-execution chain.
