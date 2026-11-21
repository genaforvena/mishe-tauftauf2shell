# Iondtn2Shell — frontier brief

## Claim (verified ground truth from public sources, read only)

- Maintainer advisory **GHSA-gmhw-vmwr-wrxh**, "Remote AMP Values Overflow
  Fixed-Size NM Manager Formatting Buffers", published 2026-11-07, High 7.5,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.
  <https://github.com/nasa-jpl/ION-DTN/security/advisories/GHSA-gmhw-vmwr-wrxh>
- VulnCheck advisory and **CVE-2026-123999** describe a matching mechanism
  (unbounded `strcat` while rendering nested AMP values in `nm_mgr`) with
  CVSS v4 8.7, also availability-only (`VA:H`, `VC:N/VI:N`).
  <https://www.vulncheck.com/advisories/ion-dtn-heap-buffer-overflow-via-nm-mgr-amp-rendering>,
  <https://www.cve.org/CVERecord?id=CVE-2026-123999>.
  **Claim conflict preserved:** the GHSA metadata says "No known CVE" while
  VulnCheck assigns one to a matching description. Neither is an observation
  from this plant.
- Affected/fixed: GHSA `3.6.2 <= 4.2.0`, patched `4.2.1-a.2`. Upstream release
  notes call 4.2.1-a.2 a security-hardening alpha and list the NM formatter
  heap OOB write explicitly.
- Reachability gate from the advisory: the remote path runs through the UDP
  CLA/AMP path only when file logging and parsed-report logging (`-l -r`)
  are enabled; both are disabled by default. Without that, the flaw is
  reachable locally through interactive UI rendering. Availability-only
  impact is claimed: crash of `nm_mgr`, halting telemetry collection.

## Mechanism, read from the patch — not from exploit narrative

Upstream fix commit `4b158b64211ad399a00be4215dd81de2f4767d1e` (parent
`ccde6a38ea95517ff2d5af3ca63daaf1db03f340`), "Fix (NM): Enhance bounds
checking in AMP string formatters", changes only
`nm/mgr/nm_mgr_print.c`. In `ui_str_from_ac()` at the affected release:

```c
char *str = STAKE(1024);
for(it = vecit_first(&(ac->values)); vecit_valid(it); it = vecit_next(it))
{
    ari_t *id = (ari_t*) vecit_data(it);
    char *alt_str = ui_str_from_ari(id, NULL, 0);
    strcat(str, (alt_str==NULL) ? "null" : alt_str);
    strcat(str, " ");
    SRELEASE(alt_str);
}
```

`STAKE(1024)` is a 1 KiB heap allocation. Each rendered AMP value is appended
with two unbounded `strcat()` calls and no running length or capacity check,
so a sufficiently long or deeply nested value list writes past the end of the
allocation. The same commit hardens `ui_str_from_mac()` (4 KiB) and
`ui_str_from_tbl()` (8 KiB) with the same capacity-tracked pattern; those
siblings are out of this brief's local scope. The fix replaces concatenation
with `istrlen()`/`istrcat()` and returns NULL after `putErrmsg()` when the
remaining capacity is exhausted.

## Pins and local harness

Byte-exact source is pinned from the two release tags, not reconstructed:

| pin | commit | sha256 of `nm/mgr/nm_mgr_print.c` |
| --- | --- | --- |
| affected, tag `ion-open-source-4.2.0` | `568df887cb9f18aa8ec013b1a566d83215e499ae` | `31b9673ccc2573da71156cca7139bdf962d718044acb0cbe9bbac7077dd12127` |
| patched, tag `ion-open-source-4.2.1-a.2` | `54d4b1f0b647e0cb7dfc558651777a042acf5e38` | `c2abf2d0ff0031bb191706bc1cebb35aa680379d779b301f7a25aef1ab06084d` |

The affected-tag file is byte-identical to the fix parent's file, so no
intervening edit contaminates the A/B comparison. Full fetch method, commit
metadata and harness boundary are in
`lab/frontier/iondtn2shell/PROVENANCE.md`.
`lab/frontier/iondtn2shell/run.sh` verifies both hashes and the exact line
positions (548 function start, 550 `STAKE(1024)`, 557/558 `strcat`; fixed
564 capacity check, 570 safe append) before compiling. `driver.c` includes
verbatim pinned lines 548–563 / 543–588 under `#line` directives;
collaborators are stubs. No production statement is reimplemented, no daemon,
socket, AMP payload or UI is created.

## Evidence ladder (observed 2026-11-21 ~05:22Z)

Working-tree replay of `bash lab/frontier/iondtn2shell/run.sh <outdir>`:
**26 PASS / 0 FAIL, `ALL CHECKS PASSED rc 0`**, trace
`sha256=e9bc1ffffb7ba2bc39b5c3c26cf29a4c1cf0f8f96160a92cc979326f29d38f71`
(canonical lines only; ASan PID/address/path text excluded). A clean
`git archive HEAD` replay is recorded below.

- **Rung 1 (reproducible trigger)** — 18 rendered values of 80 bytes each
  make the verbatim loop write `18 × 81 = 1458` bytes into a 1024-byte
  `STAKE` buffer: `LAYOUT stake_len=1024 values=18 value_len=80 written=1458
  overflow=434 calls=1`.
- **Rung 2 (observed state failure)** — `CAPTURE returned=nonnull
  result_is_arena=1 returned_len=1458 first_changed=0 state_failure=1`: the
  first byte past the 1024-byte allocation changes from its pre-call value
  and the returned string is longer than the allocation.
- **Rung 3 (ASan-confirmed corruption)** — `heap-buffer-overflow`,
  `WRITE of size 81`, frame `ui_str_from_ac` at the real pinned
  `nm_mgr_print.c:557`, allocation site at pinned line 550, victim is the
  1024-byte region, access 0 bytes past its end.
- **Rung 4 (INSTRUMENTED)** — the 8-byte token `ION2SHL!`
  (`494f4e3253484c21`) is read back byte-exact at write offsets
  1024/1088/1152/1280/1408, with `chosen_offset` equal to each request.
  The patched 4.2.1-a.2 block with the same input returns NULL before
  overflowing (`puterr=1`), leaves the adjacent region unchanged
  (`first_changed=18446744073709551615`) and never reaches the token
  (`FIXED_NO_WRITE marker_never_reached=1 victim_unchanged=1`).
  **No live `nm_mgr`, socket, UDP CLA/AMP payload, interactive UI, useful
  pointer control or execution.** Chosen-byte control is observed only in
  the instrumented harness allocator's adjacent region.

## Rung-4 feasibility assessment

What helps: the write is unbounded concatenation of attacker-influenced
rendered values with no length clamp, so chosen bytes reach well past the
allocation; the primitive is heap, not stack, and the patched version gives
an unambiguous A/B control; the advisory claims network reach with no
privileges.

What caps it: (1) the remote path needs the non-default `-l -r` logging
flags, otherwise only local UI rendering is claimed; (2) both primary
records are availability-only (`C:N/I:N`, `VA:H`) — no confidentiality or
integrity impact is claimed; (3) all rungs here run stubbed collaborators in
a lab process, so AMP wire reachability and real heap adjacency stay claims;
(4) modern glibc heap metadata sits between adjacent user chunks, so a
chosen-byte write into a neighbouring live object is not established by
these runs.

**Cheapest next rung:** build ION-DTN 4.2.0 `nm_mgr` under ASan, start it
loopback-only with `-l -r`, send a deeply nested AMP report whose rendered
value list exceeds 1 KiB, and capture the real ASan frame at pinned line
557 plus the wire bytes that produced it. That promotes remote reachability
from advisory claim to observed bytes and shows what the real allocator
places after the 1024-byte region.

## Handoff

Two required artifacts for a find: this brief and a live registered two-pane
`iondtn2shell` window. Window creation and registry entry are recorded at
yield time; the operator owns admission.
