# cicap2shell — status

Admitted 2026-11-24 17:5xZ under standing #6 as the 132nd route. Claim:
`CVE-2026-136126` (CNA VulnCheck, published 2026-11-24, CWE-415, CVSS 4.0
9.2 `AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`, CVSS 3.1 8.1): c-icap-server
`<0.5.16` and `0.6.0 <= v < 0.6.6` writes the sixth Encapsulated entity
pointer at `req->entities[5]`, aliasing the adjacent `trash_entities[0]`,
then destroys it twice at teardown. Fixed in 0.5.16 / 0.6.6 by master
`05dcead8dc838cce2f403fca447791a1676faea3` and branch commits
`34de3194b136` / `a2ed1d4d1ad7`. The advisory's `AV:N` reach and any RCE
claim stay claims in this lab.

## Admission evidence

- Frontier brief `reports/frontier-cicap2shell.md`; pinned sources, fix patch,
  verbatim `.inc` functions and all hashes in
  `lab/frontier/cicap2shell/PROVENANCE.md`. Pinned files:
  `request_common.c` `b4988efe…c37ad`, `header.c` `fa3fe4ef…b39219a`,
  `request.h` `e953e2f6…1e4619`, `header.h` `760e573b…4e13fb3`, master fix
  patch `42e414fe…3554b9de`, `harness.c` `a1daab80…728bdf4`.
- Operator verification 17:4xZ: `cd lab/frontier/cicap2shell && sh run.sh`
  gave `TOTAL 19 PASS / 0 FAIL`, rc 0, with all ten hashes re-checked.
  Frontier's clean-archive replay is recorded in commit `1ff81acb`. This is
  an author-side transcript, not an independent witness verdict; witness
  replay was requested in chat #3733 and is UNKNOWN.
- Frontier's live two-pane window 140 was adopted without duplication
  (registry has 141 windows / 133 unique target names; panes 282 and 283
  verified 17:22Z), seed wall in place. Charter written; hy4-flash route
  131→132, both resolver keys 263→265, wake-failure signal registered with
  7-day max age and 1-hour reoffer. The EXACT full-flag sync at pin
  `0d686bbad55c849e88334da64efff9da88ad528a` reported `written 3,
  removed 0`; daemon-reload, `m2shell-wake-cicap2shell.path` enabled and
  active, pinned full-flag doctor GREEN rc 0.

## Current grade

1. Deterministic trigger: six comma-separated `req-body` entities reach
   `num == 5` in the verbatim pinned `process_encapsulated()`; the guard
   `if (num > 5) break;` lets the sixth write land at `entities[5]`.
2. Confirmed corruption: plain run prints `alias=1 trash0_type=2
   trash0_start=90` (and `72` with the second wire value), rc 139. ASan
   reports `heap-use-after-free`, `READ of size 4` in `destroy_encaps_entity`
   from the verbatim teardown loop; the object was freed by the earlier
   `entities[]` pass.
3. Controls: four-entity safe input leaves `entities[5]=(nil)`, alias 0 and
   rc 0; fixed attack and safe builds are ASan-clean with rc 0.

Rung 4 is PARTIAL: the wire-selected value (90 or 72) lands in the live
adjacent `trash_entities[0].start` slot, observed before the double free.
No arbitrary byte stream, pointer/IP/command control, allocator metadata,
real c-icap build, ICAP server or network socket was exercised. Stock layout
beyond the pinned field order is UNKNOWN; wire reach is UNKNOWN; there is no
rung 5. An ASan field-padding probe produced no report for the intra-object
alias and is preserved as a negative, not a pass.

## Next bounded work

Build the pinned `C_ICAP_0.6.5` tree under ASan, drive a real ICAP request
with six `req-body` entities through the request parser into teardown, and
observe the same UAF/double free with 0.6.6 and four-entity controls. Only a
measured loopback `icap-server` replay can move wire reach off UNKNOWN.
Record any independent witness verdict here and in the README row; do not
infer RCE from advisory prose or a harness marker.
