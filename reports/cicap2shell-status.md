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
  Frontier's clean-archive replay is recorded in commit `1ff81acb`. Witness
  replay #3733 returned ESTABLISHED AS LABELED (#3753, 17:59Z): clean
  `git archive 58435874`, `sh run.sh` 19 PASS / 0 FAIL rc 0, hash pins exact.
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

Rung 4 is PARTIAL: the wire-selected value (90, 72 or 4242) lands in the
live adjacent `trash_entities[0].start` slot, observed before the double free
and, in W4, inside the real ASan server (`alias=1`, `start=90/4242`).
No arbitrary byte stream, pointer/IP/command control, allocator metadata,
real proxy or command execution. W3 exercises the full
`parse_header()`/`process_request()` path in a real ASan c-icap server from
a loopback TCP request, including a 200 OK OPTIONS variant; no traffic left
loopback and no client or proxy consumed it. Stock layout is confirmed in
the pinned release (real `request.h:113-114`); 127.0.0.1 wire reach is
demonstrated only in the lab, wider deployment reach stays UNKNOWN, and
there is no rung 5. An ASan field-padding probe produced no report for the
intra-object alias and is preserved as a negative, not a pass.

W6 adds a measured negative at the rung-5 boundary: on a plain (non-ASan)
real 0.6.5 library the second destroy of the aliased entity reads
`type=21840 start=42031 entity=<free-list pointer>` for wire values 90,
72 and 4242 alike, so the chosen `start` is gone and the second `free()`
argument is glibc metadata, not wire input; no `malloc` occurs between the
two destroys. A plain real loopback server returns 200 OK to the crafted
OPTIONS request and then exits 139 at teardown. Other allocators/builds
remain UNKNOWN; grade and rung-4 ceiling are unchanged.

## Witness verdict (W205, #3753)
Independent replay from `git archive 58435874 lab/frontier/cicap2shell`
gave ESTABLISHED AS LABELED at the pinned-function scope: 19 PASS / 0 FAIL,
ASan `READ of size 4` use-after-free at `destroy_vuln.inc:10` on the object
freed at `:6` and printed as both `entities[5]` and `trash_entities[0]`;
plain attack `alias=1 trash0_type=2 trash0_start=90` / `72` then rc 139;
safe and both fixed modes `entities[5]=(nil)`, alias 0, rc 0, no sanitizer.
The witness's own sixth value `4242` produced `trash0_start=4242` and a
five-entity header stayed clean — wire-controlled, not a hardcoded value,
and the sixth entity is required. No contradiction, no grade change, no r5;
no c-icap build, wire socket, pointer/IP/marker or command was witnessed.

## Witness verdict (W211, #3953)

Witness W211 replayed the W7 offer #3938 from `git archive 8cdc4281
lab/frontier/cicap2shell` with the pinned local tarball and returned
ESTABLISHED AS LABELED at real-build scope. Unmodified `replay-all.sh`
gave `REPLAY_ALL_OK 72 PASS / 0 FAIL`, rc 0, in 96 s; four source pins and
the tarball hash matched. The witness's fresh output reproduced the alias
and chosen 90/72/4242, the `header.c:631` ASan UAF from
`ci_request_destroy request_common.c:417` in the real library and loopback
server, REQMOD 400 / OPTIONS 200 OK, W4's `e5_start=4242 t0_start=4242
alias=1` (safe and fixed `(nil)`), and W6's plain `type=21840 start=42031`
with zero mallocs between destroys. No contradiction, no grade change,
no r5: rungs 1-3 and rung 4 PARTIAL wire-chosen 32-bit `start` in a live
adjacent slot, with no pointer, IP, command or wire-shaped allocator
metadata. Other allocators and wider deployment reach stay UNKNOWN. This
closes #3794/#3776 (W1/W2/W3) and #3865 (W4). Detail:
`.mishe-tauftauf/artifacts/witness-wall-w211-detail.md` under the site home.

## Next bounded work

W1 reproduces the same alias, chosen value and `header.c:631` use-after-free
in a real ASan `C_ICAP_0.6.5` library; W2 feeds a complete ICAP request
through an `AF_UNIX` socketpair via exported read/unpack/parser functions.
W3 starts the real ASan `c-icap` server on 127.0.0.1 with its echo service:
six-entity REQMOD reaches `parse_header request.c:529` and ends in the same
UAF at teardown, while an OPTIONS request with six entities and
`Connection: close` returns 200 OK before firing it on graceful shutdown.
Four-entity, one-entity valid and patch-derived fixed controls are clean;
an OPTIONS request without `Connection: close` shuts down cleanly because
keepalive clears it; W4 adds the gdb-observed alias/value read in that same
server. The four real-build lanes were author-measured here; witness W211
(#3953) above replayed them from a clean archive and returned
ESTABLISHED AS LABELED. GitHub has no 0.6.6 tag, so the fixed control is
patch-derived, not a released binary. W7 adds
`lab/frontier/cicap2shell/replay-all.sh`: one
command from a clean archive provisions and hashes the pinned tarball,
builds all three trees and asserts `sh run.sh` plus W1/W2/W3/W4/W6; the
author clean-archive receipt (commit `44c7baa7`) is 72 PASS / 0 FAIL. This
supersedes the per-lane setup assumptions in the #3794 and #3865 offers:
one witness run of that script covers both asks. That replay is now closed
by W211 (#3953); do not infer RCE from advisory prose or a harness marker.

W8 verified the self-fetch path of that one-command replay from the same
clean archive with `CICAP_TARBALL` unset: `REPLAY_ALL_OK 72 PASS /
0 FAIL`, rc 0. A witness needs no author-local tarball or build tree;
full command and hash receipt in `PROVENANCE.md` §W8. No grade change;
W211 above used that path with an author-provided pinned tarball.
