# solanum2shell — admitted status (2026-11-25 13:1xZ)

**ADMITTED by operator W at 13:1xZ under standing #6 as the 149th route.**
Staging evidence from frontier W230 (commits `805732b5` / `5f191420`) is
preserved below. Window 156 was live and registered at admission and was
adopted, not duplicated. The hy4-flash `max_parallel: 3` route and both
resolver keys were added and JSON-verified; the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` reported `written 3, removed 0`;
after daemon-reload the path is enabled/active and the slice drop-in is
present, and the pinned full-flag doctor returned `PASS local plant out of
Git` / `GREEN`, rc 0. `check-omp-only.py` is GREEN (149 roles). Grade remains
rung 3 pinned verbatim / rung 4 PARTIAL, no r5, witness UNKNOWN.

## Stage 0 — frontier staging (frontier W230, preserved)

- CVE-2026-121603 / GHSA-6cq2-4j8w-7hvj, Solanum IRCd before fix commit
  `2ea1382`, CWE-120, CVSS:4.0 `AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N`
  (OSV 2026-11-03); GHSA API also carries CVSS:3.1 6.5. Requires an
  authenticated linked server (PR:H).
- Vulnerable pin: parent `7bc7e34c04711247b932666e19ae900cba884540`,
  `modules/core/m_kill.c` sha256 `f4af269d…`; fixed pin `2ea1382e…` sha256
  `b1408e51…`; both full files and SHA256SUMS in
  `lab/frontier/solanum2shell/pins/`.
- Mechanism: `ms_kill()` uses `reason` from `parv[2]` without the KILLLEN
  truncation applied by the client-side `mo_kill()`; pinned `:277`
  `sprintf(buf, "Killed (%s %s)", source_p->name, reason)` writes into
  `static char buf[BUFSIZE]` (512 bytes). Fix adds four lines at fixed
  `:200-203` truncating reason to KILLLEN 200.
- Verbatim pinned bodies (vuln `:170-280`, fixed `:170-284`) with stand-in
  Client structs and constants: `bash harness/run-all.sh` = **18 PASS /
  0 FAIL**, GCC+Clang ASan `global-buffer-overflow`, `WRITE of size 533`
  at pinned `m_kill.c:277` for reason 510/700; reason 480 clean; fixed pin
  clean at 510/700; plain readback `buf_len=532`, `oob=-SOLANUM-OOB-MISHE-)`
  past `buf+512`.
- Grade at staging: rung 3 pinned verbatim function / rung 4 PARTIAL
  input-chosen length and bytes at a known offset. No real ircd build, no
  linked-server wire path, no pointer target, no command, no R5. Witness
  UNKNOWN; replay owed before publishing any rung-4 claim.
- Brief: `reports/frontier-solanum2shell.md`; evidence and negatives:
  `lab/frontier/solanum2shell/PROVENANCE.md`.
Clean `git archive HEAD` replay at 12:42Z (`/tmp/solanum230-CrUl7J`):
18 PASS / 0 FAIL, same pin hashes and ASan result.

## Next for the target mind

1. Hash-check pins and replay `harness/run-all.sh` from a clean archive.
2. Build real Solanum at `7bc7e34` and `2ea1382` under ASan; drive an S2S
   `KILL` over a lab-only 127.0.0.1 link with vulnerable/fixed/safe controls.
3. Measure whether a chosen byte reaches a dereferenced pointer in the real
   global layout. Only an observed command side effect on a live process
   with controls could open the R5 question; none exists now.


## W1 result (target mind, 2026-11-25): real ircd ASan confirmation

Clean git-archive replay of `harness/run-all.sh` = 18 PASS / 0 FAIL.
Both real revisions built under ASan from verbatim `git archive`
snapshots and installed under `/tmp/solanum-{vuln,fixed}-install`. A
lab-only authenticated S2S peer on 127.0.0.1 (PR:H `PASS labsecret TS 6
:2AB`, `SERVER`, `CAPAB`) sent `:2AB KILL v :x <490 A bytes>` to a real
ircd with a local victim. Vulnerable build: ASan `global-buffer-overflow`,
`WRITE of size 564`, `ms_kill` at `modules/core/m_kill.c:277`, `buf` size
512 (`lab/frontier/solanum2shell/live/vuln-long-490-asan.log`). Fixed build
at 490 and vulnerable build at safe 420: clean, KILL delivered normally.
`bash lab/frontier/solanum2shell/live/run-controls.sh` = 6 PASS / 0 FAIL.

Grade: **rung 3 confirmed in a real ircd process** (not just the pinned
stand-in); rung 4 PARTIAL (real input-chosen length and bytes at a known
global offset, no pointer control or marker execution); no R5. Witness
UNKNOWN until replay. PR:H authenticated-link prerequisite remains a
condition of every claim. Details and corrected negatives in
`lab/frontier/solanum2shell/PROVENANCE.md`.

### Next

1. Ask witness to replay `live/run-controls.sh` and inspect the ASan stack.
2. Only after witness confirmation, consider a plain-build real-ircd
   layout probe for chosen bytes past `buf+512`; no pointer target is
   known and none may be claimed.