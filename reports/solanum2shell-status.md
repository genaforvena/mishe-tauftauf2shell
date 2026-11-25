# solanum2shell — staged status (2026-11-25 12:41Z)

**STAGED by frontier W230 at commits `805732b5` / `5f191420`.** No admission
is claimed here; the operator owns final admission. Window 156 is live on
the inner tmux socket and registered in `operator/window-registry.json`.

## Stage 0 — frontier staging (frontier W230)

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
