# aspell2shell — admitted research lane (2026-11-25 18:1xZ)

**ADMITTED by operator under standing #6 as the 150th declared target mind.**
The staged technical evidence is preserved below. Window 157 was already
live and uniquely registered; it was adopted, not duplicated. Both resolver
keys are registered. Engine-route registration and the three generated wake
units remain UNKNOWN: engine-config changes and full-flag sync are
person-reserved, so this admission does not claim route or operational unit
delivery. Brief: `reports/frontier-aspell2shell.md`; evidence:
`lab/frontier/aspell2shell/PROVENANCE.md`.

## Stage 0 — frontier staging (preserved)

- CVE-2026-75818 / CERT Polska 2026-10-06, CWE-122 heap-based overflow in
  GNU Aspell before 0.60.8.3 `prog/prezip.c` `ADV()` macro; CNA CVSS4 1.8
  LOW `AV:L/AC:H/PR:N/UI:A` (availability-shaped claim).
- Vulnerable pin parent `bc7ffcb1473578fbaa95653c08e6f1237decd568`, fix
  `15b188437f9e0192d4ac4472ad66a4e2f62a782f` (+4/-3). Both full
  `prog/prezip.c` files pinned verbatim, sha256 in
  `lab/frontier/aspell2shell/pins/SHA256SUMS`.
- Mechanism: `ADV(w, c)` sets `ret = 3` on an embedded NUL but keeps
  walking; crafted `02 1e ff ff 41 <chosen> 1f ff` stream walks 605 bytes
  from a 256-byte heap allocation. ASan `READ of size 1` at pinned `:173`,
  fixed pin rejects cleanly.
- `bash lab/frontier/aspell2shell/harness/run-all.sh` = 14 PASS / 0 FAIL,
  GCC+Clang ASan vulnerable vs fixed and encoder-round-trip safe controls;
  clean `git archive HEAD` replay = 14 PASS / 0 FAIL.
- Grade at staging: rung 3 ASan OOB read in the verbatim full pinned
  program; rung 4 NOT CLAIMED (no chosen bytes at a chosen destination);
  no real build, dictionary consumer, wire path, pointer target, command
  or R5. Witness UNKNOWN; replay owed before any rung-4 claim.
- Sibling CVE-2026-75820 pins (`writable.vuln.cpp`/`writable.fixed.cpp`,
  `WritableDict::add` length truncation to one byte) provisioned for a
  possible chosen-byte-write lane, unworked this wake.

## Next for the target mind

1. Hash-check pins; replay `harness/run-all.sh` from a clean archive.
2. Build real Aspell 0.60.8.2 and 0.60.8.3 under ASan; drive a crafted
   prezip dictionary through the real spell-checker load path with
   vulnerable/fixed/safe controls.
3. Investigate whether the OOB read reaches a dereferenced pointer or
   whether the follow-on store can be steered. If not, open the provisioned
   CVE-2026-75820 truncation lane, which offers file-chosen word bytes.
4. Ask the witness to replay before publishing any rung-4 claim. No probe
   off loopback; no external systems.
