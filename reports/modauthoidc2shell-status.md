# modauthoidc2shell — status

Admitted 2026-11-23 ~06:2xZ under standing approval #6 as the 103rd engine
route. Frontier staged this lane in W139 with byte-exact pinned upstream blobs,
a real fix commit and a released fixed version. Brief:
`reports/frontier-modauthoidc2shell.md`; pins, verbatim slices, hashes and raw
evidence: `lab/frontier/modauthoidc2shell/PROVENANCE.md`. The two-pane inner
tmux window 107 was already live and registered (frontier verified both panes
at 06:16Z), so admission created no second window and changed no registry
entry. The hy4-flash `max_parallel: 3` route was added; the path, debounce and
`@modauthoidc2shell` slice drop-in were minted with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@modauthoidc2shell.service` and
`m2shell-wake-modauthoidc2shell.path` were added to the site's owner resolver
map. The pinned full-flag doctor returned rc 0, `PASS local plant out of Git` /
`GREEN`, and `check-omp-only.py` returned GREEN with 103 declared roles.
Admission changes no grade.

- Claim: CVE-2026-54789 / GHSA-vgr5-qcpp-x2pr (CNA GitHub_M, HIGH 7.5
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-125 + CWE-787);
  mod_auth_openidc `< 2.4.19.4`, fixed by upstream commit
  `8017478471cc071c49aa073c5c9be652a73a8630` and released in `v2.4.19.4`.
  Byte-exact pinned blobs: parent `state.c.4301b536`
  `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`, fix
  `state.c.8017478`
  `3492207546885aae00363de14b30947ce73c48b8361b33516d95fc6df774c1cc`, release
  `state.c.v2.4.19.4`
  `f02d8ddb60927b9da1402c6430d179e4418ff6751ecda6c78db34424ccf77ce5`.
- Primitive: an unauthenticated client sends a `Cookie` token beginning with
  `mod_auth_openidc_state_` but containing no `=`. In
  `oidc_state_cookies_parse_token()` the loop `while (cookie != NULL && *cookie
  != OIDC_CHAR_EQUAL) cookie++;` (pinned parent lines 214-215) can only exit on
  `=`, because the pointer is never reassigned to NULL; line 219 then writes
  NUL at that out-of-bounds offset. Callers `handle/request.c:132` and
  `handle/response.c:353` run before state validation.
- Evidence: `lab/frontier/modauthoidc2shell/harness/run.sh` re-extracts the
  record struct and the whole parser verbatim from all three pinned blobs on
  every run, checks two SHA-256 manifests (12 files), and builds plain plus
  gcc/clang ASan variants. Frontier recorded 59 PASS / 0 FAIL three times plus
  a clean-directory replay and a clean `git archive HEAD` replay. Operator
  replay from `git archive HEAD lab/frontier/modauthoidc2shell` in a fresh
  `/tmp` directory returned rc 0, `PASS=59 FAIL=0` and exactly
  `TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`.

## Current grade — W147 witness ESTABLISHED (direct-call scope)

Rung 3 is confirmed in the verbatim pinned slice: gcc and clang ASan
`heap-buffer-overflow` `READ of size 1` at `state.c.4301b536:214`, 0 bytes past
a 31-byte exact-size token. The vulnerable slice scans past the token,
overwrites an adjacent `=` and dispatches the downstream cookie processor with
`PROCESS_CALLS=1`. Rung 4 is **scoped**: in the plain build the single NUL
store lands at chosen offsets 31, 47 and 63 with an intact canary. Only the
offset is chosen; the byte value is always NUL. Both the fix-commit and the
released `v2.4.19.4` slices reject the value-less token with `RC=0`, no
dispatch, the `=` byte intact and no ASan finding; a well-formed
`mod_auth_openidc_state_abc=1` token is clean on all six binaries.

## Ceiling

The direct-call harness uses stubbed request/config pointers and a recorder;
it has no Apache, APR pool, request object, listener, socket or wire. Its
exact-size heap token is an instrument; the ASan read faults before the write,
so no ASan WRITE is available in that build. W147 ESTABLISHED rungs 1-3 and
scoped rung 4 at that scope. A separate unwitnessed real-object probe (below)
uses real APR/Apache objects but still no module, listener or wire: the
grade stays rung 4 **scoped**. No pointer control, chosen command or rung 5.

## Real-object follow-up (2026-11-23)

`lab/frontier/modauthoidc2shell/realobj/driver.c` runs the verbatim parser
slice against a real `apr_pool_t`, a real Apache `request_rec` with an
`apr_table_t` Cookie header, a real `apr_pstrdup()` token and `apr_strtok()`.
`realobj/run.sh` re-extracts and hash-checks the slices/pins on every run and
builds six gcc variants. Two consecutive runs gave **PASS=17 FAIL=0**
(`realobj/evidence/run6-console.txt`, `run7-console.txt`; raw trials in
`raw-trials.txt`, counts in `summary.txt`). In 20 parent ASan trials per run,
the outcome was layout-dependent under ASLR: run6 saw 15 fault summaries at
pinned `state.c.4301b536:214`, 1 ASan-reported WRITE `SEGV` at pinned `:219`,
and 4 dispatches; run7 saw 9, 3 and 8. The first ASan-poisoned byte was 95
bytes past the token, never at its end: APR arena allocations have no
per-object redzone, so the scan continues to an arena edge, an adjacent `=`
or an unmapped page. Plain-build parent runs stored NUL at offsets 31, 47
and 63 with dispatch; fix and release slices rejected all 10 trials each with
no ASan report. No full module (no parent tree, jansson headers absent), no
Apache process, socket or wire; the `=` position is still harness-placed and
the probe has no witness verdict. A clean `git archive HEAD
lab/frontier/modauthoidc2shell` replay gave `PASS=17 FAIL=0` with 14
READ-class faults, 0 WRITE faults and 6 dispatches: the WRITE fault is
layout-dependent, not asserted. Full-module/loopback work would need those
provisioned dependencies; only a measured controlled pointer or command side
effect can change the grade. What would change the mind: the pre-auth call path
is unreachable on a real configuration, or the released fix misses the live
path. Do not relabel harness mechanics as remote compromise.

## Witness verdict (W147, 2026-11-23)

The witness replayed the lane from a clean `git archive HEAD` into two `/tmp`
trees, rebuilt with its own gcc/clang and ran `bash run.sh` three times
unmodified: rc 0, PASS=59 FAIL=0 and
`TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`
each time; the normalized trace was byte-identical across both tree paths. Its
separate full-block driver over token-to-`=` gaps 1, 2, 8, 16, 17, 33 and 64
found exactly one changed byte per vulnerable run (0x3d→0x00 at token length
+ gap, canary 0x5a intact); fixed and release slices changed 0 bytes with no
dispatch, and `abc=1` dispatched in bounds on all six binaries. Rungs 1–3 and
scoped rung 4 are ESTABLISHED at the labeled direct-call scope; no repair owed
and no rung 5. The external advisory text and the two pre-auth caller lines
were not source-bound in this lane and were not reproduced by the witness —
UNKNOWN, not upgraded.
