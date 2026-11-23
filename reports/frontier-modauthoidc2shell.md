# Frontier brief: mod_auth_openidc — CVE-2026-54789 (modauthoidc2shell)

**PROVISIONED, NOT STAGED — no harness, no rung, no target window.** Prepared by
`frontier` on 2026-11-23 W138 after staging mongoose2shell. Pins are byte-exact
and hash-verified; the harness and any window are work for a later wake. The
operator owns final admission.

## 1. Verified ground truth

- Claim: an unauthenticated client can send a Cookie token beginning with the
  state-cookie prefix (`mod_auth_openidc_state_` by default) but without `=`.
  `oidc_state_cookies_parse_token()` scans for `=` without checking the string
  terminator, reads past the token into adjacent memory and, if it finds `=`,
  writes a NUL there — out-of-bounds read and a one-byte write. GHSA advisory
  titled "Out-of-bounds read and write in state cookie parsing", HIGH 7.5,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-125 + CWE-787; affected
  `< 2.4.19.4`, patched `>= 2.4.19.4`.
- Sources: <https://github.com/OpenIDC/mod_auth_openidc/security/advisories/GHSA-vgr5-qcpp-x2pr>,
  <https://www.cve.org/CVERecord?id=CVE-2026-54789>,
  <https://osv.dev/vulnerability/CVE-2026-54789>,
  fix commit <https://github.com/OpenIDC/mod_auth_openidc/commit/8017478471cc071c49aa073c5c9be652a73a8630>.
- Fix: commit `8017478471cc` (2026-06-09, Hans Zandbelt), 3 files +22/-1, adds a
  `test_state_cookies_clean_no_value` unit test. Released in tag `v2.4.19.4`
  (release commit `cd1534e5`, 2026-07-01); `v2.4.19.3` still has the bad loop.
- Pins in `lab/frontier/modauthoidc2shell/src/` (SHA-256 manifest `SHA256SUMS`):
  - `state.c.4301b536` — parent of the fix, git blob
    `0122cde76014f077d349489eb6fca9273de6e45a`, sha256
    `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa`;
  - `state.c.8017478` — fix-commit blob
    `92bd078a3a4a079b6d4ee8f904b08e10473c16ec`, sha256
    `3492207546885aae00363de14b30947ce73c48b8361b33516d95fc6df774c1cc`;
  - `state.c.v2.4.19.4` — released fixed tag, git blob
    `13009c17da25d008d6d245a5133f8dd4158716e2`, sha256
    `f02d8ddb60927b9da1402c6430d179e4418ff6751ecda6c78db34424ccf77ce5`;
  - `fix-8017478.patch`, sha256
    `d8ae4b4e8cda366a985368bd885591d2aaa702b463d989b140a9621a226b3e38`.
  All blob ids were checked with `git hash-object` after download.

## 2. Source-bound mechanism and fix

Read from the pinned parent blob. `oidc_state_cookies_parse_token()` at
`state.c.4301b536:204-222`:

- Line 210 gates on the state-cookie prefix, which an unauthenticated client
  can supply verbatim.
- Lines 214-215 are the bug:
  `while (cookie != NULL && *cookie != OIDC_CHAR_EQUAL) cookie++;`.
  `cookie` is only incremented, never reassigned to NULL, so the NULL test is
  dead and the only exit is finding `=` beyond the token.
- Line 219 then stores `*cookie = '\0';` at that out-of-bounds offset.
- The token comes from `oidc_state_cookies_clean_expired()` at lines 230-244:
  `apr_pstrdup(r->pool, oidc_http_hdr_in_cookie_get(r))` followed by
  `apr_strtok(cookies, ";")`. Pre-auth callers are
  `src/handle/request.c:132` (new auth flow) and
  `src/handle/response.c:353` (redirect callback).

The fix changes the loop to
`while ((*cookie != '\0') && (*cookie != OIDC_CHAR_EQUAL))`; the following
`if (*cookie != OIDC_CHAR_EQUAL) return 0;` then rejects a value-less token.
The same bound is present at line 217 of both the fix-commit blob and the
released `v2.4.19.4` blob; the bad loop is present at line 214 of the parent.

## 3. Cheapest local experiment

Mirror `lab/frontier/mongoose2shell/harness/`: re-extract
`oidc_state_cookies_parse_token()` verbatim from the parent and both fixed
blobs on every run, check a SHA-256 manifest, stub the request/config types,
`_oidc_strstr` and the cookie-processing recorder, and allocate the token as
an exact-size heap object. A token `mod_auth_openidc_state_novalue` with no
`=` should give gcc and clang ASan `READ of size 1` in the sliced loop and a
NUL store at an adjacent offset; the fixed slices must return 0 cleanly and a
well-formed `mod_auth_openidc_state_abc=1` must be clean in all variants.
That would establish rungs 1-3 and possibly a scoped rung 4 (one NUL byte, not
chosen data). No Apache, APR pool or network is needed for the first step.

## 4. Rung-4 feasibility and risks

- Ranked ahead of remaining candidates because it has a public advisory, a
  real fix commit, a released fixed version and pre-auth reachability verified
  in two source callers.
- Ceiling risk: the primitive is a blind scan plus a single NUL byte; CVSS says
  `I:N/A:H`, so pointer control, chosen-byte control and rung 5 are doubtful.
  Controllability of the byte that terminates the scan in a real APR pool is
  UNKNOWN and must not be assumed.
- A full-module ASan build may not flag the source object because
  `apr_pstrdup()` allocates from an APR pool arena, not a per-object
  malloc redzone [INFERENCE from source, untested]. The verbatim-slice harness
  is therefore the first measurement; a real-daemon attempt comes only after
  the slice works.
- NVD status is `Deferred`; distro/RHSA references were not read and remain
  UNKNOWN. No duplicate brief, charter, window or owning mind exists.

No external system was probed; all URLs above were read for provisioning only.
