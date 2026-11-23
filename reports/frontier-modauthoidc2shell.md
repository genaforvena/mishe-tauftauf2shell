# Frontier brief: mod_auth_openidc — CVE-2026-54789 (modauthoidc2shell)

**STAGED 2026-11-23 W139, admitted 06:2xZ; W147 witness replay ESTABLISHED.**
Prepared in W138 from public advisory and upstream fix pins; the harness,
measurements and handoff were added in W139.
Pins are byte-exact and hash-verified; full raw evidence is in
`lab/frontier/modauthoidc2shell/PROVENANCE.md`. The operator owns final
admission; the person owns wake units and full-flag sync.

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
  UNKNOWN. At provisioning time no duplicate brief, charter, window or owning
  mind existed; W139 then created the charter, seed wall and target window.


## 5. W139 local result — staged, rung 4 scoped

`lab/frontier/modauthoidc2shell/harness/run.sh` re-extracts the record struct
and the entire `oidc_state_cookies_parse_token()` verbatim from all three
pinned blobs on every run, checks two SHA-256 manifests (12 files, including
the driver and runner), and builds plain and ASan variants for the vulnerable
parent, the fix commit and the released tag. It reports **59 PASS / 0 FAIL**
on three consecutive runs, a clean-directory replay and a clean `git archive
HEAD` replay after handoff commit `05acfc6`, all with
`TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`
(raw logs in `harness/evidence/`).

- Rung 1: valueless state-prefixed token, dead `cookie != NULL` test, NUL at
  logical index 30, predicted write offset 47; no vulnerable call.
- Rung 2: the vulnerable slice scans past the token, overwrites an adjacent
  `=` and dispatches `PROCESS_CALLS=1`; both fixed slices return `RC=0` with
  no dispatch and leave the `=` byte intact.
- Rung 3: gcc and clang ASan `READ of size 1`, 0 bytes past a 31-byte exact-size
  token, in the verbatim slice at pinned `state.c.4301b536:214`.
- Rung 4 (scoped): the one-byte NUL store lands at chosen offsets 31, 47 and
  63 in the plain-build block, with an intact canary. The byte value is not
  chosen; only its location is. No ASan WRITE is observable because the read
  faults first.
- Controls: fix-commit and released `v2.4.19.4` slices ASan-clean; well-formed
  `mod_auth_openidc_state_abc=1` clean on all six binaries.

Ceiling: no Apache/APR pool, request object, listener, socket or wire; scanner
called directly with stubbed config and a recorder for the downstream cookie
processor. The exact-size heap token is an instrument; a real APR arena has no
per-object redzone [INFERENCE, untested]. No pointer control or chosen command.
W147 independently replayed the lane: rungs 1–3 and scoped rung 4 ESTABLISHED at
the direct-call scope, no repair owed; no rung 5. Rung 5 must not be inferred
from this.

No external system was probed; all URLs above were read for provisioning only.

## 6. Full-module ASan loopback result (2026-11-23 W6)

The full parent module was provisioned and built with ASan against the local
ASan APR/httpd stack, with jansson and cjose provisioned under `lab/`. A
released `v2.4.19.4` module is the control; both bind only `127.0.0.1:18090`.
The caller is source-bound and live: an unauthenticated GET of `/protected`
reaches `oidc_check_user_id` → `oidc_handle_unauthenticated_user` →
`oidc_request_authorization_set_cookie` (`handle/request.c:132`) →
`oidc_state_cookies_clean_expired` → `oidc_state_cookies_parse_token` before
authentication. `cd lab/frontier/modauthoidc2shell/full && bash run.sh`:
parent 30/30 ASan `READ of size 1` faults at pinned `state.c:214` with a full
native stack through `ap_run_check_user_id` and 30/30 empty replies; fixed tag
0/30 reports and 30/30 HTTP 302. An earlier layout-dependent run gave 7/30
faults and 23/30 OOB dispatches of the value-less cookie name. The overflowed
8192-byte region is a real APR arena. Evidence and limits:
`lab/frontier/modauthoidc2shell/full/evidence/README.md`.

This confirms rung 3 on a real pre-auth wire path; at this point rung 4 stayed
scoped to the direct-call harness (ASan faults before the NUL store; byte value
always NUL, offset chosen by adjacent memory, no pointer control or command).
Section 7 later reached the store on the same wire path. This probe is
unwitnessed; W147's verdict covers the earlier harness only.

## 7. Wire-chosen NUL store (2026-11-23 W8)

The full-module probe now reaches the store itself. With
`Cookie: mod_auth_openidc_state_novalue;<name>=<value>`, `apr_strtok` leaves
the second cookie's `=` after the value-less token's NUL in the copied header,
so the pinned scan finds it in bounds and line 219 writes NUL there. gdb on
the live child read `0x3d` before and `0x00` after the store at pinned
`:219`, with the full pre-auth stack; arena dumps put the store at token
offset `30 + 1 + len(<name>)` — 39 for eight `z` bytes, 63 for 32
(`full/evidence/store/gdb-dump*.txt`). Five wire lengths all returned 302;
the parent dispatched `oidc_state_cookies_process_one` with the second
cookie's value 5/5, the released tag 0/5. `halt_on_error=0` did not continue
past the value-only READ fault (negative preserved).

Rung 4 is therefore also observed on a live pre-auth wire path with a
wire-chosen offset, still unwitnessed at that scope. No chosen byte value, no
pointer-bearing target, command or rung 5. Replay: `cd
lab/frontier/modauthoidc2shell/full && bash probe-store.sh && bash probe-gdb.sh`;
evidence and limits in `full/evidence/store/README.md`.

## 8. Pointer-bearing OOB store in the plain full module (2026-11-23 W9)

The earlier "no pointer-bearing target" line applies to W8's **in-bounds**
header-copy store. A non-ASan build of the same pinned module
(`full/build-plain.sh`, module sha256
`008990618887dde66e4371d1a354c64dccf29c40d36d17c4ac1d8e5f8b375654`,
plain httpd 2.4.70 / APR, 127.0.0.1:18090) allows the **out-of-bounds** scan
to reach its store. With a value-less state cookie, gdb at pinned `state.c:219`
on the live pre-auth stack measured the store at `0x7ffff6de2221`: the byte
`0x3d` is the low byte of pointer `0x7ffff5603d`; after the store the byte is
`0x00` and the pointer `0x7ffff56000`. The target is zeroed OIDC shared-memory
data; a hardware watchpoint caught no consumer read, and non-gdb value-less
and well-formed requests both return 302. The real-object harness reproduces
the same pointer-low-byte shape stably across six pool fills.

Grade unchanged: rung 4 scoped, now with a pointer-bearing target on a live
pre-auth wire path, still unwitnessed at that scope. Byte always NUL, target
not wire-chosen, no consumer effect, chosen byte, command or rung 5;
gdb disables ASLR, so addresses are lab-layout facts. Replay: `cd
lab/frontier/modauthoidc2shell/full && bash build-plain.sh &&
bash probe-plain-oob.sh && bash probe-plain-detail.sh`; raw evidence and
limits `full/evidence/plain-oob/README.md`.

### W10 consumer check (2026-11-23)

`full/probe-plain-keepalive.sh` arms a hardware watchpoint on the corrupted
word after the store, deletes the source breakpoint, and sends three requests
on the **same TCP connection** so no new accept can clear the word. It
measured the same store (`0x7ffff6de2221`, `0x7ffff5603d` → `0x7ffff56000`),
got three HTTP 302 replies, and recorded no watchpoint hit or watch-stop
backtrace within 70 seconds. A one-off `LD_PRELOAD` allocation tracer also
found no traced APR allocation covering the word (nearest starts 0x6f bytes
later), with the caveat that intra-libapr calls bypass interposition.

Both are negative results. The word is connection-pool state with no observed
consumer in the same request or two later requests on that connection; the
"pointer-bearing" wording describes the 8-byte shape at the store, not a
demonstrated dereference. Grade stays rung 4 scoped, byte always NUL, target
not wire-chosen, no chosen byte, command or rung 5. Raw:
`full/evidence/plain-oob/keepalive/` and `alloc-trace/`.

