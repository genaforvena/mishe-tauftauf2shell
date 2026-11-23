# Provenance — modauthoidc2shell harness (W139, 2026-11-23)

## Pinned inputs

Provisioned in W138 and re-verified on every run by `src/SHA256SUMS`
(from byte-exact upstream blobs; git blob ids recorded in
`reports/frontier-modauthoidc2shell.md`):

| file | sha256 | origin |
| --- | --- | --- |
| `src/state.c.4301b536` | `ceedb687ad21c4668f546d0f1c9164890f740a1ff81bbc8fb5807a9aab1ae5aa` | parent of fix `8017478` (blob `0122cde...`) |
| `src/state.c.8017478` | `3492207546885aae00363de14b30947ce73c48b8361b33516d95fc6df774c1cc` | fix commit blob `92bd078...` |
| `src/state.c.v2.4.19.4` | `f02d8ddb60927b9da1402c6430d179e4418ff6751ecda6c78db34424ccf77ce5` | released fixed tag blob `13009c17...` |
| `src/fix-8017478.patch` | `d8ae4b4e8cda366a985368bd885591d2aaa702b463d989b140a9621a226b3e38` | `git show 8017478471cc` |

`harness/SHA256SUMS` covers `driver.c`, `run.sh`, the six extracted slices and
the four pins (12 files). The runner checks both manifests before building.

## Verbatim slices re-extracted per run by `harness/run.sh`

| slice | vulnerable blob lines | fix-commit lines | release-tag lines |
| --- | --- | --- | --- |
| `state_struct.inc` | 105-110 | 105-110 | 105-110 |
| `parse_token.inc` | 204-223 | 204-226 | 204-226 |

Each slice begins with a `#line` directive naming the pinned blob; the ASan
stack reports pinned line **214** (the unbounded `while`), not the driver line.
The driver adds only host scaffolding: opaque `request_rec` / `oidc_cfg_t`,
the `OIDC_CHAR_*` constants, a `strstr` stand-in for `_oidc_strstr`, a prefix
getter, and a `oidc_state_cookies_process_one()` recorder. No upstream parser
logic is reimplemented.

## Harness inputs and stubs

- `vtoken = "mod_auth_openidc_state_novalue"` (30 bytes); the attacker can
  supply exactly this shape in a `Cookie` header before authentication.
- `asan-read`: `malloc(31)` holds the token and its NUL. The fixed loop stops
  at the NUL; the vulnerable loop reads byte 31, one past the object, giving ASan
  `READ of size 1` in the verbatim slice. gcc + clang.
- `eqscan [gap]`: one 512-byte block contains the token at offset 0, its logical
  NUL at offset 30, an `=` at `30+gap`, and a canary `Z` at offset 400. Plain
  builds observe the resulting NUL store at offsets 31, 47 and 63 for gaps
  1, 17 and 33. The value written is always NUL — there is no chosen byte value.
- `safe`: `mod_auth_openidc_state_abc=1` with the `=` inside the object; run on
  all six binaries.
- Fixed-commit and released-tag slices reject the value-less token with `RC=0`
  and `PROCESS_CALLS=0`; their `=` byte stays `0x3d` and ASan is clean.

## Observations

- `bash lab/frontier/modauthoidc2shell/harness/run.sh`: **59 PASS / 0 FAIL** on
  three consecutive runs, identical
  `TRACE_SHA256=bbda75f0cf7e4e1789b75bd206922f7ccbbb0c24b676e8b92fb833af4c448459`
  (`evidence/run1.txt`..`run3.txt`, raw modes in `evidence/*.out`).
- Clean-directory replay (`cp` of `src/` plus `driver.c`, `run.sh` and
  `SHA256SUMS` to a fresh `/tmp` directory, no repository context):
  `PASS=59 FAIL=0`, same hash (`evidence/replay.txt`,
  `evidence/replay-normalized.txt`).
- Clean `git archive HEAD lab/frontier/modauthoidc2shell` replay after handoff
  commit `05acfc6`: `PASS=59 FAIL=0`, same hash
  (`evidence/git-archive-replay.txt`).
- Rung 1: advisory arithmetic with no vulnerable call — prefix, valueless
  token, dead NULL test, NUL index 30, predicted write offset 47.
- Rung 2: the vulnerable slice scans past the token, overwrites the adjacent
  `=` with NUL and dispatches `PROCESS_CALLS=1`; both fixed slices reject.
- Rung 3: gcc + clang ASan `READ of size 1`, 0 bytes after a 31-byte region, in
  `oidc_state_cookies_parse_token` at pinned `state.c.4301b536:214`.
- Rung 4 (scoped): NUL store at the three chosen offsets; the canary is intact,
  proving a single-byte write rather than a length-driven overwrite. The
  address is chosen by the harness block layout, not by a wire field.


## Ceiling / negatives of the direct-call harness

- The stubbed harness has no Apache, APR pool, request object, listener,
  socket or off-loopback probe; the scanner is called with stubbed request/config
  pointers. The separate real-object probe below covers the APR-pool follow-up.
- The exact-size heap token is a harness instrument, not a measured allocation.
- In that harness the ASan read necessarily faults before any write, so an
  ASan WRITE of the NUL store is not available there; the NUL store is measured
  in the plain build. The real-object probe below did observe an ASan WRITE
  fault at pinned line 219 in some layouts.
- Only the *offset* of the NUL is controllable; the byte value is fixed. No
  pointer-bearing state, chosen command or rung 5. W147 witnessed rungs 1-3
  and scoped rung 4 ESTABLISHED at this scope; the probe below is unwitnessed.

## Re-run

```
cd lab/frontier/modauthoidc2shell/harness && bash run.sh
```

## Real-object APR/Apache probe (2026-11-23, W4)

`realobj/driver.c` keeps the struct and parser slices verbatim from the three
pinned blobs and replaces the stubs with a real `apr_pool_t`, a zeroed real
Apache `request_rec` (`r->pool`, `r->headers_in`), a real `apr_table_t` Cookie
header, a real `apr_pstrdup()` token and a real `apr_strtok()` split. The
prefix getter and `oidc_state_cookies_process_one()` recorder remain local
stand-ins. This is **not** a full module build: no complete mod_auth_openidc
tree is present locally and jansson development headers are absent; there is no
Apache process, listener, socket, wire or OIDC config.

`realobj/SHA256SUMS` covers `driver.c`, `run.sh` and the six generated slices;
`src/SHA256SUMS` is checked again on every run. The runner builds six gcc
variants (plain and ASan for parent, fix, release), then runs 20 parent ASan
reads (fills 0/512/4000/8000, five trials each), 10 fix and 10 release ASan
reads, and nine plain writes (gaps 1/17/33 x three variants). Raw logs are
`realobj/evidence/raw-trials.txt`; normalized trace and counts are
`normalized.txt` and `summary.txt`; console logs are `run6-console.txt` and
`run7-console.txt`.

Measured on two consecutive runs: **PASS=17 FAIL=0** each. Parent ASan
outcomes were layout-dependent under ASLR — run6: 15 fault summaries at pinned
`state.c.4301b536:214` (READ-class `unknown-crash`), 1 `SEGV` summary at pinned
`:219` reported by ASan as caused by a **WRITE** memory access, 4 trials
dispatched; run7: 9 / 3 / 8. Across trials `__asan_address_is_poisoned()` found
the first poisoned byte 95 bytes past the 30-byte token, never at its end: a
real APR arena has no per-object redzone, so the scan continues until it hits
an arena edge, an adjacent `=` (then dispatches) or an unmapped/protected page.
One full log in `raw-trials.txt` shows the WRITE fault stack at pinned line
219, which was unavailable in the exact-size-malloc harness.

Plain-build parent writes in the real arena placed `=` at token length + gap
and measured NUL at offsets 31, 47 and 63 for gaps 1, 17, 33, with
`PROCESS_CALLS=1`; the `=` position is still a harness placement, not a chosen
wire field. Fix and release slices rejected the value-less token in all 10
trials each (`RC=0`, `PROCESS_CALLS=0`) with no ASan report. Grade unchanged:
rung 4 **scoped**, now with real APR/Apache objects; no pointer control, chosen
byte value, command, rung 5 or independent witness verdict for this probe.

Clean `git archive HEAD lab/frontier/modauthoidc2shell` replay at 07:25Z
returned rc 0 and `PASS=17 FAIL=0` (14 READ-class faults, 0 WRITE faults,
6 dispatches). The WRITE fault is layout-dependent and is deliberately not
asserted by the runner.

Re-run: `cd lab/frontier/modauthoidc2shell/realobj && bash run.sh`.
