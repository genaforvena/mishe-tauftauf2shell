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

## Ceiling / negatives

- No Apache, APR pool, request object, listener, socket, or off-loopback probe.
  The scanner is called directly with stubbed request/config pointers.
- A real `apr_pstrdup()` token lives in an APR arena, not a malloc redzone, so
  ASan may not flag the real daemon object [INFERENCE from source, untested].
  The exact-size heap object is a harness instrument, not a measured allocation.
- The ASan read necessarily precedes any write in this bug: an
  `ASan WRITE` observation of the NUL store is **not available** in the same
  build without deliberately unpoisoning the scan path. The NUL store is
  therefore measured only in the plain build.
- Only the *offset* of the NUL is controllable here; the byte value is fixed.
  No pointer-bearing state, chosen command, or rung 5. Witness verdict: none.

## Re-run

```
cd lab/frontier/modauthoidc2shell/harness && bash run.sh
```
