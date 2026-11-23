# PROVENANCE — psqlodbc2shell direct-call harness

## Target and fetch

- Advisory: GHSA-hfm6-qfx8-v4xq / CVE-2026-120061, read 2026-11-23 from
  `https://github.com/postgresql-interfaces/psqlodbc/security/advisories/GHSA-hfm6-qfx8-v4xq`.
  Ground truth in that page: High 7.5, CWE-121/193/457, affected
  `<= 18.00.0005`, patched `18.00.0006`, 16-entry `param_pos` stack array and
  128-byte body buffer, no shell/RCE claim.
- Source provisioning (read-only fetch, no probing): `git clone` of
  `https://github.com/postgresql-interfaces/psqlodbc.git` into `src/repo`.
  Pinned tags `REL-18_00_0005` / `REL-18_00_0006`; commits and git blob IDs in
  `PINS.sha256`. Working blobs `src/convert.c.vuln` / `src/convert.c.fixed`
  were produced by `git show <tag>:convert.c`, not edited.
- Fix merge `79f4631db27cdb62276d3d9d3c1e5c47dcc315c0` (2026-11-02) was
  identified by `git log REL-18_00_0005..REL-18_00_0006` and `git show --stat`;
  its `convert.c` hunks match the tag diff.

## Verbatim slices

`harness/run.sh` extracts with `sed -n` at each run:

| slice | vulnerable | fixed |
|---|---|---|
| `F_ExtractOldTo` macro | convert.c 2424-2436 | convert.c 2424-2436 |
| `processParameters` function | convert.c 5607-5698 | convert.c 5607-5710 |

Slice files `harness/slice-*.inc` are regenerated from the pinned sources;
their SHA-256 values are in `PINS.sha256`. Each is inserted into the generated
`driver-<variant>.c` after a `#line <start> "convert.c.<variant>"` directive,
so ASan frames carry the pinned source line numbers. Nothing inside either
slice was modified.

## Harness-only scaffolding (not upstream)

- Types: `UCHAR`, `BOOL`, `RETCODE`, `SQLLEN` (64-bit `long long`), `UInt4`,
  `QueryParse {statement, stmt_len, opos, encstr}` and `QueryBuild` with the
  `npos`, `query_statement`, `qbuf_len`, `errornumber`, `errormsg` and statement
  fields the slices touch.
- Macros: `SQL_SUCCESS`, `SQL_ERROR`, `STMT_EXEC_ERROR`, `ODBC_ESCAPE_START`,
  `ODBC_ESCAPE_END`, `IS_NOT_SPACE`, `TRUE`, `FALSE`, `MYLOG` (no-op),
  `MBCS_NON_ASCII` (0), `QP_in_idle_status` (1), and the `F_Old*`/`F_NewPos`
  access macros copied in shape from pinned `convert.c` (they are upstream
  macros but re-declared here so the slices compile standalone).
- `inner_process_tokens()` stub copies one character from `qp->statement` at
  the current `opos` into `qb->query_statement` at `npos`, advances `npos`,
  and **does not** advance `opos` — the caller's `for` loop performs
  `F_OldNext`. Real `inner_process_tokens` performs tokenization; this stub
  only preserves the character-stream contract the switch consumes.
- `PP_CALL` wrapper: vulnerable signature has 4 arguments, fixed has 5
  (`param_pos_count = 16`). The wrapper is harness adaptation to the pinned
  signature change, not a source edit.
- Rung-4 layout: `struct chosen_layout { SQLLEN pp[16][2]; unsigned char
  sink[512]; }` heap-allocated with `calloc`; `sink` is filled with `0xCC`;
  `qb->npos` starts at `0x5a5a5a5a5a5a5a00` so the overflowing offsets carry
  chosen `0x5a` bytes. ASan scenarios use a separate local `param_pos[16][2]`
  so the redzone catches the first OOB write; rung 4 uses a plain build and
  the contiguous struct so the bytes can be inspected.

## Repairs and negative results

- Initial driver omitted the redirection on two `cat` calls, so the slices
  were not present and the build failed with undefined references; corrected
  by appending both slice files to the generated driver.
- First slice range began at 5606 (a stray `*/`), fixed to 5607.
- `F_ExtractOldTo` was first called with `&qp`; the macro uses both `(qp)->`
  and `qp->`, so the call now passes a `QueryParse *` variable.
- Early token stub advanced `opos`, hiding the comma/parenthesis switch and
  producing a false negative (`CHOSEN_5A=0`); the stub was corrected and the
  negative result replaced by the observed overflow.
- `setbuf(stdout, NULL)` was added because ASan aborts discard buffered
  stdout; the two ASan scenarios were then split into `fn` and `extract`
  modes so both crash frames are captured in one run.
- ASan builds with `-fsanitize=address -fno-omit-frame-pointer`; plain builds
  with `-fno-stack-protector` (no canary), as in prior staged targets.
- Uninitialized-array limb (CWE-457) was not exercised: no deterministic
  observation was produced, so it stays a source claim.

## Verification and replay

- `./run.sh && ./check.sh`: `PASS=34 FAIL=0`, trace
  `d5145bdbd72b30af5a5d5d0824d6497db85781260386d6984f0455954d424d63`,
  reproduced three times in the working tree.
- ASan: gcc and clang `WRITE of size 8` at pinned `convert.c.vuln:5637` in
  `processParameters` and `WRITE of size 1` at `:2424` in `F_ExtractOldTo`;
  both fixed runs clean. Fixed also returns the upstream error string.
- Plain chosen bytes: `FIRST_DIFF=0 CHOSEN_5A=112` on vulnerable, `CHOSEN_5A=0`
  on fixed, for both compilers.
- Trace excludes PID, addresses and absolute paths; raw ASan reports keep them
  and are preserved under `evidence/`.
