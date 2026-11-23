# psqlodbc2shell — status

Admitted 2026-11-23 ~09:4xZ under standing approval #6 as the 107th engine
route. Frontier staged this lane in W144 (commits `13c835d` and `255dfd4`)
with byte-exact pinned upstream blobs, the fix commit and the released fixed
version. Brief: `reports/frontier-psqlodbc2shell.md`; pins, verbatim slices,
SHA-256 manifests and raw evidence: `lab/frontier/psqlodbc2shell/PROVENANCE.md`.
The two-pane inner tmux window 112 was already live and registered (frontier
handoff), so admission created no second window and changed no registry entry.
The hy4-flash `max_parallel: 3` route was added. The path, debounce and
`@psqlodbc2shell` slice drop-in were minted with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@psqlodbc2shell.service` and
`m2shell-wake-psqlodbc2shell.path` were added to the site's owner resolver map
(215 entries). The pinned full-flag doctor returned rc 0,
`PASS local plant out of Git` / `GREEN`; the doctor service was restarted to
`ExecMainStatus=0`, and `check-omp-only.py` returned `GREEN (107 declared
roles)`, rc 0. Admission changes no grade.

- Claim: CVE-2026-120061 / GHSA-hfm6-qfx8-v4xq, published 2026-11-03
  (CVE record 2026-11-02), High 7.5
  `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-121/193/457. Affected
  `<= 18.00.0005`, fixed `18.00.0006` by security merge
  `79f4631db27cdb62276d3d9d3c1e5c47dcc315c0`. The `{fn}` argument-offset
  array is a fixed 16-entry `SQLLEN param_pos[16][2]` stack array written
  without a bound and without initialization; `{d}`, `{t}`, `{ts}` and
  `{escape}` bodies write one byte past a 128-byte stack buffer. Workaround:
  reject SQL text containing ODBC escapes before it reaches the driver. The
  advisory claims no shell or RCE; its AV:N vector is claim text, not a lab
  observation.
- Primitive: `convert_escape()` declares `param_pos[16][2]` at pinned
  `convert.c.vuln:5830` and calls `processParameters(qp, &nqb,
  &param_consumed, param_pos)` at `:5860` with no array size. Each `,` at
  `innerParenthesis == 1` writes 8-byte `SQLLEN` offsets at pinned `:5635-
  :5638` with an unbounded `param_count`; the closing `)` repeats it. The
  `F_ExtractOldTo` macro at pinned `:2424-2436` breaks on `c >= maxsize` and
  then writes `buf[c] = '\0'`, one byte past `buf_small[128]` for a 128-byte
  body. The fix adds a size argument and two bound guards returning
  SQL_ERROR "too many parameters in the escape function call", initializes
  `param_pos` to `-1`, and changes the macro guard to `c + 1 >= maxsize`.
- Evidence: `lab/frontier/psqlodbc2shell/harness/run.sh` re-extracts the two
  verbatim pinned slices (vulnerable `processParameters` 5607-5698, fixed
  5607-5710, `F_ExtractOldTo` 2424-2436) under `#line` directives on every
  run, adds stubs for `QueryParse`, `QueryBuild`, `F_*` macros,
  `inner_process_tokens` and logging, and builds gcc and clang plain/ASan
  variants. Frontier recorded `PASS=34 FAIL=0` three times plus a clean
  `git archive HEAD` replay. Operator replay from
  `git archive HEAD lab/frontier/psqlodbc2shell` in a fresh `/tmp` directory
  returned rc 0, `PASS=34 FAIL=0` and exactly
  `TRACE_SHA256=d5145bdbd72b30af5a5d5d0824d6497db85781260386d6984f0455954d424d63`.

## Grade at admission — 09:4xZ (author-only, no witness verdict)

- Rung 1: a 24-argument `{fn}` escape is accepted by the vulnerable slice;
  the fixed slice rejects it with "too many parameters in the escape function
  call" and `CONSUMED=0`.
- Rung 2: vulnerable plain run returns `RV=0` after writing past the array;
  fixed returns `RV=-1` at the sixteenth comma. The off-by-one limb faults on
  the vulnerable build and reports `RETVAL=0 BUF127=00` on the fixed build.
- Rung 3: gcc and clang ASan both report `stack-buffer-overflow`, `WRITE of
  size 8` at pinned `convert.c.vuln:5637` in `processParameters` and `WRITE
  of size 1` at pinned `:2424` in `F_ExtractOldTo`; both fixed builds are
  clean (exit 0).
- Rung 4 is **scoped**: plain vulnerable runs report `FIRST_DIFF=0
  CHOSEN_5A=112` and a sink dump beginning `215a5a5a5a5a5a5a21` — harness-
  chosen `0x5a` in the first adjacent 32 bytes; both fixed runs leave the
  sink entirely `0xCC` (`CHOSEN_5A=0`). The bytes are the harness-chosen
  `SQLLEN` output offsets in a harness-adjacent sink, not attacker-chosen
  command or pointer bytes.

## Ceiling and negatives

No real psqlODBC build, ODBC driver manager, DSN, application SQL path,
process, socket, wire exchange, network, ASLR/grooming study, pointer control,
return-address control, gadget, ROP chain, command, marker side effect or
witness verdict. The advisory's uninitialized-array limb (CWE-457) is recorded
from source but not separately exercised. Whether a real application forwards
untrusted SQL text to this parser, and the real stack layout after
`param_pos`, remain UNKNOWN. Rung 5 is UNKNOWN at this admission snapshot.

## Next bounded work for the target mind

1. Build the pinned vulnerable and fixed tags with ASan and call
   `SQLPrepare`/`SQLExecDirect` with a `{fn}` escape carrying more than
   sixteen arguments; capture the ASan frame and the real stack layout after
   `param_pos`.
2. Repeat with a `{d}` body of 128 bytes or more; identify whether any saved
   pointer or control-flow datum sits adjacent before considering a marker.
3. Hand any live-wire rung-4 or rung-5 claim to the witness without upgrading
   this row first.
