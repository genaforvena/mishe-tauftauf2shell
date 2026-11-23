# Frontier brief: psqlODBC ODBC escape parser — CVE-2026-120061 (psqlodbc2shell)

**STAGED 2026-11-23 W144 — direct-call harness evidence and a report brief
exist; operator admission and an independent witness verdict are pending.**
Byte-exact pins, git identifiers and hashes: `lab/frontier/psqlodbc2shell/PINS.sha256`;
harness provenance: `lab/frontier/psqlodbc2shell/PROVENANCE.md`. Frontier owns
no further work on this target once its window is live.

## 1. Verified ground truth

- Advisory: GHSA-hfm6-qfx8-v4xq / CVE-2026-120061, published 2026-11-03
  (CVE record 2026-11-02), High, CVSS 3.1 7.5
  `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-121 (stack buffer
  overflow), CWE-193 (off-by-one), CWE-457 (uninitialized variable) —
  https://github.com/postgresql-interfaces/psqlodbc/security/advisories/GHSA-hfm6-qfx8-v4xq
- Affected `<= 18.00.0005`; patched `18.00.0006`. The advisory states: the
  `{fn}` argument-offset array is a fixed 16-entry stack array written without
  a bound and without initialization; an escape with too many arguments
  overflows the stack, and a reference to an unsupplied argument copies
  arbitrary bytes into the query; `{d}`, `{t}`, `{ts}` and `{escape}` bodies
  write one byte past a 128-byte stack buffer. Workaround: reject SQL text
  containing ODBC escape sequences before it reaches the driver. Finder:
  internal source review. No shell or RCE is claimed in the advisory.
- Upstream release notes `docs/release.html` at tag `REL-18_00_0006` list the
  same advisory. Security fix merge `79f4631db27cdb62276d3d9d3c1e5c47dcc315c0`
  (Dave Cramer, 2026-11-02) changes 41 lines in `convert.c` among other files.
- Repo `https://github.com/postgresql-interfaces/psqlodbc.git`, pinned tags
  `REL-18_00_0005` (commit `f6da5647355b110fc9cc005100e23ba980e20e33`,
  `convert.c` blob `829071f0b9062d35ecd67c8daa8b23674a295a3b`) and
  `REL-18_00_0006` (commit `96fa03dbc968c40920c907bf18d3b4cbd8efeebc`,
  `convert.c` blob `c0a295d950084bb16bc0942a54930b2306dc5f3c`). Fetched source
  SHA-256 `27fc049b…175b1` / `19253432…d762`. No psqlODBC target exists in
  this plant's do-not-duplicate list; the separate `memcached2shell` target is
  the memcached daemon, and `postgres2shell` is the PostgreSQL server.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; the `#line` slices in the harness carry the
raw pinned bytes and rule.

Vulnerable `convert_escape()` declares `SQLLEN param_pos[16][2]` at pinned
`convert.c.vuln:5830`, then calls `processParameters(qp, &nqb, &param_consumed,
param_pos)` at `:5860` with **no array size**. In `processParameters()`
(pinned `:5607-5698`) every `,` at `innerParenthesis == 1` executes:

```c
param_pos[param_count][1] = F_NewPos(qb) - 2;   /* pinned :5635 */
param_count++;
param_pos[param_count][0] = F_NewPos(qb);       /* pinned :5637 */
param_pos[param_count][1] = -1;                 /* pinned :5638 */
```

and the closing `)` repeats the write at `:5654-5657`. `param_count` is a
plain `int` with no bound, so a `{fn f(a,a,…)}` escape with more than sixteen
commas writes `SQLLEN` offsets past the 256-byte stack array. The array is
also left uninitialized when `convert_escape()` is entered, so a `$k`
reference to an unsupplied argument later reads stale stack bytes into the
generated query (CWE-457, recorded but not separately exercised here).

The second primitive is the `F_ExtractOldTo` macro used for `{d}`, `{t}`,
`{ts}` and `{escape}` bodies (pinned `convert.c.vuln:2424-2436`). Its guard is
`if (c >= maxsize) break;`, after which `buf[c] = '\0';` runs — with a
128-byte `buf_small`, a body of 128 or more bytes writes the terminator at
`buf_small[128]`, one byte past the array.

The fix changes exactly these sites: `processParameters()` gains a
`size_t param_pos_count` argument and two `(size_t)(param_count + 1) >=
param_pos_count` guards returning `SQL_ERROR` with "too many parameters in the
escape function call" (pinned `convert.c.fixed:5635-5640`, `:5660-5665`);
`convert_escape()` initializes every `param_pos[i][0]` and `[1]` to `-1`
before the call (`:5876-5878`); and `F_ExtractOldTo` becomes
`if (c + 1 >= maxsize) break;` (`:2429`).

## 3. Cheapest local experiment

One generated C driver per variant, no psqlODBC build, ODBC driver manager,
DSN, PostgreSQL server, SQL text path, process, socket or network. `run.sh`
extracts two verbatim slices from each pinned source under `#line` directives
(`F_ExtractOldTo` 2424-2436; `processParameters` 5607-5698 vulnerable /
5607-5710 fixed), adds stubs for `QueryParse`, `QueryBuild`, the `F_*` access
macros, `inner_process_tokens` and logging, and builds gcc and clang plain and
ASan variants. Scenarios: 24 comma-separated arguments (overflow), a
200-byte `{d}` body (off-by-one), and a plain-build adjacent 0xCC sink with a
harness-chosen `qb->npos` base of `0x5a5a5a5a5a5a5a00` for byte placement.

Command: `cd lab/frontier/psqlodbc2shell/harness && ./run.sh && ./check.sh`.

## 4. Rung-4 feasibility and risks

Favorable: two independent stack writes from attacker-controlled SQL text;
the fix is small and its error string is directly observable; the unbounded
write stores 8-byte `SQLLEN` offsets whose bytes track a harness-chosen
output position, so byte placement is measurable. Constraints measured here:
the verbatim function is called directly with stubbed token processing and
struct layouts; the fixed-variant call adds a fifth argument (harness wrapper
`PP_CALL`); the plain-build rung-4 bytes land in a harness-adjacent 0xCC sink,
not in a real `convert_escape()` stack neighbour; ASan redzones fault before
chosen bytes can be read downstream; no pointer, return address, saved RIP,
gadget, ROP chain, command or marker side effect was attempted. Whether a
real application forwards untrusted SQL text to this parser, and what the
actual stack layout after `param_pos` is, remain UNKNOWN. The advisory's
AV:N vector is a claim, not a lab observation.

## 5. Observations

- Harness `PASS=34 FAIL=0` three times in the working tree; normalized trace
  `d5145bdbd72b30af5a5d5d0824d6497db85781260386d6984f0455954d424d63`
  (no PID, address or absolute path).
- Rung 1: 24-argument `{fn}` input accepted by the vulnerable slice; the
  fixed slice rejects it with "too many parameters in the escape function
  call" and `CONSUMED=0`.
- Rung 2: vulnerable plain run returns `RV=0` after writing past the array;
  fixed returns `RV=-1` at the sixteenth comma. Fixed off-by-one run reports
  `RETVAL=0 BUF127=00`; vulnerable off-by-one run faults.
- Rung 3: gcc and clang ASan both report `stack-buffer-overflow`,
  `WRITE of size 8` at pinned `convert.c.vuln:5637` in `processParameters`,
  and `WRITE of size 1` at pinned `:2424` in `F_ExtractOldTo`; both fixed runs
  are clean (exit 0).
- Rung 4: plain vulnerable runs report `FIRST_DIFF=0 CHOSEN_5A=112` and a sink
  dump beginning `215a5a5a5a5a5a5a21`, i.e. chosen `0x5a` bytes in the first
  adjacent 32 bytes; both fixed runs leave the sink entirely `0xCC`
  (`CHOSEN_5A=0`). The bytes are the harness-chosen `SQLLEN` output offsets,
  not attacker-chosen command or pointer bytes.

## 6. Ceiling / handoff

Direct call with stubbed token processing and struct layouts; no real
psqlODBC build, driver manager, ODBC API entry point, application SQL path,
process, peer, socket, wire exchange, network, ASLR/grooming study, pointer
control, ROP chain, command, marker side effect or witness verdict. The
uninitialized-array limb (CWE-457) is recorded from source but not exercised.
A dedicated target mind should first build the pinned vulnerable and fixed
tags, call `SQLPrepare`/`SQLExecDirect` with a `{fn}` escape carrying more
than sixteen arguments, and observe the ASan frame and real stack layout;
then repeat with a `{d}` body of 128 bytes or more. Only an observed saved
pointer or control-flow diversion could change the ceiling; placed `0x5a`
bytes are not execution.
