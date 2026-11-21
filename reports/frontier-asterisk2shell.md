# Asterisk2Shell — frontier brief

**Candidate:** Asterisk H.323 `ooTrace()` unbounded `vsprintf` into a fixed
2048-byte stack buffer, CVE-2026-57201 / GHSA-x348-j6c9-77f3. **Status:**
local rungs 1/2/3 established on verbatim pinned upstream `ootrace.c` bytes;
rung 4 is instrumented chosen-byte control at chosen offsets in harness stack
storage only. No live daemon, socket, useful pointer control or execution.
**Ranking:** high tractability — remote unauthenticated network input, a real
upstream fix commit, and two pinned source snapshots (affected parent and fix)
that differ only by the fix. The ceiling is bounded by a compile-time gate and
by conflicting advisory impact claims (see below).

## Verified ground truth

- Maintainer advisory GHSA-x348-j6c9-77f3, published 2026-06-25 by `gtjoseph`:
  https://github.com/asterisk/asterisk/security/advisories/GHSA-x348-j6c9-77f3
  It reports High **8.1**, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`,
  CWE-787, credit @HarutoKimura.
- CVE record CVE-2026-57201 (CNA GitHub, Inc., published/updated 2026-10-27):
  https://www.cve.org/CVERecord?id=CVE-2026-57201 reports **7.5 HIGH**,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — availability only. **The two
  authoritative sources disagree on attack complexity and on C/I impact.** We
  rank on the conservative availability-only vector; no confidentiality or
  integrity impact was observed locally, and the maintainer advisory text only
  claims a process crash. This discrepancy is preserved, not resolved.
- Affected: Asterisk `<= 20.20.0`, `<= 21.12.2`, `<= 22.10.0`, `<= 23.4.0`;
  Certified Asterisk `<= 20.7-cert10`, `<= 22.8-cert2`. Patched: 20.20.1,
  21.12.3, 22.10.1, 23.4.1, certified 20.7-cert11 and 22.8-cert3.
- Preconditions stated by the advisory: the `chan_ooh323` addon channel driver
  must be **explicitly compiled and installed — not the default** — and its
  port must be publicly reachable. This is a deployment gate, not an
  in-protocol authentication gate: `PR:N` holds once the addon is deployed.
- Claim: a crafted H.323 packet reaches the trace logger with a long format
  argument; unbounded `vsprintf` writes past `logMessage[2048]` and crashes the
  Asterisk process. We reproduce the write primitive; the reachability of a
  specific packet from the public port is advisory text, not observed here.
- Fix history: patch `2d7b8c8dc13d9ead8b6f36cc38b6dd91cd4abd3a` ("ooh323:
  Prevent potential buffer overflow in trace logging"), with six further
  branch backports listed in the CVE references. All pins and URLs are in
  `lab/frontier/asterisk2shell/PROVENANCE.md`.

## Source-bound mechanism

Pinned affected bytes are fix parent `661d6a2f...`; fixed bytes are fix commit
`2d7b8c8...`. The affected `ootrace.c` at the fix parent is **byte-identical to
release tag `23.4.0`**, so the A/B pair differs only by the fix commit. In
`addons/ooh323c/src/ootrace.c:35-53`:

```c
static OOUINT32 gs_traceLevel = TRACELVL;              /* line 35 */

void ooTrace(OOUINT32 traceLevel, const char * fmtspec, ...) {
   va_list arglist;
   char logMessage[MAXLOGMSGLEN];                       /* line 46 */
   if(traceLevel > gs_traceLevel) return;
   va_start (arglist, fmtspec);
   /*   memset(logMessage, 0, MAXLOGMSGLEN);*/
   vsprintf(logMessage, fmtspec, arglist);              /* line 50 */
   va_end(arglist);
   ooTraceLogMessage(logMessage);
}
```

`MAXLOGMSGLEN` is `2048` (pinned `ootypes.h:149`); `TRACELVL` is `1` when no
`OOTRCLVL*` macro is selected (pinned `ootrace.h:51-52`). There is no length
argument and no bound on the formatted result: any `%s` argument longer than
2047 bytes writes past the stack buffer, including the saved frame pointer and
return address. The fix replaces the fixed array and `vsprintf` with
`char *logMessage = NULL;` + `ast_vasprintf(&logMessage, fmtspec, arglist);` +
`ast_free(logMessage)` — an exact-size heap allocation — and leaves the trace
threshold check untouched. Even a `logMessage[2048]` that were large enough
would still be unsafe for an unbounded format; the fix removes the bound
assumption entirely.

## Local evidence (verbatim pinned block)

Harness `lab/frontier/asterisk2shell/`. `run.sh` checks both pinned sha256
values, asserts the exact lines and line numbers, extracts lines 35–53
(affected) / 35–57 (fixed) verbatim under a `#line 35 "ootrace.c"` directive,
and compiles one driver with `-O0 -fno-stack-protector`. Clean replay: **24
PASS**, `ALL CHECKS PASS rc 0`, trace SHA-256
`51b5ff1b82684092340d5bd93105efed76e453681e552eb0bb84103eb74feee0`,
byte-identical across repeated runs.

- **Rung 1 (reproducible trigger)** — a 2432-byte `%s` argument against the
  pinned affected block writes `written=2433` bytes into `logMessage[2048]`.
  The upstream line numbers are asserted at `ootrace.c:46` and `:50`.
- **Rung 2 (observed state failure)** — a 512-byte harness stack object placed
  in the caller records `first_changed=0`; the measured distance from
  `logMessage` to that object is 2272 bytes, so the write crosses the buffer,
  the saved frame pointer and the saved return address. A `setjmp`/`longjmp`
  escape in the harness stub observes the victim before the corrupted return
  executes (the plain build faults otherwise). This escape is harness
  scaffolding, not a target behaviour.
- **Rung 3 (ASan-confirmed corruption)** — ASan reports
  `stack-buffer-overflow`, `WRITE of size 2433`, frame `ooTrace` at the real
  pinned `ootrace.c:50`, and names the overflowed object as `logMessage`
  `[96, 2144)` (exactly 2048 bytes; access at offset 2144). No chosen-byte
  control is claimed from this ASan run.
- **Rung 4 (INSTRUMENTED)** — the input carries the token-safe marker
  `AST2SHELL`; its bytes `415354325348454C4C` are read back byte-exact at
  requested harness-victim offsets 0 and 64 (`chosen_offset` equals the
  request). Fixed control on the same 2432-byte input: `first_changed=-1`,
  `chosen_offset=-1`, victim untouched. **No live process, no socket, no
  useful pointer control, no execution.** The overwritten return address in
  this build is not steered: our marker never targets it and the plain build
  is deliberately escaped before using it.

## Rung-4 feasibility assessment

What helps: the primitive is an unbounded `vsprintf` into a fixed stack array,
so unlike a length-clamp or count-controlled overflow it can write arbitrary
attacker-supplied bytes (subject to format-string token safety) to arbitrary
length past the buffer, crossing saved `rbp` and the return address. With the
addon deployed and its port exposed, `PR:N` is claimed by the advisory. The
upstream fix is unambiguous and gives a clean A/B.

What caps it: (1) the `chan_ooh323` compile/install gate — not a default
Asterisk build, so stock deployments are unaffected; (2) the maintainer
advisory and CVE only claim a crash, and the CVE's availability-only vector is
the conservative reading of record; (3) no live daemon, packet path or
authentication state was exercised here, so packet reachability of the trace
format's long argument remains an advisory claim; (4) the harness demonstrates
chosen bytes in a harness stack object, not control of an actual return address
in a production Asterisk binary. Modern compiler hardening (stack protector,
PIE, ASLR) in a shipping Asterisk build may stop a naive return-address
overwrite. Reaching demonstrated security impact would require a live affected
addon build and an instrumented trace from the real H.323 packet path to the
`ooTrace` format arguments.

**Cheapest next rung:** build Asterisk 23.4.0 with `chan_ooh323` enabled under
ASan, send a loopback-only H.323 packet whose decoded field reaches an
`ooTrace` call with an overlong `%s` argument, and capture the real ASan frame
and format arguments. That would promote reachability from advisory claim to
observed bytes and would show whether a shipping build's hardening leaves the
return address reachable. No such live build exists in this plant yet.

## Handoff

Two required artifacts for a find: this brief and a live registered two-pane
`asterisk2shell` window. Window creation and registry entry are recorded at
yield time; the operator owns admission.
