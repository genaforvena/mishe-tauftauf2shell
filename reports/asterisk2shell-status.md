# asterisk2shell — status

Admitted 2026-11-21 ~04:2xZ by the operator under standing approval #6 on
frontier's #550 handoff (brief commit `4c1d50d`). Advisory: GHSA-x348-j6c9-77f3
(maintainer, 2026-06-25) / CVE-2026-57201 (2026-10-27). Sources conflict —
GHSA High 8.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CVE 7.5 High
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (availability only). Both claims are
preserved; the conservative availability-only ceiling applies. CWE-787.
Affected `<= 20.20.0`, `<= 21.12.2`, `<= 22.10.0`, `<= 23.4.0` (and certified
branches); patched 20.20.1/21.12.3/22.10.1/23.4.1. Claim: unbounded
`vsprintf` past `char logMessage[2048]` in H.323 `ooTrace()`. Deployment gate:
`chan_ooh323` addon must be explicitly compiled/installed (not default) and its
port exposed. Brief: [frontier-asterisk2shell.md](frontier-asterisk2shell.md).
Pins, raw URLs and hashes: `lab/frontier/asterisk2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/asterisk2shell/run.sh <outdir>` — 24 PASS,
  `ALL CHECKS PASS rc 0`, trace SHA-256
  `51b5ff1b82684092340d5bd93105efed76e453681e552eb0bb84103eb74feee0`.
  Verified from a clean `git archive HEAD` extraction at handoff and replayed
  from committed HEAD at admission (byte-identical trace).
- Operator replay at admission ~04:22Z from committed HEAD: 24 PASS lines,
  `ALL CHECKS PASS rc 0`, trace `sha256=51b5ff1b82684092340d5bd93105efed76e453681e552eb0bb84103eb74feee0`
  — byte-identical to the brief.
- Rungs 1/2/3 on verbatim pinned upstream `ootrace.c:35-53` from fix parent
  `661d6a2f` (affected, byte-identical to release `23.4.0`) and fix `2d7b8c8`:
  a 2432-byte `%s` argument writes 2433 bytes into `logMessage[2048]`;
  harness caller object `first_changed=0` at a measured 2272-byte delta; ASan
  `stack-buffer-overflow`, `WRITE of size 2433`, frame `ooTrace` at pinned
  `ootrace.c:50`, victim `logMessage [96, 2144)`. Fix uses `ast_vasprintf`.
- Rung 4 INSTRUMENTED only: token-safe `AST2SHELL` bytes read back byte-exact
  at requested harness-stack offsets 0 and 64; fixed build leaves the neighbour
  clean. A harness `setjmp/longjmp` escape observes the victim before the
  corrupted return executes — scaffolding, not target behaviour.
- UNKNOWN: live daemon, loopback H.323 reachability of the long trace argument,
  whether the addon is ever deployed with the port exposed, stock build's frame
  layout/canaries/NX, any useful-pointer control or execution. The advisory
  claims a crash only; no RCE is demonstrated.
