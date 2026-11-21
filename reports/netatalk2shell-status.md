# netatalk2shell — status

Admitted 2026-11-21 ~05:0xZ by the operator under standing approval #6 on
frontier's #574 handoff (brief `reports/frontier-netatalk2shell.md`, commits
`bd30e2d` / `c37e96d`). Advisory: GHSA-5443-v9xg-mqgv (maintainer,
2026-05-28) / CVE-2026-45698 (2026-08-17). Both grade High 7.5
`AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`; the maintainer's authenticated-RCE
claim stays a claim. Affected `>=3.1.19, <4.4.3`, fixed 4.4.3. Claim:
`deletedir()` integer underflow makes an unbounded `strcpy` write an
attacker-chosen filename past `char path[MAXPATHLEN + 1]`. Gates: an
authenticated AFP session and a cross-device rename path inside a share.
Brief: [frontier-netatalk2shell.md](frontier-netatalk2shell.md). Pins and raw
URLs: `lab/frontier/netatalk2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/netatalk2shell/run.sh <outdir>` — 24 PASS,
  `ALL CHECKS PASS rc 0`, trace SHA-256
  `c1bba7fb17b2a2b0cf6de7c76725974f005192648287245f5ba3b8aac08339d0`.
  Verified twice from a clean `git archive HEAD` extraction at handoff.
- Operator replay ~05:05Z from a clean `git archive HEAD` extraction of
  commit `c37e96d`: 24 PASS lines, `ALL CHECKS PASS rc 0`, trace
  `sha256=c1bba7fb17b2a2b0cf6de7c76725974f005192648287245f5ba3b8aac08339d0`
  — byte-identical to the brief and to the handoff replays.
- Rungs 1/2/3 on byte-exact pinned upstream `etc/afpd/directory.c:147-203`
  from release 4.4.2 (`d2ef3e2`, sha256 `82d5f3fd…`) and fix 4.4.3
  (`79b13d9`, sha256 `bd23b576…`): a 255-byte `d_name` performs
  `strcpy(path + 1024, d_name)`, writing 256 bytes into `path[1025]`; the
  first byte of the saved-return slot changes; ASan reports
  `stack-buffer-overflow`, `WRITE of size 256`, frame `deletedir` at pinned
  `directory.c:181`, victim `path [240, 1265)`. Fix `33dbda7` uses
  `sizeof(path) - len - 1` and the fixed build never reaches the copy.
- Rung 4 INSTRUMENTED only: token `NET2SHEL` read back byte-exact at write
  offsets 0 and 64 and in the saved-return slot at offset 56; patched 4.4.3
  gives `calls=0`, no changed byte. Harness `longjmp` observes the victim
  before the corrupted return is used — scaffolding, not target behaviour.
- UNKNOWN: live afpd, loopback AFP reachability, authenticated session,
  cross-device mount/rename path, stock frame layout, canary/NX/PIE/ASLR,
  useful-pointer control and execution. No RCE is demonstrated.

Cheapest next rung: build 4.4.2 afpd under ASan, serve a loopback-only AFP
share with a nested cross-filesystem mount point, authenticate, create a
255-byte filename and trigger the `deletedir()` path. Capture the real ASan
frame and the `d_name` at pinned line 181, then measure shipping hardening.
