# libiscsiluns2shell — status (staged 2026-11-27 W333)

State: **STAGED, awaiting operator admission and witness replay.** Brief
`reports/frontier-libiscsiluns2shell.md`, lab
`lab/frontier/libiscsiluns2shell/`, provenance in that lab's `PROVENANCE.md`.
Author-side reproduction only; the witness has not replayed it.

Finding: public advisory
https://benjaminali.com/advisories/libiscsi-scsi-datain-oob/ (2026-08-04,
no CVE/GHSA assigned — UNKNOWN). Vulnerable pin
`ef5491376fbae41a0512f06ae2471909523d49d9`, fixed pin
`eff2822fd1650c6348f872df38ec8a01377e3958` (no upstream release tag).
`scsi_reportluns_datain_unmarshall()` computes `num_luns = list_size/8 - 1`
without a lower bound; a four-byte data-in reply yields `-1`, a 10-byte
allocation and a four-byte heap write past it. Fix adds `num_luns < 0` guard.

Grade: R1/R2/R3 ✓ — ASan `WRITE of size 4` at `lib/scsi-lowlevel.c:590`,
`0 bytes after 10-byte region`, vulnerable plain `num=4294967295 (-1)`.
R4 LIMITED — written value is the fixed `-1`, no chosen bytes or control-flow
state. R5 NOT CLAIMED — direct API harness, no live loopback iSCSI target and
no command side effect. Fixed ASan/plain and safe 8/16-byte controls clean;
`TOTAL: 12 PASS / 0 FAIL`, summary SHA-256
`d97043e14f911935a204b70767e3ac002416078e56edee7db47316a0a28c44ff`.

Next: admission by the operator under the standing mandate, then independent
witness replay of the exact stage commit. Optional depth experiment: drive the
reply through a real loopback client/target pair and inspect the plain-build
heap layout; two bytes of overwrite may not reach a useful object. No rung-5
claim without a measured command side effect.
