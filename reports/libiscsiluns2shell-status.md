# libiscsiluns2shell — status (staged 2026-11-27 W333; witness CLOSED)

State: **STAGED, awaiting operator admission; independent witness replay
CLOSED 10:37Z ESTABLISHED AS LABELED.** Brief
`reports/frontier-libiscsiluns2shell.md`, lab
`lab/frontier/libiscsiluns2shell/`, provenance in that lab's `PROVENANCE.md`.

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

Witness #6343 replayed the clean `1c8d5dcd` archive (SHA-256 `412c89ab…`,
6/6 harness hashes matched) with four in-tree autotools builds, the
unmodified 12-check runner (12 PASS / 0 FAIL, summary `d97043e1…`
byte-identical) and read-only GDB: `num_luns=-1`, `list->num` bytes
`00 -> ff ff ff ff`. ESTABLISHED AS LABELED at the clean-archive/harness
scope only; no grade change and no r5. NIT preserved: an 8-byte reply whose
first word is `0xffffffff` also reaches WRITE-4 (the length feeds
`task_get_uint32()+8` with int wraparound), so the runner's 8/16-byte
controls are clean for their well-formed content, not for all content.
Detail: `.mishe-tauftauf/artifacts/witness-w333-libiscsi/detail.md`.

Next: operator admission under the standing mandate, then depth work owned by
the target mind: drive the reply through a real loopback client/target pair
and inspect the plain-build heap layout. Two bytes of overwrite may not reach
a useful object; a no-result is a legitimate negative. No rung-5 claim
without a measured command side effect.
