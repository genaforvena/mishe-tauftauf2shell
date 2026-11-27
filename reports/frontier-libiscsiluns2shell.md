# Frontier brief: libiscsiluns2shell — REPORT LUNS heap WRITE-4 from data-in

**Status: STAGED 2026-11-27 W333, handoff brief ready for operator admission.**
Claim is a high-severity heap out-of-bounds write in libiscsi's SCSI data-in
unmarshalling, pinned between upstream commit `ef5491376` and its direct fix
`eff2822fd`. Reproducible lab: `lab/frontier/libiscsiluns2shell/`; author-side
only, not independent witness acceptance. No CVE/GHSA exists for this advisory
as of 2026-11-27 — that field is UNKNOWN, not inferred.

## Verified ground truth

- Claim source: Benjamin Ali advisory "Out-of-bounds reads and a write in
  libiscsi SCSI data-in unmarshalling", disclosed 2026-08-04, severity high,
  https://benjaminali.com/advisories/libiscsi-scsi-datain-oob/. Reports a
  heap WRITE-4 in `scsi_reportluns_datain_unmarshall()` at `:590` when a
  data-in reply shorter than eight bytes yields `num_luns = -1`, a wrapped
  allocation size and a four-byte write past the allocation; reachable from a
  malicious iSCSI target reply during early REPORT LUNS.
- Pinned bytes: vulnerable
  `ef5491376fbae41a0512f06ae2471909523d49d9` (fix's direct parent; advisory
  also verified `65ebd1415455d5016043a437aeec75e57b3bf043`), fixed
  `eff2822fd1650c6348f872df38ec8a01377e3958` (commit "fix several
  vulnerabilities parsing data-in"). No upstream release tag contains the fix
  as of 2026-11-27; latest tag 1.20.3 predates it. Fixed version: UNKNOWN
  release, fixed at that master commit. Advisory/patch reads were provisioning;
  no external system received a probe.
- Grade: R1 / R2 / R3 ✓; R4 LIMITED; R5 NOT CLAIMED.

## Source-bound mechanism

Vulnerable `lib/scsi-lowlevel.c:576-590` computes `list_size =
task_get_uint32(task, 0) + 8`, clamps to `task->datain.size`, then
`num_luns = list_size / 8 - 1` without a lower bound. A four-byte reply gives
`num_luns = -1`; `scsi_malloc()` allocates `sizeof(void*) + 4 + 2*(-1) = 10`
bytes and `list->num = num_luns` writes four bytes into offsets 8–11. The
fix inserts `if (num_luns < 0) { return NULL; }` before the allocation. The
same commit also bounds six companion INQUIRY/MAINTENANCE-IN read paths; those
are separate claims and not part of this staged finding.

## Cheapest local experiment and result

A direct-call harness sets `cdb[0] = SCSI_OPCODE_REPORTLUNS`, supplies a
four-byte heap data-in blob and calls the public `scsi_datain_unmarshall()`
(the exact dispatch at `:3851`). Four in-tree autotools builds (vuln/fixed ×
ASan/plain) with a 12-check runner give: vulnerable ASan rc 1,
`heap-buffer-overflow`, `WRITE of size 4` at `scsi-lowlevel.c:590`, `0 bytes
after 10-byte region` allocated via `scsi_malloc:113`; vulnerable plain prints
`num=4294967295 (-1)`; fixed ASan/plain return `unmarshall=(nil)`; safe 8- and
16-byte replies are clean on all four variants. `TOTAL: 12 PASS / 0 FAIL`,
summary SHA-256 `d97043e1...`. Full hashes, logs and build notes are in the
lab's `PROVENANCE.md` and `HARNESS_SHA256.txt`.

Honest rung-4 assessment: the overflow is deterministic and ASan-confirmed,
but the written value is the constant `-1` — no attacker-chosen bytes, saved
RIP, adjacent object or marker execution was observed. A live loopback iSCSI
target feeding the reply is conceivable but was not built, so no rung-5 claim.

## Cheapest next rung

Build a loopback iSCSI target (or replay a captured PDU through the real
`iscsi_scsi_command_sync()` client path) so a malicious target's REPORT LUNS
reply reaches `scsi_datain_unmarshall()` over 127.0.0.1; then measure whether
the 2-byte wrapped allocation's two-byte overrun reaches a heap header or an
adjacent tracked `scsi_allocated_memory` object in the plain build. Two bytes
of overwrite is a narrow target; a no-result is a legitimate negative.

## Ranking context

W333 scouts also found NanoMQ CVE-2026-73863 (pre-auth wire heap OOB READ,
published PoC, medium build), samtools GHSA-vh3p-9c59-j3hv (one-character
fix, local file), SIPp CVE-2026-90779 (wire challenge), bincookie
CVE-2026-55246 (header-only, cheapest harness) and others. libiscsi was
chosen for its exact parent/fix pins, tiny guard and wire-derived input;
those remain backups for the next wake.
