# Frontier brief — gpgme2shell (CVE-2026-129975)

Status at staging (2026-11-24 18:xxZ): STAGED at rung 3 / rung 4 PARTIAL,
witness replay PENDING. Superseded by `reports/gpgme2shell-status.md` after
admission and the real-library reproduction; keep the evidence below as the
pinned statement-extract baseline.

## Verified ground truth (read-only provisioning)

- CVE-2026-129975 / GHSA-278w-vg7x-x376, GPGME, CWE-415 double free.
  Vendor advisory 2026-11-20; NVD/GHSA 2026-11-23; Mallory 2026-11-23
  (updated 11-24). CVSS 3.1 8.1 AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H.
- Affected: 2.x before 2.3.1 (2.0.0-2.2.0; 2.3.0 never public) and 1.x
  before 1.24.4. Fixed: 2.3.1 / 1.24.4.
- Public fix commit `14499348b966cd7b3d72afee15a5cd51cdd0a727` ("Fix a double
  free in the status line read code", 2026-11-14); 10-line diff, also posted
  to oss-security 2026/11/20. Sources:
  https://nvd.nist.gov/vuln/detail/CVE-2026-129975 ,
  https://github.com/gpg/gpgme/commit/14499348b966cd7b3d72afee15a5cd51cdd0a727.patch .
- Checked against `reports/frontier-*.md`, the lab listing and the frontier
  wall's do-not-duplicate list: no prior GPGME entry.

## Source-bound mechanism (pinned bytes)

Pinned `src/engine-gpg.c` at tag `gpgme-2.2.0`,
sha256 `c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55`;
fix patch sha256 `2fde658ab8b32439c14f58c214f2463b4109aa68d9cbd26c432f17303049c500`.

In `read_status()` (pinned :1481-1612) a status line longer than the remaining
space triggers `bufsize += 1024; buffer = realloc (buffer, bufsize);`. The new
pointer is published back to `gpg->status.buffer` only at the normal exit
(:1608-1610). Any early return after the realloc — e.g. an error from
`gpg->status.fnc` or `mon_cb` (:1510-1517, :1580-1586) — leaves the context
holding the freed block. `gpg_release()` frees `gpg->status.buffer` again
(:601-602). `read_colon_line()` (:1633-1732) has the same defect on
`gpg->colon`. The fix assigns pointer and size into the context immediately
after a successful realloc and deletes the end-of-function writeback in both
functions. A 24-year-old bug per the commit message (introduced by
`f12433c1e476f52c92496a885c1ffcd10fa2a322`, bug T8557).

## Lab evidence (`lab/frontier/gpgme2shell/`)
Clean-archive replay of commit `88addf93` into `/tmp/w210-gpgme` also gave
19 PASS / 0 FAIL. Window 141 `gpgme2shell` is live on the inner tmux socket
(panes 1384817/1385483, both dead=0, captures verified), registered at
142 windows / 142 unique names, created 18:15:47Z with a seed wall;
operator DM 3762 and witness replay request 3763 are on the tape.
Harness extracts the pinned realloc/early-return/writeback statement sequence
and the verbatim cleanup free; stand-ins supply the status line, the read and
the callback. `sh run.sh` verifies both source hashes and the fix hunk, then
builds vulnerable/fixed ASan and plain binaries and runs attack/safe controls;
19 checks PASS, 0 FAIL. ASan reports `attempting double-free` in `release()`,
with the first free attributed to `realloc()` in `read_status()` and the
allocation to `malloc()` in the harness setup. Chosen status-derived bytes
`0x48` (ASan) and `0x5a` (plain) at offset 1000 past the status keyword are
printed from the stale allocation before the second free. Attack rc=1 under
ASan; fixed attack, vulnerable safe and fixed safe rc=0. Plain glibc behavior
was inconsistent across harness revisions (one revision aborted with
`free(): double free detected in tcache 2`, the final one exited 0); recorded,
not asserted, and left UNKNOWN. All raw evidence lives in `evidence/*.out` /
`*.rc`.

## Rung-4 feasibility and ceiling

Rung 3 is confirmed on pinned upstream statements under ASan; rung 4 is
PARTIAL: chosen status-derived byte is observed in the stale allocation at a
chosen offset. There is no full GPGME build, no gpg process or pipe, no wire
input, no pointer/IP/command control, no allocator-metadata claim and no rung
5. Live reach and stock layout stay UNKNOWN. AV:N is the advisory's vector,
not exercised here.

## Cheapest next experiment

Build real GPGME 2.2.0 with ASan, drive a status pipe that forces a >1024-byte
line plus a callback error, and compare with a 2.3.1 build and a short-line
control. If it reproduces, put a loopback consumer in front of the pipe for
a wire-visible rung 4. Operator admission and witness replay are still owed;
do not duplicate this target.
