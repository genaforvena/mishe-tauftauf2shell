# frontier-tinyusb2shell — HID report-descriptor underflow (CVE-2026-61497)

Status: **STAGED, rung 3 ASan-confirmed in verbatim pinned source (W275,
2026-11-26)**. The highest-ranked retained candidate after Axis2/C: a small
deterministic descriptor, a one-line bounds fix with a second hardening hunk,
and a clean wire-adjacent consumer path (USB enumeration). No physical USB
hardware was used and no network socket was opened. Pins, hashes and preserved
negatives are in `lab/frontier/tinyusb2shell/PROVENANCE.md`.

## Claim source and scope

- CVE-2026-61497, CNA VulnCheck, published 2026-11-03; NVD record
  `https://nvd.nist.gov/vuln/detail/CVE-2026-61497`; CVE record
  `https://www.cve.org/CVERecord?id=CVE-2026-61497`. CWE-191 integer
  underflow. CVSS 5.2 Medium:
  `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H` (the 4.0 vector is
  `AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/...`). **AV:P — physical access**,
  not network: a malicious USB device attached to a TinyUSB HID host.
- GHSA-qf63-w79j-qw7p `https://github.com/advisories/GHSA-qf63-w79j-qw7p` is
  an **unreviewed, NVD-imported GitHub Advisory Database entry**, not a
  repo-published GHSA: GHSA API has `type: unreviewed`,
  `repository_advisory_url: null`, `github_reviewed_at: null`; upstream
  `https://github.com/hathach/tinyusb/security/advisories` says there are no
  published security advisories and the repo-scoped GHSA URL returns 404. DB
  published 2026-11-03T21:32:30Z, updated 2026-11-10T00:32:30Z.
- **Version discrepancy preserved:** GHSA title/description and a stale CVE
  reference label say "before 0.20.1"; the CVE record, NVD, VulnCheck and the
  0.21.0 release notes say "before 0.21.0". Upstream tags contain 0.20.0 and
  0.21.0 but **no 0.20.1 tag**. Reason for the 0.20.1 string: UNKNOWN. The
  researcher reports 0.17.0–0.20.0 vulnerable. This lab reproduced on the fix
  parent (post-0.20.0) and verified the fix commit.
- Fix: commit `85047e1777f5c20b7a936aa905c746125d3ed066` ("bound item size to
  remaining length in hid report descriptor parser", 1 file, +5/-1), parent
  `5014146fef1aac07362ee35c0c361b8475f7636d`. The fix is in release 0.21.0;
  that tag also zeroes `info->usage_page` before the bounded memcpy, an extra
  change whose originating commit is UNKNOWN and is not part of 85047e1.
- Researcher disclosure: gist `https://gist.github.com/Shukhrat-03/8fe6e5881614a7f86b5d2b87d44ea706`
  (`bug3_final.c`, created 2026-11-06), which explicitly does **not** claim
  code execution and was not run against real USB hardware.
- Checked before staging: no brief, charter, lane, manifest row, wall entry or
  window named for TinyUSB; not on the do-not-duplicate list.

## Source-bound mechanism (pinned bytes)

- `tuh_hid_parse_report_descriptor()` in `src/class/hid/hid_host.c` (line 680
  at the vulnerable pin) iterates HID report items. It consumes one header,
  decrements `uint16_t desc_len`, expands a size field of 3 to 4 bytes, then
  at verbatim lines 800–801 does `desc_report += size; desc_len -= size;`
  with **no check that `size <= desc_len`**. A truncated final item wraps the
  counter (e.g. `1 - 4 = 0xFFFD`) and the parser keeps dereferencing bytes
  past the descriptor buffer.
- The same loop copies a GLOBAL_USAGE_PAGE item with
  `memcpy(&info->usage_page, desc_report, size)` (verbatim line 750) into a
  2-byte field. An item declaring 4 bytes overruns that field even when the
  descriptor itself has 4 bytes available.
- Fix hunk 1: `if (size > desc_len) break;` after the size expansion. Fix
  hunk 2: `memcpy(..., TU_MIN(size, sizeof(info->usage_page)))`. Both are
  present at the fixed pin and were exercised independently below.
- Consumer path (from pinned source): enumeration reads `wReportLength`
  (`report_desc_len = tu_unaligned_read16(...)`), fetches the device-supplied
  report descriptor with `tuh_descriptor_get_hid_report()` into the USBH
  enumeration buffer, passes it to the application's `tuh_hid_mount_cb()`,
  which calls this parser. The input is attacker-controlled device bytes;
  this lab supplies an equivalent in-memory buffer to the verbatim parser.

## Local experiment and observed bytes

`lab/frontier/tinyusb2shell/run-all.sh` slices the parser function
**byte-for-byte** from each pinned `src/class/hid/hid_host.c` into
`build/<pin>/parser.inc`, then compiles it with GCC 12 `-fsanitize=address`.
`sh run-all.sh && sh verify.sh` produced `RESULT PASS=6 FAIL=0` at 15:49Z.
Local additions are only `harness/driver.c`, `harness/shim.h` (constant values
copied from the pinned `hid.h`/`hid_host.h`) and the include paths; no upstream
source was modified.

- **Underflow, vulnerable (researcher's 4 bytes `05 01 07 DE`):** GCC ASan
  `heap-buffer-overflow`, `READ of size 4` at verbatim parser line 68 of the
  sliced function (the `memcpy(&info->usage_page, ...)`), address 0 bytes past
  the exact 4-byte heap descriptor allocated in `driver.c:40`; rc 1. The
  declared size is 4 with 1 byte remaining — the unguarded subtraction is
  what lets that read happen inside the loop.
- **Same input, fixed:** rc 0, `report_num=0` — hunk 1 breaks before the
  oversized item. This is the observed rung-2 state failure and fixed control.
- **Width overrun, vulnerable (5 bytes `07 DE AD BE EF`):** ASan
  `stack-buffer-overflow`, `WRITE of size 4` at the same verbatim parser line,
  overflowing the 4-byte `info` struct (`report_id`, `usage`, `usage_page`);
  rc 1. This is hunk 2's destination bound.
- **Same input, fixed:** rc 0, `usage_page=44510` (`0xADDE`) — the 4-byte item
  is copied with `TU_MIN(size, 2)`, so the chosen low two bytes land in the
  field. No ASan report.
- **Well-formed 13-byte descriptor:** both pins rc 0, `report_num=1`,
  `usage_page=1`, no ASan report.

## Honest grade

Rung 3: ASan-confirmed heap OOB READ (plus a stack OOB WRITE in the second
hunk) in verbatim pinned upstream source, reached through the real parser
function and a descriptor matching the public researcher PoC. Rung 2 is the
observed underflow-to-oversized-item state and the fixed clean stop. Rung 4
**NOT CLAIMED**: no chosen bytes observed at chosen offsets, no pointer or
control-flow steering, no live USB consumer, no command, no r5. The advisory's
AV:P vector is a claim; this lab used an in-memory buffer via a local driver,
not a USB stack or hardware. The stack WRITE is inside the local driver's
`info` object, not a live allocation — it demonstrates the missing bound, not
exploitation.

## Cheapest next experiment to move up a rung

Drive the same descriptor through a pinned TinyUSB HID host build with a
loopback/simulated USB device (or the upstream device-mode scaffold) so the
bytes arrive through `tuh_descriptor_get_hid_report()` and
`tuh_hid_mount_cb()`, then confirm the ASan report follows received bytes with
fixed and safe-input controls. For a rung-4 claim, groom the enumeration buffer
on a plain build so a truncated item's post-underflow header read lands on a
chosen adjacent object and read a chosen value back as a report item; a larger
crashing walk is not enough. Verify whether the parsed `usage_page`/`usage`
values reach any observable host output before claiming disclosure.

## Ranked alternatives from this sweep

- libmikmod CVE-2026-105837 / GHSA-rr6f-2vgw-5v76: DSM `numtrk` UWORD
  truncation → heap OOB write, fixed 3.3.14 by `a125eabb…`; deterministic file
  trigger derivable, but AV:L and roughly 300 KB / 4097 PATT blocks of input.

## Do-not-duplicate and boundaries

No admitted target or screened lane is reused. All execution was local against
pinned source; no external system was probed and no USB hardware was attached.
Admission is the operator's; wake units and full-flag sync stay with the
person. Witness replay from clean tarballs is owed before any ESTABLISHED
verdict.
