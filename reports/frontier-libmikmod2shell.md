# frontier-libmikmod2shell — DSM track-count truncation (CVE-2026-105837)

Status: **STAGED, rung 3 ASan-confirmed in verbatim pinned source (W276,
2026-11-26)**. A local, deterministic DSM file makes the pinned library
allocate a too-small track-pointer array and then write past it through the
real `Player_Load()` path. The fixed pin rejects the same file at the header.
No network, no external target, no audio device: only the library's `drv_nos`
was registered. Pins, hashes, generated inputs and preserved negatives are in
`lab/frontier/libmikmod2shell/PROVENANCE.md`.

## Claim source and scope

- CVE-2026-105837, CNA VulnCheck, finder Tristan Madani, published
  2026-10-06. GHSA-rr6f-2vgw-5v76
  `https://github.com/advisories/GHSA-rr6f-2vgw-5v76`; NVD
  `https://nvd.nist.gov/vuln/detail/CVE-2026-105837`; CVE record
  `https://www.cve.org/CVERecord?id=CVE-2026-105837`. The advisory description
  says: "libmikmod before 3.3.14 contains an integer overflow vulnerability in
  DSM_Load() in load_dsm.c that allows attackers to trigger heap buffer
  overflow via crafted track counts. Attackers can supply a DSM module whose
  numchn and numpat product wraps a 16-bit value, overwriting heap memory to
  cause crashes or potential code execution."
- CWE-190. CVSS 3.1 `7.8 HIGH`,
  `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`; CVSS 4.0 `8.5 HIGH`,
  `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.
  **AV:L — local vector**, user-supplied module file; not a network claim.
  The "potential code execution" phrase is advisory prose, not a demonstrated
  result here.
- GHSA API fields: `type: unreviewed`, `repository_advisory_url: null`,
  `github_reviewed_at: null`, `vulnerabilities: []`, "No package listed",
  affected/patched versions "Unknown". It is an NVD-imported advisory, not a
  repository-published GitHub security advisory.
- Affected: "before 3.3.14" per CVE/NVD; the 3.3.13 tag points at
  `b25f6ee25bdfc05d21b6e7f1f6a72eb15fa1ebb2`. The 3.3.14 tag points at
  `8de19eef766d9ba30a74c19e566edfcd61851dba`; OSV lists both that release
  commit and the fix commit as fixed. GitHub compare from the fix to the
  3.3.14 tag reports `status: ahead`, `ahead_by: 6`, `behind_by: 0`, so the
  fix is an ancestor of the release tag.
- Fix: `a125eabbd086f311496ae46d08aaebcad0a1c426` ("load_dsm.c: make sure that
  numtrk calculation fits into an UWORD", one file, +7/-1), parent
  `08d7d2106ce3d1d6ef1dddb060e04a10b7dc8ae2`. No public PoC bytes were found
  in the fetched records, so the file used here is derived from the pinned
  source, not copied from a published exploit.
- Checked before staging: no brief, charter, lane, manifest row, wall entry or
  window named for libmikmod; not on the frontier do-not-duplicate list.

## Source-bound mechanism (pinned bytes)

- `DSM_Load()` in `libmikmod/loaders/load_dsm.c` reads `mh->numpat` and
  `mh->numtrk` as `UWORD` from the file. At vulnerable lines 271–273 it sets
  `of.numchn=mh->numtrk; of.numpat=mh->numpat;
  of.numtrk=of.numchn*of.numpat;`. `MODULE` declares `numchn` as `UBYTE`,
  `numpat` and `numtrk` as `UWORD`, and `tracks` as `UBYTE**`
  (`include/mikmod.h:561,564,598,599`). The product therefore wraps to 16
  bits before the assignment.
- `AllocTracks()` (`playercode/mloader.c:213-220`) rejects a zero `numtrk`,
  otherwise `MikMod_calloc(of.numtrk, sizeof(UBYTE *))`. A wrap to zero is not
  exploitable through that path; the derived input wraps to a small nonzero
  value.
- Later, the PATT branch of the load loop (verbatim line 339) does
  `if(!(of.tracks[track++]=DSM_ConvertTrack(&dsmbuf[t*64]))) return 0;` for
  `t = 0 .. of.numchn-1` on **each** pattern. The number of writes is the
  full product, while the allocation used the truncated product. That is the
  heap WRITE.
- Fix hunk: `unsigned int numtrk;`, then
  `numtrk=of.numchn*of.numpat;`,
  `if(of.numchn>DSM_MAXCHAN || numtrk>65535) { _mm_errno=MMERR_LOADING_HEADER; return 0; }`,
  `of.numtrk=(UWORD)numtrk;`. Both bounds are present at the fixed pin; the
  `diff -u` of the two pinned files contains exactly that hunk and the new
  local variable.

## Local experiment and observed bytes

`lab/frontier/libmikmod2shell/run-all.sh` builds each pinned CMake tree with
GCC 13 `-fsanitize=address -g -O1`, compiles the local `harness/driver.c`
against the pinned static library, and generates minimal DSM files with
`harness/make_dsm.py`. The driver registers only `drv_nos` and calls the real
`Player_Load()`. Upstream source is unmodified. `sh run-all.sh` plus
`sh verify.sh` produced `RESULT PASS=12 FAIL=0` at 16:14Z.

- **Attack input (432 bytes):** SONG header with `numchn=2`, `numpat=32769`
  (product 65538, truncated `of.numtrk=2`), one empty INST chunk, two empty
  PATT chunks. Vulnerable pin: GCC ASan `heap-buffer-overflow`, `WRITE of size
  8` at verbatim `load_dsm.c:339` in `DSM_Load`, **0 bytes after a 16-byte
  region** allocated by `AllocTracks()` at `mloader.c:219`, reached from
  `Player_Load()`; rc 1.
- **Second attack input (432 bytes):** `numchn=16`, `numpat=4097` (product
  65552, truncated 16): ASan `WRITE of size 8` at the same line, 0 bytes past
  a 128-byte region; rc 1.
- **Same inputs on the fixed pin:** rc 1, `errno=9 (Failure loading module
  header)`, no ASan report. That is the observed rung-2 state failure.
- **Well-formed control (432 bytes):** `numchn=2`, `numpat=2`, product 4, two
  PATT chunks; both pins rc 0, `channels=2 patterns=2 tracks=4 samples=1`, no
  ASan report.
- No 300 KB input was needed. An earlier wall note estimating "~300 KB /
  4097 PATT blocks" is **not verified**; the derived 432-byte files trigger
  the first OOB write on the second PATT chunk. If a fuller load is needed,
  that estimate remains an unverified claim.

## Honest grade

Rung 2: observed wrap (`65538 -> 2`) and fixed header rejection. Rung 3:
ASan-confirmed heap OOB WRITE in verbatim pinned upstream source through the
real library loader, with fixed and well-formed controls. Rung 4 **NOT
CLAIMED**: no chosen bytes observed at chosen offsets, no pointer or control
flow steering, no live wire or file-consumer path beyond the local driver, no
command and no r5. The advisory's AV:L vector is a claim; the file was opened
by the local driver, not through a remote request or a user-facing application.
ASan redzones mean the overwritten 8 bytes land in poison, not in a chosen
adjacent object.

## Cheapest next experiment to move up a rung

Build the same pinned library **without** ASan, place a crafted `of.tracks`
allocation next to a chosen heap object with ordinary allocator grooming, and
read back a chosen pointer value through an observable module field or downstream
use after the OOB write. Verify the exact address/offset with a debugger and
keep fixed and safe-input controls. Only after a chosen-byte readback should a
rung-4 claim be considered; nothing here establishes rce.

## Do-not-duplicate and boundaries

No admitted target or screened lane is reused. All execution was local; no
external system was probed, no socket was opened and no audio device was used.
Admission is the operator's; wake units and full-flag sync stay with the person.
Witness replay from clean tarballs is owed before any ESTABLISHED verdict.
