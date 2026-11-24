# frontier brief — librecad2shell (candidate screened, NOT staged)

## Ground truth (read-only provisioning, 2026-11-24 04:41Z)

- Claim: VulnCheck 2026-11-23,
  <https://www.vulncheck.com/advisories/librecad-through-2.2.1.6-heap-out-of-bounds-write-via-rs-filterdxf1-readfileinbuffer>,
  CVE-2026-135294, CWE-787, CVSS4 5.8
  `AV:L/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:H`. Affected: LibreCAD <= 2.2.1.6.
  Claimed primitive: opening a crafted DXF sized `0xFFFFFFF8` bytes truncates
  the 64-bit file size into a negative 32-bit read index and writes a NUL
  byte before an 8-byte allocation, corrupting heap metadata and crashing.
  No RCE claim. Credit: Lee Keon-Hyeong, Shin Dong-Hoon.
- Fix: commit `4e51048ee7ae82e553e739b3bba82d5fa89698e1`
  (PR #3287, 2026-11-21), one file
  `librecad/src/lib/filters/rs_filterdxf1.cpp`, 17+/19-. Patch pinned at
  `lab/frontier/librecad2shell/pinned/fix-4e51048.patch` (sha256
  `9cdb82e6…7026`) alongside the vulnerable v2.2.1.6 file (sha256
  `0cde2846…0a2097`).
- Vulnerable function at pinned line 1827 of tag `v2.2.1.6`:
  `fSize=file.size(); if(_bNum==-1) _bNum=fSize; fBuf=new char[_bNum+16];
  file.read(fBuf,_bNum); fBuf[_bNum]='\0';`. `fSize` is a 32-bit unsigned
  member and `file.size()` is `qint64`; the implicit narrowing makes
  `_bNum` negative near 4 GiB, so the allocation is small and
  `fBuf[_bNum]` writes before it. The fix rejects sizes above
  `INT_MAX-16`, uses the `qint64` read result and terminates at the actual
  byte count; it also fixes a second, distinct short-read `fSize` bug.

## Source-bound mechanism and feasibility

The negative-index NUL write is a one-byte underwrite before the buffer,
with no attacker-chosen bytes: the written value is always `'\0'`. The
consumer in the same function is `dos2unix()`, so the corrupted chunk
header is exercised before `free`, but no pointer or instruction pointer
control is claimed by the advisory or visible in the hunk. The fix is
already public and numeric release information is UNKNOWN beyond
`<= 2.2.1.6`.

## Ranking and cheapest next experiment

Rank: low tractability relative to the staged W196 FontForge candidate.
The trigger needs a ~4 GiB sparse file plus a real Qt/LibreCAD build and a
GUI/CLI DXF import path; the primitive is a fixed NUL byte, not chosen
bytes, so even a successful local rung-3 result resembles the screened-out
hydra2shell case (rung 3 wire only). Cheapest experiment that would move
it: build the pinned `v2.2.1.6` DXF1 filter harness with Qt available,
create a sparse 0xFFFFFFF8-byte DXF under `lab/frontier/librecad2shell/`,
and check whether `_bNum` actually narrows to a negative `int` on this
host (64-bit long, `int` 32-bit) and whether ASan reports an underwrite
at `fBuf[_bNum]`; then apply the pinned fix hunk as a control. Do not
allocate 4 GiB of real memory: the reader copies `_bNum` bytes into the
undersized buffer, so bound the run with a timeout and a memory limit.

## Ceiling / UNKNOWNs

No local build, no trigger, no observed bytes: this is a source-bound
screening brief only, not a rung. No witness request and no window are
owed. The one-byte underwrite means rung 4 with chosen bytes is unlikely
through this path; real-file reachability, Qt build feasibility and the
consumer's behaviour under the corrupted header remain UNKNOWN. Do not
duplicate a later admission of this target.
