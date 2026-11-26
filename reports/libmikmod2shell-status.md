# libmikmod2shell — status at handoff (W276, 2026-11-26)

STAGED. CVE-2026-105837 / GHSA-rr6f-2vgw-5v76, libmikmod DSM loader
`numchn * numpat` truncation to `UWORD of.numtrk`. Brief
`reports/frontier-libmikmod2shell.md`, charter `charters/libmikmod2shell.md`,
harness `lab/frontier/libmikmod2shell/` (PROVENANCE.md has pins, hashes and
preserved negatives).

- Pins: vulnerable `08d7d2106ce3d1d6ef1dddb060e04a10b7dc8ae2` (fix parent),
  fixed `a125eabbd086f311496ae46d08aaebcad0a1c426` (fix, ancestor of 3.3.14).
- Inputs (derived locally, 432 bytes each): `numchn=2, numpat=32769` wraps
  65538 to 2; `numchn=16, numpat=4097` wraps 65552 to 16; two PATT chunks each.
- `sh run-all.sh && sh verify.sh`: `RESULT PASS=12 FAIL=0` at 16:14Z. Vulnerable
  GCC ASan `WRITE of size 8` at verbatim `load_dsm.c:339` during the real
  `Player_Load()`, 0 bytes past a 16-byte / 128-byte `AllocTracks()` region;
  fixed rejects both at the header with `errno=9`; well-formed `numchn=2,
  numpat=2` loads cleanly on both pins.
- Grade: rung 2 observed wrap + rung 3 ASan heap WRITE in verbatim pinned
  library / rung 4 NOT CLAIMED — no chosen offsets, pointer, live consumer,
  command or r5. AV:L advisory vector; no socket, no audio device.
- Preserve: unreviewed NVD-import GHSA, no public PoC bytes, unverified
  earlier "~300 KB / 4097 PATT" estimate, GCC-only ASan with poisoned
  overwrite, no chosen-byte readback.
- Owed: witness clean-archive replay, operator admission, plain-build grooming
  for a chosen adjacent object and readback.
