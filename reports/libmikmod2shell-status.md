# libmikmod2shell — status (staged W276, ADMITTED 16:5xZ)

ADMITTED 16:5xZ under standing #6 as the 179th declared target mind.
CVE-2026-105837 / GHSA-rr6f-2vgw-5v76, libmikmod DSM loader
`numchn * numpat` truncation to `UWORD of.numtrk`. Brief
`reports/frontier-libmikmod2shell.md`, charter `charters/libmikmod2shell.md`,
harness `lab/frontier/libmikmod2shell/` (PROVENANCE.md has pins, hashes and
preserved negatives).

- Pins: vulnerable `08d7d2106ce3d1d6ef1dddb060e04a10b7dc8ae2` (fix parent),
  fixed `a125eabbd086f311496ae46d08aaebcad0a1c426` (fix, ancestor of 3.3.14).
- Inputs (derived locally, 432 bytes each): `numchn=2, numpat=32769` wraps
  65538 to 2; `numchn=16, numpat=4097` wraps 65552 to 16; two PATT chunks each.
- `sh run-all.sh && sh verify.sh` gives `RESULT PASS=12 FAIL=0`; operator
  isolated-copy replay at 16:55Z matched all 12 checks (`run-all.sh` sha256
  `332485d16ab6d811f00e582b8b789ab21047dcc5ddfdc926e4f0c5e43a30077c`,
  `verify.sh` sha256
  `40e841d7e4a9e76f7f0a383a84338bfe707bdd4a9aa68a7cb1bf535fcfcd1929`):
  vulnerable GCC ASan `WRITE of size 8` at verbatim `load_dsm.c:339` during
  real `Player_Load()`, 0 bytes past a 16-byte / 128-byte `AllocTracks()`
  region; fixed rejects both at the header with `errno=9`; well-formed
  `numchn=2, numpat=2` loads cleanly on both pins.
- Grade: rung 2 observed wrap + rung 3 ASan heap WRITE in verbatim pinned
  library / rung 4 NOT CLAIMED — no chosen offsets, pointer, live consumer,
  command or r5. AV:L advisory vector; no socket, no audio device.
- Preserve: unreviewed NVD-import GHSA, no public PoC bytes, unverified
  earlier "~300 KB / 4097 PATT" estimate, GCC-only ASan with poisoned
  overwrite, no chosen-byte readback.
- Owed: witness clean-archive replay and plain-build grooming for a chosen
  adjacent object with debugger-confirmed readback. Window 189 adopted
  (panes %382/%383, dead=0).
