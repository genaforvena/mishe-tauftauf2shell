# pymupdfcallout2shell — status (staged 2026-11-27 W354)

State: **STAGED**; operator admission and independent witness replay owed.
Window 227 (inner socket, two panes) created by frontier 2026-11-27 ~17:5xZ.
Brief: `reports/frontier-pymupdfcallout2shell.md`. Lab and pins:
`lab/frontier/pymupdfcallout2shell/PROVENANCE.md`. Charter and seed wall:
`.mishe-tauftauf/{charters,walls}/pymupdfcallout2shell.md`. Wake units, routes
and sync stay person-reserved.

CVE-2026-120752 / GHSA-4gw9-9rgm-rwfx; affected PyMuPDF >= 1.25.3, < 2.0;
fix commit `d4298ead84ceeae1c9065c81cd9a275a1b092f5e`, pinned pre-fix parent
`c26130ccfc7e5d8f83a05092d959d4794c5105bb`. Pinned
`src/__init__.py:9811-9812` passes `len(callout)` to
`extra.JM_set_annot_callout_line`; `src/extra.i:787-796` writes that many
8-byte points into a three-element stack array with no bound check. The fix
rejects `count > 3`.

Grade: R1 ✓ (real Python API trigger), R2 ✓ (stack slots overwritten), R3 ✓ as
GDB-observed chosen bytes at chosen offsets (wheel is not ASan-instrumented),
R4 **LIMITED** (chosen `0x4343434343434343` reaches the saved-RIP slot and the
callee-saved RBP register, but the target is noncanonical and no control-flow
transfer, marker or command executed), R5 NOT CLAIMED. Vulnerable wheel 1.28.2
crashes at >= 8 points; fixed wheel 2.0 rejects 100 points with
`RuntimeError: bad seq of points`. `sh harness/run-all.sh` = `RUN_ALL_OK 5
PASS / 0 FAIL`; `established:false` until a witness verdict lands.

Cheapest follow-through: source-built ASan replay; canonical mapped target to
test `ret` redirection; hardening sweep (PIE, canary, CET). Do not upgrade the
grade without an observed transfer or side effect.
