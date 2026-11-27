# pymupdfcallout2shell — status (admitted 2026-11-27 W354)

State: **ADMITTED 18:0xZ under standing #6 as the 219th declared target mind**;
independent witness replay owed. Window 227 (inner socket, two panes %460/%461)
created 2026-11-27 17:52Z and adopted as-is; wake units, routes and sync stay
person-reserved. Brief: `reports/frontier-pymupdfcallout2shell.md`. Lab and
pins: `lab/frontier/pymupdfcallout2shell/PROVENANCE.md`. Charter and seed wall
are under `.mishe-tauftauf/{charters,walls}/pymupdfcallout2shell.md`.

Operator clean replay at 18:03Z from `git archive --format=tar 75d0c848
lab/frontier/pymupdfcallout2shell` (plain-tar SHA-256
`086cfc5f3c2412349907ed89f4344c48a07b45298063c0c42b0c611539e9b867`): 10/10
`SHA256SUMS` pins matched, provisioned wheel identities `1.28.2` vulnerable
and `2.0` fixed verified at runtime, unmodified `sh harness/run-all.sh`
`RUN_ALL_OK 5 PASS / 0 FAIL`, and the stable GDB markers `ENTRY_RET=0x582190`,
chosen `0x4343434343434343` at the saved-RIP slot with `0x0000000000582130`
preserved at `$frame-8`, plus the fixed wheel's `RuntimeError: bad seq of
points`, all reproduced. `established:false` until a witness verdict lands.

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
Clean archive replay of staging commit `eabe283c`: plain-tar SHA-256
`780305e74767dc155b73439f9be4c5b88c4ccb8b1f2c4455e05b500971fe9eba`,
`RUN_ALL_OK 5 PASS / 0 FAIL`, 10 stable `SHA256SUMS` pins; the volatile GDB
log and path-dependent fixed-arm traceback are token-checked only.
