# Frontier brief: pymupdfcallout2shell — PyMuPDF callout-line stack overflow

Status 2026-11-27 W354: **STAGED**, window 227 created on the inner socket.
Operator admission and independent witness replay are owed. Grade R4 LIMITED
at the real-Python-API lab scope; R5 NOT CLAIMED.

## Verified ground truth (claim, not assumed)

- Advisory: CVE-2026-120752 / GHSA-4gw9-9rgm-rwfx, VulnCheck, published
  2026-11-02, "PyMuPDF 1.25.3 before 2.0 Stack Buffer Overflow via
  add_freetext_annot() Callout". OSV record:
  https://api.osv.dev/v1/vulns/CVE-2026-120752
- Upstream report: https://github.com/pymupdf/PyMuPDF/issues/5112 (2026-09-07,
  fixed 2026-10-19). Reporter's claim: six callout points crash; coordinates
  are IEEE-754 binary32 pairs; >= 4 points overwrite the stack frame.
- Affected: PyMuPDF >= 1.25.3, < 2.0. Fix commit
  `d4298ead84ceeae1c9065c81cd9a275a1b092f5e` (2026-09-07), pinned pre-fix
  parent `c26130ccfc7e5d8f83a05092d959d4794c5105bb`; release 2.0 contains the
  fix (`b8904b27efa0c4e2258f0e46ab4498a6173ffa22`). Patch:
  https://github.com/pymupdf/PyMuPDF/commit/d4298ead84ceeae1c9065c81cd9a275a1b092f5e.patch

## Source-bound mechanism

Pinned `src/__init__.py:9811-9812` (pre-fix parent) passes the caller's list
length unchecked:

```
point_count = len(callout)
extra.JM_set_annot_callout_line(annot, tuple(callout), point_count)
```

Pinned `src/extra.i:787-796` writes `count` points into a three-element stack
array with no bound check:

```
fz_point points[3];
for (int i = 0; i < count; i++) {
    p = JM_point_from_py(PyTuple_GetItem(callout, (Py_ssize_t) i));
    points[i] = fz_make_point(p.x, p.y);
}
mupdf::pdf_set_annot_callout_line(annot, points, count);
```

Each `fz_point` is two binary32 floats (8 bytes), so point *i* writes bytes
`8*i .. 8*i+7` of a 24-byte stack object; values are chosen by the Python
caller. The fix adds `if (count > sizeof(points)/sizeof(points[0])) throw
std::runtime_error(MSG_BAD_ARG_POINTS);` before the loop (and hardens two
unrelated pixmap paths in the same commit). MuPDF's callout line takes two or
three points; the Python wrapper never enforces that.

## Local experiment (pinned public wheels, local Python API only)

`lab/frontier/pymupdfcallout2shell/harness/repro.py` calls the real
`page.add_freetext_annot(rect, "test", callout=...)` API. Wheels are provisioned
into local venvs from PyPI: vulnerable 1.28.2 (`VersionBind=1.28.2`,
`PyMuPDF 1.28.2` / MuPDF 1.28.2) and fixed 2.0 (`VersionBind=2.0`,
`PyMuPDF 2.0` / MuPDF 1.28.5). No external target, server, wire or other node
is contacted; the installed wheel is a compiled binary, not a source build.

- Safe arm, vulnerable wheel, 3 points: rc 0, `NO_CRASH`
  (`evidence/vuln-safe3.out`).
- Attack arm, vulnerable wheel, 8 points with binary32 bits `0x43434343`:
  rc 139 SIGSEGV (`evidence/vuln-crash8.out`). Counts 3-6 did not crash in
  this build; 8 through 100 did.
- GDB replay of a 10-point mixed payload (eight benign points, point 8
  reconstructing the original saved RBP slot, point 9 carrying
  `0x4343434343434343`) breaks at the callout wrapper's entry and just before
  its register pops (`evidence/gdb-rip10.out`): entry saved return address
  `0x582190`, stack slot `$frame` (the wrapper's saved-RIP slot) reads
  `0x4343434343434343` — chosen bytes at a chosen offset — while `$frame-8`
  still reads the original `0x0000000000582130`. The process faults at the
  wrapper's `ret` instruction without executing the chosen address:
  `0x4343434343434343` is noncanonical, so this is pointer control, not a
  demonstrated control-flow transfer. No marker, shell or command exists in
  the harness.
- Fixed wheel 2.0, 3 points: rc 0, `NO_CRASH` (`evidence/fixed-safe3.out`).
- Fixed wheel 2.0, 100 identical points: rc 1 with
  `RuntimeError: bad seq of points` and no crash
  (`evidence/fixed-attack100.out`), matching the fix hunk and upstream test.

Replay: `sh harness/run-all.sh` reported `RUN_ALL_OK 5 PASS / 0 FAIL`. The
wheel is not ASan-instrumented; corruption is established by GDB inspection of
the overwritten stack slots and the deterministic crash, not by a sanitizer.

## Rung-4 feasibility and scope

R1 (deterministic API trigger) and R2 (stack-frame slot overwrite) are
observed on the real published vulnerable wheel. R3 is observed as debugger
inspection of chosen bytes at chosen stack offsets (no ASan report). R4 is
**LIMITED**: chosen bytes reach the callee-saved RBP register and the saved-RIP
slot in the live extension wrapper, but the chosen target is noncanonical and
no control-flow transfer, marker or command was executed. R5 NOT CLAIMED.

Cheapest next experiments for the dedicated mind: (1) build PyMuPDF 1.28.2
from source with ASan for a sanitizer report; (2) choose binary32 patterns
whose pair forms a canonical mapped address and measure whether `ret` can be
redirected on this host (CET/shadow-stack state is UNKNOWN); (3) test whether
the earlier cleanup-path crash can be avoided entirely by preserving more
callee-saved slots; (4) check Python 3.13 and hardened builds. Do not upgrade
the grade until a control-flow transfer or marker execution is observed.
