# quickjsbcode2shell — ADMITTED 15:4xZ under standing #6 (W271); replay owed

## Admission evidence

- Target: bellard/quickjs `bc_get_leb128_int()` unsigned-to-int cast drives an
  overflowing constant-pool count into a small allocation in
  `JS_ReadFunctionTag()`; CVE-2026-88378 / GHSA-jww9-7qmq-6hv5.
- Pins: vulnerable commit `04be246001599f5995fa2f2d8c91a0f198d3f34c`, fix
  commit `42526037cfc0b2a94a875c0de0f4bbeaf597a542` (parent verified by
  GitHub commit API); no release tags exist.
- Brief: `reports/frontier-quickjsbcode2shell.md`.
- Harness: `lab/frontier/quickjsbcode2shell/run-all.sh`, `harness/driver.c`,
  `PROVENANCE.md`; tarballs and `build/` are gitignored.
- Window: dedicated two-pane target window created by frontier on the inner
  tmux socket (window 185, panes %374/%375, dead=0); registered in the site
  window registry (188 windows, no duplicate). No dedicated OMP route or
  generated wake unit yet (person-reserved).

## Measured result at handoff

`run-all.sh` sha256 `7031c42086ccaad2ee329b18c597cd0fc2b62fe98dd9a6c30f249bc3c09b1cd5`
(operator re-verified against the staged file at admission),
console `evidence-run-console.log`, `RESULT PASS=25 FAIL=0 rc 0` at 13:57Z.
GCC ASan reports `heap-buffer-overflow`, `WRITE of size 96`, `0 bytes after
88-byte region` at verbatim `quickjs.c:38820` in `JS_ReadFunctionTag` for the
exact upstream 21-byte regression input. The fixed build rejects it with
`SyntaxError: integer overflow while reading bytecode`; a real bytecode
round-trip evaluates to `value=2` in both builds. Clang 18 ASan is silent on
this input — preserved as a compiler-negative check.

## Grade and next step

Rung 3 ASan-confirmed heap OOB WRITE in verbatim pinned source; rung 4 NOT
CLAIMED (upstream-fixed bytes, no chosen-offset read-back, pointer steering,
wire consumer, command or r5). Witness replay from clean tarballs is owed;
admission is complete. Cheapest rung-moving experiment: vary the LEB128 count
and groom the plain-build heap for chosen-byte read-back; then feed the bytes
from a loopback client to a real `JS_ReadObject()` consumer with fixed/safe
controls.

Preserve PROVENANCE.md negatives: Clang silence, the driver double-free draft,
and the separate QuickJS-NG backup with its 404 advisory. Author reports are
never independent acceptance.
