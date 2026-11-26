# sdimatrix2shell — STAGED, WINDOW 176 LIVE (2026-11-26)

Brief: `reports/frontier-sdimatrix2shell.md`. Lab:
`lab/frontier/sdimatrix2shell/`. Claim: CVE-2026-70659 / GHSA-6q7q-2v9c-x8m7,
stable-diffusion.cpp `master-742-1a13107` before `master-763-4fcc6fe` lets a
duplicate tensor name in an `.imatrix` file reach the accumulation loop with
`values`/`counts` sized by the first, smaller `nval`. Fixed by four lines in
`4fcc6fef10c6f686801c6e257b22cd6a3deb906b`. State: **STAGED by
frontier**, operator admission and independent witness replay owed.
Window 176 `sdimatrix2shell` created on the inner tmux socket
(`mishe-tauftauf2shell-current`), panes %354/%355, both live (top: this
status, bottom: `plant_view --role sdimatrix2shell --output --log --follow`);
registered in `operator/window-registry.json`. No duplicate window is needed.
Witness gate closed 2026-11-26 09:5xZ: W260 replayed the unmodified canonical
runner from a clean `git archive f0eec56a` (rc 0, `RESULT PASS=10 FAIL=0`,
all seven pins held) and returned **ESTABLISHED AS LABELED** at rung 3 verbatim
/ rung 4 PARTIAL, no grade change, NO r5. The "witness replay owed" lines below
were true when written; see the dated W260 section at the end. Operator
admission remains owed to the operator, not to the witness.
Evidence: canonical `run-all.sh` sha256
`65ca30af615053e6ef0056cd3db3d7c40bc71851178ffb7f121bfd0904d7e741` verifies
pinned tarballs, fix patch, verbatim extracted function bodies and harness
SHA-256s; it rebuilds both tags under GCC+Clang ASan and GCC+Clang plain and
drives the crafted file through the real `load_imatrix` body.
`RESULT PASS=10 FAIL=0`, rc 0: vulnerable ASan `READ of size 4`, 0 bytes after
the 4-byte `values` region at verbatim `src/runtime/imatrix.cpp:302`; fixed
tags reject with `inconsistent size for a repeated entry (1 vs 3)`; safe inputs
clean. Plain vulnerable builds put chosen `0x41414141` ints two slots past the
1-element `counts` vector on both compilers. Grade: rung 3 verbatim / rung 4
PARTIAL — no named adjacent object, pointer, CLI path, command or r5.
Author clean-archive replay of the unmodified runner from `git archive
f0eec56a` into `.mishe-tauftauf/replays/sdimatrix2shell-w258/` gave the same
`RESULT PASS=10 FAIL=0`, rc 0, with runner sha256 unchanged (console
`replay-console.log`, 09:23:31Z–09:25:39Z). The first replay at `05369943`
failed PIN_FAIL on a codeload SHA-URL vs tag-URL tarball hash mismatch;
corrected in `f0eec56a` — extracted source bodies were byte-identical.
Next: operator admission only (witness replay closed in W260). Route and
wake units are person-reserved; do not add them here.

## W260 (2026-11-26 09:44–09:5xZ): witness verdict ESTABLISHED AS LABELED

Independent clean-archive replay of `run-all.sh` hash `65ca30af…d7e741`
(identical in worktree, `f0eec56a` and `git archive f0eec56a` subtree):
09:49:01Z–09:50:56Z, rc 0, 10 PASS / 0 FAIL. Provisioned tarballs, fix patch,
generator, driver and both extracted bodies were deleted first and re-fetched
by the runner; all seven SHA-256 pins matched. Vulnerable GCC+Clang ASan:
`READ of size 4`, 0 bytes after the 4-byte `values` region at verbatim
`src/runtime/imatrix.cpp:302` (`counts[i] += ncall`, read before store), with
the allocation stack at `:288`. Fixed GCC+Clang ASan and GCC plain reject the
duplicate with `inconsistent size for a repeated entry (1 vs 3)`, `ok=0`, no
ASan; safe inputs are clean in all three modes. Plain vulnerable GCC+Clang
print chosen `0x41414141` at `counts.data()[1]/[2]` past the 1-element vector,
inside its malloc chunk: no named adjacent object, pointer, CLI path, wire
input, command or r5. No counterexample found; the grade is unchanged. NIT:
Clang's `#line` path renders as a nonexistent absolute path; GCC and pinned
source agree on the relative `src/runtime/imatrix.cpp:302`. Full raw evidence:
`.mishe-tauftauf/artifacts/witness-w260-sdimatrix2shell/detail.md`.
