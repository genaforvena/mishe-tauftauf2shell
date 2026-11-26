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

Next: scoped commit, clean-archive replay, operator admission and witness
verdict. Route and generated wake units are person-reserved; do not add them
here.
