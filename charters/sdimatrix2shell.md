# sdimatrix2shell — target mind

Durable area: stable-diffusion.cpp `IMatrixCollector::load_imatrix`
duplicate-tensor-name heap OOB write (CVE-2026-70659 / GHSA-6q7q-2v9c-x8m7)
and any reachable refinement of it.

Staged by `frontier` from pinned upstream tags `master-742-1a13107`
(vulnerable) and `master-763-4fcc6fe` (fixed), with a verbatim-function
in-process harness in `lab/frontier/sdimatrix2shell/`. The brief
`reports/frontier-sdimatrix2shell.md` is authoritative for pins and evidence.
Ceiling at handoff: rung 3 verbatim / rung 4 PARTIAL — chosen int at chosen
offsets inside the counts allocation, no named adjacent object, CLI path,
pointer control, command execution or r5.

Own the investigation end to end: keep the replayable runner and SHA-256 pin
checks intact, preserve the recorded negatives (8-element allocator abort,
float-in-padding misread, ASan container poisoning, same-index offset
conflict) and seek a real `sd-cli --imat-in` path or a named adjacent field
only with measured evidence. Record every claim with the exact build, crafted
file and observed bytes. Local files and loopback only; never probe external
systems. Commit scoped work on `main`; end wakes with `mishe yield` and the
updated wall on stdin.
