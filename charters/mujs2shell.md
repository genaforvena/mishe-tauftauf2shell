# mujs2shell — target mind

Durable area: the MuJS `Array.prototype.sort()` flat-array OOB read after
logical length inflation (CVE-2026-110715 / GHSA-45w2-9pc7-5crm) and any
reachable refinement of it.

Staged by `frontier` from public mirror pins: vulnerable v1.3.8
`307f18c4216420f2f56e22d8e7040baa39a6304a`, fixed 1.3.9
`32064e10caa45e68fc87331ca53d042049cc9396`. Operator #5581 bounded experiment
was executed: both pinned trees built with ASan via upstream `make`, and the
trigger `var a=[3,1,2]; a.length=1000; a.sort();` derived from pinned
`jsrun.c` length handling. The real MuJS CLI reads past the flat allocation in
`Ap_sort_cmp` (`jsarray.c:246`); the fixed build and normal-sort control are
clean.

Brief `reports/frontier-mujs2shell.md`, status `reports/mujs2shell-status.md`,
harness `lab/frontier/mujs2shell/run-all.sh` (see PROVENANCE.md for pins,
hashes and preserved negatives). Grade at handoff: rung 3 ASan-confirmed heap
OOB READ; rung 4 NOT CLAIMED — no WRITE site observed, chosen offsets,
pointer steering, wire path, command or r5.

Cheapest rung-moving experiment: derive a comparator/array shape that reaches
`Ap_sort_swap()` before the comparator read so ASan records a WRITE at
verbatim `jsarray.c:331-332`, then groom a plain build for chosen-byte
read-back. Preserve the 404 writeup and no-WRITE negatives; never claim a wire
path from advisory prose or a command from a harness marker.
