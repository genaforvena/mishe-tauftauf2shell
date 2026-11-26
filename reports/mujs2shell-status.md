# mujs2shell — admitted status (W271/W272, 2026-11-26)

## What is admitted

- Target: MuJS `Array.prototype.sort()` flat-array OOB read after JavaScript
  inflates a simple array's logical length; CVE-2026-110715 /
  GHSA-45w2-9pc7-5crm.
- Pins: v1.3.8 `307f18c4216420f2f56e22d8e7040baa39a6304a`, fix
  `32064e10caa45e68fc87331ca53d042049cc9396` (tag 1.3.9).
- Brief: `reports/frontier-mujs2shell.md` (updated from screened to admitted).
- Harness: `lab/frontier/mujs2shell/run-all.sh`, `harness/attack.js`,
  `PROVENANCE.md`; tarballs and `build/` are gitignored.
- Window: dedicated two-pane target window 186 adopted as-is on the inner
  tmux socket (panes %376/%377 live, dead=0, one registry entry).
- Admission: operator 22:1xZ under standing #6 as the 189th declared target
  mind; no duplicate of an admitted target or CVE.

## Measured result at handoff

`run-all.sh` sha256 `5aca123ab59aae54f9bd9f96896b61ef290516d22867a6acfd655cf913f59e68`,
console `evidence-run-console.log`, `RESULT PASS=23 FAIL=0 rc 0` at 14:06Z.
The four-line JS document `var a=[3,1,2]; a.length=1000; a.sort();` gives GCC
ASan `heap-buffer-overflow`, `READ of size 1` at verbatim
`jsarray.c:246` in `Ap_sort_cmp` through the real MuJS CLI. Fixed build:
`sorted-length=1000`, clean; normal-sort control on both pins: clean,
`normal=3 1,2,3`.

Operator clean-archive admission replay at 22:1xZ (`git archive HEAD
lab/frontier/mujs2shell`, staged console and generated safe.js removed, both
pinned tarballs copied in at their asserted hashes): runner sha256
`5aca123ab59aae54f9bd9f96896b61ef290516d22867a6acfd655cf913f59e68`,
rc 0, `PASS=23 FAIL=0`; fresh ASan `READ of size 1` at verbatim
`jsarray.c:246` in `Ap_sort_cmp`, fixed and normal-sort controls clean.

## Grade and next step

Rung 3 ASan-confirmed heap OOB READ in verbatim pinned source; rung 4 NOT
CLAIMED (no OOB WRITE site observed, no chosen-offset read-back, pointer,
wire consumer, command or r5). Operator #5581 bounded experiment was
satisfied with a derived trigger rather than a decline. W272 independent
clean-archive replay (tape #5604) was ESTABLISHED AS LABELED at this rung-3
scope, no grade change, and is folded into the manifest. No replay or
admission remains owed. Cheapest rung-moving experiment: derive a shape
reaching `Ap_sort_swap()` for an ASan WRITE, then groom for chosen-byte
read-back; keep vulnerable/fixed/normal controls.

Preserve PROVENANCE negatives: 404 advisory writeup, no WRITE observed,
normal-control self-generation. Author reports are never independent
acceptance.
