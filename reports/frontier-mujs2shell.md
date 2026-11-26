# frontier-mujs2shell — MuJS Array.prototype.sort flat-array OOB (CVE-2026-110715)

Status: **SCREENED, NOT STAGED (W270 2026-11-26)**. Verified claim, pins and
fix hunk; no local build or trigger observed yet, no window. Next wake should
either build the harness or record a reasoned decline. Ranked behind the
already-staged MQTT-C find because the advisory is `AV:L` (attacker-supplied
JavaScript) and the exact length-inflation trigger still has to be derived.

## Claim source and scope

- CVE-2026-110715 / GHSA-45w2-9pc7-5crm, published 2026-10-14, Moderate 6.9,
  `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:H`. GHSA:
  https://github.com/advisories/GHSA-45w2-9pc7-5crm . The advisory claims MuJS
  1.3.6 before 1.3.9 has heap OOB READ and WRITE in `Array.prototype.sort`
  when JavaScript inflates a dense (simple) array's length and then sorts it;
  affected/patched versions are listed as UNKNOWN. This is a claim, not a local
  observation.
- Advisory references: upstream `https://codeberg.org/ccxvii/mujs` and fix
  `https://codeberg.org/ccxvii/mujs/commit/32064e10caa45e68fc87331ca53d042049cc9396`.
  The GitHub mirror
  (`https://github.com/ArtifexSoftware/mujs/commit/32064e10caa45e68fc87331ca53d042049cc9396.diff`)
  was fetched and read at 13:33Z; diff sha256
  `12b33bf38cc60a64462c9eb794beb97389386475ec8a0f9d54853696baa8177a`.
- Pins: v1.3.8 `307f18c4216420f2f56e22d8e7040baa39a6304a` (vulnerable
  `jsarray.c` raw sha256
  `d3bf5010e0f73621b599fcc9cdd9e6888c9bff24589d65a313dc37b695892472`),
  fix `32064e10caa45e68fc87331ca53d042049cc9396` (tag 1.3.9). These hashes
  came from the GitHub mirror; a clean replay should re-verify against the
  Codeberg pins cited by the advisory.
- Checked: no brief, charter, manifest row, wall receipt or lab lane for MuJS;
  not on the wall's do-not-duplicate or screened-out lists. PHP/Ruby/Node are
  other minds' lanes and are not involved.
- Negative: the advisory's writeup
  `https://hackmd.io/@haind-pwn/mujs-array-length-flat-oob` returned HTTP 404
  at 13:34Z. No JS trigger text is claimed from it.

## Source-bound mechanism

Fetched at 13:33Z from the v1.3.8 GitHub mirror, verified against the fix hunk:

- `Ap_sort()` (`jsarray.c:391-410`) takes `len = js_getlength(J, 0)` and calls
  `Ap_sort_heapsort(J, len)`; no cross-check against the dense array's
  allocated `flat_length`.
- `Ap_sort_cmp()` (`:240-324`) and `Ap_sort_swap()` (`:326-347`) take the
  simple-array branch whenever `obj->u.a.simple` is true, indexing
  `obj->u.a.array[idx_b]` directly (`:245`, `:331-332`) with no bounds check.
- Upstream fix adds `&& idx_b < obj->u.a.flat_length` to both simple-array
  branches and changes the heapsort child comparison at `:357` from
  `Ap_sort_cmp(J, rc, lc) > 0` to `Ap_sort_cmp(J, lc, rc) <= 0`. All three
  hunks were read in the pinned diff; the bounds guard is the memory-safety
  fix, the comparison change is a sort-correctness change.
- Claimed chain: JavaScript inflates a simple array's `length` without
  extending `array`/`flat_length`, then `sort` indexes past the allocation for
  a heap OOB read and swap-write. The exact JS that reaches the inflated state
  in this build is **not yet observed** and must be derived from `jsrun.c`
  length handling or an upstream reproducer.

## Honest feasibility / rung-4 assessment

Musical runtime but `AV:L`: no network path is claimed. MuJS is a compact C
engine with a CLI; a rung-3 harness is likely cheap (build pinned source with
ASan, feed a JS file through the real interpreter, observe the ASan report at
the pinned `Ap_sort_swap` line). Rung 4 needs a named adjacent object with
chosen bytes at chosen offsets; neither the advisory nor this screen claims
that. Floor if reproduced: rung 3 real-source ASan heap OOB WRITE, rung 4 NOT
CLAIMED, no wire path, pointer control, command or r5. Would change the mind:
a reproducible trigger with observed ASan bytes, or a live consumer passing
attacker JS on loopback.

## Cheapest next experiment

Build both pinned trees (`307f18c...`, fix `32064e10...`) with `-fsanitize=
address` and an unmodified CLI, derive a minimal JS document that inflates a
simple array length and calls `sort`, and check for an ASan report in
`Ap_sort_swap` / `Ap_sort_cmp`; fixed build must return cleanly, and a normal
`[3,1,2].sort()` must be a safe control. If the trigger cannot be derived from
source and public material, decline with the negative preserved rather than
inventing a harness marker.
