# frontier-mujs2shell — MuJS Array.prototype.sort flat-array OOB (CVE-2026-110715)

Status: **STAGED, rung 3 ASan-confirmed in verbatim pinned source (W271
2026-11-26)**. Operator #5581 bounded experiment executed this wake; the
trigger was derived from the pinned length setter, so a reasoned decline was
not needed. Ranked behind the two earlier W271 finds on advisory severity
(AV:L, Moderate 6.9), but the harness is cheap and the JS trigger is four
lines. Provenance and hashes are in `lab/frontier/mujs2shell/PROVENANCE.md`.

## Claim source and scope

- CVE-2026-110715 / GHSA-45w2-9pc7-5crm, published 2026-10-14, Moderate 6.9,
  `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:H`. GHSA:
  https://github.com/advisories/GHSA-45w2-9pc7-5crm . The advisory claims MuJS
  1.3.6 before 1.3.9 has heap OOB READ and WRITE in `Array.prototype.sort`
  when JavaScript inflates a dense (simple) array's length and then sorts it;
  affected/patched versions are listed as UNKNOWN. Only the pinned code below
  was reproduced locally; no wire path is claimed.
- Advisory references: upstream `https://codeberg.org/ccxvii/mujs` and fix
  `https://codeberg.org/ccxvii/mujs/commit/32064e10caa45e68fc87331ca53d042049cc9396`.
  The GitHub mirror diff was fetched and read; pins below come from the mirror
  tarball commits and should be re-verified against Codeberg on witness replay.
- Pins: v1.3.8 `307f18c4216420f2f56e22d8e7040baa39a6304a` (verbatim
  `jsarray.c` sha256 `d3bf5010e0f73621b599fcc9cdd9e6888c9bff24589d65a313dc37b695892472`),
  fix `32064e10caa45e68fc87331ca53d042049cc9396` (tag 1.3.9, `jsarray.c`
  sha256 `27361ae1d9f883164a71f0e7227d4ea3e4f378a5889a6f456ccdbc074e05792e`).
- Checked: no prior brief/charter/manifest row/lane for MuJS before W270; not
  on the wall's do-not-duplicate list. PHP/Ruby/Node are other minds' lanes.
- Negative preserved: the advisory's writeup
  `https://hackmd.io/@haind-pwn/mujs-array-length-flat-oob` returned HTTP 404
  at 13:34Z; no trigger text was taken from it. The trigger below was derived
  from pinned `jsrun.c`, not from that page.

## Source-bound mechanism (pinned bytes)

- `jsR_setproperty()` in pinned `jsrun.c:692-702` handles a simple array's
  `"length"` write by setting `obj->u.a.length = newlen` and only shrinking
  `flat_length` when `newlen <= flat_length`. Growing the logical length past
  the flat allocation leaves `simple=1` and the backing `array` unchanged.
- `Ap_sort()` (`jsarray.c:391-407`) takes `len = js_getlength(J, 0)` — the
  inflated logical length — and calls `Ap_sort_heapsort(J, len)` with no check
  against `flat_length`.
- `Ap_sort_cmp()` (`:240-324`) and `Ap_sort_swap()` (`:326-347`) take the
  simple-array branch and index `obj->u.a.array[idx_b]` without a bound. The
  fix adds `&& idx_b < obj->u.a.flat_length` to both branches and changes a
  heapsort child comparison; the bounds guards are the memory-safety fix.
- Derived trigger (`harness/attack.js`):
  `var a = [3,1,2]; a.length = 1000; a.sort();` — `flat_length` stays 3 while
  `sort` walks indices up to 999.

## Local experiment and observed bytes

`lab/frontier/mujs2shell/run-all.sh` (sha256
`5aca123ab59aae54f9bd9f96896b61ef290516d22867a6acfd655cf913f59e68`) extracts
both tarballs, checks hashes and the nine-line three-hunk diff, builds the
**unmodified** pinned trees with upstream `make` and `-fsanitize=address`, then
runs the derived JS document through the real MuJS CLI. Console
`evidence-run-console.log`: `RESULT PASS=23 FAIL=0 rc 0`.

- Vulnerable build: `AddressSanitizer: heap-buffer-overflow`, `READ of size 1`,
  frame `Ap_sort_cmp .../build/vuln/jsarray.c:246` via `Ap_sort_sift`,
  `Ap_sort_heapsort`, `Ap_sort` and the real JS call chain; rc 1. ASan labels
  the address a wild pointer in a 1-byte access range.
- Fixed build on the same document: rc 0, `sorted-length=1000`, no ASan
  report — the added guard keeps the inflated length from indexing storage.
- Normal-sort control (`[3,1,2].sort()`) on both pins: rc 0,
  `normal=3 1,2,3`, no ASan report.

## Honest grade

Rung 3: ASan-confirmed heap OOB READ in verbatim pinned upstream source,
driven by a real JS document through the unmodified CLI. No OOB WRITE site was
observed (the read aborts first); no chosen bytes at chosen offsets, pointer
steering, wire consumer, command or r5. Rung 4 **NOT CLAIMED**. Advisory AV:L
is a claim; this lab used no socket.

## Cheapest next experiment to move up a rung

Derive a variant that reaches `Ap_sort_swap()` before the comparator read —
for example a comparator or array shape that keeps `idx_b` in range during
comparisons while the swap index goes out of range — and check for an ASan
WRITE at verbatim `jsarray.c:331-332`. Then groom a plain build so the OOB
index lands on a chosen adjacent object and read the chosen bytes back. A
rung-4 claim needs observed chosen bytes at chosen offsets, not just a fault.
If an attacker-supplied JS consumer is put on loopback, it still needs a real
wire-side observation before any rung-5 wording.

## Do-not-duplicate and boundaries

No admitted target or screened lane is reused. All testing is local against
pinned source; no external system was probed. Admission is the operator's;
wake units and full-flag sync stay with the person. Witness replay from clean
tarballs is owed before ESTABLISHED.
