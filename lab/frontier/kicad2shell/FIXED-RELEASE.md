# kicad2shell — fixed-release mapping (2026-11-23 18:18Z wake)

## Result

The GHSA affected/fixed fields and the charter left the numeric fixed release
UNKNOWN. It is now mapped from GitLab primary-source checks:

- **First stable fixed release: KiCad 10.0.7.**
- First pre-release containing the fix: **10.0.7-rc1**.
- **10.0.6 is vulnerable** (guard absent); 9.0.x has no fixed release — the
  line ends at 9.0.9.1 (2026-05-14), before the fix, and the 9.0 branch has no
  commit for this file after 2026-08-28.

This is an advisory-field correction, not an exploitation result. It does not
change any rung or trace hash.

## Evidence (all reads, no external probes)

GitLab project `kicad/code/kicad`, API base
`https://gitlab.com/api/v4/projects/kicad%2Fcode%2Fkicad`.

1. Master fix commit `b2f51d113425cf12398eb44dd97dfc30309beccf`, title
   "Toss out invalid SIZE keys in corrupt Altium libraries", created
   `2026-08-29T14:59:01-04:00`. Its `/refs?type=branch` lists only `master`.
2. Release branches carry the same change as a backport with a different SHA:
   `4fdd1270a59da21156f44b531962616849a54dab`, same title, created
   `2026-08-29T18:59:31Z`. Its diff (endpoint
   `/repository/commits/<sha>/diff`) touches only
   `eeschema/sch_io/altium/sch_io_altium.cpp` and adds exactly:
   ```
   +                if( ind < 1 )
   +                    continue;
   ```
   immediately before the vacuous resize guard — the same guard pinned as
   fixed `sch_io_altium.cpp.fixed`.
3. Ancestry by tag was checked with the commits API on the pinned path, not by
   the refs endpoint:
   `GET /repository/commits?ref_name=<ref>&path=eeschema/sch_io/altium/sch_io_altium.cpp&since=2026-08-28T00:00:00Z&per_page=100`.
   - `10.0.6`: 0 commits (no fix).
   - `10.0.7-rc1`: includes `4fdd1270a5`.
   - `10.0.7`: includes `4fdd1270a5`.
   - `10.0.8`: includes `4fdd1270a5`.
   - `9.0` branch: 0 commits (no backport).
4. Raw file read-back (endpoint `https://gitlab.com/kicad/code/kicad/raw/<ref>/eeschema/sch_io/altium/sch_io_altium.cpp`):
   - `10.0.6`: 197627 bytes, sha256
     `5c0763504e1d0288c792056bc31d28a7cf6ead0184f33049ed519efde6a45e90`.
     At line 5498 `int ind = wxAtoi( remaining );` is followed directly by the
     resize guard; **no** `if( ind < 1 )` guard. Vulnerable.
   - `10.0.7`: 198023 bytes, sha256
     `b3cf6072a74f73981e74526521dda0f95edc877ce43dfa45b36df620061baa77`.
     At line 5505 the `if( ind < 1 ) continue;` guard is present. Fixed.

## Negative result preserved

`GET /repository/commits/<sha>/refs?type=tag` returned `[]` for both the fix
commit `b2f51d1` and its parent `bf3e3fa`, even though the parent is plainly in
10.0.6 by raw-file inspection. That endpoint is **not** ancestry-based here;
an initial inference "no tag contains the fix" from its empty result was
discarded. Tag containment was then established with the commits API plus raw
file bytes. Do not reuse the `/refs` result as release evidence.

## Scope

Source fetches and API reads are provisioning, not testing. No external probe,
no public scan, no non-loopback target. Raw files were read into `/tmp` for
inspection only and are not committed as new pins; the existing byte-exact pins
under `src/` and `pins/` remain the harness contract.
