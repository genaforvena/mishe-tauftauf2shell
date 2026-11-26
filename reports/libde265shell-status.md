# libde265shell — ADMITTED (165th target mind, 2026-11-26)

Brief: `reports/frontier-libde265shell.md`. Lab: `lab/frontier/libde265shell/`.
Claim: CVE-2026-33165 / GHSA-653q-9f73-8hvg, libde265 <=1.0.16 stale
`ctb_info.log2unitSize` after an SPS change with constant
`PicWidthInCtbsY`/`PicHeightInCtbsY`; `set_SliceHeaderIndex()` writes a 16-bit
slice-header index 2 bytes past a 2496-byte heap array; fixed in 1.0.17 by
`c7891e412106130b83f8e8ea8b7f907e9449b658`. State: **ADMITTED 07:4xZ under
standing #6**; window 173 adopted from frontier (panes %348/%349 live, no
duplicate). Route and three generated wake units are not present in the
current omp-only/doctor readings, person-reserved. Independent witness W254
verdict is recorded below.

Evidence: `run-all.sh` sha256
`acf09b514fad9465cefe481e4a3cff7cccf19419be41dd87267afe3d62d19d1b` verifies
every pin, builds pinned v1.0.16/v1.0.17 with CMake under clang ASan, gcc ASan
and gcc plain, and runs the advisory's unmodified public-API `poc.c` against
its 254-byte reproducer plus a 254-byte benign control. Vulnerable GCC and
Clang ASan give `WRITE of size 2` at verbatim `libde265/image.h:741` from
`slice.cc:2866`, 2 bytes after a 2496-byte region; fixed builds and benign
controls are clean; the plain vulnerable build exits 0 silently. Grade: rung 3
verbatim / rung 4 PARTIAL — no chosen bytes, pointer control, wire path,
command execution or r5.

Operator admission replay: the unmodified `run-all.sh` (sha256 above) from a
clean `git archive 8b4caaf9` at
`.mishe-tauftauf/replays/libde265shell-op-20261126T0747Z` returned
`RESULT PASS=12 FAIL=0`, rc 0. All 12 PASS lines matched the expected cells;
both vulnerable ASan traces show `WRITE of size 2` at `image.h:741` from
`slice.cc:2866`, 2 bytes past the 2496-byte region; fixed 1.0.17 and benign
control traces contain no ASan report. Frontier's author clean-archive replay
at `.mishe-tauftauf/replays/libde265shell-w249` also gave 12 PASS / 0 FAIL.
Neither replay is independent witness acceptance.

Next: a rung-4 upgrade only if a measured plain-allocator layout shows the
2-byte write reaching a named adjacent field with a chosen value. Preserve
the autotools-on-fixed-tag and C++-driver-link negatives in `PROVENANCE.md`,
and the advisory's downstream deblocking OOB reads as unrelated to the write
primitive.

Witness receipt (2026-11-26 07:5xZ, W254): ESTABLISHED AS LABELED at the
claimed scope — rung 3 verbatim / rung 4 PARTIAL, no contradiction, no grade
change, NO r5. The unmodified `run-all.sh` (sha256 `acf09b51…d19d1b`,
identical in worktree, at 8b4caaf9 and HEAD f209d6fa) ran once from a clean
`git archive 8b4caaf9` in 187.45 s with rc 0: 12 PASS / 0 FAIL. Three inputs
were re-fetched independently and matched their pins; both vulnerable ASan
traces show `WRITE of size 2` at verbatim `image.h:741` from `slice.cc:2866`,
2 bytes after a 2496-byte region, fixed and benign traces are empty, plain
vulnerable exits 0 silently. Extra benign inputs (128-byte truncation,
deterministic random 254 bytes) were clean on the same ASan binary; a
first-byte-flipped reproducer still hit the same sink, which is
bitstream-derived `shdr->slice_index`, not arbitrary chosen bytes. Detail:
`.mishe-tauftauf/artifacts/witness-w254-libde265shell/detail.md`.
