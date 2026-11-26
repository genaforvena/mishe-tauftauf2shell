# libde265shell — STAGED (frontier, 2026-11-26)

Brief: `reports/frontier-libde265shell.md`. Lab: `lab/frontier/libde265shell/`.
Claim: CVE-2026-33165 / GHSA-653q-9f73-8hvg, libde265 <=1.0.16 stale
`ctb_info.log2unitSize` after SPS change; `set_SliceHeaderIndex()` writes 2
bytes past a 2496-byte heap array; fixed 1.0.17 by `c7891e412…`.
State: **STAGED, admission owed**. Window 173 created by frontier; operator
admission and independent witness replay owed. No wake unit or route change
by frontier (person/genome-reserved).

Evidence: `run-all.sh` sha256
`acf09b514fad9465cefe481e4a3cff7cccf19419be41dd87267afe3d62d19d1b`
rebuilds pinned v1.0.16/v1.0.17 sources with clang ASan, gcc ASan and gcc
plain, verifies all input SHA-256 pins, and runs the advisory's unmodified
public-API `poc.c` against its 254-byte reproducer plus a benign 254-byte
control. Result `RESULT PASS=12 FAIL=0` at 07:32Z. Vulnerable ASan builds give
`WRITE of size 2` at verbatim `libde265/image.h:741` from `slice.cc:2866`, 2
bytes after a 2496-byte region; fixed builds and benign control are clean.
Plain vulnerable build exits 0 silently (write not faulted), as the advisory
predicts. Grade: rung 3 verbatim / rung 4 PARTIAL — no chosen bytes, pointer
control, wire path, command execution or r5.

Frontier clean-archive replay: unmodified `run-all.sh` (sha256
`acf09b514fad9465cefe481e4a3cff7cccf19419be41dd87267afe3d62d19d1b`)
from `git archive 8b4caaf9` at
`.mishe-tauftauf/replays/libde265shell-w249` gave `RESULT PASS=12 FAIL=0`,
same verbatim WRITE-2 frames and clean controls. This is an author replay,
not independent acceptance; witness replay is still owed.
Next: independent witness verdict (author clean-archive replay 12/0 above); then, only if a measured plain
allocator layout shows the 2-byte write reaching a named adjacent field with
chosen value, consider a rung-4 upgrade. Preserve both build-path negatives in
`PROVENANCE.md` (autotools on fixed tag, C++ driver link) and the advisory's
downstream deblocking OOB reads as unrelated to the write primitive.
