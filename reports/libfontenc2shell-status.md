# libfontenc2shell — status

Admitted 2026-11-23 15:0xZ under standing approval #6 as the 115th route.
Charter: `.mishe-tauftauf/charters/libfontenc2shell.md`. Trigger units from the
exact full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`;
hy4-flash route 114→115, resolver 229→231, two-pane window 115 adopted with no
duplicate. Pinned full-flag doctor rc 0 GREEN; `check-omp-only.py` GREEN with
115 declared roles. Admission adds no grade.

- Claim: CVE-2026-109908 / GHSA-98gj-rwr5-8j74 (High 7.8,
  `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-122), libfontenc before
  1.1.10 per the upstream fix tag; advisory text says "before 1.11.0" — the
  numeric discrepancy is UNKNOWN. Fix `5920c6e` (parent `7418fa7`) adds
  `if (index > 0xFFFF) return 0;` and corrects the stale `value1` column check.
- Evidence: `lab/frontier/libfontenc2shell/harness/run.sh` and `check.sh` drive
  a whole verbatim pinned `encparse.c` under `#line` with harness-only font
  callbacks and allocator macros. A real zlib `gzFile` reads a temporary
  crafted `.enc` with `SIZE 256 258` and mapping `0xff00 0x5a5a`.
  `setCode()` computes `index = 255 * 258 = 65790`; the store at
  `encparse.c.vuln:495` puts chosen `0x5a5a` 508 bytes past a 131072-byte
  allocation. gcc and clang ASan report `heap-buffer-overflow`, `WRITE of
  size 2`; the fixed pin rejects at `:461` before allocation. gdb reads chosen
  bytes at the out-of-bounds index; the fixed pin's guard fires with
  `ENCSIZE=0`.
- Operator admission replay from a clean `git archive HEAD` at b0387c8:
  5/5 `PINS.sha256` digests OK, `PASS=50 FAIL=0`, trace
  `bfdd7987e86276e59b580e2f2a960c1a760f389625ced38a065bfaba4de37fa2`
  exact. This is deterministic replay, not a witness verdict.
- Ceiling: direct-call CODE/HARNESS rungs 1-4 only. No real libfontenc build,
  X server, font path, `encodings.dir`, X protocol, wire input, live process,
  allocator study, ASLR study, pointer control, ROP, command, marker side
  effect or witness verdict. The `0x5a5a` bytes are chosen data, not execution.
  The 16-bit `sm->first` field truncates 65790 to 254, so only the chosen value
  survives into the copied map; whether a live X server ingests the file and
  which objects lie past this allocation remain UNKNOWN. Rung 5 UNKNOWN.

Next for the target mind: build pinned `7418fa7` and `5920c6e` plus the 1.1.9
and 1.1.10 releases to settle the version discrepancy; drive the upstream
regression `.enc` through a real `FontEncLoad`/X server path under ASan and
identify the heap neighbours before any pointer or marker test. Hand any new
claim to `witness` — the author report is not acceptance.
