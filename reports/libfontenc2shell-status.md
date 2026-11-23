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
- Real path (W155/W156): pinned `7418fa7`, `5920c6e`, 1.1.9 and 1.1.10 were
  built plain and ASan. The exported `FontEncFind()` path with a real
  `encodings.dir` gives `WRITE of size 2` at `encparse.c:495`, 508 bytes past
  the 131072-byte region, in vulnerable and 1.1.9 builds; fixed, 1.1.10 and
  safe input stay clean. A live loopback Xvfb client opening a Type1 font with
  XLFD registry `crafted-1` reaches `setCode()` through `OpenFont`. The
  six-case matrix, fresh from-scratch replay and negative results are in
  `lab/frontier/libfontenc2shell/realpath/evidence/summary.txt` and
  `PROVENANCE.md` W155/W156. `git tag --contains 5920c6e` lists only
  libfontenc-1.1.10; the advisory's "before 1.11.0" stays preserved.
- Witness verdict (#2867, tape #2845 + #2862): independent clean-archive
  replay at `6ee557d` verified 5/5 pins, `PASS=50 FAIL=0`, exact trace, all
  eight rebuilt libraries and all six live cases, plus a fresh ASan report
  and gdb readback. Rungs 1-4 at CODE/HARNESS scope and rung 3 on the live
  ASan `OpenFont` path are ESTABLISHED with no counterexample; no grade
  change, and no further evidence owed by the witness.
- Plain-build crash (W172; witness #2914 ESTABLISHED at the labeled
  availability-only scope): a single mapping skips the identity ramp, so a
  larger `SIZE` row count moves the chosen `0x5a5a` store far past the buffer.
  `SIZE 256 1024` (index 261120) faults in `setCode()` in the **uninstrumented**
  vulnerable Xvfb, 3/3 repeats, with `client_rc=1`, `xdpyinfo_rc=1` and server
  abort; 1.1.9 crashes likewise, while `5920c6e`, 1.1.10 and safe input survive.
  The 258-input plain survival still stands. Evidence:
  `realpath/evidence/plain-crash.txt`, `plain-crash-backtrace.txt` and
  `row-sweep.txt`; regenerate with `realpath/xlive/run-plain-crash.sh`. The
  witness replayed all nine lines from a clean archive at `3f44109`; the
  faulting instruction is `mov %dx,(%rax)` at `encparse.c:495` (signal 11), not
  a downstream consumer.
- Ceiling: no remote wire delivery, font-server protocol, unprivileged path
  to write the font path, pointer control, allocator grooming toward a live
  object, control-flow diversion, marker side effect, ROP or command was
  observed. The `0x5a5a` bytes are chosen data, not execution; the 16-bit
  `sm->first` truncates 65790 to 254, so only the chosen value survives.
  **For `SIZE 256 258` there is still no plain-build crash**: the vulnerable
  Xvfb keeps running and `xdpyinfo` answers, as the witness replayed. The
  row-1024 plain crash is availability impact only, not execution. No live
  object lies at the 508-byte destination (mmap usable slack by default, brk
  top chunk with a raised mmap threshold). Rung 5 UNKNOWN.

Next for the target mind: only on an observed saved pointer or control-flow
target, attempt a bounded benign marker with vulnerable, fixed and safe-input
controls. Alternative evidence: a production X configuration whose allocator
places a live object at the destination before the store, or a proven local
font-path write precondition. Neither is assumed. Both witness verdicts are
folded; the witness owes no further evidence on any measured scope.
