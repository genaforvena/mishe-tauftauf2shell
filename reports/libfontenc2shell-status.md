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
- Runtime injection (W180): `realpath/xlive/run-xset-fp.sh` starts Xvfb with an
  unrelated font path, injects a writable temp font dir into the running server
  with `xset +fp` / `xset fp rehash`, then writes the malicious `SIZE 256 258`
  `.enc` **after** server start (timeline: launch 20:54:51.489Z, attack write
  20:54:54.576Z). Vulnerable build: no-xset and safe-after-xset clean,
  attack-after-write `WRITE of size 2` at `encparse.c:495`, 508 bytes past the
  region; fixed build clean in all three cases. Matrix and logs:
  `realpath/evidence/xset-fp/`, details in `PROVENANCE.md` W180 and report §3.5.
  This proves the injection can target a running server through a writable
  directory without a privileged font dir; OS-level unprivileged X display
  access and server privilege remain UNKNOWN. No grade change.
- Ceiling: no remote wire delivery, OS-level unprivileged X display access,
  command, ROP or control flow in a privileged/live X server was observed.
  A benign marker diversion is demonstrated at the real-library public API
  under a fixed ASLR-off, non-PIE layout (W186); it is not a command.
  X-protocol font path injection into a running server is demonstrated
  (W180); privileged font-dir write is not required in that model.
  Pointer control over a live object's data pointer is demonstrated at the
  public API under a fixed ASLR-off layout (W183), and W186 replaces a live
  `FontMapRec.recode` function pointer with a chosen address that executes a
  benign marker through `FontEncRecode` (ASLR-off, non-PIE harness only).
  The `0x5a5a` bytes are chosen data, not execution; the 16-bit
  `sm->first` truncates 65790 to 254, so only the chosen value survives.
  **For `SIZE 256 258` there is still no plain-build crash**: the vulnerable
  Xvfb keeps running and `xdpyinfo` answers, as the witness replayed. The
  row-1024 plain crash is availability impact only, not execution. No live
  object lay at the 508-byte destination for a **single** mapping (mmap usable
  slack by default, brk top chunk with a raised mmap threshold); W183 does
  place live objects there with seven mappings. Rung 5 UNKNOWN.
- Second OOB write site (W181): a two-mapping `.enc` (`SIZE 256 1024`,
  indices 255 and 261375) bypasses the single-mapping skip of the identity
  ramp and makes `setCode()` write 195840 contiguous 16-bit values past the
  65536-entry buffer at `encparse.c:492`, before the `:495` store. Real-library
  matrix: vulnerable plain rc=139, vulnerable ASan `WRITE of size 2` at
  `:492` 0 bytes after the region; safe2, fixed `5920c6e` and 1.1.10 all
  rc=0 with no ASan report. Plain brk gdb shows the ramp reaching the exact
  `[heap]` mapping end (`rax=0x5555555a4000`) after 67176 OOB entries.
  Evidence and reproduction: `lab/frontier/libfontenc2shell/realpath/evidence/
  ramp/README.txt`; details in `PROVENANCE.md` W181. The values are index-derived,
  not chosen data, and no live object or pointer was observed: grade unchanged.
- Live-object pointer control (W183): a seven-mapping `SIZE 256 258` `.enc`
  writes chosen words at +508 and +24..+30 bytes past the buffer. The later
  stores replace all four 16-bit halves of mapping2's already-live
  `sm->map` pointer; `FontEncRecode(254, mapping2)` then returns the chosen
  `0x5558` from the redirected address instead of `0x1111`. Vulnerable safe
  input keeps `0x1111`; fixed `5920c6e` rejects all out-of-range mappings;
  vulnerable ASan reports `WRITE of size 2` at `encparse.c:495`, 508 bytes
  past the 131072-byte region. Evidence: `lab/frontier/libfontenc2shell/
  realpath/evidence/ptrctrl/` (run with `sh .../ptrctrl/run.sh`);
  details in `PROVENANCE.md` W183 and report §3.7. Rung 4 at the real-library
  public API; not a saved return address, not rung 5, and the absolute target
  needs ASLR off.
- Control-flow diversion (W186): a seven-mapping `SIZE 256 258` `.enc` uses
  `from=0xfe34..0xfe37` to write indices 65584..65587, the four 16-bit halves
  of live `m3->recode` at `buffer_base+0x20060`. `marker.c` defines a benign
  function whose non-PIE address is baked into the file by `fptr/run.sh`.
  Vulnerable crafted: `m3 recode=0x4011d6`, `FontEncRecode` prints
  `BENIGN_MARKER_EXECUTED` and returns `0xabcd1234`, all other mappings
  unchanged, rc=0; vulnerable safe and fixed `5920c6e` crafted show no marker.
  Three runs matched. An earlier trailing `0xcafe` store crashed
  `install_mapping()` via `m6->next`; that mapping was removed. Evidence:
  `lab/frontier/libfontenc2shell/realpath/evidence/fptr/` (`bash .../run.sh`);
  details in `PROVENANCE.md` W186 and report §3.8. Rung 4 at the public API;
  a lab-chosen function in a non-PIE harness, not a command or rung 5.

- Function-pointer overwrite inside Xvfb (W187): a test-only LD_PRELOAD
  interposer (`realpath/xlive/interpose.c`) logs the 131072-byte buffer, every
  live `FontMapRec` and every `FontEncRecode` target; `xlive/run-xfptr.sh`
  recalibrates the index from an in-bounds run, then writes the benign marker
  address into `m3->recode`. Vulnerable crafted (twice) sets `m3->recode =
  0x7ffff7fb9159` (the marker), with client_rc=0 and no crash; vulnerable safe
  leaves `0x7ffff7fb2885`, fixed `5920c6e` leaves `0x7ffff7fb2891`. In all
  cases `FontEncRecode` is called only on m1 (`0x5555558424b0`), allocated
  before the buffer, so the hijacked pointer is never invoked and 0 marker
  calls occur. Consumer behaviour blocks control-flow diversion in Xvfb; the
  overwrite itself is rung 4 memory control in a live server. Evidence:
  `realpath/evidence/xfptr/`; details in `PROVENANCE.md` W187 and report §3.9.
  Not a command, remote input or privileged context; rung 5 UNKNOWN.

- Clean-archive replay (W188): from `git archive HEAD` at `7091755`, W186
  reproduced exactly; the committed W187 runner initially failed because it
  hardcoded map n=3 as the post-buffer target (clean layout: n=1..4 before the
  buffer). The repaired runner selects the first post-buffer map and keeps an
  early `0xff00` decoy so the buffer is allocated before that map; the final
  replay targeted n=5 at buffer+0x20050 and again set its recode to the marker
  in both crafted runs, with safe/fixed clean, 0 marker calls and recode
  invoked only on m1. Three failed intermediates are preserved. Receipts:
  `lab/frontier/libfontenc2shell/realpath/evidence/xfptr/replay-w188/REPLAY.md`.
  Author replay, not a witness verdict; grade unchanged.

Next for the target mind: W187 showed the chosen-address overwrite works
inside Xvfb but libXfont2 only invokes m1, which is allocated before the
buffer, so control-flow diversion there is blocked by consumer behaviour. The
remaining lane is a privileged X server reachable by an unprivileged OS user
on a real deployment; on this host no setuid X server and no active display
manager were found, so that precondition is not demonstrable here. Layout-
independent redirect is blocked: ASLR randomizes heap bits 12-15 while
`setCode()` writes full 16-bit words from a static file. Both witness verdicts
are folded; the witness has not replayed W183, W186, W187 or W188.
