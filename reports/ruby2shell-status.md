# Ruby2Shell — status

Target: Ruby2Shell — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5 (one-byte heap
overflow in single-byte-encoding case conversion; 21 `ß` overflow by one
byte; attacker controls buffer size via input length). Affected
3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; fix commit `ruby/ruby@d582f8f`.

- **2026-11-25 (later wake) — consumer provenance closed: the 0x21c/0x1f8
  pops are fixed-size, not wire-shaped; surviving unsorted-split overlap
  measured; rung 5 stock remains NOT ACHIEVED.** The named experiment
  closed by shaping only wire bytes: attacker headers padded to
  L=0/60/120/240 and route paths lengthened +100/+300 left the
  post-attack victim pops at exactly `0x21c` then `0x1f8` in all ten
  surviving samples — framework-internal fixed-size allocations, C-internal
  content, allocator mechanics, not a request-shaped Stage-B analog. New
  measured levers: (1) run consH-20 class survives end to end — the forged
  unsorted split carves a fake 0x20 chunk into the neighbor region and real
  request-thread allocations recycle it, with an on-thread free (Q), 404 +
  later 200, graceful teardown — so the 11-25 "Q=0" was geometry-specific;
  (2) in B=0x451-class geometries the upcase result string itself pops and
  splits the victim from unsorted (`C request=0x414 size=0x425`, gdb catch
  gdbF-5); (3) the dev error page reflects all params verbatim (~169 KB) —
  a candidate oracle-free disclosure channel, clean in the one parsed
  surviving sample. Instrument caution: the preload's mapped page span is
  a geometry knob (4-page builds keep the ~10% surviving class; the 6-page
  RA build gave 0/124). Veria re-checked at the dated trigger: stamp
  unchanged since 21 Nov 03:52Z, PoC still unpublished; the day's public
  GitHub PoC repos are crash/sanitizer-level only. Named next: shape the
  carve position (N, drain sizes) into a reflected drain-string body for
  wire-visible allocator-metadata disclosure + readback. First
  carve-landing pass is negative: the 60-run N ∈ {508,524,556} × drain
  {1024,1152,1280} sweep (consS-*) produced 11 survivors and zero
  reflected-value corruption; remaining knobs are drain part count,
  filler shape, part order.
- **2026-11-25 — consumer-visibility correction: the forged `0x251` qword
  is structurally inert; Veria PoC still unpublished.** The committed case
  probe compared malloc user pointers against the forged chunk-start
  address, so its "no consumer" P-line check could never fire. Fixed probe
  (window P/Q/G lines, `process_vm_readv` reads) + committed tabulator
  `ruby2shell-cons-vis-tabulate.py`; 49-run batch of the N=524 stock-Rails
  attack: 5 survivors, zero window frees (Q=0/49) — the real neighbor is
  never freed on the request thread, so the tail-forged `0x251` qword (which
  lands in the live neighbor's user area) can never enter any free list.
  New measured fact: post-attack `0x21c`/`0x1f8` request-thread allocations
  return at the victim and would cover the live neighbor in expansion
  geometries — their content provenance is the next named experiment. Veria's
  page (checked on the dated 25 Nov trigger, twice): stamp unchanged since
  21 Nov 03:52Z, PoC still "25 November, or later" — unpublished. Rung 5
  remains NOT ACHIEVED for stock/oracle-free/persistent; the
  witness-ESTABLISHED harness-condition rung 5 is unchanged.

- **2026-11-24 — stock Rails follow-up: true allocator split, rung 5 NOT
  ACHIEVED.** New `ruby2shell-stock-rails{,-setup}.sh` runs an unmodified
  `rails new --minimal` app (optional full `rails new`). With N=524 and 32
  1024-byte multipart parts, analysis-only case tracing captured a real
  `0x200→0x250` expansion and the second mapping buffer returning V as a
  `0x230` chunk (`stage2d-n524-r498.server.log`). Four trailing invariant bytes
  replace the original remainder's size with `0x251`, but no useful physical
  consumer followed. A seeded 512-layout search found no `0x3f0` neighbor; the
  full app did not provide one either. Final clean matrix: **3/3 attacks abort
  pre-response; 3/3 safe affected and 3/3 fixed controls return 404 plus later
  200 and survive.** No address disclosure, command execution, persistent
  process or second command exists. This is new rung-4-class allocator evidence,
  not stock/oracle-free/persistent RCE. Exact recipes and negative hypotheses
  are in the investigation report.

- **2026-11-22 — stock/oracle-free/persistent RCE attempt: bounded NEGATIVE.**
  New `lab/repro/ruby2shell-stock-baseline.{ru,sh}` runs classic Sinatra/Puma
  with no routes, custom middleware, preload, ObjectSpace, maps or debugger in
  the request path. N=828 aborts 3/3 pre-response; N=556 completes a later GET
  in only 2/3 fresh runs and then faults on teardown, while 1/3 aborts earlier;
  final safe/fixed N=556 controls survive normally. The N=556 corrupted chunk
  is fastbin (second qword != tcache_key), and its 0x30→0x50 class change is
  source-closed for consolidation, not an overlap. ASLR-on sweeps, filler/order
  variants and safe primers produced no stable valid unsorted expansion;
  expanded headers held invalid Ruby data. Empty multipart/unknown charset gave
  no address disclosure. No stock command, oracle, reliable survival or second
  command was achieved; stock Rails remains UNKNOWN pending Veria's unpublished
  25 Nov mechanics. Existing instrumented rung 5 is unchanged. Full evidence in
  the investigation report's new bounded-negative section.

- **2026-11-22 — rung 5 witness-ESTABLISHED at the labeled conditions.** Candidate
  repro `lab/repro/ruby2shell-rung5-http.{ru,sh}` converts the Stage C HTTP
  poison into a forged untyped CRuby `RData` in a measured 640-byte VWA slot:
  `dfree = libc system`, `data =` the same request's NUL-terminated benign
  `touch <unique evidence marker>` command. GC's real
  `rb_data_free → make_zombie → run_final` path executes it; there is no
  direct Ruby `system` call or debugger write. Final matrix: **3/3 affected
  attacks** returned HTTP 200 + `rce=OBSERVED`, created three distinct marker
  files and had the target mtrace pop; **safe affected input** and **identical
  malicious input on plain fixed 3.4.13** returned HTTP 200 + `rce=ABSENT`,
  no marker and no target pop. Separate `strace -f -e execve` evidence
  `rung5-http-r5-dev-strace2.execve.log:1118-1122` shows `/bin/sh -c --
  /usr/bin/touch …` then `/usr/bin/touch`, both exit 0. Exact conditions:
  plain 3.4.12/3.4.13, stock glibc 2.39-0ubuntu8.12, ASLR ENABLED but
  in-process mtrace/ObjectSpace.dump//proc/self/maps oracles, custom grooming
  and GC-trigger middleware, GC disabled until the forged copy, loopback only.
  Process can abort after the response; no persistence, stock-app wire-only
  reach or portability claim. Full recipe/controls in the investigation
  report's new "Rung 5 over HTTP" section. Independent clean-archive replay of
  full commit `8b9d8f97f0ec1237fe1fb2bc30339d1a32db1341` returned ESTABLISHED:
  witness-alpha/beta each had HTTP 200, a distinct target-created marker and
  exactly one independently scanned target pop; safe/fixed had no marker/pop.
  Evidence index `lab/build/evidence/w-ruby-r5/tree/lab/build/evidence/
  witness-verification.json`. No contradiction or code repair; the fixed-vs-
  attack byte wording now correctly names the identical `_method` payload.

- **Rung:** 3 → **3+ (Stage A: chosen-victim deterministic corruption
  on the production consumer)** (researcher wake 4, 2026-11-20,
  08:21-08:55Z). Rungs 1-3 unchanged (ASan repro + 3.4.13 negative
  control + stock-glibc aborts; see `reports/ruby2shell-investigation.md`
  and history below). NEW this wake:

  Stage A OBSERVED: the one-byte 0x53 write now hits a chunk WE place,
  at the chosen offset (its glibc size-field LSB), deterministically —
  13/13 aborts (8 traced + 5 untraced runs, fresh processes, stock
  glibc 2.39, no tunables, no ASLR-off):
  `lab/repro/ruby2shell-stageA.rb` → `munmap_chunk(): invalid pointer`
  every run. Mechanism: a pure-`ß` *primer* upcase (780 chars) fills
  its first mapping buffer to exactly capa (no overflow) and chains an
  ADJACENT buffer2' (traced: buffer2' = buffer1' + 0x340), both freed
  to tcache; the *real* mixed upcase ('a' + 779 `ß`, N ≡ 11 mod 16)
  pops buffer1' via tcache LIFO, the overflow byte 0x53 lands on
  buffer2''s size LSB while it is still a tcache entry (tcache_get
  does not check size fields), the same chunk is then popped as the
  real buffer2, and its free aborts. mtrace free-hook proof:
  `F ... buffer2-chunk 331` (clean, primer) → `F ... SAME ADDRESS 353`
  (corrupted, real upcase) → abort — one such pair per run, 8/8.
  Deterministic, no GC/luck involved; heap holes drained first
  (512+512 live strings of the two chunk classes) so the primer
  buffers come from the top chunk.

  Tooling: `lab/preload/mtrace.c` — synthetic LD_PRELOAD
  malloc/free tracer (approved standing mechanic), logs every
  malloc/calloc/realloc/free plus the glibc size field at free time;
  it captured the corrupted size LSB before glibc's own check aborted.
  Key evidence: `lab/build/evidence/stageA4b-*.trace` (8 runs),
  `stageA4-plain-*.err` (5 untraced runs), plus the failed-variant
  traces `stageA-n27-*.trace`, `stageA3-*.trace` preserved as negative
  results (string-embedding discovery: Ruby 3.4 embeds strings up to
  ~800 bytes in VWA slots, so groom strings must have len ≥ 809 to
  malloc; `embedprobe*.trace`).

- **Next action (wake 5, 2026-11-20):** Stage B — the unsorted-bin
  overlap route. Byte alphabet resolved: exactly {0x53, 0x73} across
  all 14 patched encodings (no attacker-chosen value; `capitalize`
  structurally inert — titlecase expands only the first char). Fold
  value OBSERVED: `downcase(:fold)` lands 0x73 with the same Stage A
  geometry, 5/5 aborts, mtrace size LSB 0x373
  (`lab/repro/ruby2shell-stageA-fold.rb`,
  `lab/build/evidence/stageA-fold-*`). Consumer audit (glibc 2.39
  `malloc.c`, fetched from sourceware release/2.39/master): free/
  realloc CLOSED (IS_MMAPPED abort); fastbin consolidation CLOSED
  (`fastbin_index` check forces class-preserving pairs 0x51→0x53,
  0x71→0x73 which change only flags, laundered by `set_head`);
  unsorted-bin loop OPEN — no IS_MMAPPED check, five groomable
  checks (fake next-size/prev_size from a live neighbor string's
  content). Plan: [S 0x340][V 0x430][W live] → 0x53 grows V's size
  0x431→0x453 → V binned 0x450 → 0x448-class request returns a
  chunk overlapping W's header and first user bytes.
- **Last evidence:** wake 5: `stageA-fold-1.trace` (`F ... 331` →
  `F ... 373` same address → abort), 4 fresh-process fold aborts,
  ASan fold probe RC=1 at `iso_8859_1.c:293` + fixed-build RC=0;
  wake 4 evidence unchanged below.
- **Unknowns:** whether the unsorted-bin groom survives Ruby's GC
  and buffer chaining in practice (next wake implements it);
  Rails/Sinatra exposure mapping still open (unstarted).

Owner: the researcher, from its wake 2 on (operator seeded and repaired
this file on 2026-11-20 after a write race; facts above are sourced to
the researcher's wall and commit `a4825ca`).
