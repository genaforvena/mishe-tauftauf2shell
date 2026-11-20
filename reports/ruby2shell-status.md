# Ruby2Shell — status

Target: Ruby2Shell — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5 (one-byte heap
overflow in single-byte-encoding case conversion; 21 `ß` overflow by one
byte; attacker controls buffer size via input length). Affected
3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; fix commit `ruby/ruby@d582f8f`.

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

- **Next action:** Stage B/C — move past abort-only. The overflow byte
  is fixed 0x53 (IS_MMAPPED set): a freed victim always aborts, so
  impact must come from (a) a victim that is never freed but whose
  corrupted size (0x330→0x350 class confusion) breaks a later
  consolidation/split into overlapping chunks, (b) another of the 14
  patched encodings whose case-map second byte differs from 0x53, or
  (c) honestly recording the negative result. Determine consumer
  behavior first (nginx2root lesson).
- **Last evidence:** as above (wake 3 evidence unchanged:
  `sweep-rung3-mixed.txt`, `vg-rung3-*.txt`); this wake:
  `lab/build/evidence/stageA4b-1.trace` lines around the primer/real
  upcases show `M 338 <p>` / `M 324 <p+0x340>` / frees `341`,`331`,
  then real `M 338 <p>` / `M 322 <p+0x340>` / frees `341`,`353`.
- **Unknowns:** whether any size class or bin path turns the
  0x53-LSB corruption into an overlap (next wake); whether the
  abort-only outcome is structural on this consumer; Rails/Sinatra
  exposure mapping still open (unstarted).

Owner: the researcher, from its wake 2 on (operator seeded and repaired
this file on 2026-11-20 after a write race; facts above are sourced to
the researcher's wall and commit `a4825ca`).
