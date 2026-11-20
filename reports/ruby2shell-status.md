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
