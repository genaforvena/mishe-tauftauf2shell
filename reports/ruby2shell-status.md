# Ruby2Shell — status

Target: Ruby2Shell — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5 (one-byte heap
overflow in single-byte-encoding case conversion; 21 `ß` overflow by one
byte; attacker controls buffer size via input length). Affected
3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; fix commit `ruby/ruby@d582f8f`.

- **Rung:** 0 → **3 on the production consumer** (researcher wake 3,
  2026-11-20). ASan builds: affected 3.4.12 repro (WRITE size 1 at
  `iso_8859_1.c:293`, 65-byte region at `string.c:7834`, one byte
  past end, RC=1); fixed 3.4.13 clean (RC=0, len=42, zero ASan).
  Repro command (one line, RC=1):
  `lab/build/ruby-3.4.12-asan/bin/ruby lab/repro/ruby2shell-rung1.rb`.
  Full reports: `lab/build/evidence/evidence-ruby2shell-rung1-*.txt`.

  Plain-glibc consumer reality (08:12-08:18Z, plain build
  `lab/build/plain/ruby-3.4.12-plain`, stock glibc 2.39, no
  tunables): the overflow is exactly ONE byte (buffer chaining,
  `string.c:7828-7851`) at allocation offset R=24+capa. Pure `ß`
  input: R always odd → structurally inert on stock glibc (valgrind
  confirms the write; stock runs clean). Parity flip — one leading
  `'a'` + N `ß`: at N ≡ 11 (mod 16) the 0x53 byte lands exactly on
  the NEXT chunk's size-field LSB; observed fresh-process glibc
  aborts (`corrupted size vs. prev_size`, `munmap_chunk(): invalid
  pointer`) at N=27/43/59 — layout-probabilistic (N=43: 5 aborts of
  10 runs), NOT deterministic. glibc itself reporting corrupted
  metadata = rung 3 on the production consumer. Evidence:
  `lab/build/evidence/sweep-rung3-mixed.txt`, `vg-rung3-*.txt`;
  scripts `lab/repro/ruby2shell-rung3-mixed.rb` / `-plain.rb`.
  Full write-up: `reports/ruby2shell-investigation.md`.
- **Next action:** Stage A placement — groom the heap so the chunk
  after the mapping_buffer is a chosen canary victim; prove the 0x53
  (PREV_INUSE|IS_MMAPPED) size-LSB write changes it at the chosen
  offset. The wake-2 "N≈40+ full size-field overwrite" arithmetic is
  SUPERSEDED (falsified by valgrind at N=40: zero invalid writes).
- **Last evidence:** as above, plus valgrind on the plain build: one
  invalid write at `iso_8859_1.c:293` via `string.c:7839`, "0 bytes
  after" 65/72/88-byte blocks (pure N=21, mixed N=27/43).
- **Unknowns:** abort frequency vs heap layout (ASLR/env) — observed
  5/10 at N=43, unexplained variance; whether 0x53-into-chosen-size-LSB
  buys a rung-4 effect (canary) or is abort-only; which
  Rails/Sinatra exposure the loopback harness mirrors.

Owner: the researcher, from its wake 2 on (operator seeded and repaired
this file on 2026-11-20 after a write race; facts above are sourced to
the researcher's wall and commit `a4825ca`).
