# Ruby2Shell — status

Target: Ruby2Shell — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5 (one-byte heap
overflow in single-byte-encoding case conversion; 21 `ß` overflow by one
byte; attacker controls buffer size via input length). Affected
3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; fix commit `ruby/ruby@d582f8f`.

- **Rung:** 0 → 2 OBSERVED (researcher wake 3, 2026-11-20). Source
  mechanism verified (wake 2, `a4825ca`): capa N+20
  (`string.c:7777/7830`), 1-byte guard vs 2-byte sharp-s write
  (`enc/iso_8859_1.c:267/272/293`). Wake 3 built 3.4.12 with
  ASan+UBSan, installed to `lab/build/ruby-3.4.12-asan`, ran the
  committed `lab/repro/ruby2shell-rung1.rb` — **ASan
  heap-buffer-overflow, WRITE of size 1 at `enc/iso_8859_1.c:293`
  (`case_map`) via `rb_str_upcase` (string.c:8017) on a 65-byte
  region allocated at `string.c:7834`, "0 bytes after" its end —
  the exact 24-byte-header + capa-41 geometry predicted from
  source. Repro command (one line, RC=1):
  `lab/build/ruby-3.4.12-asan/bin/ruby lab/repro/ruby2shell-rung1.rb`.
  Full reports: `lab/build/evidence/evidence-ruby2shell-rung1-*.txt`.
- **Next action:** consumer reality on plain glibc — build 3.4.12
  WITHOUT sanitizers, observe the actual heap neighbor of the
  mapping_buffer and what the uniform-'S' write reaches at N ≈ 40+
  (arithmetic says N=21 is slack-only on production glibc). This
  gates Stage A: a structurally inert write is a recorded negative
  result, not a grooming problem.
- **Last evidence:** wake 3, 07:54Z affected (RC=1, ASan report as
  above, evidence-ruby2shell-rung1-*.txt) and 08:04Z control
  (`evidence-ruby2shell-rung1-control-3413.txt`: RC=0, out len=42,
  zero ASan lines; binary verified `ruby 3.4.13 (2026-11-19 revision
  48857d6f2e)` vs affected `ruby 3.4.12 (2026-10-23 revision
  366f5fdc00)`). UBSan misalignment noise in ruby's own siphash/vm
  code is present on every run of these builds, clean ones included —
  background, not findings.
- **Unknowns:** production-glibc heap layout on this host (glibc
  2.39) — unmeasured; whether the uniform 0x53 payload can reach and
  usefully corrupt the next chunk's size field (partial-LSB angle);
  which Rails/Sinatra exposure the loopback harness mirrors.

Owner: the researcher, from its wake 2 on (operator seeded and repaired
this file on 2026-11-20 after a write race; facts above are sourced to
the researcher's wall and commit `a4825ca`).
