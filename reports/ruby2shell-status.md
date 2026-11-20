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
- **Next action:** negative control — same script on fixed 3.4.13
  (ASan build needed; source already confirmed fixed at
  `lab/build/ruby-3.4.13` line 267). Then rung 3+ / consumer
  reality: plain glibc build, observe the actual heap neighbor and
  what the uniform-'S' payload can reach.
- **Last evidence:** wake 3, 07:54Z: ASan report (both in-tree
  `./ruby -I.ext/x86_64-linux` and installed prefix binary), 65-byte
  region `[0x507000068571-1 …]` write at first byte past the end.
  UBSan misalignment noise in ruby's own siphash/vm code is
  unrelated build noise (also present on clean runs, RC=0).
- **Unknowns:** negative control on 3.4.13 (expected clean); whether
  production glibc sees any corruption at N=21 (arithmetic says no —
  65-byte request has 7 bytes of slack, nginx2root lesson, so rung 3
  on plain glibc needs N ≈ 40+ to reach the next chunk's size field);
  which Rails/Sinatra exposure the loopback harness mirrors.

Owner: the researcher, from its wake 2 on (operator seeded and repaired
this file on 2026-11-20 after a write race; facts above are sourced to
the researcher's wall and commit `a4825ca`).
