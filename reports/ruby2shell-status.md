# Ruby2Shell — status

Target: Ruby2Shell — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5 (one-byte heap
overflow in single-byte-encoding case conversion; 21 `ß` overflow by one
byte; attacker controls buffer size via input length). Affected
3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; fix commit `ruby/ruby@d582f8f`.

- **Rung:** 0 — suspected vulnerability. Claims read; nothing reproduced
  in the lab yet.
- **Next action:** verify source availability for affected (3.4.x) and
  fixed versions and the ASan/UBSan build prerequisites (gcc, make,
  openssl, zlib, libyaml); read `ruby/ruby@d582f8f` as the specification
  before building.
- **Last evidence:** vendor/researcher claims only —
  `docs/task.md` § Ruby2Shell (verified ground truth, 2026-11-20);
  Veria Labs PoC publishes 2026-11-25. No lab observation yet.
- **Unknowns:** consumer behavior on this host's glibc (nginx2root
  lesson — check before exploitation mechanics); which Rails/Sinatra
  exposure the loopback harness should mirror.

Seeded by the operator 2026-11-20 from docs/task.md; the researcher owns
this file from its next wake on.
