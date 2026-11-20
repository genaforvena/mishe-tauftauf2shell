# Ruby2Shell — status

Target: Ruby2Shell — CVE-2026-132825 / GHSA-34m4-m9fh-gqp5 (one-byte heap
overflow in single-byte-encoding case conversion; 21 `ß` overflow by one
byte; attacker controls buffer size via input length). Affected
3.3<3.3.14, 3.4<3.4.13, 4.0<4.0.10; fix commit `ruby/ruby@d582f8f`.

- **Rung:** 0 → 1 in progress. Source-level mechanism VERIFIED from the
  tarball trees (researcher wake 2, commit `a4825ca`): `string.c:7777`
  `CASE_MAPPING_ADDITIONAL_LENGTH 20`; `string.c:7830` capa = N+20;
  `enc/iso_8859_1.c:267` guard `to < to_end` guarantees one byte but
  sharp-s upcase writes two (`:272`/`:293`) — 21 sharp-s → 42 bytes into
  capa 41, byte at index 41 written one past the end, value 0x53 'S'.
  Fixed 3.4.13 has `to_end - to > 1` at the same line. **The ASan
  reproducible crash is not yet observed** — the 3.4.12 ASan build was
  still compiling at the last researcher record.
- **Next action:** finish the 3.4.12 ASan build, then run
  `lab/repro/ruby2shell-rung1.rb` under it — expected ASan
  heap-buffer-overflow WRITE of size 1 in `onigenc_iso_8859_1_case_map`;
  negative control on fixed 3.4.13 after that.
- **Last evidence:** researcher wall (wake 2, 2026-11-20) and commit
  `a4825ca` (`lab/repro/ruby2shell-rung1.rb`, 14 lines); provenance
  sha256-verified tarballs in `lab/src/`; fix patch at
  `lab/src/ruby-fix-d582f8f.patch` (243 lines, one loop bound per each
  of 14 single-byte encodings).
- **Unknowns:** the ASan observation itself (make was running, log
  `/tmp/ruby-make.log`, prefix `lab/build/ruby-3.4.12-asan`); consumer
  behavior on this host's glibc (nginx2root lesson) before grooming
  mechanics; which Rails/Sinatra exposure the loopback harness mirrors.

Owner: the researcher, from its wake 2 on (operator seeded and repaired
this file on 2026-11-20 after a write race; facts above are sourced to
the researcher's wall and commit `a4825ca`).
