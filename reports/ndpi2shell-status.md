# ndpi2shell — status

Admitted 2026-11-23 18:1xZ under standing approval #6 as the 118th route.
Charter: `.mishe-tauftauf/charters/ndpi2shell.md`. Trigger units from the
exact full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`); path enabled/active, hy4-flash route 117→118,
resolver entries 235→238 (wake `.path` and `@.service`), two-pane window 121
adopted by registry with no duplicate. The inner tmux server was down at
admission, so live panes were not verified this wake and remain UNKNOWN.
Pinned full-flag doctor rc 0 GREEN; `check-omp-only.py` GREEN with 118 declared
roles. Admission adds no grade.

- Claim: CVE-2026-86098 / GHSA-c8vx-3h2j-4f8m (GitHub CNA, Unreviewed, High
  7.4, CWE-787, published 2026-09-05). The advisory describes a heap overflow
  in `ndpi_json_string_escape()` reachable from crafted TLS SNI, HTTP headers
  or DNS names in nDPI before 6.0; its fix message says "nDPI <= 5.0, HEAD
  `ea3586e`". Fix commit `94e82c1de12323d992895830231865736a8abf2c`
  (2026-08-25); numeric fixed release UNKNOWN. Reachability is a claim, not a
  reproduction here.
- Evidence: `lab/frontier/ndpi2shell/harness/run.sh` and `check.sh` slice the
  pinned parent/fixed `src/lib/ndpi_serializer.c` (lines 90-166 / 90-226) under
  `#line` with a `u_char` typedef and lab stub driver. The loop guard
  `j < dst_max_len` is checked once per source byte while a JSON escape writes
  two bytes at `:106-107`, a UTF-8 sequence four at `:155-158`, and the closing
  quote and NUL at `:162-163` are unchecked. With an 8-byte caller buffer gcc
  and clang ASan report `heap-buffer-overflow WRITE of size 1` at pinned
  `:107`, `:158` and `:163`; plain tail bytes are `2f 22 a5 00` (escape),
  `80 22 a5 00` (utf8) and `a5 00 a5 a5` (off-by-one NUL), and gdb reads
  `J=8 C=0x2f` with the same bytes. The fixed pin prechecks `safe_max_len`,
  writes the NUL in bounds and returns -1 on overflow.
- Operator admission replay from a clean `git archive 6510950` at 18:18Z:
  54 files, 4/4 `PINS.sha256` digests OK, 8 binaries rebuilt, `PASS=172 FAIL=0`,
  trace `16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b`
  exact. This is deterministic replay of the author's harness, not witness
  acceptance.
- Ceiling: direct-call CODE/HARNESS rungs 1-4 only. No real nDPI build,
  serializer struct, packet, parser, socket, wire delivery, live process,
  pointer or IP control, benign marker, command, witness verdict or rung 5.
  Advisory wire reachability stays UNKNOWN; rung 5 is UNKNOWN.

Next for the target mind: build nDPI with ASan and determine which real caller
passes an exact-size or undersized `dst_max_len` and whether crafted SNI/HTTP/
DNS data reaches this function with attacker-controlled length; keep parser
rejections as negatives. Only on an observed pointer or control-flow target,
attempt a bounded benign marker with vulnerable, fixed and safe-input controls
and an independent witness replay. Hand any new claim to `witness` — the author
report is not acceptance.
