# fluentbit2shell — status

Admitted 2026-11-23 ~07:0xZ under standing approval #6 as the 105th engine
route. Frontier staged this lane in W141 (commits `d695504` and `0bcddf8`)
with byte-exact pinned upstream blobs, the fix commit and the released fixed
version. Brief: `reports/frontier-fluentbit2shell.md`; pins, verbatim slices,
SHA-256 manifests and raw evidence: `lab/frontier/fluentbit2shell/PROVENANCE.md`.
The two-pane inner tmux window 109 was already live and registered (registry
110/110 unique), so admission created no second window and changed no registry
entry. The hy4-flash `max_parallel: 3` route was added; the path, debounce and
`@fluentbit2shell` slice drop-in were minted with the exact full-flag sync at
pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@fluentbit2shell.service` and
`m2shell-wake-fluentbit2shell.path` were added to the site's owner resolver map
(211 entries). The pinned full-flag doctor returned rc 0,
`PASS local plant out of Git` / `GREEN`; the doctor service was restarted and
returned rc 0, and `check-omp-only.py` returned GREEN with 105 declared roles.
Admission changes no grade.

- Claim: CVE-2026-61674 / GHSA-jrp8-r9hx-gf73 (Critical 9.2
  `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-121,
  787, 843). Fluent Bit `>= 0.11.0, < 5.0.8`, fixed in `5.0.8` by commit
  `45486556be9d023e194665e243f156b228e195e0`. The GHSA "Patched versions:
  None" field is stale; the CVE record, fix commit and release agree on 5.0.8.
  Byte-exact pins: vulnerable `forward.c.47db630c` and `forward.c.v5.0.7` are
  identical (`406f2d229d805bae08c6570e333f22b3cfc4db361780d21a28725a7dc37c9687`);
  fixed `forward.c.45486556` and `forward.c.v5.0.8` are identical
  (`cb2f62d730736827b13e0cc5fde6135d3f1c47c43248913d5d81e7dd1ec71ea7`).
- Primitive: during the first flush on a non-keepalive Secure-Forward
  connection with `Shared_Key`/`Empty_Shared_Key` configured,
  `secure_forward_pong()` takes the server's `PONG[2]` "reason" msgpack object
  and executes `memcpy(msg, o.via.str.ptr, o.via.str.size)` into a 32-byte
  stack `char msg[32]`, checking neither type nor length
  (pinned `forward.c.47db630c:567`). The fix bounds the copy with
  `o.via.str.size >= sizeof(msg)` and rejects non-STR objects. The advisory
  documents saved-RBP control at reason offset 48 and saved-RIP control at
  offset 56; those offsets are claim text until replayed.
- Evidence: `lab/frontier/fluentbit2shell/harness/run.sh` re-extracts the
  complete verbatim `secure_forward_pong()` from four pinned blobs per run
  under `#line` directives, checks a 6-file source manifest and a 12-file
  harness manifest, builds plain and sanitizer variants with gcc and clang,
  and drives rungs 1–4. Frontier recorded 65 PASS / 0 FAIL three times plus
  clean `/tmp` and `git archive` replays. Operator replay from
  `git archive HEAD lab/frontier/fluentbit2shell` in a fresh `/tmp` directory
  returned rc 0, `PASS=65 FAIL=0` and exactly
  `TRACE_SHA256=35e7c470871e94379158696aa6899f13db4413b61153d53c4df6296f04061d96`.

## Grade at admission — 07:0xZ (author-only, no witness verdict)

Rung 1 measures the advisory arithmetic: a 1000-byte reason into a 32-byte
destination is 968 bytes past the object. Rung 2 shows the vulnerable parent
and v5.0.7 accept and copy the oversized STR with chosen bytes at offsets
0/17/24/33/40/48/56/63, while the fix commit and v5.0.8 reject it with a NUL
terminator at byte 31 and log one error. Rung 3 is confirmed with gcc and
clang ASan: `stack-buffer-overflow`, `WRITE of size 1000` at pinned
`forward.c.47db630c:567` in `secure_forward_pong`, object `msg` at line 526;
fixed, v5.0.8 and safe-input builds are clean. The harness's rung 4 is
**scoped**: chosen bytes land at the eight copy offsets in the plain build,
and gdb at pinned line 568 reads `saved rip = 0x414141414141417b` before the
process faults at line 574. That verdict came from a direct call with stubbed
msgpack/flb plumbing and `-fno-stack-protector` plain builds.

## Ceiling and negatives

No real `fluent-bit` process, listener, socket, TLS/SRP handshake, HELO/PONG
wire exchange, event loop or attacker server. No stack canary (plain builds
need `-fno-stack-protector`), no ROP chain, command, `/tmp/PWNED` side effect
or witness verdict. The advisory's ROP → `system()` → root claim and the
`--supervisor` BROP path remain claims. An earlier frontier-nanomsg brief's
one-line "client-side" rejection of this CVE is overridden in the brief's
section 6: this plant's ladder tests attacker-controlled wire bytes into a
live process, which the sink satisfies in principle, not in this harness.
Rung 5 stays UNKNOWN.

## Next bounded work for the target mind

1. Build the pinned vulnerable release and fix release with ASan and drive
   `secure_forward_pong()` through a real Secure-Forward PONG exchange on a
   loopback connection, with stubbed crypto if needed, labeled accordingly.
2. Inspect the real frame for a controllable pointer or canary boundary;
   record fixed and safe-input controls. A benign marker is required before
   any rung-5 claim; a chosen saved-RIP byte is not execution.
3. Hand any live-wire rung-4 or rung-5 claim to the witness without upgrading
   this row first.
