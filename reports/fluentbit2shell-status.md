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
Rung 5 stays UNKNOWN at this admission snapshot; W2 and W3 below supersede the grade.

## Next bounded work for the target mind

1. Build the pinned vulnerable release and fix release with ASan and drive
   `secure_forward_pong()` through a real Secure-Forward PONG exchange on a
   loopback connection, with stubbed crypto if needed, labeled accordingly.
2. Inspect the real frame for a controllable pointer or canary boundary;
   record fixed and safe-input controls. A benign marker is required before
   any rung-5 claim; a chosen saved-RIP byte is not execution.
3. Hand any live-wire rung-4 or rung-5 claim to the witness without upgrading
   this row first.

## Live-wire update — 2026-11-23 07:42Z (superseded by W2 below for control transfer and rung 5)


- First target-mind wake built real Fluent Bit 5.0.7 from the pinned public
  source with ASan and drove a malicious Secure-Forward server on 127.0.0.1.
  A valid HELO then `["PONG", false, <1000-byte STR>, "h", "d"]` produced
  `AddressSanitizer: stack-buffer-overflow`, `WRITE of size 1000` in
  `secure_forward_pong` at `forward.c:567` of a live `flb-out-forward`
  thread, reached from `secure_forward_handshake:645` and
  `cb_forward_flush:1629`. Full evidence and provenance:
  `reports/fluentbit2shell-livewire.md`.
- Controls on the same binary: `PONG[1]=true` gives `handshake status = 0`;
  a 4-byte reason gives a bounded `failed authorization`; both clean. The
  pinned fix patch rebuilt into a clean binary (source SHA matches v5.0.8)
  bounds the same 1000-byte PONG to a 31-byte log with no ASan report.
- gdb on the real flushing thread placed chosen bytes at `msg` offsets
  0/17/24/33/40/48/56/63; in the default plain build `$rbp - &msg = 0x30`,
  `x/gx $rbp+8 = x/gx msg+56 = 0x414141414141417b` and the backtrace frame 1
  is that value. The default canary aborts at return, so no control transfer
  was executed in this build; the earlier direct-call harness with
  `-fno-stack-protector` remains the only observed transfer.
- Grade now: rung 3 confirmed on living bytes; rung 4 met at frame/pointer
  level with the canary caveat above; rung 5 still UNKNOWN — no ROP chain,
  command, side effect or witness. Threat model unchanged: malicious/upstream
  forward destination versus a forwarding agent.
- Next: a real no-canary 5.0.7 process under gdb to see the chosen RIP taken,
  then witness replay; do not upgrade this row before that observation.

### No-canary follow-up — 2026-11-23 07:47Z

- Real `-fno-stack-protector` 5.0.7 binary (SHA
  `060b41249115344ba6c4dc6df8a94d1b74d266a5ed6c78077c2e3d5c5656a18e`)
  driven by the same loopback PONG: after the memcpy the saved-RIP slot holds
  `0x414141414141417b`, but the process faults inside
  `secure_forward_pong` at line 574 with `rip` still in the function,
  `$rbp = 0x4141414141414142` and frame 1 equal to the chosen value.
- Actual transfer to the chosen address was NOT observed in any live build;
  no benign marker or command ran. Rung 5 stays UNKNOWN. Next blocker is the
  pre-return fault at line 574, not the canary alone; report and harness
  updated (`reports/fluentbit2shell-livewire.md`,
  `lab/fluentbit2shell/gdb_nocanary.sh`).

### W2 — control transfer and conditional rung 5, 2026-11-23 08:20Z

- The 07:47 "pre-return fault" was diagnosed as x86-64 #GP at `ret`: the
  chosen `0x414141414141417b` is NON-CANONICAL. With a canonical address at
  saved-RIP offset 56, a live no-canary 5.0.7 process transferred control to
  the chosen address (`rip = 0x555556a255c9`, `rbp = 0`, port 20262).
- A ROP chain carried entirely in the 1000-byte PONG reason (offsets 48/56/
  64/72/80/88 and a command string at 128) called `system()` on a lab-chosen
  benign `touch` in the live process. Under gdb ASLR-off this created a marker
  (port 20263); with NO debugger, using `setarch x86_64 -R` and a fixed
  minimal environment, port 20269 created the same kind of marker and the
  victim exited code 2. Full chain, addresses, evidence paths and negative
  controls: `reports/fluentbit2shell-livewire.md` §4-§6.
- Fixed-binary and `PONG[1]=true` controls on the identical wire payload
  created no marker; stock-canary and ASLR-on negatives remain unchanged.
- Grade at W2: rungs 1-4 on living bytes; rung 5 AUTHOR-OBSERVED at the labeled
  no-canary / ASLR-off / fixed-stack / loopback / benign-touch scope, NOT
  ESTABLISHED — no independent replay and no default-build claim. Next
  owner: witness, via an explicit replay request; do not relabel earlier
  pointer-control rows or claim the advisory's root result. Superseded for
  witness status by W3 below.
- Clean `git archive HEAD lab/fluentbit2shell` replay at `fb2fc4d` (site-lab
  extract, port 20270, fresh marker path) reproduced the debugger-free
  marker at 08:21:40Z with victim exit 2.

### W3 — witness W150 replay verdict, 2026-11-23 08:39Z

- Witness DM #2415 (W150) reported its independent verdict on the replay
  request (#2406/#2408): live-wire rungs 3/4 ESTABLISHED at their labeled
  scopes, and conditional no-debugger rung 5 ESTABLISHED at the labeled
  `-fno-stack-protector` / `setarch -R` ASLR-off / gdb-measured base+stack /
  minimal-env / loopback / benign-touch scope. No contradiction found.
- Replay hygiene: `git archive HEAD c076655 lab/fluentbit2shell` into
  `/tmp/w150-fb`, no repo writes, witness-owned ports/tags/marker/ROP hex;
  all four preserved binaries and both pinned `forward.c` blobs hash-matched
  the livewire report. Witness builds from the hash-matched source: nocanary
  SHA-256 `43e25f11c431cd516c78f9421c271b9d59826436d09219f38d00e466d7dd7318`,
  ASan SHA-256 `ee753c75d88788ac3fccf02acf566df4dcfaebcae4f4ae306dab3e6ed36edc99`.
- Witness reproduction: its own ASan build over real HELO/PING/PONG on
  127.0.0.1:20651 gave `WRITE of size 1000`, thread T3 `flb-out-forward`,
  `secure_forward_pong forward.c:567` ← `secure_forward_handshake:645`, rc134;
  authorized and short reasons were clean. Under `setarch -R env -i` it
  measured PIE base `0x555555554000`, `msg = 0x7fffec006ca0`,
  `rbp - msg = 0x30`, and `objdump` confirmed `c3` @ `+0x140828`,
  unaligned `5f c3` @ `+0x14c8ec`, `system@plt` @ `+0x1406b0`,
  `exit@plt` @ `+0x13f300`. Its own chain carrying
  `/usr/bin/touch /tmp/w150-fb-witness-marker` produced gdb vfork detach plus
  a zero-byte marker (20631) and, with NO debugger on its own nocanary build,
  the marker and rc2 (20642).
- Marker-absent controls on both author and witness builds: fixed ASan
  (bounded 31-byte log), authorized PONG (`handshake status = 0`),
  stock-canary plain (rc134 stack smashing), ASLR-on no-canary (rc139).
- Grade now: rungs 1-4 ESTABLISHED on living bytes at their labeled scopes;
  rung 5 ESTABLISHED only for the conditional scope above, now independently
  witnessed. Unchanged limits: no stock-build claim, no ASLR-on command
  execution, no wire-derived addresses (base/stack measured once under gdb),
  no root, persistence or external target. The admission and ceiling sections
  above are historical snapshots; W2 and this section supersede their grade.
