# Frontier brief — 389ds2Shell (389 Directory Server, CVE-2026-11610 / GHSA-2g8g-f92j-g4gq)

Status: **frontier find, ADMITTED by operator under standing approval #6**
(commit `9d75b45`, dedicated mind `389ds2shell`). Brief written
2026-11-21T09:09Z; witness verdict #740 ESTABLISHED AS CLAIMED, grade
unchanged (precision nit fixed this wake).

Harness: `lab/frontier/389ds2shell/`; `PROVENANCE.md` carries every pin, hash,
verbatim range and repair. The operator owns admission; this brief never
activates a target mind by itself.

## Verified ground truth (primary sources, fetched 2026-11-21)

- GitHub advisory `GHSA-2g8g-f92j-g4gq` / `CVE-2026-11610`, published
  `2026-07-07`, HIGH 8.8, CVSS `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  (advisory API pin `sha256=a03a6156…`), and the CVE record (pin
  `1be123890…`) both state: **389-ds-base affected from 1.3.2 through
  3.3.0**, CWE-122. Description: after a successful SASL bind with integrity
  protection (`SSF > 0`), an attacker sends an oversized LDAP UNBIND whose
  padded BER length drives a copy into a **512-byte heap receive buffer**
  without a bounds check in `sasl_io_recv()` in `sasl_io.c`, up to ~2 MB of
  attacker-controlled data. The claim is DoS/server crash; "further
  exploitation given sufficient heap-corruption control" is not claimed as
  demonstrated by the advisory.
- Upstream tracker issue #7658 (pin `6163717e…`) names the missing check
  directly: when `sasl_io_start_packet()` returns
  `SASL_IO_BUFFER_NOT_ENCRYPTED` (unencrypted LDAP UNBIND after SASL layer
  setup), there is no check that
  `sp->encrypted_buffer_count <= len` before the `memcpy`.
- Fix commit `f15ffd63e2bd70b3244881424ef903f17f7f0394`
  (`2026-08-13T16:53:25Z`, commit JSON pin `6b251fb6…`), parent
  `e63592d5e6b0c69ecb2799db3904743b9202b64d`. A different commit `dd16813`
  fixes CVE-2026-78701 (integer wraparound in `sasl_io_start_packet`); it was
  read and **excluded** as a different bug. The CVE record lists unaffected
  RHEL builds from July 2026, confirming the affected/fixed split but not an
  upstream semantic version pin beyond 3.3.0 → 3.3.1.
- Claimed primitive: one post-authentication LDAP UNBIND with attacker data
  and a BER-declared length larger than the caller's 512-byte buffer produces
  an unbounded attacker-controlled heap write. Authentication (`SSF > 0`,
  Kerberos/GSSAPI or DIGEST-MD5 bind) is required — this is **not** pre-auth.

## Source-bound mechanism (pinned bytes)

Pinned `sasl_io.c` bytes: vulnerable parent `sha256=9cea2e7b…` (30489 B),
fixed `sha256=f82aa846…` (31934 B).

- Vulnerable `sasl_io.c:25-27` defines `SASL_IO_BUFFER_SIZE 1024`,
  `SASL_IO_BUFFER_NOT_ENCRYPTED -99`, `SASL_IO_BUFFER_START_SIZE 7`; `:39-56`
  defines `struct PRFilePrivate` with `encrypted_buffer`,
  `encrypted_buffer_size`, `encrypted_buffer_count`, `encrypted_buffer_offset`.
- Vulnerable `sasl_io_start_packet()` at `:344-348` sets
  `sp->encrypted_buffer_count = sp->encrypted_buffer_offset` to the full
  BER-declared packet length and returns `SASL_IO_BUFFER_NOT_ENCRYPTED` when
  the plaintext LDAP tag is an UNBIND. No upper bound against the caller's
  receive length exists on that path.
- Vulnerable `sasl_io_recv()` at `:451-457` then executes, verbatim:

  ```c
  if (SASL_IO_BUFFER_NOT_ENCRYPTED == ret) {
      /* ... unbind ... */
      memcpy(buf, sp->encrypted_buffer, sp->encrypted_buffer_count);
      return sp->encrypted_buffer_count;
  }
  ```

  `buf` is the caller's buffer (`len`, 512 bytes in the advisory), while the
  copy length and source bytes are both attacker-controlled from the wire.
  The return value also claims `encrypted_buffer_count` bytes were delivered.
- The fix adds `sasl_io_drain_unencrypted_buffer()` at fixed `:156-182`, which
  computes `bytes_to_copy = count - offset`, caps it at `(uint32_t)len`
  (`:169-171`), copies from `encrypted_buffer + offset`, and tracks the offset
  across calls. Both `sasl_io_recv()` entry (`:476-478`) and the
  `SASL_IO_BUFFER_NOT_ENCRYPTED` branch (`:493-499`) now call that drain. A
  local `diff` of the pinned files shows exactly that change plus BER header
  sizing in `sasl_io_start_packet`.

## Local harness and observed rungs

`./run.sh` verifies every pin hash, generates two C drivers whose
faulting/copying code is copied **verbatim** from the pinned files under
`#line` directives, builds ASan and plain variants, and writes a normalized
trace. The generator aborts on any pin drift. No socket, daemon, SASL library
or network is used; the "wire" length is a local variable. Full command:
`cd lab/frontier/389ds2shell && ./run.sh`.

Latest run: **19 PASS / 0 FAIL**, rc 0, trace
`sha256=5ac6faaeec38553369518aae643572de70cdfd0d5e9bd2ab2356220a968ba6f6`.

Witness #740 (precision nit; grade unchanged): before this fix the generated
`CLEANUP()` called `free(buf)` unconditionally, so collab cases (mmap base)
died rc=139 and a no-overflow guard case (interior pointer) died rc=134 with
`free(): invalid pointer`. The printed chosen-byte counts stand because they
are emitted before cleanup. The cleanup now uses a harness-owned heap flag:
only the malloc-backed ASan/benign caller buffer is freed, mapped regions are
`munmap`ed, and every other allocation is freed once per mode. `run.sh` now
asserts rc=0 for `vuln_collab_5a`, `vuln_collab_41`,
`vuln_collab_benign` and `fixed_collab`, plus rc=77 for the guard fault case.
Observed before and after: the overflow write, pinned ASan frame and chosen
bytes are unchanged; only cleanup and exit-status hygiene changed.

- **Rung 1 — reproducible trigger.** Vulnerable build, declared 9000,
  caller 512: deterministic ASan abort. Benign 512 and the fixed build at
  declared 9000 stay clean. Exact boundary sweep: declared 511/512 clean,
  513 faults with `WRITE of size 513` — the fault begins precisely when the
  declared count exceeds the caller length.
- **Rung 2 — observed accounting failure.** Declared 9000 exceeds caller 512
  by 8488 bytes; the vulnerable path returns 9000, telling the caller 9000
  bytes were placed in a 512-byte buffer.
- **Rung 3 — ASan-confirmed corruption.** Vulnerable ASan:
  `heap-buffer-overflow`, `WRITE of size 9000`, frame
  `sasl_io_recv pins/sasl_io.c.vuln:456`, `0 bytes after 512-byte region`.
  No such report in the fixed or benign builds.
- **Rung 4 — INSTRUMENTED, honestly split.** With a 1 MiB zeroed collaborator
  as the caller buffer, chosen `0x5a` appears at offsets 0–8487 past the
  512-byte boundary; `0x41` reproduces the same 8488 offsets (pattern
  differential); benign declared 512 and the fixed build write none; a
  guard-mapped page faults at exit 77. No pointer, return address,
  heap-metadata field, function pointer or control-flow diversion was
  observed or attempted — the collaborator and guard page are
  instrumentation, not upstream allocator properties.

## Feasibility assessment

High tractability: a network-facing C daemon, a named upstream function, an
explicit fix commit, an upstream ASan test with a concrete 9000-byte padded
UNBIND, and an attacker-controlled write length and payload. The primitive is
a single `memcpy` whose length is a wire-declared count, so rungs 1–4 map
cleanly. Weaker points: authentication is required (`SSF > 0`), so this is a
post-auth primitive; the advisory claims DoS, not code execution; the harness
proves pinned C logic in a synthetic frame, not a built `ns-slapd`; the 512-byte
receive buffer size is the advisory's account and the real caller's `len` in
a deployed build is UNKNOWN here; rung 4 is chosen bytes in a collaborator
only. Overall status: **rungs 1/2/3 established locally, rung 4
INSTRUMENTED**; live-daemon reachability and shipping-allocator behavior are
UNKNOWN.

Cheapest experiment to move up a rung: build the vulnerable pinned parent with
ASan, configure a loopback 389-ds instance with a DIGEST-MD5/GSSAPI user,
perform the SASL bind with `SSF > 0`, send the upstream test's 9000-byte padded
plaintext UNBIND on the raw socket FD, and capture the daemon ASan frame plus
the real heap layout around the 512-byte connection buffer; repeat at the
fixed commit for the guard. Only an observed pointer or control-flow result
would drop the INSTRUMENTED label. If the shipping allocator faults before
chosen bytes persist, preserve that negative and cap this path at rung 3 in
practice.

All advisory, version and reachability claims are reproduced from public
sources; this brief proves the pinned code paths and their local memory
effects, not live-daemon exploitability or RCE.

## Replay status (2026-11-21)

The earlier `9ff285d` clean-replay record predates the witness #740 cleanup
fix and is superseded; its trace and count are not the current harness result
and its hash is not repeated here. Post-nit-fix replay of integration commit
`3d556c5`: two independent `git archive 3d556c5 lab/frontier/389ds2shell`
extractions (`/tmp/replay-389-post-a`, `/tmp/replay-389-post-b`) and the
working tree each ran the unmodified `./run.sh`: **19 PASS / 0 FAIL**, rc 0,
normalized trace
`sha256=5ac6faaeec38553369518aae643572de70cdfd0d5e9bd2ab2356220a968ba6f6`
byte-identical in all three. A no-overflow guard case was also exercised
directly at declared 512 in both builds: rc 0 with `return=512`, no invalid
free.
