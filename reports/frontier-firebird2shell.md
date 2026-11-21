# Frontier brief — Firebird slice `dtype_cstring` overflow (Firebird2Shell)

**Status: new frontier find, pre-created two-pane window ready for operator
admission (2026-11-21 ~11:0xZ).** Rungs 1/2/3 are ESTABLISHED in an extracted,
verbatim-pin harness; rung 4 shows attacker-chosen bytes at chosen offsets in
an instrumented collaborator only. No live Firebird server, wire packet,
allocator neighbour, pointer overwrite or execution was observed — those stay
UNKNOWN. Both artifacts exist: this brief and an inner-socket two-pane
`firebird2shell` window. Admission is the operator's call; wake units and the
presentation entry remain the person's full-flag sync.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-33337 / GHSA-89mq-229g-x47p, published
  2026-04-17T18:48:47.953Z by GitHub's CNA (`GitHub_M`). CWE-120 / CWE-502,
  CVSS 3.1 **7.5 High**
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — availability-only. Claim: when
  deserializing a slice packet, `xdr_datum()` does not validate a cstring
  length against the slice descriptor bounds, so a cstring longer than the
  allocated buffer overflows it; an unauthenticated attacker can trigger this
  with a crafted packet. The advisory also reports a PoC to TCP/3050 and a
  crash stack trace. It claims "crash or other security impact", not proven
  code execution.
- **Affected/fixed**: Firebird `>= 3.0.0, < 3.0.14`, `>= 4.0.0, < 4.0.7`,
  `>= 5.0.0, < 5.0.4`; fixed in 3.0.14 / 4.0.7 / 5.0.4. The harness pins the
  5.0 line: `v5.0.3` affected, `v5.0.4` fixed.
- **Fix**: master commit `2a5303dc9fb2cfc035a6aeb6274377d0e2dd3488` and the
  v5.0.4-branch commit `62fc37eda82fa1f8120aff7fb0fdd7c72b493a75`; both add
  exactly two lines, `n = MIN(n, desc->dsc_length - 1);` and a blank line,
  immediately after `xdr_short()` in the `dtype_cstring` case. The 5.0.4
  patch is exactly the diff between the pinned v5.0.3 and v5.0.4 `xdr.cpp`
  blobs (`555e6e1f40c..a5698288419`).
- **Sources read**: CVE Program JSON, GitHub security advisory, both fix
  patches, raw `src/common/xdr.cpp` at tags `v5.0.3` (affected) and `v5.0.4`
  (fixed), raw `src/remote/protocol.cpp` and `src/common/dsc.h` at `v5.0.3`.
  URLs, SHA-256 digests and git blob IDs are in
  `lab/frontier/firebird2shell/PROVENANCE.md`. Read-only provisioning only;
  **no probe, listener or traffic to any non-loopback system**.
- **Scope separation**: distinct from every owned X2Shell target and from
  GpfD2Shell, Kermit2Shell, Dcmtk2Shell, Gct2Shell and Imgproxy2Shell. A
  pre-auth network-serialisation bug in a relational database server, in the
  same class as the admitted Gct2Shell / Dcmtk2Shell slice-record bugs.
- **Ranking**: high tractability. One missing bound, one two-line fix, one
  decode `memcpy` with a wire-controlled 16-bit length; no full Firebird build
  needed for the pinned statements. Rung 4 is honest chosen-byte control, not
  a live-server claim.

## Source-bound mechanism (read from both pinned tags)

Line numbers are from `v5.0.3` unless marked fixed.

1. `protocol.cpp:1813` reads `slice->lstr_length` from the wire; `:1835`
   allocates `UCHAR[lstr_length]`; `:1884-1889` loops
   `lstr_length / desc->dsc_length` times calling `xdr_datum(xdrs, desc, p)`
   with `p += dsc_length`. Each `p` is a `dsc_length`-sized slot inside that
   allocation.
2. `xdr.cpp:169` computes `p = buffer + (IPTR) desc->dsc_address`; the
   `dtype_cstring` case starts at `:206`.
3. `:207` declares `USHORT n`; `:214` reads `n` from the wire with
   `xdr_short(xdrs, reinterpret_cast<SSHORT*>(&n))`. On `XDR_DECODE` the
   value is attacker-controlled (up to 65535).
4. `:216` calls `xdr_opaque(xdrs, reinterpret_cast<SCHAR*>(p), n)` with no
   bound; the decode side of `xdr_opaque` funnels through `GETBYTES` to a
   `memcpy` of `n` bytes into the `dsc_length`-sized slot. `:219` then writes
   `p[n] = 0`, a further past-end byte.
5. Fixed `v5.0.4:216` adds `n = MIN(n, desc->dsc_length - 1)` before the
   copy; `v5.0.4:218` is the bounded call and `:221` the in-bounds NUL.

The advisory's "other security impact" is a claim only; this lab claims no
execution.

## Consumer-reality check

The write is a `memcpy` performed by a stand-in expanded directly at the
verbatim `xdr_opaque` call, not a libc routine whose dispatch depends on the
host. Exact-size `malloc` under ASan detects the first past-end store; a 1 MiB
mmap collaborator places the 32-byte slot at a known offset so chosen body
bytes can be read back; an `mprotect` guard page turns the first past-end
store into a fault. The pinned consumer confirms the destination is a
`dsc_length`-sized slot inside a wire-sized allocation, so an `n` of 60000
corrupts neighbouring slots when the descriptor is small. Real Firebird
pool allocation layout, the `REMOTE_getbytes` buffering path, wire framing
and which object a given slot reaches in a live `fbserver` were not measured
and stay **UNKNOWN**.

## Local harness evidence (10 PASS / 0 FAIL, replayed)

Harness `lab/frontier/firebird2shell/{gen_driver.py,run.sh}` plus
`PROVENANCE.md`, `.gitignore` and eight pinned `src/` artifacts.
`gen_driver.py` verifies all eight pins and copies the affected statements
(`:206-221`) and fixed statements (`:206-223`) verbatim under `#line`; the
generator aborts on drift. A byte-for-byte comparison found zero mismatches
over 16 and 18 copied lines. From committed HEAD,
`bash lab/frontier/firebird2shell/run.sh <outdir>` prints **10 PASS / 0 FAIL**,
`ALL CHECKS PASS rc 0`, with two five-run groups at
`sha256=807b47150a58fe88094966b0affed9b35604a7b3730c68f53eeaa61057a25fbf`.

- **Rung 1 (reproducible trigger)**: wire length 60000 reaches `xdr_opaque`
  unclamped for a 32-byte cstring descriptor (`copy_len=60000`).
- **Rung 2 (observed state failure)**: chosen wire bytes are read back at
  `buffer+40` and `buffer+100`, far past the 32-byte slot.
- **Rung 3 (ASan-confirmed corruption)**: exact-size allocation gives
  `heap-buffer-overflow`, `WRITE of size 60000`, frame pinned at
  `xdr_v5.0.3:216`.
- **Rung 4 (instrumented chosen-value control)**: seed `0x5a` reads back
  byte-exact as `5a5b5c5d…` at the chosen OOB offsets; a `PROT_NONE` guard
  page faults on the first past-end store; the fixed source clamps to 31 and
  is ASan-clean on hostile and benign inputs, as is the vulnerable source on
  a benign length.
- **Determinism**: two independent five-run groups hash identically; ASan
  PID/address/path text is excluded from the digest.

The same result is replayed from a clean `git archive HEAD` extraction; see
`PROVENANCE.md` for the recorded digest and commit.

**Grade**: rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4 is
INSTRUMENTED chosen-byte control at chosen offsets, not a live Firebird
demonstration. No server process, wire packet, stock neighbour, pointer
control or execution claim. This is a claim for the witness to replay, not
acceptance.

## Cheapest next experiment to move a rung

Build pinned v5.0.3 `fbserver` on loopback with ASan, send the advisory's
slice packet to a locally started TCP/3050 listener, and capture a symbolised
ASan report at the real `xdr_datum` / `xdr_opaque` frame. Then measure the
actual Firebird pool and wire-buffer neighbours of the 32-byte slot before
any pointer or marker claim; no external target is ever contacted.

## What would change my mind

A primary source showing the cstring length is validated elsewhere on the
decode path, a replay losing ASan or chosen-byte readback, evidence that the
slice path requires authentication, or a measured live layout that puts every
reachable write in unmapped memory would all lower the grade.
