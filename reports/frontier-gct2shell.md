# Frontier brief — Grid Community Toolkit GSS-assist SSLv2 length underflow (Gct2Shell)

**Status: new frontier find, pre-created two-pane window ready for operator
admission (2026-11-21 ~10:4xZ).** Rungs 1/2/3 are ESTABLISHED in an extracted,
verbatim-pin harness; rung 4 shows attacker-chosen bytes at a chosen offset in
an instrumented collaborator layout only. No live gatekeeper/myproxy build,
GSI handshake over a socket, stock allocator neighbour, pointer overwrite or
execution was observed — those stay UNKNOWN. Both artifacts exist: this brief
and an inner-socket two-pane `gct2shell` window. Admission is the operator's
call; wake units and the presentation entry remain the person's full-flag sync.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-123975, CNA VulnCheck, published 2026-11-13. Title:
  "Grid Community Toolkit globus-gss-assist before 12.9 Pre-Authentication
  Heap Out-of-Bounds Write". CWE-787, CVSS 4.0 **8.7 High**
  `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` and CVSS 3.1
  7.5 High. Claim: a remote unauthenticated client sends a crafted GSI
  handshake record with an SSLv2 record length below 3 and corrupts heap
  memory / crashes the service. No RCE is claimed.
- **Affected/fixed**: Grid Community Toolkit before 6.2.20261111, i.e.
  globus-gss-assist before 12.9. Fixed in GCT 6.2.20261111 /
  globus-gss-assist 12.9. Vendor advisory also lists distro backports:
  Debian `globus-gss-assist 12.7-5` and EPEL/Fedora
  `globus-gss-assist-12.7-13.*`.
- **Consumers named by the vendor**: `globus-gatekeeper` and `myproxy` call
  `globus_gss_assist_token_get_fd()`. The write happens before any
  authentication result is used, so network reachability is pre-auth on those
  services.
- **Fix**: commit `3df2be4834c146bdcec90009a0f2e5771ff63cca` (2026-11-10,
  "Fix CVE-2026-123975"), parent `edf946b55460b6730e174f2f68f5340ab2f9bd15`.
  Ten inserted lines add one lower/upper bound check on `dsize`.
- **Sources read**: CVE Program JSON, vendor advisory at `gridcf.org`, GitHub
  release notes, fix patch, and raw `gsi/gss_assist/source/tokens_f.c` at both
  the parent and the fix commit, plus the 2019 tag as an independent
  cross-check. URLs and SHA-256 digests are in
  `lab/frontier/gct2shell/PROVENANCE.md`. Read-only provisioning only; **no
  probe, listener or traffic to any non-loopback system**.
- **Scope separation**: distinct from every owned X2Shell target. Open-source
  C GSS-API helper library reached through a pre-auth grid service; a closer
  class fit than the held DCMTK toolkit. No relationship to the owned
  postgres2shell, Babelfish, ProxySQL or gpfdist lanes.
- **Ranking**: high tractability. One missing lower bound, a ten-line fix, a
  5-byte fixed write plus a `size_t`-cast `fread` of attacker bytes, and a
  single small C harness with no third-party build needed.

## Source-bound mechanism (read from both pinned commits)

Line numbers are from the affected parent `edf946b5` unless marked fixed.

1. `tokens_f.c:92-95` — a four-byte length header is accepted as an SSL token
   when `(int_buf[0] & 0x80) && int_buf[2] == 1` (SSLv2 backward-compatible
   hello), and one more byte is read at `:99`.
2. `:120-121` — the SSLv2 length is the low 15 bits of bytes 0-1; the body size
   is that length minus 3. Length 1 gives `dsize = -2`; there is no lower
   bound check.
3. `:160`/`:162` — `size = dsize + 5` gives 3, and `malloc(size)` returns a
   3-byte token buffer.
4. `:171-173` — `pp = cp; memcpy(pp, int_buf, 5); pp += 5` writes five chosen
   header bytes into that 3-byte buffer: a two-byte heap overflow.
5. `:181` — `fread(pp, 1, dsize, fd)` passes a negative `int` as `size_t`,
   i.e. roughly `2^64`, so the read consumes every available body byte and
   writes it at `cp + 5`, far past the allocation. The short-read return
   (`GLOBUS_GSS_ASSIST_TOKEN_EOF`) happens after the write.
6. Fixed `3df2be48:127-131` — `if (dsize < 0 || dsize > (1 << 24))` returns
   `GLOBUS_GSS_ASSIST_TOKEN_ERR_BAD_SIZE` before the allocation and both
   writes, mirroring the existing guard in the raw-length branch at `:197`.

The advisory's availability-only score reflects the observed crash, not an
upper bound on the write primitive; this lab claims no execution.

## Consumer-reality check

The write is a C `memcpy` and a `fread` compiled from the pinned source lines,
not a libc routine with implementation-dependent dispatch. Exact-size
`malloc` under ASan detects the first 5-byte store; a 1 MiB mmap collaborator
places the 3-byte allocation at a known offset so attacker-selected body
bytes can be read back; an `mprotect` guard page turns the first past-end
store into a fault. No stock glibc chunk neighbour or live GSI service layout
was measured, so which useful object a hostile record reaches in a live
gatekeeper or myproxy is **UNKNOWN**.

## Local harness evidence (10 PASS / 0 FAIL, replayed)

Harness `lab/frontier/gct2shell/{gen_driver.py,run.sh}` plus `PROVENANCE.md`,
`.gitignore` and eight pinned `src/` artifacts. `gen_driver.py` verifies every
pin and copies the full function body (affected `:49-227`, fixed `:49-237`)
verbatim under `#line`; the generator aborts on drift. From committed HEAD,
`bash lab/frontier/gct2shell/run.sh <outdir>` prints **10 PASS / 0 FAIL**,
`ALL CHECKS PASS rc 0`, with two five-run groups at
`sha256=e5ca3f256b9fd58bd493ad841286819c2dd8f731874424ab26f3b287af5c6204`.

- **Rung 1 (reproducible trigger)**: record length 1 → `rv=1 size=0 alloc=3`;
  the undersized allocation is the observable trigger state.
- **Rung 2 (observed state failure)**: in the collaborator, the five header
  bytes are read back at `cp+0..4` and 32 body bytes at `cp+5..36`, all past a
  3-byte allocation; the benign fixed path uses exactly 8 bytes.
- **Rung 3 (ASan-confirmed corruption)**: exact 3-byte allocation gives
  `heap-buffer-overflow`, `WRITE of size 5`, frame pinned at
  `tokens_f_edf946b5:172` (the verbatim `memcpy`).
- **Rung 4 (instrumented chosen-value control)**: body seed `0x5a` reads back
  byte-exact as `5a5b5c5d…` at `cp+5`; a `PROT_NONE` guard page faults on the
  first past-end store; the fixed commit rejects the hostile length before
  allocation and is ASan-clean on both hostile and benign inputs.
- **Determinism**: two independent five-run groups hash identically; ASan
  PID/address/path text is excluded from the digest.

**Grade**: rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4 is
INSTRUMENTED chosen-byte control at a chosen offset, not a live GSI
demonstration. No listener, handshake through real GSSAPI, stock neighbour,
pointer control or execution claim. This is a claim for the witness to replay,
not acceptance.

## Cheapest next experiment to move a rung

Build the vulnerable globus-gss-assist (12.8) on loopback, call the real
`globus_gss_assist_token_get_fd()` with a local file or pipe containing
`0x80 0x01 0x01 …` plus chosen body bytes, and capture a symbolised ASan
report at the true function frame. Then measure the real glibc neighbours of
the 3-byte token buffer before any pointer or marker claim; no external target
is ever contacted.

## What would change my mind

A primary source showing a lower bound before the write in the affected
parent, a replay losing ASan or chosen-byte readback, evidence that a live
gatekeeper/myproxy cannot reach this function pre-auth, or a measured layout
putting every reachable index in unmapped memory would all lower the grade.
