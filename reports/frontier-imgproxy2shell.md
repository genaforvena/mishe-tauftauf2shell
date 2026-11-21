# Frontier brief — imgproxy ICO `data_size` wrap (Imgproxy2Shell)

**Status: new frontier find, pre-created two-pane window ready for operator
admission (2026-11-21 ~10:5xZ).** Rungs 1/2/3 are ESTABLISHED in an extracted,
verbatim-pin harness; rung 4 shows attacker-chosen bytes at a chosen offset in
an instrumented collaborator only. No live imgproxy HTTP server, libvips
runtime, real uploaded ICO, stock allocator neighbour, pointer overwrite or
execution was observed — those stay UNKNOWN. Both artifacts exist: this brief
and an inner-socket two-pane `imgproxy2shell` window. Admission is the
operator's call; wake units and the presentation entry remain the person's
full-flag sync.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-123614 / GHSA-hff9-5pqw-6w9f, published 2026-11-08,
  CNA GitHub. CWE-122, CVSS 4.0 **9.3 Critical**
  `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CVSS 3.1 9.8.
  Claim: a remote attacker submits a crafted ICO image whose `data_size`
  wraps the allocation in `vips/icoload.c`, corrupting heap memory to crash
  the process or achieve code execution. RCE is claimed by the CVE prose, not
  demonstrated here.
- **Affected/fixed**: `pkg:golang/github.com/imgproxy/imgproxy/v4` from 4.0.0
  before 4.0.16; 4.0.16 is the fixed version. imgproxy is an HTTP image
  processing service; the crafted image is supplied through its normal
  unauthenticated request path (CVSS `PR:N/UI:N`).
- **Fix**: commit `a821b6a4cb07a1bf2bb9077431d1c1e734d79917` (2026-09-24,
  "Fix segfaults during invalid ICO load"), which adds a 10 MiB bound on
  `data_size`, computes `full_data_size` after that guard, and adds three
  regression ICO files plus Go tests.
- **Sources read**: CVE Program JSON, GitHub security advisory, fix patch, and
  raw `vips/icoload.c` at tags `v4.0.15` (affected) and `v4.0.16` (fixed).
  URLs and SHA-256 digests are in `lab/frontier/imgproxy2shell/PROVENANCE.md`.
  Read-only provisioning only; **no probe, listener or traffic to any
  non-loopback system**.
- **Scope separation**: distinct from every owned X2Shell target and from
  GpfD2Shell, Kermit2Shell, Dcmtk2Shell and Gct2Shell. A Go HTTP image server
  with a C/libvips loader: stronger claim class (unauthenticated HTTP,
  confidentiality/integrity impact scored) than the availability-only
  advisories behind several earlier finds.
- **Ranking**: highest tractability of the current queue. One unchecked
  `uint32_t` addition, one small fix, and a write through a `read_full` call
  into a buffer 11 bytes past a 3-byte allocation. No full build needed for
  the pinned statements.

## Source-bound mechanism (read from both pinned tags)

Line numbers are from `v4.0.15` unless marked fixed.

1. `icoload.c:154` — `uint32_t data_size` comes from the largest ICO directory
   entry's `data_size`, read from the uploaded file with `GUINT32_FROM_LE`.
2. `:158` — `VIPS_MALLOC(NULL, data_size + BMP_FILE_HEADER_LEN)` performs
   `uint32_t` arithmetic; `data_size = 0xfffffff5` plus 14 wraps to 3.
3. `:159` — `actual_data = data + 14`, so the destination begins 11 bytes
   past that 3-byte allocation.
4. `:161` — `vips_foreign_load_read_full(ico->source, actual_data, data_size)`
   writes the attacker's ICO payload into `actual_data`. A short source can
   still copy the bytes it has; the function returns a positive count, so the
   error branch at `:162-164` is not taken and the loader continues with the
   corrupted buffer.
5. Fixed `v4.0.16:165-168` rejects `data_size > 10 * 1024 * 1024` before the
   addition; `:172-173` allocate `full_data_size` and check the allocation.

The CVE's code-execution claim is an advisory claim only; this lab claims no
execution.

## Consumer-reality check

The write is a `memcpy` performed by a stand-in for `vips_foreign_load_read_full`
compiled from the pinned call site, not a libc routine whose dispatch depends
on the host. Exact-size `malloc` under ASan detects the first past-end store;
a 1 MiB mmap collaborator places the 3-byte allocation at a known offset so
chosen body bytes can be read back; an `mprotect` guard page turns the first
past-end store into a fault. Real libvips source/read behaviour, Go callback
boundaries and glibc chunk neighbours were not measured, so which object a
given ICO entry reaches in a live imgproxy is **UNKNOWN**.

## Local harness evidence (10 PASS / 0 FAIL, replayed)

Harness `lab/frontier/imgproxy2shell/{gen_driver.py,run.sh}` plus
`PROVENANCE.md`, `.gitignore` and five pinned `src/` artifacts.
`gen_driver.py` verifies every pin and copies the affected statements
(`:154-164`) and fixed statements (`:162-185`) verbatim under `#line`; the
generator aborts on drift. From committed HEAD,
`bash lab/frontier/imgproxy2shell/run.sh <outdir>` prints **10 PASS / 0 FAIL**,
`ALL CHECKS PASS rc 0`, with two five-run groups at
`sha256=6b0391599520bc899f169268e08699155888f0018274f9c2a2e12bcd31c2dad5`.

- **Rung 1 (reproducible trigger)**: `data_size = 0xfffffff5` → `alloc=3`
  despite a declared ~4 GiB payload.
- **Rung 2 (observed state failure)**: in the collaborator, 32 chosen bytes
  are read back at `data+14`, 11 bytes past the 3-byte allocation.
- **Rung 3 (ASan-confirmed corruption)**: exact 3-byte allocation gives
  `heap-buffer-overflow`, `WRITE of size 32`, frame pinned at
  `icoload_v4.0.15:161`.
- **Rung 4 (instrumented chosen-value control)**: seed `0x5a` reads back
  byte-exact as `5a5b5c5d…` at `data+14`; a `PROT_NONE` guard page faults on
  the first past-end store; the fixed commit rejects the hostile size before
  allocation and is ASan-clean on hostile and benign inputs.
- **Determinism**: two independent five-run groups hash identically; ASan
  PID/address/path text is excluded from the digest.

The same result was replayed from a clean `git archive HEAD` extraction at
commit `2366ef4`: 10 PASS / 0 FAIL, rc 0, identical trace digest.

**Grade**: rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4 is
INSTRUMENTED chosen-byte control at a chosen offset, not a live imgproxy
demonstration. No HTTP request, libvips process, stock neighbour, pointer
control or execution claim. This is a claim for the witness to replay, not
acceptance.

## Cheapest next experiment to move a rung

Build pinned v4.0.15 imgproxy on loopback, serve a 23-byte crafted ICO through
its normal HTTP image URL endpoint, and capture a symbolised ASan report at
the real `vips_foreign_load_ico_header` / `read_full` frame. Then measure the
actual libvips/glibc neighbours of the 3-byte buffer before any pointer or
marker claim; no external target is ever contacted.

## What would change my mind

A primary source showing the addition happens in 64-bit arithmetic, a replay
losing ASan or chosen-byte readback, evidence that the endpoint requires
authentication, or a measured live layout that puts every reachable write in
unmapped memory would all lower the grade.
