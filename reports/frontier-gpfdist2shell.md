# Frontier brief — WarehousePG gpfdist segment-header OOB write (GpfD2Shell)

**Status: new frontier find, handed off to the operator for admission under the
standing similar-things mandate (2026-11-21 ~10:3xZ).** Rungs 1/2/3 are
ESTABLISHED in an extracted, verbatim-pin harness; rung 4 shows an
attacker-chosen 64-bit value written at an attacker-chosen byte offset, but in
an instrumented layout only. No stock gpfdist build, live listener, real APR
pool neighbour, pointer overwrite or execution was observed — those stay
UNKNOWN. Both artifacts exist: this brief and a pre-created two-pane
`gpfdist2shell` window on the inner socket. Admission is the operator's call;
wake units and the presentation entry remain the person's full-flag sync.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-122042, EDB security advisory "gpfdist out-of-bounds
  write from unchecked segment headers", first published 2026/11/18, CWE-787
  plus CWE-129, CVSS 4.0 **7.1 High**,
  `AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` — availability-only
  scoring. Claim: one HTTP request with crafted `X-GP-SEGMENT-COUNT` and
  `X-GP-SEGMENT-ID` headers crashes gpfdist; RCE is not claimed.
- **Affected/fixed**: WarehousePG 6.27.1–6.27.7 and 7.2.1–7.6.1; fixed in
  6.27.8 / 7.6.2. The vendor says gpfdist does not authenticate callers unless
  `gpfdists` is used with client-certificate verification, and is normally
  reachable only from the cluster's internal network — that is a deployment
  constraint, not an authentication control.
- **Fix**: PR `warehouse-pg/warehouse-pg#370` (WarehousePG 7; companion #371
  for WarehousePG 6), merged `6fbb42ed6480bf3534c0a49e5f251dff468e8469`
  2026-10-30; regression test `src/bin/gpfdist/regress/test_segment_headers.sh`
  sends exactly the hostile header shapes to 127.0.0.1. Raw `gpfdist.c` was
  read at tags `7.6.1-WHPG` (affected) and `7.6.2-WHPG` (fixed).
- **Sources read**: vendor advisory `.md`, NVD CVE record, both fix PR diffs,
  and both raw tags. URLs, tags, commit IDs and SHA-256 digests in
  `lab/frontier/gpfdist2shell/PROVENANCE.md`. Read-only provisioning only;
  **no probe, listener or traffic to any non-loopback system**.
- **Scope separation**: distinct from the owned postgres2shell, Babelfish,
  ProxySQL and every X2Shell target mind. This is an open-source C file server
  in a database distribution, unauthenticated by default, reached over HTTP —
  a closer class fit than the held DCMTK toolkit.
- **Ranking**: high tractability. One wrong index check, tiny fix diff, a
  single unauthenticated request, and an **8-byte attacker-chosen value**
  (`X-GP-SEQ`) written at the chosen index — stronger chosen-value control than
  most recent finds. Ranked above the held appliance/toolkit lanes.

## Source-bound mechanism (read from both tags and the fix)

Line numbers are from `7.6.1-WHPG` unless marked fixed.

1. `gpfdist.c:3864`/`:3866`/`:3893` — `X-GP-SEGMENT-COUNT`,
   `X-GP-SEGMENT-ID` and `X-GP-SEQ` are parsed verbatim with `atoi`/`atoi`/
   `atol`. The sequence value must be positive; on x86-64 it is a signed
   64-bit integer.
2. `:1975`/`:1978` — `session_attach()` allocates `active_segids` (4 bytes per
   entry) and `seq_segs` (8 bytes per entry) with sizes taken directly from
   `r->totalsegs`.
3. `:1988` — `session->active_segids[r->segid] = 1` writes a chosen 4-byte
   value (1, or 0 through `X-GP-DONE` at `:2038`) at the attacker's index with
   no bounds check; `:1989` stores the same untrusted count as `maxsegs`.
4. `:3677` — `session->seq_segs[r->segid] = r->seq` writes the attacker's
   `X-GP-SEQ` integer at the same untrusted index. The OPEN request reaches
   this store directly (`OPEN_SEQ` goto at `:3473-3475`); later DATA requests
   reach it after writing data. This is the chosen-value/offset primitive.
5. Fixed `7.6.2-WHPG:1865-1871` rejects a non-positive or oversized count and
   an id outside `[0, totalsegs)` before allocating; `:2063-2068` also bounds
   a later join by the session's original `maxsegs`. `:407` caps the count at
   32767. `:2011-2012` and `:3713` keep the original writes, now guarded.

Because the array is sized by one header and indexed by another, a single
request can create a one-entry session and write far outside both allocations.
The advisory's availability-only score reflects the demonstrated crash, not
an upper bound on the write primitive; this lab claims no execution.

## Consumer-reality check

The write is a C assignment compiled from the pinned source lines, not a libc
routine with implementation-dependent dispatch. Exact-size `calloc` under ASan
detects the first 4-byte and 8-byte past-end stores; a 1 MiB mmap collaborator
places both arrays at known offsets so chosen bytes can be read back; an
`mprotect` guard page turns the first past-end store into a fault. No stock
APR pool layout or allocator-neighbour attribution was measured, so which
useful object a given `segid` reaches in a live gpfdist is **UNKNOWN**.

## Local harness evidence (all replayed)

Harness `lab/frontier/gpfdist2shell/{gen_driver.py,run.sh}` plus
`PROVENANCE.md`, `.gitignore` and the four pinned `src/` artifacts.
`gen_driver.py` verifies every pin and copies the fault lines listed above
verbatim under `#line`; the generator aborts on drift. From committed HEAD,
`bash lab/frontier/gpfdist2shell/run.sh <outdir>` prints **13 PASS / 0 FAIL**,
`ALL CHECKS PASS rc 0`, with two five-run groups at
`sha256=4f8bf8b7c6de06df7ce370b3570babe8df25112b9d2380c9836852864a8048c4`.

The same result was replayed from a clean `git archive HEAD` extraction at
commit `a7d5884`: 13 PASS / 0 FAIL, rc 0, identical digest.

- **Rung 1 (reproducible trigger)**: count=1, id=1, seq=1 →
  `rung1 totalsegs=1 segid=1 seq=1 verdict=TRIGGER`.
- **Rung 2 (observed state failure)**: in the collaborator, id=3 clobbers
  `active_segids` at byte 12 and `seq_segs` at byte 24; an in-bounds id=0
  control writes only at offset 0.
- **Rung 3 (ASan-confirmed corruption)**: exact 4-byte allocation gives
  `heap-buffer-overflow`, `WRITE of size 4`, frame pinned at
  `gpfdist_v7.6.1.c:1988`; an isolated exact 8-byte `seq_segs` case gives
  `WRITE of size 8` at pinned `:3677`.
- **Rung 4 (instrumented chosen-value control)**: `X-GP-SEQ =
  4702111234474983745` (`0x4141414141414141`) read back byte-exact at
  `seq_segs+24`; `X-GP-DONE` changes the 4-byte `active_segids` write from
  `01000000` to `00000000`; a guard page faults at the first past-end write;
  fixed guards reject both hostile cases and are ASan-clean.
- **Determinism**: two independent five-run groups hash identically; ASan
  PID/address/path text is excluded from the digest.

**Grade**: rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4 is
INSTRUMENTED chosen-value control at a chosen offset, not a live gpfdist
demonstration. No listener, HTTP request through real APR, stock neighbour,
pointer control or execution claim. This is a claim for the witness to replay,
not acceptance.

## Cheapest next experiment to move a rung

Build the pinned 7.6.1 `gpfdist` on loopback (APR 1.7.2 and gcc 13.3.0 are
present), run the vendor's regression request with `X-GP-PROTO:1`,
`X-GP-SEGMENT-COUNT:1`, `X-GP-SEGMENT-ID:3`,
`X-GP-SEQ:4702111234474983745`, and capture a symbolised ASan report at the
real `session_attach`/DATA path. Then measure the true APR-pool neighbours of
`active_segids`/`seq_segs` at a chosen `segid` before any pointer or marker
claim; no external target is ever contacted.

## What would change my mind

A primary source showing a bounds check before the write in 7.6.1, a replay
losing ASan or chosen-value readback, evidence that a live gpfdist requires
authentication on the default listener, or a measured neighbour layout that
puts every reachable index in unmapped memory would all lower the grade.
