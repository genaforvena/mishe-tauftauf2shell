# Frontier brief: Perl2Shell — CVE-2026-15534 (regex superlinear-cache I32 wrap)

Status: RANKED CANDIDATE / RUNG 0 (no build, no trigger, no bytes, no window).
Written 2026-11-21 ~20:45Z by `frontier`. Ranked #1 unadmitted at write time
(netty2shell was admitted 20:32Z as window 68; MsQuic CVE-2026-62815 stays #2,
deferred by the operator). Case for admission is standing approval #6 evidence,
not a request for a decision already made elsewhere.

## Verified ground truth

- **Claim sources.** Authoritative CPAN Security Group CVE record
  `https://cveawg.mitre.org/api/cve/CVE-2026-15534` (published 2026-08-09T17:49:50Z,
  updated 2026-09-08T21:31:42Z; CNA `9b29abf9-4ab0-4765-b253-1875cd9b441e`).
  Public disclosure by Stig Palmquist on oss-security, 2026-08-09 19:51:48 +0200,
  `http://www.openwall.com/lists/oss-security/2026/08/09/12` (message-id
  `<26D09784-6FF0-4690-81CC-9F9DE92E8903@stig.io>`), text fetched and read.
  Secondary: NVD (marked "Awaiting Enrichment"), GHSA-2cxw-qmfc-3vx3,
  Ubuntu USN-8736-1, Debian security tracker. CISA ADP scores CVSS 3.1 5.7
  `AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H`; the CNA itself publishes no score.
  The AV:L vector is a claim about the reporter's threat model, not a measured
  property of this plant's loopback experiments.
- **Identifier / file / routine.** CVE-2026-15534; `regexec.c`, `S_regmatch`;
  CWE-190 + CWE-125 + CWE-787.
- **Version range (CNA).** Affected `0` through `5.45.1` inclusive; fix included
  in the 5.45.2 development release, or apply the two patches. The 5.45.x line
  is development; CNA does not name fixed *stable* releases. Source check below
  shows a released stable tree still carries the same arithmetic.
- **Upstream fix commits (CNA patch references).**
  `568e6fd238867bb9e99fa3f47cba3169009239e0` (2026-06-30, "regex super-linear
  cache: make countdown unsigned", 5 insertions / 3 deletions in `regexec.c`)
  and `54cf3d44cbbedd17d774e9a37921963e8fd5d0cb` (2026-06-30, "regex: make
  superlinear cache 64-bit clean", 16 insertions / 11 deletions across
  `regexec.c` and `regexp.h`). Both `.patch` bodies were fetched verbatim.
- **Pinned raw bytes.** `lab/frontier/perl2shell/src/SHA256SUMS`: raw
  `v5.45.1/regexec.c`, `v5.45.2/regexec.c`, `v5.44.0/regexec.c`,
  `v5.45.1/regexp.h`, `v5.45.2/regexp.h`, plus both commit patches. Seven of
  seven `sha256sum -c` OK at write time (self-computed digests: GitHub tag archives
  and rendered files have no published sidecar). Provenance in
  `lab/frontier/perl2shell/PROVENANCE.md`. Rendered advisory line numbers are
  claims; the raw line numbers below are from the pinned files.

## Source-bound mechanism (raw pinned bytes)

Affected `v5.45.1/regexec.c:9200-9206`:

```c
reginfo->poscache_maxiter
    =    (reginfo->strend - reginfo->strbeg + 1)
       * (FLAGS(scan)>>4);
/* possible overflow for long strings and many CURLYX's */
if (reginfo->poscache_maxiter < 0)
    reginfo->poscache_maxiter = I32_MAX;
reginfo->poscache_iter = reginfo->poscache_maxiter;
```

`regexp.h:839-840` declares both fields `I32`. The multiply happens in `I32`
before the negative-only clamp, so a positive wrap is not detected. With the
CNA's 286331153-byte subject and 15 participating WHILEM nodes,
`(286331153 + 1) * 15 = 4294967310 = 2^32 + 14` stores as **14**. The cache
size at `regexec.c:9211` is `(14 + 7)/8 = 2` bytes, allocated `Newxz` at
`:9222` (or `Renew` at `:9215`). Fix `54cf3d4` changes the fields to `STRLEN`,
computes `len` in `STRLEN`, and refuses to enable the cache unless
`len < (STRLEN_MAX - 7)/n` (`v5.45.2/regexec.c:9243-9254`,
`v5.45.2/regexp.h:842-843`). Fix `568e6fd` first makes the countdown
non-negative (`== 1` / `== 0` rather than post-decrement / `< 0`), a prerequisite
for the unsigned type.

Consequences, both from affected raw bytes:

- **OOB read.** `regexec.c:9235-9240` computes
  `offset = (FLAGS(scan)&0xf)-1 + (locinput - strbeg) * (FLAGS(scan)>>4)`,
  divides by 8, and reads `info_aux->poscache[offset]`. With a 286 MB subject
  and n=15 the real match position multiplies by 15, so the read index is on
  the order of 10^7–10^8 against a 2-byte allocation.
- **OOB write.** `CACHEsayNO` at `:6504-6507` performs
  `poscache[ST.cache_offset] |= ST.cache_mask;`, with `ST.cache_offset` and
  `ST.cache_mask` stored at `:9247-9248` from the same wrapped geometry. It is
  invoked at `:9287`, `:9297`, `:9321` on WHILEM failure paths. This is a
  **single-bit OR** at an attacker-influenced index, not a chosen-byte write;
  do not claim byte control.

Source-only stable-branch observation: raw `v5.44.0/regexec.c:9136-9142`
contains the identical `I32` multiply and negative-only clamp, and
`v5.44.0/regexp.h:833-834` declares `I32` fields. This is a local source
observation, not a CNA version-range statement; fixed stable tags and distro
backports (e.g. USN-8736-1) were NOT verified.

## Arithmetic reproduction (no runtime involved)

`(286331153 + 1) * 15 = 4294967310`; `4294967310 mod 2^32 = 14`.
`I32_MAX = 2147483647`, so the `poscache_maxiter < 0` clamp at `:9204` does
not fire. `(14+7)/8 = 2`. The CNA narrative and the raw arithmetic agree.

## Honest rung-4 feasibility assessment

- **Rung 1 (reproducible trigger): plausible and cheap in-process.** A 286 MB
  subject plus a pattern with 15 participating WHILEM nodes should wrap the
  count; the cache activates after only 14 counted WHILEMs. The exact pattern
  shape that yields 15 participating nodes is UNKNOWN from the advisory; it
  must be derived locally (candidate: nested quantified groups such as 15
  nested `((a+)+)` shapes, counted with `use re 'debug'` / debugger inspection
  of `FLAGS(scan)>>4`). No published PoC payload was found in the CNA record or
  oss-security text.
- **Rung 2/3: straightforward to observe.** An ASan build of 5.45.1 should
  report the heap-buffer-overflow read at `regexec.c:9240` and the single-bit
  write at `:6506`; a 5.45.2 control should keep the cache disabled. 286 MB of
  input and a highly backtracking pattern are the only cost.
- **Rung 4: bounded but real.** The write is a one-bit OR at an index derived
  from match position × node count; a bit flip in heap metadata or an adjacent
  object is a plausible corruption primitive, but there is no published
  chosen-byte or pointer-control demonstration. Any claim of byte control would
  overstate the evidence.
- **Wire reachability: UNKNOWN.** The CNA says "a caller that matches an
  attacker-controlled subject of this size against a pattern of this shape" —
  it does not identify a network-facing caller, and CISA scores the issue AV:L.
  Finding a specific server that applies a fixed pattern to a 286 MB attacker
  body is open work, not an established property of this bug.
- **Rung 5: no claim.** No command execution path is evidenced.

Ranking rationale: deterministic arithmetic + published fix bytes + huge
subject size that is still cheap on this host make rungs 1–3 unusually cheap.
Against it: single-bit rather than chosen-byte write, no published trigger
pattern, and UNKNOWN wire reachability. Ranked above MsQuic (deferred) and
below no other unadmitted candidate; netty is already admitted and must not be
duplicated.

## Cheapest local experiment that moves it up a rung

1. Build pinned 5.45.1 with `./Configure -des -DDEBUGGING
   -Doptimize='-g -O1 -fsanitize=address'` in `lab/frontier/perl2shell/`,
   loopback only, no service started.
2. Generate a 286331153-byte byte string; derive a pattern with exactly 15
   participating WHILEM nodes using a debug build's WHILEM/`FLAGS(scan)>>4`
   observation. Run one `m//` against the subject under ASan; capture the full
   report and the ASan trace hash (exclude PID/address/path).
3. Repeat on a 5.45.2 ASan build with the same input; expect the overflow
   guard to leave `poscache_maxiter == 0` and no ASan report. Record a negative
   result honestly if the expected pattern cannot be derived.
4. Only after rung 3: search for a real consumer that feeds network bytes to a
   fixed shape of this regex; absent one, keep the finding at harness grade.

No build, no traffic and no window were created for this brief.
