# Frontier brief — Knot Resolver DoQ `pers_inbuf` size drift OOB write (KnotResolver2Shell)

**Status 2026-11-26 ~05:2xZ: research closed at the documented ceiling.**
Admitted 2026-11-21 ~18:0xZ by the operator under standing approval #6
(similar-things mandate); hash pins re-verified 3/3 OK at admission. Final
grade: rung 3 ESTABLISHED (witness W87), rung 4 witness-ESTABLISHED (#1138),
rung 5 author-observed at the labeled ASLR-off / gdb-parent / jemalloc-debug
scope and witness W114 MIXED; ASLR-on/stock chosen control UNKNOWN. The
wake-23 closure, its closed negative lanes and the reopen triggers are in
`reports/knotresolver2shell-rung3.md`; the `again 12h` chain is retired.
Ranked #1 of four new server-side candidates screened (Apache Traffic Server
CVE-2026-58154, BIND 9 CVE-2026-3593, Exim CVE-2026-45185 below). The
claim-source notes below are the admission record; lab results supersede them.

## Verified ground truth (claim sources, 2026-11-21)

- **Advisory**: CVE-2026-66374, MITRE record published 2026-07-25T00:28:34Z,
  updated 2026-07-27T14:36:16Z: "Knot Resolver before 6.4.1 allows remote code
  execution via a heap-based buffer overflow in the DoQ (DNS-over-QUIC) receive
  path." CVSS 3.1 8.1 HIGH
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:L`, CWE-1284 in the CVE record
  (the researcher calls it CWE-787). Records:
  `https://cveawg.mitre.org/api/cve/CVE-2026-66374`,
  `https://www.cve.org/CVERecord?id=CVE-2026-66374`.
- **Researcher follow-up**: oss-sec #234, 2026-07-24 08:43:38 +0200, raw-read at
  `https://seclists.org/oss-sec/2026/q3/234`: the researcher says the vendor
  did not request a CVE and asks for one — consistent with MITRE creating the
  record on 2026-07-25.
- **Researcher report**: oss-sec 2026-07-23 by Przemyslaw Frasunek, raw-verified
  at `https://seclists.org/oss-sec/2026/q3/226` (also linked by the CVE as
  `https://openwall.com/lists/oss-security/2026/07/23/6`). Claims: affected
  6.3.0 (verified `6.3.0-cznic.1` on Debian 12), fixed 6.4.1 released
  2026-07-22; unauthenticated single QUIC connection; six STREAM frames drive
  `pers_inbuf` through five jemalloc size classes and then a controlled ~814
  byte OOB write into the neighbouring slot; grooming puts a libgnutls cleanup
  handler there, whose `flag`, `fn` and `arg` are overwritten for an indirect
  call with controlled RIP and RDI at teardown; PoC routes to `system()` with
  ASLR **disabled**; ~7/8 RIP-control attempts, full `system()` less reliable
  and retried across worker respawns. With ASLR on, an information leak would
  additionally be required — existence UNKNOWN. PoC (not run here):
  `https://github.com/venglin/knot-doq`. Reference environment: Debian 12,
  glibc 2.36, knot-resolver6 6.3.0-cznic.1~bookworm, libgnutls30
  3.7.9-2+deb12u7.
- **Vendor**: 6.4.1 release notes 2026-07-22, raw-verified at
  `https://www.knot-resolver.cz/documentation/v6.4.1/NEWS.html`: "DNS-over-QUIC
  (DoQ) had severe issues, allowing even RCE"; DoQ serving is a beta feature
  since 6.2.0 (same notes). Fixed versions 6.4.0 → 6.4.1, no floating branch.
- **Fix**: commit `7eb2e11810966323ed7c2385b8922eb8d57c46d2` ("daemon/doq:
  improve recv function", +60/−17 in `daemon/quic_conn.c`), patch bytes
  raw-verified at
  `https://github.com/CZ-NIC/knot-resolver/commit/7eb2e11810966323ed7c2385b8922eb8d57c46d2.patch`.
  A related commit `2e18114ade8ce8781c1d7e37ca803dc5136d2802` ("daemon/quic:
  remove assert and handle partial query data with FIN safely") was identified
  by the scout within the 6.4.0...6.4.1 range but its bytes were NOT read this
  wake. The 6.4.1 tarball already contains a more evolved form of the guard
  than this patch, so the tag is authoritative for the fixed side.
  Tag containment verified from the GitHub compare API
  `https://api.github.com/repos/CZ-NIC/knot-resolver/compare/7eb2e11810966323ed7c2385b8922eb8d57c46d2...v6.4.1`:
  `status: ahead`, `ahead_by: 11`, `behind_by: 0`, merge base is the fix commit
  itself; `2e18114a…` is the first commit after it.
- **Pins**: two tagged tarballs plus the patch, exact SHA-256 in
  `lab/frontier/knotresolver2shell/src/SHA256SUMS`; URL/digest table in
  `lab/frontier/knotresolver2shell/PROVENANCE.md`. Vulnerable is tagged
  **v6.4.0** (`e8e771de…`), fixed is tagged **v6.4.1** (`20eb8b31…`); the CVE's
  "before 6.4.1" range is broader than the two tags provisioned here.

## Source-bound mechanism (raw bytes in the pinned tarballs)

From the extracted `daemon/quic_conn.c` of each tag (only this file was
extracted; no build was attempted):

- Vulnerable 6.4.0 `kr_recv_stream_data_cb()` at `:102–108`: when
  `wire_buf_free_space_length(&stream->pers_inbuf) < datalen`, the code
  `realloc`s to `wire_buf_data_length(...) + datalen` but then does
  `stream->pers_inbuf.size += datalen`. The tracked `size` (capacity) and the
  realloc target follow different accounting; across frames `size` drifts above
  the real allocation while `wire_buf_consume()` advances the data position.
- Vulnerable `:119–127`: `memcpy(wire_buf_free_space(&stream->pers_inbuf), data,
  datalen)` at `:120` (offset 0) and at `:124` (offset != 0, skip the 2-byte
  size prefix) writes through the inflated free-space computation; `:125-126`
  also rewrites the stored length prefix. No offset/continuity check precedes
  either copy, and the FIN branch at `:133–136` queues the stream without a
  prefix-vs-payload consistency check. That is the source shape matching the
  reported OOB write; the actual drift arithmetic and consumer effect are NOT
  observed in this lab.
- Fixed 6.4.1 `:158–161` rejects a non-contiguous offset; `:166–203` parses a
  split 2-byte query-size prefix explicitly, computes `qsize_prefixed` and
  grows capacity with `wire_buf_reserve()`; `:216–224` checks remaining free
  space and goes to `malformed` instead of copying; `:229–238` checks that the
  declared query size equals the received payload length on FIN. The
  `pers_inbuf.size += datalen` line is absent from pinned 6.4.1. The fix patch
  above shows the intermediate form (`size = qsize_prefixed`,
  `kr_require(free_space >= datalen)`); both forms bound the copy.

## Rung-4 feasibility and ranking

This is the strongest new candidate found this wake on the evidence ladder:
an unauthenticated server-side listener, a heap OOB **write** with an
advisory/vendor RCE claim, a source-bound accounting bug in the exact receive
callback, a tagged fixed release, and a published network PoC with a claimed
controlled function-pointer overwrite. It outranks the three alternates below
on claimed impact. Caveats that keep it honest: DoQ must be enabled (beta,
non-default); the write destination and the claimed RIP/RDI control depend on
jemalloc size classes, the exact gnutls version and connection grooming; the
published end-to-end RCE needs ASLR off (this plant's standing approval #3
permits labeled ASLR-disabled lab runs, but that is not a stock-build claim);
the PoC was not run and nothing was built here. Rung 0 until a loopback build
produces bytes.

Ranking of the other three (scout claims, primary sources noted but not
independently byte-verified this wake):
1. Apache Traffic Server CVE-2026-58154 — pre-auth HTTP MIME obs-fold OOB
   write, fixed tags 9.2.15/10.1.4, master fix commit
   `f4561a945ac52010a598e0cd19b12d058044c3d2` present in raw 10.1.4
   `src/proxy/hdrs/MIME.cc`; large build, byte-level control UNKNOWN.
2. BIND 9 CVE-2026-3593 — DoH/HTTP2 SETTINGS UAF, fixed 9.20.23/9.21.22, fix
   commit `e33ff6bb0ac7110ea2b64ba5adde0fb72200f37d`; the only code change is
   `isc_buffer_initnull(&sock->h2->wbuf)`, so the stale-buffer consumer and any
   controlled write are UNKNOWN.
3. Exim CVE-2026-45185 — pre-auth TLS close_notify during BDAT leaves a
   one-byte write into a freed buffer, fixed tag 4.99.3
   (`040c1ce6889f435206677ed532c9a4185cf0bcaf` / original
   `f7387b3ba8944791d6ed8a3e4bf8f6f4239c74d1`), config needs GNUTLS+STARTTLS
   +CHUNKING; grooming/RCE claims UNKNOWN. Smaller build than Knot/ATS/BIND,
   so a useful fallback if Knot's QUIC toolchain proves expensive.

## Research closed at documented ceiling (wake 23, 2026-11-26 ~05:2xZ)

The admission experiment was completed: pinned tagged 6.4.0/6.4.1 builds, a
loopback-only DoQ listener and the six STREAM frames produced the ASan OOB
WRITE and the clean fixed-side control (wakes 1-5), chosen bytes at a live
`gnutls_deinit` argument (wake 6, witness #1138), and a benign command at the
labeled ASLR-off scope (wake 12, witness W114 MIXED). Every later ASLR-on
route tested is negative on the sampled objects: full-span pointer inventory,
libgnutls PLT retarget, 3-byte partial-overwrite entropy, fixed-address PIE
route, and same-library pointer arithmetic. No information leak exists on the
wire. Chosen control under stock ASLR stays UNKNOWN and this lane is closed;
`reports/knotresolver2shell-rung3.md` records the exact conditions and triggers.

## Scope and boundaries

All runs used 127.0.0.1 only; no external scanning, no host sysctl changes
(`kernel.randomize_va_space` stayed 2), and the wake-12 rung-5 attempt
disabled ASLR for the gdb inferior only — a labeled lab condition, not a
stock-build claim. No other plant's lane was touched. Unknowns stay UNKNOWN:
ASLR-on exploitability, whether the 6.4.1 fix covers every drift path
reachable from QUIC, and whether the sibling commits in the release range add
further needed checks.
