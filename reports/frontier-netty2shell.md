# NettyTcnative2Shell — frontier brief: CVE-2026-116539 (ring-buffer wrap → unbounded native heap write)

**State: RANKED CANDIDATE / RUNG 0 (no local build, no PoC run, no wire traffic, no window).**
Scouted and source-pinned read-only in W88 (2026-11-21). Not admitted; the
operator owns admission under standing #6. Nothing here is an independent
acceptance — the witness re-runs any published claim. This is a **new**
candidate, ranked **first among unadmitted candidates** (Exim is now admitted;
MsQuic remains deferred at #2). It is chosen because the maintainer published a
deterministic trigger, the fix is one line, the tag pair and patch are pinned
from primary sources, and the primitive is a native out-of-bounds **write** —
not because any local bytes have been observed by this plant.

## Verified ground truth

- **Claim sources (primary, read this wake):**
  - Maintainer advisory `GHSA-gf9q-9mg7-g5qh` at
    `https://github.com/netty/netty-tcnative/security/advisories/GHSA-gf9q-9mg7-g5qh`
    (published 2026-10-26 by `normanmaurer`, reporter `@August829`). Packages
    `io.netty:netty-tcnative` and `io.netty:netty-tcnative-boringssl-static`:
    affected `<= 2.0.83.Final`, patched `2.0.84.Final`. CVSS 3.1
    `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = 8.1. Weaknesses
    CWE-191 (integer underflow), CWE-787 (OOB write), CWE-125 (OOB read).
    The advisory embeds a complete PoC (`FindingRingBuffer_Overflow.java`),
    a 4-step trigger table, a verbatim JVM crash report and a native stack.
  - Aggregated advisory `https://github.com/advisories/GHSA-22qq-f4wc-4vfx`
    (NVD-sourced) and Debian tracker `https://security-tracker.debian.org/tracker/CVE-2026-116539`
    (Debian bug 1152301): "Remote TLS peers can drive handshake, renegotiation,
    or post-handshake messages into this buffer, triggering an out-of-bounds
    memcpy that crashes the JVM process." Debian lists source package
    `netty-tcnative` 2.0.28-1 vulnerable, sid 2.0.85-1 fixed.
  - Fix commit
    `https://github.com/netty/netty-tcnative/commit/92dd66fd1243d85c05a61288f96367a70260b6b8`
    (Norman Maurer, 2026-08-07, parent `e28f849eff0f`), subject "Correctly
    handle wrap around in ring buffer used internally to buffer application
    data", +3/−1 in `openssl-dynamic/src/main/c/ssl.c`. Its own message says a
    negative value cast to `size_t` becomes close to `SIZE_MAX` and is used in
    `memcpy`, causing a heap buffer overflow; likelihood rises when
    `nonApplicationBufferSize` is very low.
  - The CVE record (`https://cve.org/CVERecord?id=CVE-2026-116539`) and NVD
    were located in search results but their full bodies were not retrieved
    this wake; the version range, fix commit and mechanism above come from the
    maintainer and Debian primary pages, which were read.
- **Claimed primitive:** `memcpy(&bioUserData->nonApplicationBuffer[startIndex],
  in, (size_t) writeChunk)` where `startIndex >= nonApplicationBufferSize` and
  `writeChunk` is a negative `jint` cast to a length near `SIZE_MAX` — an
  effectively unbounded heap write — plus a companion OOB read of
  `&in[writeChunk]`. The maintainer's **demonstrated** consequence is a hard
  process crash (SIGBUS in `memmove`) on the published harness. Confidentiality
  and integrity impact are CVSS **potential**, not observed; no RCE is claimed
  in the maintainer advisory. Keep "RCE" out of any accepted wording.

## Pinned source (raw bytes, verified this wake)

- Vulnerable tag archive `2.0.83.Final.tar.gz`, sha256
  `f6ae09cf544397edd33ffd23affd7cad09059d757b1510d4d909539cadbcb335`.
- Fixed tag archive `2.0.84.Final.tar.gz`, sha256
  `cb419d0132a970338087a677a82dc4e5e3a4837c1da6ff1f15bd1a0ba94ccef0`.
- Fix patch `fix-92dd66f.patch`, sha256
  `b51333461dfbbc261f9e8463a1f602482de9c59efcafade677caf0431a88a7ec`.
- Fetched from the GitHub tag archives and the commit `.patch` URL;
  `lab/frontier/netty2shell/src/SHA256SUMS` records all three and
  `sha256sum -c` passed 3/3; both `tar tzf` listings validate. Tag objects via
  read-only GitHub API: `netty-tcnative-parent-2.0.83.Final`
  `cfc91e9f5e26a269c68db343ca8c698233dfa7c2`, `netty-tcnative-parent-2.0.84.Final`
  `bce36b6906f2fbe35b3bf90e9d1bc99e976e04bd`; fix commit SHA verified via the
  same API. Auto-generated archives have no published hash sidecar; these are
  our own digests.
- Raw hunk in `openssl-dynamic/src/main/c/ssl.c`, `tcn_write_to_bytebuffer`:

  v2.0.83.Final file line 199:
  ```
      startIndex = bioUserData->nonApplicationBufferOffset + bioUserData->nonApplicationBufferLength;
      writeChunk = bioUserData->nonApplicationBufferSize - startIndex;
  ```
  v2.0.84.Final file lines 199–201:
  ```
      // use modulo to account for wrap around the ring buffer that buffers data.
      startIndex = (bioUserData->nonApplicationBufferOffset + bioUserData->nonApplicationBufferLength)
                                            % bioUserData->nonApplicationBufferSize;
      writeChunk = bioUserData->nonApplicationBufferSize - startIndex;
  ```
  The patch hunk header `@@ -196,7 +196,9 @@` matches the raw release-tag
  numbering. The advisory's inline line numbers (e.g. "ssl.c:187-213",
  "ssl.c:208", "ssl.c:146-151") are 12–28 lines off from these tag bytes;
  use the raw hunk and the function names as authoritative.

## Source-bound mechanism read (not a runtime observation)

- `tcn_flush_sslbuffer_to_bytebuffer` (raw v2.0.83.Final from line 138) is the
  partially-correct sibling: on a drain wrap it computes
  `newoffset = writeAmount - writeChunk`, writes the two chunks, assigns
  `nonApplicationBufferOffset = newoffset`, and resets the offset to 0 when
  length reaches 0. So the offset is bounded on the **drain** side.
- `tcn_write_to_bytebuffer` (raw line 171) has no equivalent renormalization.
  With `nonApplicationBufferSize = 10`, the maintainer's sequence is confirmed
  by the raw code: write 6 → `offset=0,length=6`; partial flush 4 →
  `offset=4,length=2`; write 5 → `startIndex=6, writeChunk=4`, wrap branch
  taken, `offset` left at 4, `length=7`, so `offset+length=11 > size=10`;
  write 1 → `startIndex=11, writeChunk=-1`, wrap branch taken again because
  `1 > -1`, reaching the sink at raw lines 207–209:
  ```
  memcpy(&bioUserData->nonApplicationBuffer[startIndex], in, (size_t) writeChunk);
  memcpy(bioUserData->nonApplicationBuffer, &in[writeChunk], (size_t)(writeAmount - writeChunk));
  ```
  First call: OOB destination pointer plus `SIZE_MAX`-near length. Second call:
  `&in[-1]` OOB read. The allocation is `OPENSSL_malloc` in `SSL.bioNewByteBuffer`;
  this is a genuine cross-object heap write, not an in-object field corruption.
- The buffer is the library's "non-application" ring: it queues bytes OpenSSL
  must emit while the BIO is configured as a read source (handshake,
  renegotiation, TLS 1.3 post-handshake). The documented condition is at
  `openssl-classes/src/main/java/io/netty/internal/tcnative/SSL.java:250-251`.
  The vulnerable C function is backend-independent (`BIO_java_bytebuffer`),
  so both OpenSSL and BoringSSL artifacts share it.

## Rung-4 feasibility (honest)

- **Standing:** rung 0. No build, no harness, no PoC run, no loopback traffic.
  The published reproduction is a **JNI-harness** trigger: four calls to
  public methods `SSL.bioNewByteBuffer`, `SSL.bioWrite`, `SSL.bioSetByteBuffer`,
  `SSL.bioFlushByteBuffer` on an unmodified from-source OpenSSL 3.6.3 build
  (macOS/arm64, Zulu 25, `-Xint`). It faults the lab process deterministically
  (3/3 runs) with a native stack through `bio_java_bytebuffer_write` →
  `BIO_write` → `netty_internal_tcnative_SSL_bioWrite`; that is a credible
  rung-1 input, but it is not wire input and would remain a harness-grade
  marker if reproduced here.
- **Wire-only reachability is UNKNOWN.** The maintainer explicitly states the
  PoC "does not itself demonstrate deriving the exact trigger purely from
  unmodified TLS wire bytes against a specific downstream integration (e.g.
  Netty's engine)"; it depends on the integrator's `nonApplicationBufferSize`
  and on partial drains driven by momentarily-small outbound buffers. No
  attacker-crafted handshake content is needed in theory — repeated
  renegotiation and unlucky timing are the suspected route — but that route is
  a claim to test, not a measured path. This is the main rung-5 gate.
- **Control goal:** with the 10-byte configuration, confirm the negative
  `writeChunk` and OOB pointer in the vulnerable build under a debugger or ASan,
  then show the fixed build taking the modulo path. Because the overflow length
  is `SIZE_MAX`-near, the first bytes written after the ring buffer are chosen
  input bytes — a promising rung-4 chosen-byte-at-chosen-offset experiment —
  but a real allocator layout and a survivable write window must be measured;
  the published observation is a crash, not pointer control.
- **Cheapest local experiment:** build the `openssl-dynamic` native library at
  v2.0.83.Final against a Linux OpenSSL with a small JDK, port the advisory's
  four-step JNI harness to Linux, run under ASan to capture the exact
  `heap-buffer-overflow WRITE` at the sink, and repeat at v2.0.84.Final as the
  fixed control (no report). This is a harness-level rung-1/rung-3 step only;
  a separate loopback Netty-engine experiment with repeated renegotiation is
  required before any wire/rung-5 wording.
- **What would change the ranking:** an observed ASan WRITE in the 2.0.83.Final
  harness absent in 2.0.84.Final; or a wire-only loopback negotiation that
  drives the same sink against an unmodified engine. Conversely, evidence that
  downstream integrators always size the ring buffer generously enough to make
  the wrap unreachable would drop this candidate sharply.

## Alternates and ranking (this wake)

1. **Netty netty-tcnative CVE-2026-116539** (this brief) — first unadmitted:
   published deterministic trigger, one-line fix, clean tag pins, native OOB
   write with an OOB read sibling. Wire-only reachability is the open gate.
2. **MsQuic CVE-2026-62815** (W87 pin) — second, deferred by the operator:
   clean pin but in-object struct swap needing a custom detector and a
   hand-built QUIC packet sequence.
3. **Perl CVE-2026-15534 / CVE-2026-8376** — language-runtime OOB reads/writes
   with CPAN fixes (5.40.5-RC1 / 5.42.3-RC1 lines); promising class, **not
   pinned** this wake and network reachability unexamined. Next-search item.
4. **OpenLDAP LMDB CVE-2026-22185** — heap buffer underflow in `readline()`,
   fixed before commit `8e1fda8`, version 0.9.14-before-0.9.34; tracker frames
   it as DoS/information disclosure, not an RCE/write primitive to book time on.
5. **Apache httpd CVE-2026-119618** (mod_http2 race) and **gdbserver
   CVE-2026-121997** (QTDPsrc `hex2bin` overflow) — re-screened this wake and
   still not chosen: the former is hard to stabilize (W87) and the latter still
   reports UNKNOWN affected/patched versions and no fix bytes, so the existing
   gdbserver HOLD stands.

Excluded without new work: NGINX CVE-2026-123633/123634/113425 and Node.js
CVE-2026-123828 (other minds' lanes); Java4Shell/OpenJDK CVE-2026-114938,
Valkey, MS SQL, Git, FreeRADIUS, C-Kermit and BZFlag (already screened or
admitted). Full recon lives in the W88 scout payload and the chat tape.

## Status

RANKED CANDIDATE / RUNG 0. No build, no traffic, no PoC run, no window.
Operator owns admission under standing #6; witness owns independent replay.
All pins live in `lab/frontier/netty2shell/{PROVENANCE.md,src/SHA256SUMS}` and
this brief.
