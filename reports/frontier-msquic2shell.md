# MsQuic2Shell — frontier brief: CVE-2026-62815 (QUIC path-promotion stale-pointer UAF)

**State: HEAD of the unadmitted queue, DEFERRED by the operator; RUNG 0
(no local build, no packets, no window).** Scouted and source-pinned read-only
in W87 (2026-11-21). Not admitted; the operator owns admission. Operator
correction #1158 (2026-11-21 21:37Z) makes MsQuic the deferred head after
Apache2Shell (admitted 2026-11-20) and Perl (admitted 21:34Z, #1157) left the
queue. Nothing here is an independent acceptance — the witness re-runs any
published claim. Chosen for a clean one-line fix, paired tagged source pins
and a server-facing unauthenticated RCE claim, not demonstrated mechanics.

## Verified ground truth

- **Claim sources (primary, read this wake):**
  - MITRE CVE API `https://cveawg.mitre.org/api/cve/CVE-2026-62815`
    (CNA Microsoft, published 2026-08-11T17:04:30.645Z, updated
    2026-11-19T22:17:01.881Z, CWE-416,
    `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C`, 9.8):
    "Use after free in Microsoft QUIC allows an unauthorized attacker to
    execute code over a network." CISA ADP SSVC: exploitation none,
    automatable yes, technical impact total. The CPE applicability block lists
    only Windows products (Server 2022/2025, Win11 23H2/24H2/25H2/26H1 build
    cutoffs); it does not enumerate the OSS package versions.
  - GitHub advisory `https://github.com/microsoft/msquic/security/advisories/GHSA-92f5-vc22-8j33`
    (published 2026-08-11 by `guhetier`). Packages
    `Microsoft.Native.Quic.MsQuic.OpenSSL` and `.Schannel`: affected `< 2.5.10`,
    patched `2.5.10, 2.4.19`. "New network path creations and removals
    triggered by incoming packets can lead to a pointer invalidation." Impact:
    "An unauthenticated attacker could exploit this vulnerability by sending a
    specially crafted packet ... execute code on the target system. No
    authentication or user interaction is required." CVSS 4.0
    `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` = 10.0.
    Patch identified as commit `e0f55b5`.
  - MSRC vendor advisory URL
    `https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62815` is
    recorded from the MITRE reference; its page body was **not** retrieved —
    do not treat it as independently read.
  - Fix commit `https://github.com/microsoft/msquic/commit/e0f55b5fdc9fff0b4465976d066ebd22fb7e2b3b`
    (Guillaume Hetier, patch header `Date: Tue, 11 Aug 2026 11:26:45 -0700`),
    subject "Fix path migration UAF: guard path promotion with InUse check
    (#6217)". Its own description names the causal chain: `QuicConnReplaceRetiredCids`
    during NEW_CONNECTION_ID processing calls `QuicPathRemove`, which removes
    the path; `QuicConnRecvPostProcessing` later promotes that same path via
    the stale `*Path` pointer without checking validity.
- **Claimed primitive:** a stale `QUIC_PATH*` is passed to `QuicPathSetActive`,
  which swaps whole `QUIC_PATH` structs between the stale slot and
  `Connection->Paths[0]` — corrupting connection path state (active flag,
  destination CID, route, allowance). "Execute code over a network" is the
  vendor/GHSA **claim** (CISA exploitation: none); no public PoC, no allocator
  layout or downstream control-flow analysis was found. RCE stays a labeled
  claim, not an observed fact.

## Pinned source (raw bytes, verified this wake)

- Vulnerable tag archive `msquic-v2.5.9.tar.gz`, sha256
  `ccf4170e96f834f6c417ea5e0039bbd67d8bb40a42b5d3966ef75f48f5f5fa38`.
- Fixed tag archive `msquic-v2.5.10.tar.gz`, sha256
  `b77be2c956bee31809eb6138064b6471d7f697a7226d1b9faddf01df36b166d5`.
- Fix patch `fix-e0f55b5.patch`, sha256
  `c74bfda59f7585223b9d92188d2a1e70764b8dcdd2dc16e17ae8b2ab9b8e61af`.
- Fetched from GitHub tag archives and the commit `.patch` URL;
  `lab/frontier/msquic2shell/src/SHA256SUMS` records all three and
  `sha256sum -c` passed 3/3. GitHub auto-generated archives have no published
  hash sidecar; these are our own digests. Tag objects via read-only
  `git ls-remote`: v2.5.9 `87b53085d76bd7920d490a6f226c9999b6614d14`,
  v2.5.10 `9ff06b71fd4b4d5258361598ada5b24cbc1beb20`, v2.4.19
  `583e7d5b509bb0bfa3518482d98879b6eda41ad0`.
- Raw hunk in `src/core/connection.c`, `QuicConnRecvPostProcessing`:

  v2.5.9 file line 5516:
  ```
      if (Packet->HasNonProbingFrame &&
          Packet->NewLargestPacketNumber &&
          !(*Path)->IsActive) {
          QuicPathSetActive(Connection, *Path);
          *Path = &Connection->Paths[0];
  ```
  v2.5.10 file line 5534:
  ```
          !(*Path)->IsActive && (*Path)->InUse) {
  ```
  The GitHub patch's `@@ -5572,7 +5572,7 @@` is default-branch numbering;
  the release-tag line numbers above are authoritative for these pins.

## Source-bound mechanism read (not a runtime observation)

- `src/core/path.c:51-86` `QuicPathRemove` does **not** call `free()` on a heap
  object: it shifts `Connection->Paths[Index+1..PathsCount-1]` down by one,
  decrements `PathsCount`, and sets `Paths[PathsCount].InUse = FALSE`. The bug
  is an embedded-array slot invalidation (CWE-416 as claimed by Microsoft), not
  a malloc-object UAF. Correct the scout's "freed path" framing.
- `src/core/path.c:263-291` `QuicPathSetActive`:
  `QUIC_PATH PrevActivePath = Connection->Paths[0]; ...;
  Connection->Paths[0] = *Path; *Path = PrevActivePath;` — a whole-struct swap.
  If `*Path` aliases a shifted-out or cleared slot after `QuicPathRemove`, the
  swap writes the old active path into a path slot that no longer owns it and
  copies the stale/alien path into `Paths[0]`. `src/core/path.h:55` declares
  `BOOLEAN InUse : 1;`. The one-line fix makes promotion conditional on the
  path still being in use.
- Trigger shape from the fix's own description: within one receive cycle, a
  NEW_CONNECTION_ID frame whose CID replacement retires a path (path removal),
  followed by a non-probing frame on that path with a new largest packet
  number (promotion condition). Whether a real peer can satisfy this ordering
  is **UNKNOWN** without a build and traffic.

## Rung-4 feasibility (honest)

- **Standing:** rung 0. No build, no harness, no packets. The trigger is
  protocol-state work rather than memory-layout guesswork, which is good, but
  the corruption is an in-object struct swap: ASan will **not** flag it as a
  heap UAF because every access stays inside `Connection->Paths[]`. Rung 3
  (sanitizer-confirmed corruption) needs a logical-state detector — an assert
  or canary on path ownership/CID↔path consistency — not a stock ASan run.
  That is a real cost and the main reason this ranks below Exim's one-byte
  write into freed heap metadata.
- **Control goal:** show a chosen stale `*Path` causing `Paths[0]` to receive a
  non-active/alien path, then measure what downstream consumer uses that slot
  (send path, loss detection, CID mapping). Code execution is a claim only.
- **Cheapest local experiment:** build only the `msquic` core + interop server
  target at v2.5.9 with debug assertions, run a loopback QUIC server, and drive
  a controlled client that sends a new connection ID retiring a path followed
  by a non-probing frame on the old path. Add a temporary canary/assert around
  `QuicPathSetActive` to observe the stale-slot swap; repeat against v2.5.10 as
  the fixed control (guard should suppress it). No public PoC exists, so the
  packet sequence must be constructed — that is the experiment's risk.
- **What would change the ranking:** a deterministic loopback trace showing
  the stale-path swap in v2.5.9 and its absence in v2.5.10; or evidence that
  `QuicPathRemove` cannot be reached before post-processing from a real peer.

## Alternates and ranking (W87, historical)

At write time Exim was first and this brief second. Exim, Netty, WAMR,
Apache2Shell and Perl have since been admitted; BIND 9 remains SCREENED LOW
(#1158). MsQuic is now the head of the unadmitted queue, deferred by the
operator. The entries below are preserved reconnaissance, not current ranks.

1. **Exim CVE-2026-45185** (W86 pin) — first at write time (since admitted):
   one-byte write into freed heap metadata with a public escalation narrative.
2. **MsQuic CVE-2026-62815** (this brief) — new, second: strongest claim and
   cleanest pin, but in-object corruption needs a custom detector and a
   hand-built packet sequence.
3. **Apache httpd CVE-2026-63292** — `mod_vhost_alias` stack overflow, plain
   >8192-byte Host header when `VirtualDocumentRoot` uses a hostname specifier
   and `LimitRequestFieldSize` is raised; affected 2.4.0–2.4.68, fixed 2.4.69,
   hardening commit `a34cc81def40f5cee30c41f6c3eeffb03b4c75eb`, tarballs 2.4.68
   `ed9a9d4500fb48bb28eaffb3ba71d06ccf86d498fa13ab9f781da010cc488498` /
   2.4.69 `c551b9861e26f146f57e1b1765e69c89a60b3db0ec252ccab0d36283487016bb`
   (scout-reported, not re-hashed here). Easiest trigger, but the code-exec
   wording is vendor-hedged ("potentially") and CISA scores DoS-only; a follow-on
   boundary bug, CVE-2026-109163, fixed in 2.4.71, warns the boundary is subtle.
4. **Apache httpd CVE-2026-119618** — `mod_http2 assign_headers()` CWE-362 race,
   one-line wrong-table write (`req->headers` → `r->headers_in`), affected
   2.4.55–2.4.70, fixed 2.4.71, commit `824beab9b9424d6cfb29595248fdbf6c3dddeab1`.
   Natural HTTP/2 listener, trivial pin, but converting a thread race into a
   stable controlled write is the hard part; CISA exploitation none.
5. **ATS CVE-2026-58154** (W85 pin) — post-decrement read with `input.data()-1`
   only; contiguous IO views may make the adjacent byte in bounds.
6. **BIND 9 CVE-2026-3593 — SCREENED LOW.** Strongest byte pin of the set
   (fix `637a127f6506db4260584ce3840fb4a6fde9112a`, `lib/isc/netmgr/http.c`
   adds `isc_buffer_initnull(&sock->h2->wbuf);`, v9.20.22→v9.20.23) but it is a
   UAF **read** with no write/chosen-byte primitive, and the reporter
   explicitly withdrew the code-execution claim in ISC issue GL #5755
   ("A UAF read does not enable code execution"; ISC CNA I:N). RCE line in
   Red Hat's ADP is a CLAIM. Not worth a rung-5 attempt.

KnotResolver2Shell CVE-2026-66374 is already admitted and owned by its own
mind; do not duplicate. Exclusions and the full recon record are in the W87
scout payload and the tape.

## Status

HEAD OF UNADMITTED QUEUE (DEFERRED), RUNG 0. No build, no network traffic to
any target, no PoC run, no window. Operator owns admission under standing #6;
witness owns independent replay. All bytes and claims live in
`lab/frontier/msquic2shell/{PROVENANCE.md,src/SHA256SUMS}` and this brief.
