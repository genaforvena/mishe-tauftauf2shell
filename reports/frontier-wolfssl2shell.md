# Frontier brief — wolfSSL DTLS 1.3 ACK serialization overflow (WolfSsl2Shell)

**Status: frontier find, brief + harness COMPLETE (2026-11-21 ~15:25Z);
UNADMITTED, witness replay and operator admission pending. Rungs 1/2/3 are
ESTABLISHED on real, verbatim-pinned wolfSSL v5.9.0 built with ASan: rung 3 is
the ASan `WRITE of size 8` at `src/dtls13.c:2604`, rungs 1/2 run without
sanitizers. Rung 4 is INSTRUMENTED: chosen 64-bit epoch/seq values read back at
chosen offsets past a 31-byte output buffer in a staged non-ASan heap build. No
DTLS listener, real handshake record path, live neighbour object, pointer,
control-flow diversion or execution was observed — all stay UNKNOWN.**
13 PASS / 0 FAIL, trace
`sha256=fb6831dc85fe7afeaaf688ac519a49bccde954a03159211fb256247c1c7ac05d`.
Live two-pane window `wolfssl2shell` index 61 on the inner socket (to be
capture-verified when created). Fixed side is the normal tagged release 5.9.1.

## Verified ground truth (claim sources, 2026-11-21)

- **Advisory**: CVE-2026-6679, CNA wolfSSL Inc., published and updated
  2026-06-25. Title: "DTLS 1.3 ACK serialization heap buffer overflow via
  integer truncation". Description: a heap buffer overflow in the DTLS 1.3 ACK
  serialization path **before the connecting peer is authenticated**; integer
  truncation when computing the length of the ACK record-number list allocates
  an undersized buffer that is then overrun. Affected builds use DTLS 1.3,
  wolfSSL **5.4.0 through 5.9.0**; fix added in the **tagged 5.9.1 release**.
  CWE-190 (integer overflow), CWE-197 (numeric truncation), CWE-787 (OOB
  write). CVSS 4.0 8.8 HIGH, vector
  `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`. Credit: Nicholas
  Carlini (Anthropic). Records: `https://www.cve.org/CVERecord?id=CVE-2026-6679`,
  `https://cveawg.mitre.org/api/cve/CVE-2026-6679`,
  `https://github.com/advisories/ghsa-c9q2-5c67-xg9p`, vendor table
  `https://www.wolfssl.com/docs/security-vulnerabilities/`.
- **Fix**: PR `wolfSSL/wolfssl#10116` (`https://github.com/wolfSSL/wolfssl/pull/10116`,
  diff pinned) adds `#define DTLS13_MAX_ACK_RECORDS 512` and a
  `count >= DTLS13_MAX_ACK_RECORDS` early return in `Dtls13RtxAddAck`. The
  **released v5.9.1 is stronger than that PR diff**: `wolfssl/internal.h:5852-5859`
  defines `DTLS13_ACK_MAX_RECORDS 128` with a compile-time assertion it stay
  below `0xffff/16`; `src/dtls13.c:742` drops inserts when
  `seenRecordsCount >= 128`; the fixed `Dtls13WriteAckMessage` gained a
  `word16 recordsCount` argument with a `recordsCount > 128` rejection at
  `:2618` and a per-record `written + 16 > msgSz` bound check at `:2653`. The
  harness observed the 128 cap, not 512; both are in the pinned release. The PR
  diff also carries unrelated unit-test additions; do not cite those as this fix.
- **Pins**: exact SHA-256 digests for both full source tarballs, the PR diff,
  and the CVE JSON are in `lab/frontier/wolfssl2shell/src/SHA256SUMS`, with a
  digest table in `lab/frontier/wolfssl2shell/PROVENANCE.md`. All are tagged
  releases: vulnerable `v5.9.0-stable`, fixed `v5.9.1-stable`.
- **Related but distinct**: CVE-2026-5264 is a *different* DTLS 1.3 ACK heap
  overflow (in ACK message **processing**, credited to KENTECH, also fixed in
  5.9.1). Do not collapse the two; this brief is only about the serialization
  truncation in CVE-2026-6679.

## Source-bound mechanism (raw pinned bytes, `v5.9.0-stable/src/dtls13.c`)

- `#define DTLS13_RN_SIZE 16` ("64 bits epoch + 64 bits sequence").
- `static int Dtls13GetAckListLength(Dtls13RecordNumber* list, word16* length)`
  walks the whole linked list into an `int numberElements`, then executes
  `*length = (word16)(DTLS13_RN_SIZE * numberElements);`. The pinned source has
  a literal `/* TODO: check that we don't exceed the maximum length */` at that
  spot. Since the cast is to `word16`, `numberElements >= 4096` wraps the
  computed byte count: 4096 → 0, 4097 → 16, and so on.
- `int Dtls13WriteAckMessage(WOLFSSL*, Dtls13RecordNumber*, word32*)` uses that
  wrapped `word16 msgSz` to size `sendSz`, calls `CheckAvailableSize`, writes
  `c16toa(msgSz, ackMessage)`, then emits **16 bytes for every element** with
  `c64toa(&recordNumberList->epoch, ackMessage)` and the same for `seq`. With
  N just above 4096 the declared length is ~16 bytes while ~65,552 bytes are
  written: a large heap overwrite whose per-record values are the epoch and
  sequence numbers chosen by the sender.
- `int Dtls13RtxAddAck(WOLFSSL*, w64wrapper epoch, w64wrapper seq)` inserts a
  new 16-byte record into `ssl->dtls13Rtx.seenRecords`, sorted and with exact
  duplicate suppression. `Dtls13RecordRecvd()` calls it for **every received
  handshake record** with `ssl->keys.curEpoch64/seq`, without requiring peer
  authentication — this is the remote reach the advisory describes.
- Verified pinned numbers (from the raw tarballs, not rendered estimates):
  vulnerable `src/dtls13.c:2535` `DTLS13_RN_SIZE 16`, `:2537`
  `Dtls13GetAckListLength`, `:2550` the truncating cast, `:2554`
  `Dtls13WriteAckMessage`, `:2588` `CheckAvailableSize`, `:2604`/`:2606` the
  epoch/seq `c64toa` stores; `wolfcrypt/src/misc.c:1010` is the XMEMCPY sink
  frame. `Dtls13RtxAddAck` is at `:723` and its in-library caller
  `Dtls13RecordRecvd` at `:1547` (the latter was NOT driven by this harness).
  The fixed-side guards are at the lines listed in the Fix bullet above.

## Lab evidence (`lab/frontier/wolfssl2shell/`, `bash run.sh <outdir>`)

`13 PASS / 0 FAIL`, rc 0, trace
`sha256=fb6831dc85fe7afeaaf688ac519a49bccde954a03159211fb256247c1c7ac05d`
over the ordered PASS lines (no PIDs, addresses or paths). All four pins verify
with `sha256sum -c src/SHA256SUMS`.

- **Rung 1** — the unsanitized pinned v5.9.0 build accepts 4097 distinct
  `(epoch, seq)` inserts through the real `Dtls13RtxAddAck` and reaches
  `Dtls13WriteAckMessage` without sanitizer instrumentation.
- **Rung 2** — the accounting failure is measured directly: 4097 records imply
  `16*4097 = 65552` bytes of payload, while `Dtls13GetAckListLength` returns a
  `word16` length of **16** and `CheckAvailableSize` sizes a 31-byte output
  region from that truncated value.
- **Rung 3** — ASan on the verbatim pinned source reports
  `heap-buffer-overflow`, `WRITE of size 8`, 0 bytes after a 31-byte region
  allocated by `GrowOutputBuffer` (`src/internal.c:11415`) via
  `CheckAvailableSize` (`:11581`), in `c64toa` (`wolfcrypt/src/misc.c:1010`)
  called from `Dtls13WriteAckMessage` (`src/dtls13.c:2604`). The write continues
  through the remaining records.
- **Fixed side** — tagged v5.9.1, same 4097 inserts: the list is capped at
  `DTLS13_ACK_MAX_RECORDS=128`, `msgSz=2048`, no truncation, write return 0,
  returned length 2050, empty stderr, rc 0. Notably stronger than PR 10116's
  512 cap alone.
- **Rung 4 INSTRUMENTED** — `chosen_readback.sh` (6 PASS / 0 FAIL, rc 0) uses a
  separate non-ASan staged-heap build and gdb to read back the chosen epoch
  `0xc0ffee1122334455` and per-record seq patterns `0xa55a0000000000ii` at
  offsets 31/47/63/159 past the 31-byte output buffer. Those are chosen bytes
  at chosen offsets, byte-exact, but in staged heap space, not an identified
  live object.
- **Not exercised** — no DTLS socket, listener, real handshake record path,
  real peer, pointer field, control-flow diversion or execution. The two real
  library entry points are called directly in-process; this is a sink-level
  result, not a demonstration of the remote path in the advisory.

## Rung-4 feasibility assessment

This is the strongest X2Shell-class candidate in the current queue:

- **Remote, pre-auth, network-facing**: DTLS 1.3 is a datagram transport used
  by web-facing servers; the ACK list fills from received handshake records
  before the peer is authenticated. No client certificate, no session, no
  application data needed.
- **Large, structured overwrite**: 16 bytes per record, values are 64-bit
  epoch/sequence fields chosen by the sender. That is a chosen-write primitive
  at attacker-controlled offsets in the overflow region, comparable in kind to
  the OpenJpeg 8-byte stream-offset writes but reached over the network and
  without a crafted file format.
- **Tagged fixed release** (5.9.1): fixed-side claims can use a normal release
  rather than an unmerged pin.
- **Cost**: a real DTLS 1.3 handshake plus thousands of distinct record
  numbers is more expensive than a single crafted file. The cheapest local
  route is an in-process harness that calls the real pinned
  `Dtls13RtxAddAck`/`Dtls13WriteAckMessage` entry points with chosen epoch/seq
  pairs; that proves the sink and the chosen bytes but does **not** by itself
  prove a listener, a live neighbouring object, pointer control or execution.
  Those stay UNKNOWN unless a subsequent loopback server experiment observes
  them.

Ranking against the remaining queue: wolfSSL CVE-2026-6679 ranks first for a
dedicated mind because it is network-facing and pre-auth; HTSlib
CVE-2026-62257 (CRAM v4 XPACK/XRLE out-of-bounds *pointer* write, fixed 1.24)
is a library-only file-parser route and needs a web-facing consumer to reach
the same class. Neither duplicates the already-windowed targets 21–60.

The remote reach is a claim from the advisory and the pinned call site, not a
lab observation here. Cheapest next step for an admitted target mind: put a
real wolfSSL DTLS 1.3 server on 127.0.0.1, send >4096 distinct handshake record
numbers from a loopback UDP sender, and observe with gdb whether
`Dtls13RecordRecvd` actually fills `seenRecords` to the wrap point and whether
the overwritten region holds a live object or pointer. Until that is observed,
rung 4 stays INSTRUMENTED and pointer/control-flow/execution stay UNKNOWN.

## Scope and boundaries

Local process only; all source fetching was read-only provisioning, no probing
of external systems, no traffic off 127.0.0.1, no other plant's lane. Witness
re-runs any published claim from a clean `git archive` replay.
