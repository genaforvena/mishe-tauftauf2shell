# frontier-gnutlsdtls2shell — DTLS handshake-fragment merge heap overwrite (CVE-2026-33846)

Status: **STAGED in W286 (2026-11-26); rung 3 ASan-confirmed attacker-controlled
heap overwrite in the shipped GnuTLS library API; rung 4 and rung 5 NOT
CLAIMED.** `lab/frontier/gnutlsdtls2shell/run-all.sh` reported `RESULT PASS=12
FAIL=0` at 20:05Z with all three pinned tarball hashes re-asserted. Charter,
status report, seed wall and live two-pane window 195 (%394/%395, dead=0,
registry 196/196 unique names) exist; operator admission and witness replay
are owed.

## Claim source and scope (re-verified read-only 2026-11-26)

- Upstream advisory `GNUTLS-SA-2026-04-29-1`, "Severity High; heap overwrite",
  on `https://www.gnutls.org/security-new.html`: GnuTLS did not check that DTLS
  fragments claimed a consistent `message_length`, and an array size check was
  missing, enabling a heap overwrite. Fixed in **GnuTLS 3.8.13**. Independently
  reported in issues [#1816](https://gitlab.com/gnutls/gnutls/-/issues/1816),
  [#1838](https://gitlab.com/gnutls/gnutls/-/issues/1838) and
  [#1839](https://gitlab.com/gnutls/gnutls/-/issues/1839).
- CVE-2026-33846 (CNA Red Hat, published 2026-05-04, updated 2026-11-04),
  `https://cveawg.mitre.org/api/cve/CVE-2026-33846`: CVSS 3.1 7.5 High
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` plus a 7.4 `AC:H/I:H` vector in the fix
  commit. Debian tracker lists fixed 3.8.13-1 (unstable), 3.8.9-3+deb13u4
  (trixie), 3.7.9-2+deb12u7 (bookworm), 3.7.1-5+deb11u10 (bullseye).
  Pre-auth, network-reachable DTLS handshake path; no client certificate or
  application data needed.
- Fix commit
  [`65ab33fa54e34fba69d793735b7df3d383d1ff78`](https://gitlab.com/gnutls/gnutls/-/commit/65ab33fa54e34fba69d793735b7df3d383d1ff78)
  ("buffers: add more checks to DTLS reassembly", Alexander Sosedkin,
  2026-04-17): 20 inserted lines in `lib/buffers.c`, no other files.
- Release announcement `https://lists.gnu.org/archive/html/info-gnu/2026-04/msg00011.html`
  (3.8.13, 2026-04-29) names the same fix and CVE.
- Pinned provisioning: `gnutls-3.8.12.tar.xz` SHA-256
  `a7b341421bfd459acf7a374ca4af3b9e06608dcd7bd792b2bf470bea012b8e51`,
  `gnutls-3.8.13.tar.xz` SHA-256
  `ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e`,
  both from `https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/`. Host nettle 3.9.1 is
  below the 3.10 minimum, so pinned `nettle-3.10.tar.gz` SHA-256
  `b4c518adb174e484cb4acea54118f02380c7133771e7e9beb98a0787194ee47c`
  (`https://ftp.gnu.org/gnu/nettle/nettle-3.10.tar.gz`) was built into
  `lab/frontier/gnutlsdtls2shell/opt`. GnuTLS configure needs
  `--with-included-unistring` on this host.
- The advisory's one-click PoC and pasted ASan trace are treated as claims,
  not evidence; the local run below is the authority.

## Source-bound mechanism (from the fix hunk)

`merge_handshake_packet()` in `lib/buffers.c` matches an incoming fragment to
an existing reassembly entry by handshake `htype` alone. The fix adds three
guards immediately before the merge branches:

1. `hsk->length != recv_buf[pos].length` -> clear and return
   `GNUTLS_E_UNEXPECTED_PACKET_LENGTH` (reject inconsistent `message_length`);
2. `hsk->length < hsk->start_offset + hsk->data.length` -> reject impossible
   claims (the missing array size check);
3. `hsk->length > recv_buf[pos].data.data.max_length` -> reject writes past
   the actually allocated buffer.

Without them, a first fragment with a small `message_length` creates a
reassembly buffer (ASan trace in issue #1816 shows a 2048-byte `MIN_CHUNK`
allocation), and later fragments with a larger `message_length` are merged by
`memcpy(&recv_buf[pos].data.data[hsk->start_offset], hsk->data.data,
hsk->data.length)` using only their own per-fragment validation. The write
destination is computed from attacker-supplied `fragment_offset`, with no
comparison against the original allocation.

## Local experiment (cheapest rung-raising step)

Build pinned 3.8.12 and 3.8.13 with GCC ASan, link the loopback DTLS server
reproducer in `lab/frontier/gnutlsdtls2shell/poc_dtls_fragment_overflow.c`
against each, and drive four fragments: `msg_len=50, off=25, len=25` (create
small buffer), then `msg_len=3000` at `off=0/len=48`, `off=40/len=1475`, and
`off=1500/len=1475` (927 bytes past the 2048-byte allocation). The server loops
`gnutls_handshake()` over `GNUTLS_E_AGAIN` as DTLS requires. Expected: ASan
`heap-buffer-overflow WRITE` on 3.8.12; a length error with no ASan report on
3.8.13.

## Observed local result (2026-11-26 W286)

- Vulnerable 3.8.12 under GCC ASan: `ERROR: AddressSanitizer:
  heap-buffer-overflow`, `WRITE of size 1475`, sink
  `merge_handshake_packet ../../src/gnutls-3.8.12/lib/buffers.c:1035`, caller
  `_gnutls_parse_record_buffered_msgs` at buffers.c:1320; address is 0 bytes
  after a 2048-byte region allocated by `buffer_resize_reclaim`
  (`lib/str.c:187`) via `gnutls_buffer_append_data` (`lib/str.c:116`). Attacker
  filler is 'E'. `evidence/attack-asan-3.8.12.out`.
- Safe input on the same vulnerable build (`SAFE=1`, consistent
  `message_length=3000`): no ASan report, handshake -319 (timeout).
  `evidence/safe-asan-3.8.12.out`.
- Fixed 3.8.13 with the identical attack input: no ASan report, handshake -9
  (`Error decoding the received TLS packet.`).
  `evidence/attack-asan-3.8.13.out`.
- The advisory's own trace is independently matched on this host (same sink,
  same WRITE size, same 2048-byte allocation) but is not the source of the
  grade; the local traces above are.

## Honest feasibility assessment

- Rung 1/2/3 are cheap: a deterministic loopback UDP sequence through the
  shipped library API, with an ASan-instrumented build and a fixed-version
  control. The advisory's trace already names the sink; no fuzzing or
  guesswork is required.
- Chosen bytes are attacker-controlled ('E' filler in the reproducer), so
  this is a genuine attacker-controlled write into an adjacent heap region,
  not merely a read or a crash. It is a stronger starting point than the
  usual ASan-redzone-only finds.
- Rung 4 is plausible but not automatic: ASan poisons the bytes past the
  allocation, so demonstrating *which* adjacent object is overwritten needs a
  plain build with an observable victim (heap grooming or a neighboring
  allocation whose state changes). No such victim is claimed here.
- Rung 5 is not claimed: the lab process would need to execute a chosen benign
  command from wire input, with vulnerable/fixed/safe-input controls.
- Scope: loopback-only server; no external target, no probing, no public
  infrastructure.
