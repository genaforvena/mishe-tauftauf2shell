# frontier brief — socat2shell (SOCKS5 reply DOMAINNAME length sign extension)

Status 2026-11-25 W221: staged at rung 3 with a scoped, partial rung 4.
Pinned-function harness replays 15 PASS / 0 FAIL. No real socat build, no loopback
wire, no pointer/IP control, no marker execution and no rung 5. Witness UNKNOWN;
the operator owns admission.

## Verified ground truth

- Claim source: Socat security advisory 10,
  `http://www.dest-unreach.org/socat/contrib/socat-secadv10.html`, pinned
  verbatim as `lab/frontier/socat2shell/src/advisory.html`. It names
  CVE-2026-56123, CWE-122, CVSS 4.0 9.2 (`AV:N/AC:H`), affected 1.8.0.0 through
  1.8.1.1, corrected 1.8.1.2 and later, and credits Tristan Madani. The advisory
  states a malicious SOCKS5 proxy can choose the DOMAINNAME length byte and
  write attacker-controlled bytes past the 262-byte `SOCKS5_MAX_REPLY_SIZE`
  reply buffer during connection setup, with no authentication.
- Upstream fix: `http://www.dest-unreach.org/socat/download/socat-1.8.1.2.patch`
  (gzip-encoded, pinned as `src/socat-1.8.1.2.patch`). Its only source change is
  `char dstdata[]` -> `unsigned char dstdata[]` in `struct socks5_request` and
  `struct socks5_reply` of `xio-socks5.h`; it adds the regression test
  `SOCKS5_OVERFL` and a CHANGES entry noting the issue needs a malicious server
  with knowledge of client binary details.
- Vulnerable source: `socat-1.8.1.1.tar.gz`, SHA-256 in
  `lab/frontier/socat2shell/src/pins.sha256`. Every fetched byte has a pin; no
  external system was probed.

## Source-bound mechanism

`xio-socks5.c:414-499`, `_xioopen_socks5_read_reply()`, pinned verbatim as
`src/xio-socks5.inc` (86 lines):

    case SOCKS5_ATYPE_DOMAINNAME:
        bytes_to_read = 7 + reply->dstdata[0];
        break;

`dstdata[]` is `char` (signed on x86-64). A length byte 0xfb therefore promotes
to -5, making `bytes_to_read = 2` while `bytes_read = 5`. The next call passes
`bytes_to_read-bytes_read` (-3, implicitly `size_t`) as the read count to
`readfull()`, so all bytes the proxy sends are written at `reply+5`. The real
caller allocates exactly 262 bytes at `xio-socks5.c:551`
(`Malloc(SOCKS5_MAX_REPLY_SIZE)`). The 1.8.1.2 header makes the length
unsigned, giving 258 for 0xfb and keeping the write in bounds.

## Observed evidence

`cd lab/frontier/socat2shell && sh harness/run-all.sh` -> **15 PASS / 0 FAIL**,
rc 0, on a fresh rebuild that re-extracts and SHA-checks every pin. Vulnerable
attack under gcc ASan:

    ERROR: AddressSanitizer: heap-buffer-overflow
    WRITE of size 600 at 0x...146 thread T0
        #1 readfull harness.c:42
        #2 _xioopen_socks5_read_reply xio-socks5.inc:12
    0x...146 is located 0 bytes after 262-byte region

clang ASan reports the same error. Plain build prints
`canary=4d495348452d534f434b53` ("MISHE-SOCKS") starting at reply offset 262,
i.e. the proxy's chosen bytes land at the first byte past the reply. Controls:
a safe IPv4 reply (`address_type=1`) and the attack against the official 1.8.1.2
header are both ASan-clean with rc 0; the fixed plain build leaves the canary
zeroed. Harness detail, stand-in scope and the fortify caveat are in
`lab/frontier/socat2shell/PROVENANCE.md`.

## Rung assessment and honest ceiling

- **Rung 1/2** — met: deterministic trigger from a five-byte SOCKS5 reply and a
  sign-extending length byte; the negative-to-`size_t` transition is observed
  as an unbounded write.
- **Rung 3** — met on the verbatim pinned function: gcc and clang ASan report
  a heap out-of-bounds WRITE immediately after the 262-byte reply allocation.
- **Rung 4** — PARTIAL: the proxy chooses the length byte (0xF9-0xFD), the write
  extent (bytes actually sent) and the bytes at chosen offsets past the reply.
  Costs: no real socat build or wire replay, the harness stand-in models the
  bytes a malicious server sends, glibc fortify aborts before ASan at default
  `-O1` so the harness explicitly disables it, and the upstream advisory notes
  the attack needs knowledge of client binary details. No pointer/IP control.
- **Rung 5** — not attempted; no process, pointer, command or side effect.

## Cheapest next experiment

Build socat 1.8.1.1 with clang ASan, run the upstream `SOCKS5_OVERFL` test or a
loopback-only malicious SOCKS5 listener that sends
`05 00 00 03 fd` followed by the payload, and drive a real
`socat /dev/null SOCKS5:127.0.0.1:...` client against it. Expect the same ASan
write at the real `_xioopen_socks5_read_reply()`; repeat with 1.8.1.2 as the
clean control. Preserve a negative result if the surrounding read loop or a
build flag prevents reaching the write.

Staged as `socat2shell` with a live two-pane inner window, charter at
`.mishe-tauftauf/charters/socat2shell.md`, seed wall at
`.mishe-tauftauf/walls/socat2shell.md`. Frontier owns no further work after
handoff.
