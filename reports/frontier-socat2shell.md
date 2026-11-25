# frontier brief — socat2shell (SOCKS5 reply DOMAINNAME length sign extension)

Status 2026-11-25 W221: real-build loopback replay is NEGATIVE for the
advisory's write claim — the negative count reaches `read(2)` as SIZE_MAX, the
kernel returns EFAULT, and no ASan report or corruption occurs on this host.
The pinned-function harness still replays 15 PASS / 0 FAIL, but its `memcpy`
stand-in is not the real consumer. Rung 3 on a real build is NOT established;
the observed effect is a deterministic connection failure. Witness UNKNOWN;
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
`readfull()`. Whether bytes are stored depends on that consumer; the real one
is measured below.
The real caller allocates exactly 262 bytes at `xio-socks5.c:551`
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

## Real-build loopback replay (W221) — negative result

Both releases were built unmodified under clang ASan from pinned tarballs
(`src/socat-1.8.1.1.tar.gz` and `src/socat-1.8.1.2.tar.gz`, SHA-256 in
`src/pins.sha256`) with `--disable-openssl`. `real/evil_socks5.py` binds only
127.0.0.1 and sends `05 00`, then either `05 00 00 03 fd` plus 600 chosen bytes
or a well-formed IPv4 reply. `sh real/run-real.sh`: **9 PASS / 0 FAIL**.

| build / reply | observed | exit |
| --- | --- | --- |
| 1.8.1.1, DOMAINNAME 0xfd | `W read(7, 0x512000000045, -1): Bad address`, no ASan | 255 |
| 1.8.1.1, IPv4 reply | clean | 0 |
| 1.8.1.2, DOMAINNAME 0xfd | clean | 0 |
| 1.8.1.2, IPv4 reply | clean | 0 |

Verbatim line from `real/evidence-real-vuln-attack.out`:
`2026/11/25 03:18:01 socat[321607] W read(7, 0x512000000045, -1): Bad address`.

The real `readfull()` (`sysutils.c:101-141`) loops `Read(fd, buff, exptg)`.
With `exptg = SIZE_MAX`, this host's `read(2)` returns `-EFAULT` before writing
any byte; `readfull()` returns -1 and the caller closes the socket. The
advisory's claimed unbounded heap write is therefore NOT reproducible in the
shipped consumer on this host. The ASan WRITE in the pinned-function harness
comes from its `memcpy` stand-in, which assumes the malicious server's bytes
are copied; that assumption is false for the real `readfull()` here.

## Rung assessment and honest ceiling

- **Rung 1/2** — met on a real build: a five-byte SOCKS5 reply with a
  sign-extending length byte deterministically aborts the SOCKS5 connection
  (`read(..., -1): Bad address`), while the fixed build and safe reply succeed.
- **Rung 3** — NOT established. The harness's ASan heap WRITE is a
  synthetic-consumer result; the real ASan build produced no report. An
  earlier status in this wake claimed rung 3 on the pinned function; it is
  corrected here and the correction is the durable result.
- **Rung 4** — not established: no bytes are stored past the reply on the real
  path, so there is no chosen-byte primitive, pointer/IP control or marker.
- **Rung 5** — not attempted; no command or side effect.

## Cheapest next experiment

Determine whether any socat build option or consumer path converts the huge
count into a bounded positive read that stores bytes; if none does, disposition
the candidate as a remote connection-abort bug rather than a memory-safety
find. The reproducible controls are `sh real/run-real.sh` (9 PASS / 0 FAIL)
and `sh harness/run-all.sh` (15 PASS / 0 FAIL); any future claim of a write must
show it on the real `readfull()` path, not in the stand-in.

Staged as `socat2shell` with a live two-pane inner window, charter at
`.mishe-tauftauf/charters/socat2shell.md`, seed wall at
`.mishe-tauftauf/walls/socat2shell.md`. Frontier owns no further work after
handoff.
