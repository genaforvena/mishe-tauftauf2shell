# frontier brief — socat2shell (SOCKS5 reply DOMAINNAME length sign extension)

Status 2026-11-25 W2: **dispositioned as a remote connection-abort bug on this
host, not a memory-safety find.** W221 established the real-build negative;
W2 closes the remaining consumer-path question with a source census and a
measured kernel count boundary (`sh real/run-count-probe.sh`: 8 PASS / 0 FAIL).
Every count this bug can generate is rejected by `read(2)` with EFAULT before
any byte is stored; no socat build option changes that count. Rung 1/2 met;
rung 3/4/5 NOT established; witness UNKNOWN; the operator owns admission.

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

Verbatim line from the W2 re-run of `real/evidence-real-vuln-attack.out`:
`2026/11/25 03:55:34 socat[807215] W read(7, 0x512000000045, -1): Bad address`.

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

## Consumer-path census and kernel boundary (W2) — closes the question

Source census in the pinned real tree (`lab/frontier/socat2shell/real/socat-1.8.1.1`):

- `sycls.c:539-558`: `Read(fd, buf, count)` is `read(fd, buf, count)`,
  unconditionally. `WITH_SYCLS` (`config.h:773` = 1) only adds Debug calls;
  there is no cap, clamp, or alternate read path behind any configure option.
- `sysutils.c:101-141`: `readfull()` sets `exptg = bytes` and calls
  `Read(fd, buff, exptg)`; a negative `int` arrives as a huge `size_t`.
- `xio-socks5.c:419-427,467-470`: `int bytes_to_read = 7 + reply->dstdata[0]`
  with signed `char`. Length bytes `0xf8..0xff` make `bytes_to_read < 0`, so
  the `while (bytes_to_read >= 0)` loop exits after the first 5-byte read and
  **no second read happens**. Bytes `0xf9..0xff` yield `bytes_to_read` 0..6,
  i.e. a count of `-1 .. -5` passed as `size_t` (`SIZE_MAX .. SIZE_MAX-4`).
  No value produces a bounded positive read past the first five bytes. On a
  target where `char` is unsigned (or with the 1.8.1.2 header) the length is
  248..255 and `7 + length <= 262`, within the allocation: no overflow.

`sh real/run-count-probe.sh` **8 PASS / 0 FAIL** measures the kernel boundary
on this host (x86-64, Linux 6.8.0-149-generic) with loopback-only AF_UNIX
socketpairs; evidence in `real/evidence-count-probe.out`:

| count | queued socket | canary store | meaning |
| --- | --- | --- | --- |
| `SIZE_MAX`, `SIZE_MAX-3`, `SIZE_MAX-126`, `SIZE_MAX/2` | `rc=-1 errno=14` | 0 | EFAULT before any byte |
| `0x80000000` | `rc=600 errno=0` | 1 | control: kernel does store a large positive count |
| empty socket `2^62` | `rc=-1 errno=11` | — | EAGAIN: count accepted |
| empty socket `2^63-1` and `SIZE_MAX-126` | `rc=-1 errno=14` | — | EFAULT: range rejected |

Therefore EFAULT is the rule for every count this bug generates, not an
incidental one-off on one build: those counts are at least `SIZE_MAX-125`,
far above the measured rejection boundary. The advisory's write primitive has
no path through the shipped `readfull()` on this host. A 32-bit `size_t` build
remains **UNKNOWN** — this host lacks multilib (`gcc -m32`: missing
`Scrt1.o`/`crti.o`) and no external provisioning was done; it would not change
the x86-64 disposition.

**Disposition:** remote connection-abort / denial of service, not a
memory-safety find. Rung 1/2 met; rung 3/4/5 NOT established; witness UNKNOWN.
Replays: `sh real/run-count-probe.sh` (8 PASS / 0 FAIL), `sh real/run-real.sh`
(9 PASS / 0 FAIL), `sh harness/run-all.sh` (15 PASS / 0 FAIL, stand-in only).
Would change this disposition: an observed store through real `readfull()` on
this host under ASan with fixed/safe controls, or a build whose `size_t` makes
the converted count acceptable to `read(2)` and observed to store bytes.

Staged as `socat2shell` with a live two-pane inner window, charter at
`.mishe-tauftauf/charters/socat2shell.md`, seed wall at
`.mishe-tauftauf/walls/socat2shell.md`. Frontier owns no further work after
handoff.
