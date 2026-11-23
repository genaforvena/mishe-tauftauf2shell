# Frontier brief: BusyBox TFTP client blksize-fallback heap overflow (busybox2shell)

**STAGED 2026-11-23 W182.** This brief, a loopback wire harness with a
vulnerable/fixed/control matrix and a registered two-pane target window exist.
Claim sources, pins, transcript hashes and the exact replay are below. No
external system was probed; every packet stayed on 127.0.0.1.

## 1. Verified ground truth (claims, not acceptance)

- NVD `CVE-2026-124737`, "A flaw was found in BusyBox. When the TFTP client
  requests a custom small block size and receives a standard response, it
  falls back to the default block size without resizing the allocated memory
  buffer. A malicious TFTP server can exploit this issue by sending
  standard-sized network packets during a transfer, causing a heap buffer
  overflow... arbitrary code execution or ... DoS." Published 2026-11-11,
  modified 2026-11-17; CNA Red Hat, Inc.; reference bugzilla.redhat.com
  `2571607`; CWE-787; CVSS 3.1 7.5 HIGH
  `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H`. NVD status Awaiting Analysis;
  the RCE sentence is a vendor **claim**, not reproduced here.
- Red Hat CVE page: "Important", pre-auth rogue network server, non-default
  reduced blocksize needed, no mitigation meeting its criteria; credits
  Duc Anh Luu. Ubuntu/Debian/OSV mirror the same description. Debian OSV
  lists affected package versions across Debian 12/13/14 (1:1.35.0-4 …
  1:1.38.0-3), introduced `0`. No upstream BusyBox release number carrying
  the fix and no affected-version range for the upstream tarball were found:
  **numeric fixed version UNKNOWN**.
- Upstream patch: `[PATCH] tftp: don't overflow the receive buffer after
  blocksize fallback`, Yehyeong Lee, busybox mailing list,
  2026-09-19T15:01:43Z (archive msg31059). Its diff header is
  `networking/tftp.c e13223d..c3bebc5`; that blob is from a different
  upstream revision than the pinned 1.37.0 file (`f5b4367…`), but the same
  two lines exist verbatim in 1.37.0 and the patch applies semantically.

## 2. Source-bound mechanism

Pinned `busybox-1.37.0/networking/tftp.c` (SHA-256
`183410e8b1bbf9e07397d6ccf9eb20fa13c2644b8fffb4a40b94855f1d3b7044`):

- `:323` `int io_bufsize = blksize + 4;` and `:331-332` allocate `xbuf` and
  `rbuf` at that size. `-b 64` therefore gives two 68-byte heap allocations.
- `:459-475` rejects very small request blocks (a 64-byte request passes;
  the client also appends `tsize`, so the observed RRQ is 33 bytes).
- `:590` (first datagram) and `:602` (subsequent datagrams) call
  `recvfrom`/`safe_read(socket_fd, rbuf, io_bufsize, …)`.
- `:643-674` expects OACK. A first packet that is *not* OACK (and not ERROR)
  takes `:679-682`, which prints `falling back to blocksize 512`, sets
  `blksize = 512` and `io_bufsize = 516` **without reallocating `rbuf`**.
- `:726-727` sends an unrecognized first packet back to the receive loop. The
  next `safe_read(..., 516, ...)` copies a full 512-byte TFTP DATA payload
  plus 4-byte header into the still-68-byte allocation: 448 bytes past the
  end, all server-controlled.

Upstream fix replaces `:323` with an allocation sized
`(blksize < TFTP_BLKSIZE_DEFAULT ? TFTP_BLKSIZE_DEFAULT : blksize) + 4`.
The local fixed tree applies that one-line equivalent; its tftp.c SHA-256 is
`015669f9c8924fd006b02abcc2cb6665d9ec5cd7f749d8ca8b16859c996c888f`.

## 3. Local experiment (all loopback)

`lab/frontier/busybox2shell/`:

- `busybox-1.37.0.tar.bz2` SHA-256
  `3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4`
  (busybox.net provisioning). Minimal config (`make allnoconfig` with
  `CONFIG_TFTP`, `CONFIG_FEATURE_TFTP_GET`, `CONFIG_FEATURE_TFTP_BLOCKSIZE`
  enabled) avoids an unrelated `networking/tc.c` build break against current
  kernel headers. ASan and fixed binaries are built with
  `CFLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer"
  LDFLAGS="-fsanitize=address"`; the plain build is `-g -O0`, unstripped.
- `malicious_tftp.py` binds an ephemeral UDP socket to 127.0.0.1, reads the
  real RRQ, then either (attack) sends a 4-byte unmatched DATA block 0 to
  force fallback followed by a 516-byte DATA block 1, (oack) acknowledges
  `blksize`, or (default) answers a client that never requested a small block.
- `run-all.sh` replays five legs; full transcript `evidence.log` SHA-256
  `3e52a8627e6c435f5e20d1394a31085e8a837dbe2c3718003ea9bfcfecbff300`,
  2026-11-23T22:36:59Z–22:37:34Z.
A clean `git archive HEAD` (commit `0c3b4a1`) extraction replayed the same
five legs with identical ASan summary and chosen bytes; transcript SHA-256
`064e7b1fd4bb72497200c1fbc299d374623d5d4b73da59dd6327b1071397ae96`.

Measured results:

1. Vulnerable ASan binary (`a5ff8849…`), attack: stderr
   `tftp: falling back to blocksize 512`, then
   `ERROR: AddressSanitizer: heap-buffer-overflow`,
   `WRITE of size 516`, address `0x507000000144`
   `located 0 bytes after 68-byte region [0x507000000100,0x507000000144)`;
   allocated by `malloc` in `tftp_protocol` (source-inlined stack in the
   report), client rc 1.
2. Safe OACK control: rc 0, ASan clean. Safe default-blksize control:
   rc 0, ASan clean.
3. Fixed ASan binary (`2e2b327c…`) against the identical attack: same
   fallback message, rc 1 timeout at the harness's final block, **no ASan
   report** — the 516-byte read now fits the 516-byte allocation.
4. Plain build (`4ec897f3…`) under gdb, breakpoint at
   `networking/tftp.c:604` after the second read: first hit shows
   `IO_BUFSIZE=68 LEN=4`; second shows `IO_BUFSIZE=516 LEN=516` at the same
   `rbuf`. Bytes at `rbuf+68..75` are `4d 49 53 48 45 2d 4f 4f`
   ("MISHE-OO") and `rbuf+76..83` are `54 41 55 46 54 41 55 46`
   ("TAUFTAUF") — attacker-chosen UDP payload bytes at chosen offsets past
   the heap allocation. `x/s rbuf+68` prints `MISHE-OOTAUFTAUF…`. Backtrace:
   `tftp_protocol` ← `tftp_main` ← `run_applet_no_and_exit`.

## 4. Rung-4 feasibility and grade

**Rung 1** (deterministic trigger) and **rung 2** (observed state failure:
`io_bufsize=516` with a 68-byte `rbuf` under gdb) are met through the real
TFTP wire protocol, not a direct function call. **Rung 3** is ASan-confirmed
and **rung 4** is demonstrated security impact at the byte level: chosen
server bytes land at chosen offsets past the heap allocation, in a real
client process on loopback. This is stronger than the plant's usual
direct-call staging because the attacker-controlled input crosses a socket.

**Ceiling / UNKNOWN:** ASLR is measured (W1) but not defeated; no groomed
live object holding a controlled pointer, no function-pointer or
return-address control, no shellcode, no command execution, no witness replay.
Both safe controls need the operator's
`-b 64` action (UI:R in the advisory) and the server must ignore the option;
that precondition is advisory-consistent but not deployment-measured.
Rung 5 is **not attempted**. Advisory RCE prose remains a claim.

W1 (below) adds chosen-byte corruption of live glibc heap metadata and a
server-triggered allocator abort on the stock plain build; it adds no
pointer/IP control and does not change the rung-5 ceiling.

## 5. Cheapest next steps for a dedicated mind

1. Replay `sh lab/frontier/busybox2shell/run-all.sh` in a clean archive and
   verify `evidence.log` structure and the chosen-byte line; request witness
   reproduction.
2. On the plain build, groom a live adjacent heap object and show a chosen
   pointer-shaped value or deterministic crash at a chosen offset; measure
   ASLR and glibc bin behaviour before claiming any control-flow consequence.
3. Build a stock `tftpd` control that acknowledges `blksize` and confirm the
   same RRQ cannot trigger fallback; then test a plain distribution BusyBox
   applet under the same loopback server. Do not infer RCE from a crash.

## 6. Ranking

High tractability: small pinned C file, no third-party library build, a real
network trigger already reproduced in under a minute, and an unambiguous
one-line upstream fix. Ranked above advisory-only candidates with unknown
versions (HID parser CVE-2026-122173, BusyBox-unrelated Corosync/MS SQL/
PostgreSQL paths) and below targets with an already demonstrated wire-to-code
path. Operator owns admission.

## 7. W1 heap-metadata experiment (2026-11-23 23:5xZ, all loopback)

`lab/frontier/busybox2shell/heap_probe.py` and `run-heap.sh` replay to
`heap_evidence.log` (SHA-256
`9aef785cdd5f5386d65c9afc369c917f0e63ecb2e0cd171162ef8b37d75966c6`,
2026-11-23T23:51:41Z–23:52:20Z). No code is injected into the client: the
same stock unstripped BusyBox binary and real UDP path as legs 1-5 are used.

Measured heap geometry under gdb with `set disable-randomization off`:
`xbuf = rbuf - 0x50`; the rbuf chunk header at `rbuf-8` reads `0x51` (a
68-byte request rounded to a 0x50-byte chunk); the next chunk's size word at
`rbuf+72` (the top/wilderness chunk) reads `0x20cb1`. Five runs gave rbuf
addresses `0x5a572bf3e310`, `0x60ab8d8c1310`, `0x58e20307e310`,
`0x629542956310`, `0x588580dc3310`: ASLR moves the heap base while relative
offsets stay invariant.

After fallback, the server's second datagram is a 516-byte TFTP ERROR
(opcode 5) packet. Wire bytes `payload[68:76]` land at `rbuf+72..79`, the
top-chunk size word; the rest is a 511-byte NUL-free error text. The client's
`tftp.c:632-639` calls `bb_error_msg("server error: (%u) %s", ...)`; its
long-message path (`libbb/verror_msg.c:50`) calls `vasprintf` -> `malloc` on
the corrupted heap.

- Chosen `0x4141414141414141`: plain client rc -6 (SIGABRT), stderr
  `malloc(): corrupted top size`. Under gdb, `NEXT_SIZE` changes
  `0x20cb1` -> `0x4141414141414141` across the second `safe_read`
  (`IO_BUFSIZE=516 LEN=516`), then SIGABRT with backtrace `tftp_protocol`
  (`tftp.c:604`) <- `tftp_main` (`tftp.c:867`) <- `run_applet_no_and_exit`.
- Chosen `0x4242424242424242`: same abort. Chosen `0x21`: rc -6 with glibc
  `malloc.c:2599 (sysmalloc)` assertion. The failure mode follows the
  chosen bytes.
- Isolation: writing back the original word `0x20cb1` yields rc 1 and a
  clean server-error exit despite the overflow having occurred.
- Control: the same 516-byte ERROR packet without `-b 64` (rbuf=516 from
  the start) yields rc 1 and no abort. The fixed one-line ASan build with
  the identical attack yields rc 1 and no ASan overflow report.

Grade unchanged at rungs 1-4, now with chosen-byte corruption of live glibc
allocator metadata and a server-triggered abort on the stock client; no
harness-forced execution is involved. Ceiling unchanged: no controlled
function pointer or return address, no command, no rung 5. ASLR is measured
but not defeated — only relative offsets are used. This W1 result is an
author claim pending witness replay, like the original five legs.
