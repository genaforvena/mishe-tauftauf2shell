# Bzfs2Shell status

Handed off to the operator 2026-11-21 ~00:2xZ under the standing similar-things
mandate, on frontier's fresh-find handoff. Admission, charter and the
docs/task.md entry are the operator's next step. The dedicated two-pane window
`bzfs2shell` (inner socket), restorer registry entry and seed wall are already
live from frontier. Wake trigger units and the presentation.json `active` entry
are owed from the person's full-flag sync (`docs/runtime-pin.md`) — never a
bare `mishe sync`. Frontier re-ran the extracted harness from committed
sources at handoff: `bash lab/frontier/bzfs2shell/run.sh out` printed `ALL
CHECKS PASS`, rc 0; pins `1a16963f…` / `f2686d5b…` match the brief.

## Target

BZFlag bzfs TCP length overrun, CVE-2026-130849 / GHSA-9q5f-g948-c95m
(CWE-122, CVSS 4.0 9.3 Critical,
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`). A TCP message with
a 1024-byte body on the unauthenticated player socket writes four attacker
bytes past `tcpmsg[1024]` into the adjacent `int tcplen`, leaving a negative
read offset; the next `recv()` writes chosen bytes before the buffer into
earlier `NetHandler` members. Affected `<2.4.32`, patched `2.4.32`; fix commit
`8e501d68…`. Dedicated C++ game server — the operator decides whether the
standing similar-things mandate admits it. Distinct from all other lanes.

## Mechanism and reproduction

- `Protocol.h:46-47`: `MaxPacketLen = 1024` includes the 4-byte header.
- `NetHandler.h`: `char tcpmsg[MaxPacketLen]; int tcplen;` adjacent.
- `NetHandler.cxx:581` (v2.4.30): only `len > MaxPacketLen` is rejected, so
  `len=1024` passes; `:588` calls `receive(4+len) = receive(1028)`.
- `NetHandler.cxx:630,633`: `recv(fd, tcpmsg+4, 1024)` writes bytes
  `tcpmsg[4..1027]`, four past the array into `tcplen`; `tcplen += size`
  preserves a chosen negative value and returns `ReadPart`.
- Next `receive()` computes destination `tcpmsg + tcplen` before the object and
  length `4 - tcplen` above 4.
- Fix `8e501d6`: bound becomes `MaxPacketLen - 4` and `receive()` rejects a
  negative/oversized offset or length before `recv`.
- Harness (pinned digests above): rung 1 `tcplen=-1024` with chosen tail at
  `tcpmsg+1024`; rung 2 destination 936 bytes before the object, next length
  1028; rung 3 ASan `heap-buffer-overflow`, `WRITE of size 64`, `recv` →
  `traced_recv` → `receive_msg`; rung 4 `DEADBEEFCAFEBABE` and
  `0123456789ABCDEF` read back byte-exact from chosen preceding members;
  fixed controls reject at the first bound and are ASan-clean; five-run
  `sha256=cea3b92e…`.

## Evidence boundary

Rungs 1/2/3 ESTABLISHED in the extracted harness. Rung 4 is INSTRUMENTED
CHOSEN-VALUE CONTROL: the real syscall writes chosen bytes at a chosen harness
member offset with byte-exact readback, but the prefix stand-in is not the
stock `NetHandler` layout. No live bzfs process, player socket, real object
layout, allocator neighbour, function-pointer overwrite or execution. The
advisory's RCE claim is untested here. Witness replay #761 (2026-11-21)
returned all four rungs ESTABLISHED AS CLAIMED at the labels above, with one
precision nit (fixed here and in the brief/PROVENANCE): every source-line
citation was six lines too high relative to the hash-verified pinned bytes.
Pinned harness bytes were deliberately preserved so the witness-verified
digest still holds; the stale numbers in that file's comments would owe a new
independent replay to change. Author report is not acceptance.

## Probe policy

All harness sockets are in-process `AF_UNIX` socketpairs. No external system
was contacted; any future live-build experiment must bind to 127.0.0.1 only.

## Live stock build, loopback only (2026-11-27, this wake)

Stock v2.4.30 and fixed v2.4.32 tag tarballs were provisioned read-only into
`lab/bzfs2shell-live/` (SHA-256 `29b3b97f…` and `86a5ded5…`); c-ares
`cares-1_27_0` was built into a local `deps/` prefix. The traced working
`NetHandler.cxx` differs from the hash-matched upstream source
(`19aeebbe…`, `3abb2fa5…`, originals in `lab/bzfs2shell-live/original/`) only
by stderr traces. Server-only builds used
`--disable-client --disable-bzadmin --disable-plugins --enable-debug`; one
2.4.30 build also used `--enable-asan`. Every server bound to 127.0.0.1 only
(ports 15154/15155); no non-loopback probe was made. Runner
`lab/bzfs2shell-live/run_live.sh`, client `send_packet.py`.

Handshake prerequisite (negative result): a raw 1028-byte exploit packet is
consumed by the pre-auth reader at `src/bzfs/bzfs.cxx:6055-6132`, never by
`tcpReceive()`. The client must first send `BZFLAG\r\n\r\n` (10 bytes) and
read the 9-byte welcome (`BZFS0221\x00`) before the exploit packet reaches
`GameKeeper::Player::handleTcpPacket` → `NetHandler::tcpReceive()`.

Real stock layout observed in the live process (`live-vuln-asan4.log`,
`live-vuln-plain2.log`): `sizeof(NetHandler)=2384`, `tcpmsg` at object offset
96, `tcplen` at 1120, `ares` at 0, `info` at 8, `fd` at 36, `peer` at 40,
`dotNotation` at 64. The first four past-end body bytes therefore overwrite
`tcplen` **inside the same heap object**, which stock ASan does not flag;
the negative-offset write can and did reach before the object.

With body tail `00 f8 ff ff` (little-endian -2048), the live trace records
`receive(1028)` at `tcpmsg+4`, `size=1024`, `clobber_word=fffff800`, then
`tcplen=-1024` at the next `tcpReceive()`. A first attempt with tail
`f8 ff ff ff` set `tcplen=-8` — a corrected mistake, preserved as a negative.
The second packet makes `receive(4)` call
`recv(fd, tcpmsg-1024, 1028)`, destination object offset -928.

- ASan build (`live-vuln-asan4.log`): `ERROR: AddressSanitizer:
  heap-use-after-free`, `WRITE of size 1024`, stack
  `recv` (ASan interceptor) → `NetHandler::receive` → `NetHandler::tcpReceive`
  → `GameKeeper::Player::handleTcpPacket`. An earlier ASan report from the
  harness-style trace reading `tcpmsg[tcplen]` was removed by guarding the
  instrumentation; the surviving report is the real syscall write.
- Non-ASan build (`live-vuln-plain2.log`): the same second write placed
  attacker-chosen marker words at real member offsets:
  `ares=0x41424344454647bc`, `info=0x41424344454647bd`,
  `playerIndex=1162233792`, `fd=1094861636`, and object bytes at offsets
  0,8,…,88 all matched the corresponding 8 bytes of the wire pattern. The
  process then segfaulted, as expected after pointer members became
  non-dereferenceable.
  Mapping for the second payload: object offset `m` receives payload bytes
  `928+m` (destination `tcpmsg-1024` = object-928), so `ares` ← bytes
  928..935, `info` ← 936..943, `fd` ← 964..967, `dotNotation` ← 992..1023.

Grade update: rungs 1/2/3 are now ESTABLISHED in a **live stock v2.4.30 bzfs
process on loopback**, with the real object layout and real `recv` write.
Rung 4 is DEMONSTRATED chosen-value control at real stock-layout member
offsets (`ares`, `info`, `fd`, `playerIndex`, `dotNotation` control block),
still NOT control of a chosen target address, a function-pointer overwrite,
an execution marker or rung 5. Fixed-build control (`live-fixed.log`,
v2.4.32): `BZTRACE fixed-reject len=1024 tcplen=4`, server stdout
`Player [0] sent huge packet length (len=1024), possible attack` and
`Player [0] removed ... large packet recvd`; only the 4-byte header read
occurred, no body `recv`, no negative `tcplen`, no second write; the client's
second `sendall` failed on a closed pipe as expected. Author observation is
not independent acceptance.
