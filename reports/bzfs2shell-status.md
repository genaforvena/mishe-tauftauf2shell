# Bzfs2Shell status

Admitted 2026-11-21 ~00:5xZ as a dedicated target mind under standing approval
#6 (similar-things mandate), on frontier's #430 handoff. Charter, wall,
two-pane window and restorer entry are live. Presentation fold: operator
#6273 at `c0d6b5fd` (R4 demonstrated, tier LIVE/CODE/HARNESS). Independent
witness replay of the live wire (#6283, W330): ESTABLISHED AS LABELED,
no grade change, NO r5. Unit re-rendering stays with the
person and uses the full-flag sync in `docs/runtime-pin.md` — never a bare
`mishe sync`. Frontier re-ran the extracted harness from committed sources at
handoff: `bash lab/frontier/bzfs2shell/run.sh out` printed `ALL CHECKS PASS`,
rc 0; pins `1a16963f…` / `f2686d5b…` match the brief.

## Target

BZFlag bzfs TCP length overrun, CVE-2026-130849 / GHSA-9q5f-g948-c95m
(CWE-122, CVSS 4.0 9.3 Critical,
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`). A TCP message with
a 1024-byte body on the unauthenticated player socket writes four attacker
bytes past `tcpmsg[1024]` into the adjacent `int tcplen`, leaving a negative
read offset; the next `recv()` writes chosen bytes before the buffer into
earlier `NetHandler` members. Affected `<2.4.32`, patched `2.4.32`; fix commit
`8e501d68…`. Dedicated C++ game server, admitted as an X2Shell-class extension
under standing approval #6. Distinct from all other lanes.

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

Harness (2026-11-21, witness replay #761): rungs 1/2/3 ESTABLISHED; rung 4
ESTABLISHED at INSTRUMENTED CHOSEN-VALUE CONTROL — the real syscall wrote
chosen bytes at a chosen stand-in member with byte-exact readback, but the
prefix stand-in was not the stock `NetHandler` layout. Witness #761 returned
all four rungs ESTABLISHED AS CLAIMED at those labels: 20 PASS / 0 FAIL, rc 0,
five-run digest `cea3b92e…`, pins hash-matching, with one precision nit
(source citations six lines high, fixed here and in the brief/PROVENANCE).
Pinned harness bytes were preserved so the witness-verified digest still
holds; the stale line numbers remain only as comments in that file.

Live stock process (2026-11-27, section below): rungs 1/2/3 ESTABLISHED on
loopback with the real layout; rung 4 DEMONSTRATED chosen-value control at
real stock member offsets (`ares`, `info`, `fd`, `playerIndex`,
`dotNotation`), still NOT chosen-target pointer control, a function-pointer
overwrite, an execution marker or rung 5. The author observation is now
backed by W330's independent replay (#6283, section below), which did not
reuse the author's binaries and did not extend the grade.

## Probe policy

All harness sockets were in-process `AF_UNIX` socketpairs and every live
experiment bound to 127.0.0.1 only; no external system was contacted.

## Live stock build, loopback only (2026-11-27)

Stock v2.4.30 and fixed v2.4.32 tag tarballs were provisioned read-only into
`lab/bzfs2shell-live/` (SHA-256 `29b3b97f…` and `86a5ded5…`); c-ares
`cares-1_27_0` was built into a local `deps/` prefix. The traced working
`NetHandler.cxx` differs from the hash-matched upstream source
(`19aeebbe…`, `3abb2fa5…`, originals in `lab/bzfs2shell-live/original/`) only
by stderr traces. Server-only builds used
`--disable-client --disable-bzadmin --disable-plugins --enable-debug`; one
2.4.30 build also used `--enable-asan`. Every server bound to 127.0.0.1 only
(ports 15154/15155/15156); no non-loopback probe was made. Runner
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
  heap-use-after-free`, `WRITE of size 1024` (the bytes actually delivered by
  that run's 1024-byte second packet; a 1028-byte second packet reports
  `WRITE of size 1028`), stack `recv` (ASan interceptor) →
  `NetHandler::receive` → `NetHandler::tcpReceive` →
  `GameKeeper::Player::handleTcpPacket`. An earlier ASan report from the
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
second `sendall` failed on a closed pipe as expected. Independent witness
acceptance is recorded in the next section.

## Author self-replay, 2026-11-27 W330 (not independent)

Re-ran the documented recipe with the same binaries on fresh loopback ports
15157/15158/15159: `live-w330-plain.log`, `live-w330-asan.log`,
`live-w330-fixed.log` (+ `.client`, `.out`). All three reproduced: real layout
`tcpmsg +96` / `tcplen +1120`, `tcplen=-1024`, destination object-928,
`ares=0x41424344454647bc` / `info=0x41424344454647bd` readback and a segfault
in the plain build; ASan `heap-use-after-free` `WRITE of size 1028` through
`recv` with the 1028-byte second packet; v2.4.32 `fixed-reject len=1024` and
a second `sendall` on a closed pipe. This is an author durability check of
the lab assets; independent acceptance is the separate W330 replay below.

## Independent witness replay, 2026-11-27 W330 (not author)

Witness #6283 replayed the live wire with its own builds from hash-matched
stock tarballs (`29b3b97f…` / `86a5ded5…`), private reflink copies and the
unmodified `send_packet.py` on 127.0.0.1 ports 15157/15158/15159. Verdict:
**ESTABLISHED AS LABELED, no grade change, NO r5** — the same real layout
(`tcpmsg +96`, `tcplen +1120`), `tcplen=-1024`, destination object-928, ASan
`WRITE of size 1028` through `recv` → `NetHandler::receive` → `tcpReceive`
→ `handleTcpPacket`, chosen member readback with SIGSEGV in the plain build,
and v2.4.32 rejection at the first bound with BrokenPipe on the second send.
No chosen target address, function pointer, execution marker or command was
observed. Full hashes, logs and counterexamples are in the gitignored
witness artifact `.mishe-tauftauf/artifacts/witness-w330-bzfs/detail.md`.
ASan write size tracks the offered second-packet bytes (see above); no
grade change.
