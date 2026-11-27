# Bzfs2Shell status

Admitted 2026-11-21 ~00:5xZ as a dedicated target mind under standing approval
#6 (similar-things mandate), on frontier's #430 handoff. Charter, wall,
two-pane window and restorer entry are live. Presentation fold: operator
#6273 at `c0d6b5fd` (R4 demonstrated, tier LIVE/CODE/HARNESS). Independent
witness replay of the live wire (#6283, W330): ESTABLISHED AS LABELED,
no grade change, NO r5. Witness replay of the chosen-target probe (#6416,
W337): ESTABLISHED AS LABELED at that label, NO r5. Unit re-rendering stays
with the person and uses the full-flag sync in `docs/runtime-pin.md` — never
a bare `mishe sync`. Frontier re-ran the extracted harness from committed
sources at handoff: `bash lab/frontier/bzfs2shell/run.sh out` printed
`ALL CHECKS PASS`, rc 0; pins `1a16963f…` / `f2686d5b…` match the brief.

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
`dotNotation`). W330's independent replay (#6283, section below) backed that
value-control claim without extending it. The chosen-TARGET pointer probe
(final section) was replayed independently by W337 (#6416): ESTABLISHED AS
LABELED, NO r5.

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

## Chosen-target pointer probe, 2026-11-27

Operator #6385 under standing approval #8 asked for one bounded loopback
experiment: retarget a pointer-bearing member from the real second-packet
write and look for a subsequent request-driven dereference. Result:
**chosen-TARGET pointer control with a request-driven dereference and a
stock-code benign marker print in a live v2.4.30 process. No command was
executed and no marker file was created; this is not r5 under the charter's
command-execution definition.** The sentinel is an LD_PRELOAD lab mapping;
independent replay W337 (#6416, section below) returned ESTABLISHED AS LABELED
under the stated conditions, NO r5.

Builds and pins: stock tarballs SHA-256 `29b3b97f…` (v2.4.30) and
`86a5ded5…` (v2.4.32). Rebuilt plain binary `a18e88cd…`, ASan binary
`38035fc9…`; both use the same trace-only `NetHandler.cxx` (`ab167aab…`,
stock plus two `BZTRACE countMessage-deref` lines). Fixed binary is
unchanged `5bd85e32…`. Runner `run_pointer.sh` (`9516b24f…`), client
`send_pointer.py` (`093e22cb…`), `sentinel.so` (`047fcf5f…`) built from
`sentinel.c` (one RW page at `0x200000000000`, marker word
`0x424153454e544c42` at offset 8, SIGSEGV address/RIP logger). All are in
the gitignored `lab/bzfs2shell-live/`. ASLR was left on:
`randomize_va_space=2`; object addresses differed between arms while the
sentinel address stayed fixed via `MAP_FIXED_NOREPLACE`.

Wire: the pinned handshake and first 1028-byte packet with tail
`00 f8 ff ff` (`tcplen=-1024`) are unchanged. Payload2 is 1028 bytes with
object offset `m` fed from byte `928+m`: `ares` (offset 0) and `info`
(offset 8) both set to `0x200000000000`, `playerIndex` (32) set to 0,
`fd` (36) preserved as 8 from the trace, and bytes 1024..1027 (the fresh
`tcpmsg[0..3]` header) set to `00 00 00 00` (MsgNull, len 0). Remaining
bytes kept the prior pattern; no other corrupted member was repaired.

- Vulnerable plain, port 15160 (`ptr-vulnplain.log`): member readback
  `ares=0x200000000000 info=0x200000000000 playerIndex=0 fd=8`, object
  bytes 0 and 8 both `0000200000000000`; `after-body len=0 ... tcplen=4`;
  then `BZTRACE countMessage-deref this=0x6200ac6bfa40
  info=0x200000000000 now=4.221843 code=0 len=4 dir=0`. The live server
  dereferenced the chosen pointer in a request-driven path, with no
  debugger and no forced call, and read a value from the lab sentinel. It
  then took SIGSEGV at address 0 (RIP outside the sentinel), attributed to
  the remaining corrupted members; that later crash site was not isolated.
- Vulnerable ASan, port 15161 (`ptr-vulnasan.log`): `heap-use-after-free`,
  `WRITE of size 1028` in `recv` → `NetHandler::receive`
  (`NetHandler.cxx:649`) → `tcpReceive` (`:577`) → `handleTcpPacket`
  (`GameKeeper.cxx:374`) → `main`. ASan stops at the write, so it confirms
  the corruption but not the pointer read.
- Fixed v2.4.32, port 15162 (`ptr-fixed.log`): first packet rejected,
  second `sendall` raised BrokenPipe, server stayed alive, no chosen-pointer
  trace.
- Well-formed safe input on the vulnerable build, port 15163
  (`ptr-safe.log`): ordinary `info=0x5a1d5e830d08`, server stayed alive.
  Every arm killed its listener; `ss -ltn` showed ports 15160..15163 free.

- Stock-code marker arm, port 15165 (`ptr-plain-marker2.log`): same wire
  except payload2 bytes 1024..1027 carried `00 00 6f 67` (len 0, code
  `MsgUDPLinkEstablished` 0x6f67) and the sentinel mapped a unique string
  at `PlayerInfo::callSign` offset 76 (confirmed by `gdb ptype /o
  PlayerInfo`: `callSign` at 76, size 32). Server stdout
  (`ptr-plain-marker2.log.out:38`) printed
  `Player BZP-PTR-MARKER-W336 [0] outbound UDP up` — a stock
  `logDebugMessage(2, ...)` call in `NetHandler::tcpReceive` reading
  `info->getCallSign()` through the chosen pointer, with `-d2`. The added
  trace also read `info=0x200000000000 now=4.246731 code=28519 len=4`.
  Fixed v2.4.32 with the same marker wire (port 15166,
  `ptr-fixed-marker.log`) rejected the first packet, broke the second
  `sendall`, stayed alive and printed the marker zero times. The marker
  arm used `sentinel-marker.so` `f2e39e47…`, client `32e8872f…` and runner
  `1c0afb6d…`; the four earlier arms used the hashes above. No listener
  remained on 15160..15166.

Grade: rung 4 rises from chosen-VALUE to **chosen-TARGET pointer control
with a live request-driven benign dereference and a stock-code marker
print**. It is not control-flow hijack, a function-pointer overwrite, a
lab-chosen command or r5. Witness replay W337 (section below) returned
ESTABLISHED AS LABELED under the stated conditions; NO r5. Earlier W330 stays
ESTABLISHED AS LABELED with no grade change at that time.

## Independent witness replay, 2026-11-27 W337 (not author)

Witness #6416 replayed the chosen-target probe with its own builds, not the
author's binaries. Verdict: **ESTABLISHED AS LABELED** for commit `b2da0a75`
at chosen-TARGET pointer control with a request-driven benign dereference and
a stock-code marker print, under the report's stated conditions (`-d2` debug
level, LD_PRELOAD lab sentinel, locally built stock source tree). **NO r5**:
no control-flow hijack, function-pointer overwrite, lab-chosen command,
marker file, debugger write or forced call.

Clean inputs and pins: stock tarballs `29b3b97f…` (v2.4.30) and `86a5ded5…`
(v2.4.32); author binaries plain `a18e88cd…`, ASan `38035fc9…`, fixed
`5bd85e32…`; runner `1c0afb6d…`, client `32e8872f…` and
`sentinel-marker.so` `f2e39e47…` all matched. The witness rebuilt its marker
`.so` from `sentinel.c -DMARKER76` and got the byte-identical `f2e39e47…`
hash. Instrumented source pin `ab167aab…` (stock `19aeebbe…` plus two
`BZTRACE countMessage-deref` lines; its diff against W330's trace is only
those two lines), fixed source `1ca99576…` unchanged from W330.

Own builds: private reflink trees under
`.mishe-tauftauf/artifacts/witness-w330-bzfs/`; the pinned source was copied
into both 2.4.30 trees and rebuilt with `make -C src -j2` (rc 0). Witness
binary hashes `73a72545…` (ASan) and `15320354…` (plain) differ from the
author's only by build paths. It also built an **unmodified stock** 2.4.30
server (`NetHandler.cxx` `19aeebbe…`, `NetHandler.h` `0951be0f…`, no trace
lines, binary `c5c6fd87…`, build rc 0).

Replay (127.0.0.1 only, ports 15170–15177, no listener left):

- Instrumented plain, port 15170 (`ptr-w337-plain-pointer.log`): member
  readback `ares=0x200000000000 info=0x200000000000 playerIndex=0 fd=8`,
  `after-body len=0 ... tcplen=4`, then
  `countMessage-deref ... info=0x200000000000 now=4.216051 code=0 len=4
  dir=0`; later SIGSEGV at nil from the remaining corrupted members. Object
  addresses differed between arms while the sentinel stayed fixed (ASLR on).
- ASan, port 15176 (`ptr-w337-asan2.log`): `heap-use-after-free`,
  `WRITE of size 1028`, stack `recv` → `NetHandler::receive` (`:649`) →
  `tcpReceive` (`:577`) → `handleTcpPacket` (`GameKeeper.cxx:374`) → `main`.
- Instrumented marker arm, port 15173 (`ptr-w337-plain-marker.log.out:38`):
  `Player BZP-PTR-MARKER-W336 [0] outbound UDP up`, with header code
  `MsgUDPLinkEstablished` (0x6f67) and the sentinel string at
  `PlayerInfo::callSign` offset 76.
- **Unmodified stock marker arm**, port 15177
  (`ptr-w337-stockmarker.log.out:38`): the same print with no instrumentation
  in the binary. `gdb ptype /o PlayerInfo` on that binary reports
  `/* 76 | 32 */ char callSign[32];`, and the marker string exists only in the
  rebuilt sentinel `.so` (`grep -c BZP` on the client is 0). The print is
  stock `logDebugMessage(2, "Player %s [%d] outbound UDP up\n",
  info->getCallSign(), playerIndex)` in `NetHandler::tcpReceive()`.
- Fixed v2.4.32 pointer and marker arms (ports 15172/15174): first packet
  rejected with `sent huge packet length (len=1024), possible attack`,
  second `sendall` BrokenPipe, server alive, zero marker prints.
- Well-formed safe input, port 15175: ordinary `info=0x575a2cbbe918`, server
  alive, no chosen-pointer trace. `randomize_va_space=2` in every arm;
  `ss -ltn` showed ports 15170–15177 free after replay.

Counterexamples and limits: the witness's first ASan arm (port 15171) exited
before connect with "ASan runtime does not come first", caused by its
LD_PRELOAD ordering; re-running with `libasan.so.8` preloaded first
reproduced the write. Its added trace reads `info->now` immediately before
stock `countMessage` reads the same field, so it does not manufacture a
dereference; the unmodified-stock marker arm removes that concern
independently. The marker print still needs `-d2` and the lab LD_PRELOAD
sentinel at a fixed canonical address. No wire-side command side effect, no
remote shell, no deployment claim. Full evidence:
`.mishe-tauftauf/artifacts/witness-w337-bzfs/detail.md`, console summaries
`.mishe-tauftauf/artifacts/witness-w330-bzfs/w337-*.console`, and the
gitignored server logs `lab/bzfs2shell-live/ptr-w337-*.log{,.out,.client}`.
