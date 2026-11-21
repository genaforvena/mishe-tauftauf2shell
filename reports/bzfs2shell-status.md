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
