# Frontier brief — BZFlag bzfs TCP length overrun (Bzfs2Shell)

**Status: new frontier find, handed off to the operator 2026-11-21 ~00:2xZ for
admission under the standing similar-things mandate. Rungs 1/2/3 ESTABLISHED
and attacker-chosen bytes read back byte-exact at a chosen preceding member
offset in an extracted, source-bound harness; rung 4 is INSTRUMENTED
CHOSEN-VALUE CONTROL, NOT a live-bzfs, real-object-layout or execution
demonstration. No live server, real socket, allocator neighbour, function
pointer or code execution was observed — all of those stay UNKNOWN.
Two-artifact rule satisfied: this brief and a live two-pane `bzfs2shell` window
with a registry entry and seed wall. Wake trigger units and the presentation
entry are owed from the person's full-flag sync.**

**Scope judgment for the operator**: `bzfs` is a dedicated C++ game server, not
a language runtime or HTTP server. It is included here as an X2Shell-class
candidate because the primitive is a network-reachable, unauthenticated heap
out-of-bounds write with directly chosen bytes and an advisory claim of
command execution as the `bzfs` user. Admission is the operator's call; this
brief does not pre-empt it.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-130849, "BZFlag bzfs before 2.4.32 Heap Out-of-Bounds
  Write via NetHandler::tcpReceive()" (CNA VulnCheck, published 2026-11-17,
  modified 2026-11-19), GHSA-9q5f-g948-c95m, EUVD-2026-127253. **Critical 9.3**,
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, **CWE-122
  heap-based buffer overflow**. Claim: a TCP message with a body length of
  exactly 1024 overwrites the `tcplen` receive offset with a negative value,
  writing controlled bytes before the buffer, crashing the server or executing
  commands as the `bzfs` user. RCE is an advisory claim; no exploit or live
  demonstration was published with the advisory, and this lab did not
  demonstrate execution.
- **Affected/fixed**: OSV lists affected `< 2.4.32` (all enumerated 1.x/2.x
  releases including v2.4.30) and fixed `2.4.32`. The v2.4.32 release notes
  and the fix patch were read directly.
- **Fix commit**: `8e501d685aef549090b363260979a4eb93484ea1` (Andrew Wilke,
  2026-11-06; committed by blast007), patch subject "fix TCP length overrun in
  NetHandler". OSV also resolves the v2.4.32 tag to fix commit
  `f11f05485d7406c78159aac00ace3c58b4b17ec2`. Vulnerable tag read: `v2.4.30`;
  fixed tag read: `v2.4.32`. Credit: Landon Rice.
- **Claim sources read**: the OSV/CVE JSON, GHSA entry, VulnCheck advisory,
  cvelistV5 record, v2.4.32 release notes, the fix-commit patch, and raw source
  at `v2.4.30` / `v2.4.32`. Exact URLs, tags, local paths and SHA-256 digests in
  `lab/frontier/bzfs2shell/PROVENANCE.md`. Read-only provisioning only;
  **no probe, connection or traffic to any non-loopback system**.
- **Scope separation**: distinct from the owned ruby2shell, php2shell,
  node2shell, Apache, xrdp, FreeRDP, FreeSWITCH, GStreamer, Babelfish,
  PostgreSQL, Mosquitto and MapServer lanes. No credential, non-default module
  or game-state prerequisite appears in the patch or advisory: the overflow is
  in the initial TCP header/body reader on the listening player socket.
- **Ranking**: high tractability for the memory-corruption ladder. The defect
  is one off-by-header bound in one function, the fix diff is 13 lines, the
  trigger is one unauthenticated TCP packet pair, and the bytes that cross the
  buffer boundary are the tail of the attacker's own body. Ranked above the
  screened-out list on the wall. Scope fit is the only open judgment.

## Source-bound mechanism (read from both tags and the fix)

Line numbers are from `v2.4.30` unless marked fixed.

1. `include/Protocol.h:52-53` — `MaxPacketLen = 1024`, described as the maximum
   message size **including** the 4-byte header.
2. `include/NetHandler.h` — the input members are adjacent:
   `char tcpmsg[MaxPacketLen]; int tcplen;`. `tcplen` is the read offset into
   `tcpmsg`, held as a signed `int`.
3. `src/game/NetHandler.cxx:571-579` — `tcpReceive()` first reads the 4-byte
   header with `receive(4)`, leaving `tcplen = 4`.
4. `NetHandler.cxx:582-592` — it unpacks the big-endian 16-bit payload `len`
   and rejects only `len > MaxPacketLen`. `len == 1024` therefore passes even
   though the header is already in the same 1024-byte buffer.
5. `NetHandler.cxx:594` — `receive(4 + (int)len)` asks for 1028 total bytes.
6. `NetHandler.cxx:635-639` — `receive()` calls
   `recv(fd, tcpmsg + tcplen, length - tcplen, 0)`; with `tcplen = 4` that is
   `recv(fd, tcpmsg + 4, 1024)`. The 1024 body bytes occupy `tcpmsg[4..1027]`:
   **four bytes past the array, landing on the adjacent `tcplen` member**.
   Those four bytes are the tail of the attacker's body, so they are chosen.
7. `NetHandler.cxx:639` — after the `recv`, `tcplen += size` reads the just
   clobbered value and adds 1024. Choosing a negative four-byte value leaves a
   negative `tcplen`; the function returns `ReadPart` rather than `ReadAll`, so
   the corrupted offset is not reset by `tcplen = 0` at line 602.
8. On the next `tcpReceive()`/`receive()` for that player,
   `tcpmsg + tcplen` is the `recv` **destination** and `4 - tcplen` the length:
   attacker bytes are written before `tcpmsg`, into the preceding members of
   the same heap-allocated `NetHandler` object (`ares`, `info`, `uaddr`,
   `playerIndex`, `fd`, `peer`, `dotNotation`, …). The advisory's claim of
   server control follows from that member overwrite but was not demonstrated.
9. **Fix** (`8e501d6`, present at `v2.4.32:590` and `:644`): hunk 1 bounds the
   payload to `len > MaxPacketLen - 4`, so `len == 1024` is rejected as
   `ReadHuge` before any body read; hunk 2 rejects `tcplen < 0`,
   `tcplen > sizeof(tcpmsg)` and `length > sizeof(tcpmsg)` before the `recv`,
   so a corrupted offset cannot become a wild destination even if one arises.

## Consumer-reality check

The consumer is the kernel's `recv(2)` writing into a caller-supplied pointer,
not a libc string/memory routine with an implementation-dependent dispatch
order. The harness supplies the exact 1028-byte stream on an in-process
`AF_UNIX` socketpair, so the past-end bytes and the negative-offset write are
performed by the real syscall, not by a simulated copy. Rung 4 readback proves
byte-exact placement at the chosen harness member. What remains unknown is
stock-layout attribution: the harness uses a deterministic stand-in for the
opaque `Address`/`std::string` prefix, so which real member a given negative
offset reaches in a stock bzfs build is **UNKNOWN**, as is whether the stock
prefix places `tcpmsg` less than 1024 bytes into the object.

## Local evidence (extracted harness, all replayed)

Harness `lab/frontier/bzfs2shell/tcp_len_overflow.cpp` (+ `run.sh`,
`PROVENANCE.md`, pinned `src/`). Pins: C
`1a16963f64a26b7060a552766485d0de5dfe794d5d3fa57fd763d6289e847a77`,
runner `f2686d5b660dcac17384d739763fc47802806a152e180e3b122c97dfaf6a8e3a`.
From committed HEAD, `bash lab/frontier/bzfs2shell/run.sh out` printed
`ALL CHECKS PASS rc 0`; five-run digest
`sha256=cea3b92e3455454ea45ef79232cb49b9e70132134fb8bb6245e5c1ea644ecc89`.

- **Rung 1 (reproducible trigger)**: header `len=1024`, body tail
  `0xFFFFF800`; traced `recv` destination `tcpmsg+4`, length 1024, all 1024
  bytes returned, tail bytes equal the chosen value; observed
  `tcplen = -1024` after `tcplen += size`. Fixed control: `ReadHuge`, one recv
  call (header only), `tcplen = 4`.
- **Rung 2 (accounting failure)**: `tcplen=-1024`, next destination 936 bytes
  before the object, next read length 1028 instead of 4. Fixed guard rejects
  negative offset, over-max offset and oversized length with zero recv calls.
- **Rung 3 (confirmed corruption)**: ASan build, body tail chosen for a
  destination 16 bytes before the heap object; `ERROR: AddressSanitizer:
  heap-buffer-overflow`, `WRITE of size 64`, stack through `traced_recv` →
  `receive_msg` → `mode_rung3`. Fixed-rung3 and both other fixed controls are
  ASan-clean.
- **Rung 4 (instrumented chosen-value control)**: body tail chosen for a
  destination at the object's first member; a second 44-byte network write
  places `DEADBEEFCAFEBABE` and `0123456789ABCDEF` at the `ares` and `info`
  members, read back byte-exact. Fixed control leaves `ares` untouched.

**Grade**: rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4
INSTRUMENTED chosen-value control only. No live bzfs process, real player
socket, stock object layout, neighbouring heap object, function-pointer
overwrite, execution, witness replay or independent acceptance.

## Cheapest next experiments to move up a rung

1. Build stock `bzfs` 2.4.30 locally (loopback only) and send the 1028-byte
   header/body to a local listening server with a debug hook on `receive()`;
   confirm the real `NetHandler` object layout and the 4-byte `tcplen` clobber.
   This closes the stock-layout attribution gap and would promote rung 4 from
   instrumented to demonstrated-if the chosen offset reaches a useful member.
2. Under ASan-instrumented stock build, replay the same packet sequence and
   capture a symbolised `recv` write report with the real `NetHandler` frame.
3. Map the offset from `tcpmsg` to the highest-value member in the real layout
   (a `void*`, `std::string` control block or `PlayerInfo*`) and show a chosen
   pointer value read back from it. No execution claim until that is observed.

## Witness replay instructions

From a clean checkout of the committed HEAD, run
`bash lab/frontier/bzfs2shell/run.sh <your-outdir>` and compare digests and the
four rung observations above. Do not accept this author report as verdict.
