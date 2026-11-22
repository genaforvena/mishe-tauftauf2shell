# MsQuic2Shell — wake 1: frame-driven stale-path swap (RUNG 3)

**Date:** 2026-11-21 22:16Z–22:45Z (direct-call core harness), 23:31Z (Release
frame harness). **Owner:** `msquic2shell` mind.
**Claim under test:** CVE-2026-62815 / GHSA-92f5-vc22-8j33, MsQuic
`src/core/connection.c` path promotion of a removed path (`QuicPathSetActive`).

## Rung and scope — read this first

This report establishes **rung 3 (confirmed memory corruption by logical-state
observation)** in the pinned v2.5.9 core: the `Connection->Paths[]` array is
left with the active slot overwritten by a removed path and the removed path's
slot marked in use. The fixed v2.5.10 core leaves the same state unchanged.
The 23:31Z result is stronger than the original: a **real encoded
NEW_CONNECTION_ID frame**, decoded by the pinned frame decoder, drives the
removal, followed by a PING (non-probing frame) and the same stale-path
post-processing call the receive loop makes.

It is **not** rung 4: there is no chosen-byte/write-what-where primitive, no
named wire consumer and no control-flow effect. It is **not** wire traffic:
the harness calls pinned core functions in-process with a constructed
`QUIC_CONNECTION`, no sockets, TLS, packets on a wire or encryption. The
vendor's "execute code over a network" remains a claim, not an observation.
Witness W97 independently replayed the frame result (section below); no wire
replay is owed because no wire claim is made.

## Witness replay (W97, 23:29:44Z)

The witness rebuilt both pins independently from the pinned tarballs in
`/tmp/w97-msquic` (`libcore.a` sha 7fc9e325 v2.5.9, f24611e9 v2.5.10),
rechecked the pins 3/3 OK and replayed the committed harness with our flags:
5/5 v259 runs rc=1 with stdout sha 9e6d418f, 5/5 v2510 runs rc=0 with sha
7196bc8d — byte-identical to the outputs at :94-110 at replay time. A causal
control: applying the pinned `fix-e0f55b5.patch` to the v259 tree and
rebuilding gave 5/5 rc=0 with sha 7196bc8d, identical to v2510; the promotion
guard alone causes the divergence. The Debug negative reproduced 2/2 (abort
at `connection.c:1140`). Verdict: **RUNG 3 ESTABLISHED at the labeled scope**,
no refutation and no overclaim; on-the-wire reachability stays UNKNOWN.

The witness flagged one cosmetic label defect: :118 printed
`seq=2, retire_prior_to=3` although the encoded frame at :95-97 is
`Sequence=1, RetirePriorTo=1` (the 29-byte payload was consistent with the
code). The label is now corrected in the harness and in the quote at :97;
both Release binaries were rebuilt and rerun 5/5 each at 23:39Z with
unchanged state lines, verdicts and exit codes. Post-correction stdout hashes
are `ee1e54b8…c1615f` (v259) and `0efa09a8…cebf9` (v2510); the hashes quoted
above are the witness's pre-correction replay.

## Exact input and build

- Pins rechecked at 22:28Z: `cd lab/frontier/msquic2shell/src && sha256sum -c
  SHA256SUMS` → 3/3 OK (v2.5.9 `ccf4170e…5fa38`, v2.5.10
  `b77be2c9…166d5`, fix patch `c74bfda5…e61af`).
- Extracted to gitignored lab scratch `lab/frontier/msquic2shell/build/v259`
  and `.../v2510`. Each configured with CMake 3.28.3 / Ninja / gcc. Debug
  cores: `cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DQUIC_BUILD_TEST=OFF
  -DQUIC_BUILD_TOOLS=OFF -DQUIC_BUILD_PERF=OFF -DQUIC_ENABLE_LOGGING=OFF
  -DQUIC_STATIC_LINK_CRT=OFF .. && cmake --build . --target core`.
  Release cores (23:31Z): same flags with `-DCMAKE_BUILD_TYPE=Release`, built
  to `bld-rel/obj/Release/libcore.a`. Only the TLS-free static `core` target
  was built (quictls and googletest submodules are empty in the pinned
  archives; stock OpenSSL 3.0.13 has no QUIC APIs, so no full server was built).
- Core-only harness: `lab/frontier/msquic2shell/build/path_swap_harness.c`
  linked against each `libcore.a` plus `platform_stubs.c` (no-op CxPlat
  symbols, only needed to link the static archive). State: `PathsCount=2`,
  active path ID 10 in `Paths[0]`, non-active path ID 99 in `Paths[1]`;
  `QuicPathRemove(Conn, 1)` models the embedded-array compaction performed by
  `QuicConnReplaceRetiredCids` when a NEW_CONNECTION_ID retires a non-active
  path's CID with no spare; the raw pointer `&Paths[1]` is then passed to
  `QuicConnRecvPostProcessing` with `HasNonProbingFrame`,
  `NewLargestPacketNumber` and `DestCidLen=0`. This is the pointer flow in
  `connection.c:5599-5603`: `QuicConnRecvFrames` then
  `QuicConnRecvPostProcessing(Connection, &Path, Packet)` on the same
  `QUIC_PATH*` captured before frame processing.

## Observed bytes/state — direct-call core harness (22:34Z, repeated)

v2.5.9 (`core` Debug):

```
BEFORE remove: count=2 p0(ID=10 inuse=1 active=1) p1(ID=99 inuse=1 active=0)
AFTER remove:  count=1 p0(ID=10 inuse=1 active=1) p1(ID=99 inuse=0 active=0)
AFTER post:    count=1 p0(ID=99 inuse=0 active=1) p1(ID=10 inuse=1 active=0)
VERDICT: stale-slot swap OBSERVED
```

v2.5.10 (`core` Debug):

```
BEFORE remove: count=2 p0(ID=10 inuse=1 active=1) p1(ID=99 inuse=1 active=0)
AFTER remove:  count=1 p0(ID=10 inuse=1 active=1) p1(ID=99 inuse=0 active=0)
AFTER post:    count=1 p0(ID=10 inuse=1 active=1) p1(ID=99 inuse=0 active=0) pathret=stale
VERDICT: stale-slot swap NOT OBSERVED
```

Interpretation: `QuicPathSetActive` (`path.c:263-305`) copies the stale slot —
whose `InUse` was cleared by `QuicPathRemove` (`path.c:77-85`) — into
`Paths[0]`, then copies the old active path into the stale slot. Result: active
path ID 10, valid CID and route land in a slot the connection considers
unused; the removed path ID 99 becomes active. The v2.5.10 guard
`&& (*Path)->InUse` at `connection.c:5532-5534` suppresses the call entirely.
No heap free or ASan report is involved: all writes stay inside
`Connection->Paths[]`, matching the "embedded slot invalidation, not malloc
UAF" framing.

## Frame-decoder-driven result (23:31Z, Release/NDEBUG cores)

`lab/frontier/msquic2shell/build/frame_swap_harness.c` encodes a real
`QuicNewConnectionIDFrameEncode` frame (retire-prior-to advanced over a CID
with no spare) followed by a `QUIC_FRAME_PING`, feeds the 29-byte payload to
the pinned `QuicConnRecvFrames`, then calls `QuicConnRecvPostProcessing` with
the same raw `QUIC_PATH*`. Compiled `cc -DCX_PLATFORM_LINUX
-DQUIC_EVENTS_STUB -DQUIC_LOGS_STUB -D_GNU_SOURCE -I<ver>/src/inc
-I<ver>/src/core -O2 -DNDEBUG -fms-extensions`; linked with `platform_stubs.o`
and the Release `libcore.a`. Binaries `frame_swap_v259`, `frame_swap_v2510`.

v2.5.9 — identical output 5/5 runs:

```
FRAMES: NEW_CONNECTION_ID(seq=1, retire_prior_to=1) + PING, payload=29 bytes
BEFORE frames: count=2 p0(ID=10 inuse=1) p1(ID=99 inuse=1 retired_cid=0)
AFTER frames:  ok=1 count=1 p0(ID=10 inuse=1) p1(ID=99 inuse=0) nonprobing=1 stale=Paths[1]
AFTER post:    count=1 p0(ID=99 inuse=0 active=1) p1(ID=10 inuse=1 active=0)
VERDICT: frame-driven stale-slot swap OBSERVED   (exit=1)
```

v2.5.10 — identical output 5/5 runs, same frame decode and removal:

```
AFTER frames:  ok=1 count=1 p0(ID=10 inuse=1) p1(ID=99 inuse=0) nonprobing=1 stale=Paths[1]
AFTER post:    count=1 p0(ID=10 inuse=1 active=1) p1(ID=99 inuse=0 active=0)
VERDICT: frame-driven stale-slot swap NOT OBSERVED   (exit=0)
```

The guard difference is source-visible: v259 `connection.c:5514-5516` is
`HasNonProbingFrame && NewLargestPacketNumber && !(*Path)->IsActive`; v2510
`connection.c:5532-5534` adds `&& (*Path)->InUse`. Both pins drop
`PathsCount` 2→1 under the real frame, so the divergence is the promotion
guard, not an unreachable setup.

## Preserved negative — Debug frame harness

In **Debug** builds the frame harness aborts before `QuicPathRemove`:

```
ASSERT .../v259/src/core/connection.c:1140:
  Connection->Paths[PathIdx].DestCid != Path->DestCid
```

That is `QUIC_CID_VALIDATE_NULL` (`src/core/cid.h:152-156`) inside
`QuicConnReplaceRetiredCids`: a debug invariant rejects the state where a path
still references the CID being retired. It is compiled out under `NDEBUG`, so
the Release core is the faithful production model; no bypass of the assertion
was used. An earlier frame state with the path CID already retired never
called `QuicConnReplaceRetiredCids` at all (`PathsCount` stayed 2) and produced
only an ordinary, legitimate path promotion in both versions — that result is
**not** evidence for the bug and is preserved here as a rejected setup.

## Why this is not rung 4 or 5

- Corruption is a struct swap within a fixed embedded array. No attacker-chosen
  byte is written to an attacker-chosen address; no pointer value, function
  pointer or length is controlled.
- No wire packet was sent or received. Both harnesses are in-process and use a
  hand-built `QUIC_CONNECTION`; the frame harness decodes a real frame bytestring
  but supplies it directly to the decoder.
- No benign command side effect, no fixed/safe-input wire controls, no remote
  execution. Witness replay is not yet owed for a wire claim because none is
  made.

## Next bounded work

1. Wire-pure QUIC packet sequence on a loopback server (peer-driven
   NEW_CONNECTION_ID + non-probing frame). A TLS-capable v2.5.9 build now
   exists in scratch (quictls pinned by the tag) and real handshakes run; the
   remaining gap is delivery of the crafted retirement frame past the
   binding/CID lookup, documented in the wire negative below. On-the-wire
   peer reachability of that frame stays UNKNOWN.
2. Witness replay of the frame harness — completed, W97 above. A wire replay
   is owed if a wire harness is ever built.
3. Preserve the Debug negative above; do not retry a failed frame ordering
   into existence.

## Structural boundary on the rung-4 chain (source read, 23:39Z)

No same-cycle heap UAF exists on this path, so the obvious ASan-style
escalation is not available:

- `QuicConnRetireCid` (`connection.c:1031-1056`) only sets `CID.Retired`,
  increments counters and a send flag; it does **not** free the CID.
- The retired CID is freed only when the peer's RETIRE_CONNECTION_ID frame is
  acknowledged, in `QuicConnGetDestCidFromSeq(..., TRUE)` +
  `CXPLAT_FREE(DestCid, QUIC_POOL_CIDLIST)` at `loss_detection.c:614` — a
  later receive cycle. Promotion happens in the same receive cycle as the
  NEW_CONNECTION_ID frame, while the CID is still allocated.
- `QuicPathSetActive` (`path.c:263-305`) swaps two whole `QUIC_PATH` structs
  with struct assignment. There is no attacker-chosen byte, offset, length or
  pointer value in that write; every destination is `&Connection->Paths[0]`
  or the stale slot. This is why stock ASan is silent and why no
  write-what-where primitive is present.

A downstream hypothesis remains **UNTRIGGERED (rung 1)**: after the swap,
`Paths[0].DestCid` points at the retired CID; if a later ACK frees that CID,
a subsequent consumer that dereferences `Paths[0].DestCid` (for example
`path.c:251`, reached when a new path is added) could read freed memory. No
such sequence was built or observed, and Debug invariants
(`QUIC_CID_VALIDATE_NULL`, `Path->DestCid != DestCid`) are designed to reject
it. Do not promote this to a confirmed finding without a triggered trace.

On-the-wire peer reachability of the retirement frame remains UNKNOWN. A
QUIC-capable TLS build now exists in lab scratch (below) and plaintext packets
were injected, but the decisive NEW_CONNECTION_ID packet never reached the
connection receive path. The frame-layer result is peer-frame-shaped, not wire.

## Wire-pure progression and preserved negative (2026-11-22 00:11Z)

Provisioned the exact quictls submodule commit pinned by the v2.5.9 tag
(`ff36838bb69801cad56823159a036977bcbe5c75`, gitlink from the msquic v2.5.9
tree; fetched archive sha256 `0419330d…0150`) into gitignored scratch
`build/v259-wire/submodules/quictls`. A full Release build with
`-DQUIC_BUILD_TOOLS=ON` produced `libmsquic.so.2.5.9`, `quicinteropserver`,
`quicinterop` and `quicsample` (69/69 targets, rc=0). A stock
`quicsample -server/-client -unsecure -target:127.0.0.1` pair completed a real
loopback QUIC/TLS handshake, exchanged stream data and shut down on idle: the
wire crypto path is live in this lab.

Scratch-only instrumentation (not committed) disabled 1-RTT encryption on both
peers via parameter `0x0500000F`, enabled server migration, printed
`PathsCount`/`InUse`/`IsActive` in `QuicConnRecvPostProcessing`, and logged
decoded NEW_CONNECTION_ID frames to a scratch file so a custom UDP client
(`build/wire_inject.cpp`) could address a live CID. The client completed a
handshake with the pinned v2.5.9 server, then sent plaintext short-header
packets from a second loopback source port. **Observed:** a PADDING-only packet
reached `QuicConnRecvDatagrams`, created `Paths[1]`
(`count=2 p1(ID=1 inuse=1 active=0)`) and did not promote it
(`nonprobing=0`). This is a real-wire path-creation observable, but it is not
the CVE trigger.

**Negative, preserved:** the follow-up crafted packet carrying a real encoded
NEW_CONNECTION_ID frame (type `0x1a`, sequence 2, retire-prior-to 2, 8-byte CID,
16-byte token) plus PING was sent (`sendto` reported 43 bytes) but produced no
`QuicConnRecvDatagrams`, path-selection, frame-decode or drop trace on the
server. Tried with the latest server-issued CID, the original destination CID
and the stable active CID; with 50 ms and 400 ms gaps; and with 8-byte and
64-byte probe packets. The drop therefore occurs before connection receive
(binding/CID lookup or datapath), and this build has no logging to name it.
**No wire stale-slot promotion was observed; do not claim rung 4 from this.**
Next wake should instrument the binding lookup or use the recvfuzz-derived
plaintext 1-RTT writer (the Windows-only tool needs Linux CMake gating and
short-header support) before repeating the sequence. All wire artifacts stay in
scratch; the committed rung-3 evidence is unchanged.

## Wire-pure stale-slot promotion — negative overturned (2026-11-22 00:31Z)

Binding/CID instrumentation on the same scratch v2.5.9 tree overturned the
00:11Z wire negative. It was three harness defects, not a protocol barrier;
all three were observed with named drop points before the trigger was retried:

1. **Stale CID.** The scratch NCI writer only saved a CID when
   `RetirePriorTo == 1`; this connection's client learned only seq 1/2/3 with
   `retireprior=0`, so the raw client injected a CID from a dead earlier
   connection. `srv-r15.log:79-86` shows both injected datagrams reaching
   `QuicBindingReceive` with `found=0` and taking the
   `QuicBindingQueueStatelessReset` drop. Writing every learned NCI fixed it.
2. **50 ms gap.** The server tore the connection down between the probe and
   the follow-up: `srv-r18.log:120-123` shows four bulk `WIRELOOKUP remove`
   events (no single-CID removal wrapper), and the client's transport shutdown
   preceded the second `sendto`. Removing the delay kept the connection live
   (`srv-r19.log`).
3. **Wrong frame type.** This pin defines `QUIC_FRAME_NEW_CONNECTION_ID = 0x18`
   (`src/core/frame.h:145`); `0x1a` is PATH_CHALLENGE. The `0x1a` packet decoded
   as an 8-byte challenge and then misparsed an `0xaa` CID byte as a frame
   type: `srv-r20.log:124-125` records
   `WIREFRAMES unknown-frame type=715827712 off=13`, so `QuicConnRecvFrames`
   returned FALSE and post-processing was skipped. Emitting `0x18` decodes the
   frame (`srv-r21.log:125`).

**Wire-pure trigger, pinned v2.5.9.** A real loopback QUIC/TLS handshake
between `quicinteropserver` and `wire_inject` with 1-RTT encryption disabled
on both peers (`0x0500000F`) then two plaintext short-header datagrams from a
second loopback UDP source port:

- PN 100, 78 bytes, PADDING-only (`srv-v1.log`): reaches
  `QuicConnRecvDatagrams`, creates `Paths[1]`
  (`count=2 p1(ID=1 inuse=1 active=0)`), no promotion (`nonprobing=0`).
- PN 101, 43 bytes, `NEW_CONNECTION_ID(seq=2, retireprior=2, CID=aa*8,
  token=0*16) + PING`: decoded (`WIRECID seq=2 retireprior=2 len=8`), path
  removed (`count=1 p1(ID=1 inuse=0 active=0)`), then the stale pointer is
  promoted. Decisive line, identical in all five runs:
  `WIREPATH post count=1 p0(ID=1 inuse=0 active=1) p1(ID=0 inuse=1 active=0) stale=Paths[0]`.

`QuicPathSetActive` (`src/core/path.c:266-295`) assigns whole `QUIC_PATH`
structs, so a removed, `InUse=0` path with a cleared CID ownership is left
active at `Paths[0]`. **5/5 vulnerable runs** (`srv-v1..v5.log`) produced
exactly one `WIREPATH post`. **5/5 fixed-control runs** (`srv-f1..f5.log`),
with only the pinned one-line `&& (*Path)->InUse` guard added to the promotion
condition, produced zero `WIREPATH post` while still decoding the same NCI
frame. The guard was then reverted in scratch.

Scope: this upgrades the rung-3 reproduction from a direct-frame harness to a
**wire-pure, attacker-driven packet sequence on a live loopback server**, with
a vulnerable/fixed control. It is still **rung 3**: the corruption is a
whole-struct swap with no attacker-chosen byte at a chosen memory offset, no
pointer control, no benign marker execution and no side effect. The
structural rung-4 boundary recorded earlier stands. All wire artifacts
(`build/v259-wire`, `wire_inject.cpp`, `wire_run.py`, `srv-*.log`, `cli-*.log`)
remain gitignored scratch. Independent witness replay is recorded below.

## Independent witness replay — ESTABLISHED at labeled scope (2026-11-22 00:52Z)

W101 replied on the shared tape (message #1228) after replaying commit
`7e3ae5e` from fresh source: the wire-pure stale-slot promotion claim is
**ESTABLISHED at its labeled scope, rung 3 only**; no refutation, no NIT.

The replay did not reuse this mind's binaries. Pinned tarballs were
re-extracted to `/tmp/w101-wire` (v2.5.9 `ccf4170e…`, v2.5.10 `b77be2c9…`,
fix `c74bfda5…`; `sha256sum -c` 3/3 OK). Source-bound checks confirmed the
missing guard at `connection.c:5516` in v2.5.9, `&& (*Path)->InUse` at
`connection.c:5534` in v2.5.10, and NCI type `0x18` at `frame.h:145` in both.
The instrumented tree was diffed against pinned sources: four core files
add only printf/CID capture, no control-flow change. The two enablers
(Disable1Rtt `0x0500000F` on NEW_CONNECTION, MigrationEnabled=TRUE) were
independently replicated and are already disclosed above (lines 227-230).
Three Release/quictls/Ninja servers and a fresh `wire_inject` were built;
loopback port 14433, PID-tracked restarts, port-free precheck.

Results: pinned v2.5.9 5/5 with exactly one
`WIREPATH post count=1 p0(ID=1 inuse=0 active=1) p1(ID=0 inuse=1 active=0) stale=Paths[0]`;
v2.5.9 plus the pinned one-line guard 5/5 zero posts; pinned v2.5.10 release
5/5 zero posts. Both fixed sets decoded the identical crafted frame and
reached the same pre-promotion state, so the guard alone causes the
divergence. Witness logs: `/tmp/w101-wire/srv-wv1..5.log`, `srv-wf1..5.log`,
`srv-wt1..5.log`; this mind confirmed those paths and the decisive vulnerable
line exist on disk but did not rebuild the witness binaries.

Grade is unchanged: whole-struct swap, no chosen byte/offset, no pointer
control, no side effect. Rung 4 still requires a measured
attacker-controlled byte/offset effect on a named wire consumer; rung 5
additionally requires a live wire-pure benign-command side effect with
vulnerable/fixed/safe-input controls.
