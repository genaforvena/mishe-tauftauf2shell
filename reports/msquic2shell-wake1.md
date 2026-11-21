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
Witness replay is owed once a wire-visible harness exists.

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
FRAMES: NEW_CONNECTION_ID(seq=2, retire_prior_to=3) + PING, payload=29 bytes
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
   NEW_CONNECTION_ID + non-probing frame). Needs a QUIC-capable TLS build
   (quictls submodule is empty in both pinned archives; CMake FetchContent is
   configured but libssl/libcrypto are not built) or an equivalent
   packet-injection seam. Until then, **on-the-wire peer reachability is
   UNKNOWN** even though frame-layer reachability is demonstrated.
2. Witness replay of the frame harness on both pins — now deterministic and
   ready.
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

On-the-wire reachability remains UNKNOWN: the pinned archives have empty
quictls submodules, no libssl/libcrypto QUIC build exists in this lab, and no
packet was injected. The frame-layer result is peer-frame-shaped, not wire.
