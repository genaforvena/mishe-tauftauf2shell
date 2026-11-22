# Frontier brief — VRPN SENDER/TYPE_DESCRIPTION length index (CVE-2026-123200)

**Status (2026-11-22 ~01:1xZ, operator admission): ADMITTED as `vrpn2shell`
under standing approval #6.** RUNG 3 in a direct-call harness on the real
pinned 07.36 library; wire dispatch of the crafted message confirmed under
gdb. Rung 4 UNKNOWN, wire ASan negative so far, no rung 5. The operator
adopted frontier's staged two-pane window 74, charter, seed wall and registry
entry, and added the 69th wake route. Witness replay required for any
published claim; none in hand at admission.

## Verified ground truth (primary sources)

- Claim: NVD record `CVE-2026-123200` — "VRPN through 07.36 contains an
  out-of-bounds stack write vulnerability in `vrpn_Endpoint::handle_sender_message()`
  and `handle_type_message()` that allows unauthenticated remote peers to write
  outside a stack buffer via an unchecked length index. Attackers can connect,
  complete the version-cookie exchange, and send a SENDER_DESCRIPTION or
  TYPE_DESCRIPTION message with an out-of-range or negative index to crash the
  process." CWE-787, network vector.
- Fix: upstream `vrpn/vrpn` commit `0da5b0b71e06e8c318a4e674c84caee12251a782`
  ("Fixes unchecked write past bounds bugs reported by Deus Rex"), with a
  follow-on `c893b583d928fd17d756b39271b2eae71766e7f2` bumping the wire cookie
  from `vrpn: ver. 07.38` to `07.39`. Both patches fetched verbatim; SHA-256 in
  `lab/frontier/vrpn2shell/PROVENANCE.md`.
- Affected/fixed: through 07.36 per the CVE; the fix first appears after the
  pinned 07.38 source and is identified by the 07.39 cookie bump. The precise
  released fixed version is UNKNOWN from these two commits alone.
- Consumer: `vrpn_server` (VRPN generic server) registers both system handlers
  in `vrpn_Connection.C:4917-4920` and accepts unauthenticated TCP clients.

## Source-bound mechanism (pinned bytes, not rendered line numbers)

Pinned `vrpn_Connection.C` at `79deb000cc0b47ae49a80c92c78167c02d8a04d8`:

- `vrpn_CNAME` is `char[100]` (`vrpn_Connection.h:156-157`).
- `handle_sender_message()` (`:4534-4554`): `p.payload_len` is checked to be
  `<= sizeof(vrpn_CNAME)`, then the name bytes are copied with `strncpy` using
  `p.payload_len - 4`. That copy is bounded. The following statement
  `i = ntohl(*((const vrpn_int32 *)p.buffer)); sender_name[i] = '\0';` uses the
  wire-supplied signed 32-bit value as an index with **no check at all** against
  the 100-byte buffer or the payload length.
- `handle_type_message()` (`:4462-4482`) has the identical defect on
  `type_name[i]`.
- The fix clamps with `min(i, sizeof(name) - 1)` and changes the index type to
  `vrpn_uint32`, confirming the unbounded index was the defect.

Primitive: a single NUL byte written at an attacker-chosen signed offset from
a 100-byte stack array. The byte value is fixed (NUL), not attacker-chosen.
Reach is pre-auth after the 24-byte version-cookie exchange; no credentials.

## Local work performed this wake (all observed)

- Shallow clone of tag `v07.36` and a full ASan `vrpn_server` build succeeded
  (`lab/frontier/vrpn2shell/build-asan-07.36/.../vrpn_server`, CMake configure
  and build logs in `cfg-asan.log` / `build-asan.log`).
- `wire_inject.py` performs the loopback-only 24-byte cookie exchange, then
  sends one `SENDER_DESCRIPTION` (type `-1`) message: 24-byte VRPN header
  (length, tv_sec, tv_usec, sender, type, seqno), payload `int32_be(index) +
  "AAAA"` padded to `vrpn_ALIGN=8`. Framing was read from
  `marshall_message()` (`:4377-4458`) and `getOneTCPMessage()` (`:4163-4245`).
- `run.sh` with indices `-64` and `4` on 127.0.0.1:13893: server accepted the
  TCP connection and stayed alive, with no ASan report. A first attempt failed
  mechanically (unsigned `struct.pack` of `-1`, missing `vrpn.cfg`) and was
  fixed; the second run is the valid observation.
- `gdb-wire.sh` at 127.0.0.1:13896 with index `-64` proved the wire path:
  breakpoint hit at `vrpn_Connection.C:4535`, frames `#1
  vrpn_TypeDispatcher::doSystemCallbacksFor:1446`, `#2 ...:1424`, `#3
  vrpn_Endpoint::dispatch:4331`, with `type=-1, sender=0, payload_len=8`.
  This is a real server process receiving a real TCP message, not a synthetic
  call. `out-gdb-01/gdb.log`.
- Direct-call harness `harness/handler_direct.cpp` links the **real**
  `build-asan-07.36/libvrpnserver.a` and calls
  `vrpn_Endpoint::handle_sender_message()` with a wire-shaped payload.
  Indices `100`, `128`, `-256` give `ERROR: AddressSanitizer:
  stack-buffer-overflow`, `WRITE of size 1` at the real write site
  `vrpn_Connection.C:4554` (`out-direct-01/i*.out`). Indices landing inside the
  frame reach a later null-`userdata` dereference at `:4560` — a harness
  artifact, not the vulnerability.
- Fixed control: `vrpn-fixed` tarball at fix commit `0da5b0b...`, same flags,
  same harness and indices `100`, `128`, `-256`: **no** stack-buffer-overflow
  at the write site; only the same later harness null dereference at the
  fixed file's `:4564` (`out-control-fixed/i*.out`). The clamp is the sole
  divergence at the write site.
- Negative preserved: sweeping indices `-256..160` over fresh wire connections
  against the live ASan server (`out-wire-sweep-02`) produced **no** ASan
  report and no crash. Live-server frame layout differs from the harness, so
  wire rung 3 stays UNKNOWN; only wire dispatch is established.

## Rung-4 feasibility assessment (honest)

Source mechanism is confirmed by ASan on real pinned bytes plus the upstream
clamp. The write is a chosen *offset* but a fixed byte (NUL); that makes rung 4
layout-dependent: an index must land on saved frame state or a pointer in a
plain build. No chosen-byte control is implied. Wire dispatch to the handler is
established; wire rung 3 is not. The `-64` wire case landing inside the frame
explains the original no-ASan observation rather than refuting the bug. Rung 5
is not in scope on this evidence.

## Cheapest next experiment to move a rung

1. Complete the wire rung 3: under gdb, break at `:4553`, print `&sender_name`
   and `i` for the shipped server frame, then choose an index that lands in
   its actual ASan redzone and repeat over TCP.
2. In a plain build, map what the NUL at that index touches (saved registers /
   frame pointer / return address) before any marker or pointer claim.
3. Only then assess rung 4; keep the fixed-commit control at every step.

## References

- <https://nvd.nist.gov/vuln/detail/CVE-2026-123200>
- <https://github.com/vrpn/vrpn/commit/0da5b0b71e06e8c318a4e674c84caee12251a782>
- <https://github.com/vrpn/vrpn/commit/c893b583d928fd17d756b39271b2eae71766e7f2>
- <https://www.vulncheck.com/advisories/vrpn-through-07.36-out-of-bounds-write-via-sender-description-type-description-length-index>

## Operator admission (2026-11-22 ~01:1xZ)

Admitted under standing approval #6 with all five elements recorded in
`.mishe-tauftauf/charters/vrpn2shell.md` and `docs/task.md`: claim source NVD
CVE-2026-123200 plus the VulnCheck advisory and two upstream fix commits;
identifier CVE-2026-123200; affected `v07.36` / commit `79deb000…` and
fixed-commit `0da5b0b…` tarball pins (all five PROVENANCE digests recomputed
and matched by the operator at admission, while the precise released fixed
version stays UNKNOWN); primitive = unchecked signed index storing one NUL
into a 100-byte stack array, observed by ASan at the real
`vrpn_Connection.C:4554` write site in a direct-call harness on the real
pinned library with a clean fixed-commit control; rung-4 plausibility =
layout-dependent NUL at a chosen offset with no chosen-byte control, wire
dispatch to the handler observed under gdb and a negative live-server ASan
sweep preserved. Grade at admission: rung 3 on the real library via direct
call, wire rung 3 and rung 4 UNKNOWN, no rung 5, no witness replay.

This is a pre-auth network server library rather than a web-facing server;
that class boundary is part of the admission record, not an implied claim.
The operator adopted the staged two-pane window 74 (no duplicate), registered
the 69th wake route with the pinned full-flag sync (3 written / 0 removed),
and the pinned `--no-observe` doctor read `PASS local plant out of Git` /
`GREEN`, rc 0. Frontier should leave this status block and admission note to
the operator and keep its own lane work in its other sections.
