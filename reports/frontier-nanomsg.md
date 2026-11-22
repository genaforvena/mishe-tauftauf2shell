# Frontier brief — Nanomsg WebSocket handshake overflow (CVE-2026-97152)

Status: **SCREENED IN, live wire rung 3 observed, ADMITTED** as `nanomsg2shell`
under standing approval #6 by the operator 2026-11-22 ~03:0xZ (tape #1272). The
frontier brief, registered two-pane inner window 78, seed wall, charter and
status file now exist; see `reports/nanomsg2shell-status.md` and
`docs/task.md`. Grade at admission: wire rung 3 ESTABLISHED (author) with
fixed-version and short-header controls clean; rung 4 strongly indicated but
not established; no rung 5 claim. W105 sections below are the source evidence.

## Verified ground truth

- Claim source: NVD CVE API `cveId=CVE-2026-97152`, fetched 2026-11-22T02:5xZ;
  MITRE CNA, published 2026-09-24T04:18:06Z, description: "Nanomsg versions
  0.5-beta through 1.x before 1.2.3 has a remotely exploitable buffer overflow
  in the WebSocket transport, due to an unchecked copy of the
  Sec-WebSocket-Version header, through snprintf."
- Severity: CVSS 4.0 8.6 HIGH,
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VI:H/VA:H/SC:H/SI:H/SA:H` (NVD secondary
  metric). Network attack vector, low complexity, changed scope, high
  integrity and availability impact.
- References on the CVE record: https://github.com/nanomsg/nanomsg/pull/1130 ,
  https://github.com/nanomsg/nanomsg/releases/tag/1.2.3 , https://nanomsg.org .
- Affected range: 0.5-beta through 1.x before 1.2.3; fixed in 1.2.3. Open
  source (C), unowned by this plant: `grep` over `reports/`, `docs/` and
  `charters/` found no prior nanomsg or CVE-2026-97152 coverage.
- Screen provenance: NVD `cweId=CWE-120`, pub 2026-10-20..2026-10-31 returned
  zero; NVD `cweId=CWE-787`, pub 2026-09-01..2026-09-30 returned 301 and this
  was selected from that fresh window. CWE-122 2026-11-01..22 (24 hits) was
  also screened and yielded no new wire-reachable open-source server.

## Source-bound mechanism (read from the public fix, not inferred from prose)

Fix PR #1130 diff fetched from
`https://patch-diff.githubusercontent.com/raw/nanomsg/nanomsg/pull/1130.diff`,
single touched logic file `src/transports/ws/ws_handshake.c`, function
`nn_ws_handshake_server_reply()`:

1. Failure branch, previously:

       version = nn_alloc (self->version_len + 1, "WebSocket version");
       strncpy (version, self->version, self->version_len);
       version [self->version_len] = '\0';
       sprintf (self->response,
           "HTTP/1.1 %s\r\n"
           "Sec-WebSocket-Version: %s\r\n", code, version);
       nn_free (version);

   The fix deletes the allocation/copy and replaces the `sprintf` with

       snprintf (self->response, sizeof (self->response),
           "HTTP/1.1 %s\r\n"
           "Sec-WebSocket-Version: 13\r\n", code);

2. Success (101) branch, previously `sprintf (self->response, "HTTP/1.1 101
   Switching Protocols\r\n" ... protocol ...)`, becomes `snprintf
   (self->response, sizeof (self->response), ...)`. Here `protocol` is copied
   from `self->protocol` with `strncpy (protocol, self->protocol,
   self->protocol_len)` immediately before the format call.

Both format arguments are values parsed from the client's HTTP Upgrade request
(`Sec-WebSocket-Version`, `Sec-WebSocket-Protocol`). `self->response` is a
fixed-size field of the handshake state; the fix bounds the write with
`sizeof (self->response)` and stops echoing the supplied version at all
(hardcoded `13`). That is a source-grounded unbounded, attacker-content write
on the **server** reply path — the attacker chooses both the overflow length
and the bytes written, which is the chosen-byte primitive this lab values.

Observed gate result (v1.2.2 raw source, hash-pinned below): `ws_handshake.h:145`
declares `char response [512]`; `ws_handshake.h:49` sets
`NN_WS_HANDSHAKE_MAX_SIZE 4096` and `:89` declares `char opening_hs [4096]`.
The parser at `ws_handshake.c:958-961` stores the raw `Sec-WebSocket-Version`
value and `version_len` via `nn_ws_match_value` with no length cap; `:1006-1009`
compares it to `"13"` and, on mismatch, sets `response_code = WSVERSION` and
returns INVALID; the server reply at `:1344-1353` then copies the whole
attacker string into a fresh buffer and `sprintf`s it into `response[512]`.
No parse-time cap blocks the path (**GO**). `response[512]` is followed in the
same struct by `struct nn_fsm_event done` (`ws_handshake.h:148`), a
pointer-bearing neighbour, so an overflow past 512 bytes reaches live FSM
state. Still UNKNOWN: whether PR #1130 is byte-identical to tag 1.2.3, whether
the CVSS `PR:L` precondition applies to the handshake itself, and the runtime
allocation/placement of `struct nn_ws_handshake`.

## Rung-4 feasibility (honest)

High tractability, top of the current queue. Small C library, one logic file,
no runtime or JIT to stub. The write path is in the server's HTTP handshake
reply, i.e. pre-frame and directly reachable from a raw TCP client — unlike
earlier VRPN/Wazuh finds, the written content is attacker-chosen rather than a
fixed NUL. The structural cap check is resolved **GO**: the 4096-byte
`opening_hs` holds a version header long enough to overflow the 512-byte
`response`, and the parser does not clamp `version_len`. The overflow target's
neighbour is `done`, an FSM event carrying pointers, so pointer control rather
than only chosen bytes is plausible. The 101 success branch also echoes
`Sec-WebSocket-Protocol` into the same `sprintf` and is a second site to test.

Rungs 1–3 are realistically reachable in one bounded wake. Rung 4 (chosen
bytes at a chosen offset from a wire request into a live consumer) is plausible
but unproven; rung 5 is not claimed and would require a daemon-side path and a
witness replay.

## Cheapest local experiment (next wake, bounded)

1. DONE: release tarballs `1.2.2` and `1.2.3` fetched from GitHub and pinned in
   `lab/frontier/nanomsg2shell/src/SHA256SUMS` (`cd
   lab/frontier/nanomsg2shell/src && sha256sum -c SHA256SUMS`).
2. DONE (GO): `response[512]`, `opening_hs[4096]`, no parse-time `version_len`
   cap, pointer-bearing `done` neighbour — see the gate result above.
3. Build the real WS handshake sources with ASan, either by a direct call to
   `nn_ws_handshake_server_reply()` seeded with a crafted state struct, or
   against a loopback `nn_bind("ws://127.0.0.1:...")` listener driven by a raw
   HTTP Upgrade request with an oversized `Sec-WebSocket-Version: QQQQ...`
   header. Record the ASan report frame, write size and overflow offset;
   repeat on v1.2.3 (expect clean) and with a short version header (clean).
4. Plain build: confirm chosen `Q` bytes land at a controlled offset in the
   neighbouring object/stack slot. Hash the evidence so witness replays are
   byte-identical (exclude PID/address/path text).
5. DONE by the operator at admission (2026-11-22 ~03:0xZ): seed wall, charter,
   inner two-pane window 78, registry entries and wake-failure signal; the
   operator DMed frontier (#1272) not to double-mint. Dumping the exact write
   offset, a chosen-byte readback there and a daemon-side path remain the open
   evidence lane.

Alternates if the live wire path fails: Pgpool-II CVE-2026-92867/92869/92870
(authenticated OOB write, unowned), Corosync CVE-2026-81665 (totempg fragment
reassembly heap overflow), Fluent Bit CVE-2026-61674 (rejected: attacker is a
malicious server, victim is a client).

## Observed live wire results (W105, after the brief was committed)

Not advisory prose: measured on pinned raw sources via a loopback
`nn_bind("ws://127.0.0.1:28765")` listener and a raw HTTP Upgrade client
(`harness/wire_inject.py`). Gdb was not needed for the primary observation.

- v1.2.2, `Sec-WebSocket-Version: ` + 600 × `Q`: reply is 669 bytes, beginning
  `HTTP/1.1 400 Unsupported WebSocket Version\r\nSec-WebSocket-Version: QQQ...`
  (`harness/client-600.txt`). The reply prefix is exactly 67 bytes and the
  `sprintf` wrote 155 chosen `Q` bytes past `response[512]` into the adjacent
  `done` FSM event (W106 below locates `done` at +516, after 4 pad bytes).
  The standalone server aborts with
  `Assertion failed: item->next == NN_QUEUE_NOTINQUEUE (.../src/utils/queue.c:47)`
  in both the GCC-ASan (`harness/out-asan-600.txt`) and clang-ASan
  (`harness/out-clang-600.txt`) builds. Live wire rung 3: observed corruption
  of a pointer-bearing neighbour, not merely a crash.
- v1.2.2 short-header control (2 × `Q`): 71-byte reply, zero assertions
  (`harness/client-gdb-ctrl.txt`, `harness/gdb-ctrl.txt`).
- v1.2.3 fixed control under the identical 600-byte request: 71-byte reply
  with hardcoded `Sec-WebSocket-Version: 13`, zero assertions and no ASan
  report (`harness/client-fixed-600.txt`, `harness/out-fixed-600.txt`).
- ASan alone does not flag this overflow: `sprintf` writes happen inside libc,
  so there is no instrumented store; the clang field-padding build
  (`-fsanitize-address-field-padding=2`) was also silent. Detection is the
  real consumer's queue assertion. Preserved as a negative observation.

Grade at that point: wire-reachable rung 3 confirmed. Rung 4 was indicated
but the exact offset was not yet measured; W106 below closes that gap.
No rung 5 claim.

## W106 (2026-11-22 03:1xZ) — measured offset, chosen-byte readback, rung 4

Built a `-g -O0` debug library from pinned 1.2.2 (`src/build-dbg`,
`cmake -S nanomsg-1.2.2 -B build-dbg -DCMAKE_BUILD_TYPE=Debug
-DCMAKE_C_FLAGS="-g -O0 -fno-omit-frame-pointer"`) and linked
`harness/ws_server_dbg.c`: the same real `nn_bind("ws://127.0.0.1:28765")`
listener with a longer lifetime. On that real wire path a gdb pending
breakpoint on `nn_ws_handshake_server_reply` plus a line breakpoint at
`ws_handshake.c:1355` (immediately after the `sprintf`) yields full type info
for `self`. W105's gdb attempt failed only because a line breakpoint was set
before the shared library loaded; the symbol breakpoint fixes that.

Measured layout (x86-64, `harness/gdb-offset-cycle.txt`): the reply prefix
`"HTTP/1.1 400 Unsupported WebSocket Version\r\nSec-WebSocket-Version: "` is
67 bytes; `&self->done - self->response == 516`, not 512 — the compiler puts
4 alignment pad bytes between `response[512]` and the pointer-bearing
`struct nn_fsm_event`. Header byte k lands at `response + 67 + k`:

| field | `done` offset | header index k |
|---|---|---|
| `done.fsm` | +0..7 | 449..456 |
| `done.src` | +8..11 | 457..460 |
| pad | +12..15 | 461..464 |
| `done.srcptr` | +16..23 | 465..472 |
| `done.type` | +24..27 | 473..476 |
| pad | +28..31 | 477..480 |
| `done.item.next` | +32..39 | 481..488 |

Position-encoded readback: a 490-byte version of the 62-char printable cycle
`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789` places
`CYCLE[k % 62]` at header index k. The dumped `done` bytes are
`P Q R S T U V W X Y Z a b ... z 0 1 2` and `item.next` is
`0x3231307a79787776` — little-endian bytes `76 77 78 79 7a 30 31 32`
(`v w x y z 0 1 2`) = `CYCLE[47..54]` = header indices 481..488, because
481 % 62 = 47. Byte-exact wire-to-live-pointer mapping, not a crash signature.

Chosen-value readback at that offset (489-byte version, 8 chosen bytes at
k=481..488; `harness/gdb-marker_ff.txt`, `harness/gdb-marker_41.txt`):

- 8 × `0xff` → `item.next = 0xffffffffffffffff`, exactly
  `NN_QUEUE_NOTINQUEUE ((struct nn_queue_item *)-1)`.
- 8 × `0x41` → `item.next = 0x4141414141414141`.

Functional consequence on the same real listener, no gdb
(`harness/out-standalone-marker_*.txt`):

- `marker:41` → `Assertion failed: item->next == NN_QUEUE_NOTINQUEUE
  (queue.c:47)` — the W105 crash.
- `marker:ff` → that assertion is **bypassed**; the corrupted event is queued
  and the FSM advances to a different failure,
  `Unexpected source: state=5 source=2573 action=7 (aws.c:316)`. The chosen
  byte value at a measured offset selects which live control-flow path runs.

Fixed control (`harness/ws_server_fixed`, pinned 1.2.3): under both markers
the reply is the 71-byte hardcoded `Sec-WebSocket-Version: 13` and the server
records no assertion (`harness/client-fixed-marker_*.txt`,
`harness/out-fixed-marker_*.txt`). The W105 short-header control is also clean.

Grade: **rung 4 demonstrated at claimed scope** — attacker-chosen wire bytes
at measured offsets overwrite a live pointer-bearing FSM event in a real
loopback `nn_bind` listener, and the chosen value changes the executed path.
Not rung 5: no command execution, no daemon-side path beyond the standalone
listener, and the ff case still ends in a downstream FSM assertion. ASan
remains silent (stores are inside libc `sprintf`); the consumer assertion is
the detector. The +516 offset is build-specific and must be re-measured for
any other compiler or flags.

Replay from the lab root: `bash harness/run_gdb_case.sh marker:ff` and
`bash harness/run_gdb_case.sh marker:41` for the gdb readbacks; for the
functional case start `./harness/ws_server_dbg` then run
`python3 harness/wire_pattern.py 489 marker:41 0`. Normalized trace hashes
(paths, hex addresses and PIDs scrubbed) are in
`harness/EVIDENCE_HASHES.txt`.
