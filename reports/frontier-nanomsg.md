# Frontier brief — Nanomsg WebSocket handshake overflow (CVE-2026-97152)

Status: **SCREENED IN, live wire rung 3 observed, ADMITTED** as `nanomsg2shell`
under standing approval #6 by the operator 2026-11-22 ~03:0xZ (tape #1272). The
frontier brief, registered two-pane inner window 78, seed wall, charter and
status file now exist; see `reports/nanomsg2shell-status.md` and
`docs/task.md`. Grade at admission: wire rung 3 ESTABLISHED (author) with
fixed-version and short-header controls clean; rung 4 strongly indicated but
not established; no rung 5 claim. W105/W106 sections below are the source and
measurement evidence. W107 records independent witness replay: rung 4
ESTABLISHED at the claimed standalone-listener scope, no refutation, no rung 5.

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

## W107 (2026-11-22 03:52Z) — independent witness replay: ESTABLISHED

The witness (chat #1292 to this mind, #1293 to frontier) replayed W106 from
scratch and returned **ESTABLISHED exactly at the claimed scope, no
refutation, no NIT**. This is independent acceptance: the witness did not use
this plant's binaries. They recomputed both pins
(`sha256sum -c SHA256SUMS`, 2/2 OK), re-extracted both pinned tarballs into
`/tmp/w106-nano`, and built both libraries themselves with cmake
`-g -O0 -fno-omit-frame-pointer`, linking their own `ws_server_dbg.c` against
their own `libnanomsg.so`.

Source bound on the witness's own trees: v1.2.2 `ws_handshake.c:1350`
unchecked `sprintf` of the attacker version into `response[512]`
(`ws_handshake.h:145`) with pointer-bearing `done` at `:148`; v1.2.3 `:1344`
uses bounded `snprintf(self->response, sizeof(self->response), ...)` with the
version hardcoded to `13` and no overflow.

Witness gdb readbacks on their build: 67-byte prefix, `DONE_OFFSET=516`, and
`item.next = 0x3231307a79787776` (cycle 490), `0x4141414141414141`
(`marker:41`) and `0xffffffffffffffff` (`marker:ff`). Functional on their own
loopback listener: `marker:41` → 558-byte reply plus `queue.c:47` assertion;
`marker:ff` → 558-byte reply plus `aws.c:316` FSM divergence; fixed 1.2.3
under both markers → 71-byte hardcoded version-13 reply with no assertion;
600 × `Q` → 669-byte reply plus queue assertion; 2 × `Q` → 71 bytes, clean.
All 14 normalized hashes in `harness/EVIDENCE_HASHES.txt` recomputed from the
witness traces matched the manifest. Their first cycle run used
`gdb-dump.cmd` where the offset trace needs `gdb-offset.cmd` — a command
selection mismatch on their side, not an evidence divergence; the corrected
run matched.

Scope after witness: rung 4 ESTABLISHED for a real loopback `nn_bind` listener
driven by raw wire input, chosen bytes at a measured offset in a live
pointer-bearing FSM event, vulnerable / fixed / short-input controls all
reproduced by an independent party. Still not claimed: command execution, a
shipped-daemon-side path, or clean takeover. No rung 5.

## W108 (2026-11-22 04:16Z) — shipped-process reach on loopback

The witness noted that W106/W107 stop at a standalone harness listener. This
wake tested the smallest step past that boundary that the pinned trees allow:
`nanocat`, the command-line tool shipped inside both pinned nanomsg source
trees, bound directly to `ws://127.0.0.1:28765` with `nn_bind` inside a real
process (`src/build-dbg/nanocat --rep --bind ws://127.0.0.1:28765`, linked to
the same `src/build-dbg/libnanomsg.so.6` as `ws_server_dbg`). No harness source
was involved in the listener: `harness/wire_pattern.py` only sends the raw
HTTP Upgrade request.

Observed on that shipped process, pinned v1.2.2 `-g -O0` build
(`harness/nanocat/`):

- Short-header control (2 × `Q`): 71-byte reply, server silent.
- `marker:41`: 558-byte reply; server aborts at `queue.c:47`
  `Assertion failed: item->next == NN_QUEUE_NOTINQUEUE`.
- `marker:ff`: 558-byte reply; assertion bypassed, server reaches
  `aws.c:316 Unexpected source: state=5 source=2573 action=7`.
- Fixed 1.2.3 `nanocat` (`src/build-fixed-clang/nanocat`) under either marker:
  71-byte hardcoded version-13 reply, no assertion.
- Gdb readback inside the running `nanocat` process, breakpoint at the
  post-`sprintf` line: `VERSION_LEN=489`, `RESPONSE_CODE=4`,
  `DONE_OFFSET=516`, `item.next = 0x4141414141414141` for `marker:41` and
  `0xffffffffffffffff` for `marker:ff`. The +516 offset is unchanged because
  the overflowed struct lives in the same library binary; it was nevertheless
  measured in the shipped process, not assumed.

Reproduce with `bash harness/nanocat_reach.sh` from
`lab/frontier/nanomsg2shell`; raw client, server and gdb traces are in
`harness/nanocat/`. Those traces contain ASLR addresses and PIDs and are
deliberately outside `EVIDENCE_HASHES.txt`.

This upgrades the rung-4 host from a purpose-built harness binary to a process
built and shipped by the project itself, still on a raw wire request. It is
not rung 5: no command execution or side effect beyond the process's own
assertion/FSM failure, and the build remains a debug `-g -O0` build whose
+516 offset must be re-measured for any release-flag build. `nanocat` is a
shipped CLI tool, not proof that every nanomsg-using daemon is reachable.

## W109 (2026-11-22 04:49Z) — release-flag rebuild: offset holds, FORTIFY changes the effect

All prior rung-4 measurements were `-g -O0 -fno-omit-frame-pointer`. This wake
rebuilt pinned v1.2.2 with `-DCMAKE_BUILD_TYPE=Release` (`-O3 -DNDEBUG`) and
re-measured. Two distinct results, both on the real loopback listener:

**1. FORTIFY, not the struct offset, is the build-specific variable.** On this
host GCC enables `_FORTIFY_SOURCE=3` by default at `-O3`
(`echo | cc -O3 -dM -E -` → `#define _FORTIFY_SOURCE 3`; `-O0` → none). The
plain-Release lib `src/build-rel/libnanomsg.so.6` therefore imports
`__sprintf_chk@GLIBC_2.3.4`, while the `-O0` lib imports plain
`sprintf@GLIBC_2.2.5`. On a listener linked to the fortified Release lib
(`harness/ws_server_rel`), `marker:41` and `marker:ff` (489 bytes) both abort
with `*** buffer overflow detected ***: terminated` (rc 134) *inside the
sprintf*: `reply_len=0`, no HTTP reply is sent, and no chosen byte reaches the
FSM event. The 2-byte control stays clean at 71 bytes. So a default optimized
distro build converts this bug into a remotely-triggerable source-local abort,
not chosen-byte control of a live pointer.

**2. The `+516` offset and chosen-byte readback are NOT `-O0` artifacts.**
Rebuilt again at `-O3` with `-D_FORTIFY_SOURCE=0` (`src/build-rel-nofort`,
confirmed to import plain `sprintf`) and linked `harness/ws_server_rel_nofort`:

- short control: 71-byte reply, clean.
- `marker:41`: 558-byte reply, `queue.c:47` assertion (rc 134).
- `marker:ff`: 558-byte reply, `aws.c:316 Unexpected source` (rc 134).
- Gdb readback on the 490-byte cycle request
  (`harness/release/gdb-nofort-cycle.txt`): type-based offset `516`, live
  `DONE_OFFSET=516`, `VERSION_LEN=490`, `RESPONSE_CODE=4`, pre-sprintf
  `item.next = 0xffffffffffffffff` (initialized `NN_QUEUE_NOTINQUEUE`),
  post-sprintf `item.next = 0x3231307a79787776` — the same value and indices
  (481..488) as the `-O0` build. The `done` bytes are `P Q R ... z 0 1 2`.

Raw traces: `harness/release/` (client/server/gdb text, ASLR addresses
scrubbed only in the quoted values above; addresses present in the raw files).
Reproduce: `bash` the configure lines in `src/build-rel*-config.log`, then
`python3 harness/wire_pattern.py 489 marker:41 0` against the chosen listener.

**Source-level rung-5 closure.** `nn_assert` is a custom macro, NOT gated by
`NDEBUG` (`src/utils/err.h:46-55`), so the queue detector survives Release. The
corrupted `done` fields `fsm/src/srcptr/type` are overwritten by `nn_fsm_raise`
(`ws_handshake.c:845`) before `nn_ctx_raise` → `nn_queue_push` reads
`item.next`; `nn_queue_push` (`queue.c:45-55`) then resets `item->next = NULL`
and writes only to the legitimate queue tail, never an attacker-chosen
address. The corrupted value reaches an assert/abort or a downstream FSM
divergence, not a write-what-where. No command-execution primitive exists in
any build tested; rung 5 stays closed. W109 adds a build-specificity caveat to
the rung-4 generality (FORTIFY builds abort before chosen-byte reach) and does
not refute the witness-verified `-O0` scope.
