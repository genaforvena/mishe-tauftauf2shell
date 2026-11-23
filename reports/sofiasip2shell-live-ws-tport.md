# sofiasip2shell — live loopback WS SIP tport reachability

CVE-2026-116791 / GHSA-whfw-c3jj-99rp, pinned `v1.13.17` (`6198851a`) against
`v1.13.18` (`ad36ac8f`). Wake W2, 2026-11-22. All paths repo-relative.

## Result

The unmask over-run is reachable from a **live, plant-started sofia-sip
process through its own SIP-over-WebSocket transport**, fed by
attacker-controlled bytes on a loopback socket. No test driver calls
`ws_read_frame()` directly: the call chain is the library's event loop and
`tport_recv_stream_ws()`.

With a 65544-byte masked BINARY frame on the vulnerable pin, ASan reports
`heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after` the reallocated
65544-byte frame buffer, with `ws_read_frame` at `ws.c:1073` called from
`tport_recv_stream_ws` at `tport_type_ws.c:217`. A 65520-byte short frame on
the same pin and both frame sizes on the fixed pin reach the tport's receive
callback cleanly (`TPORT_RECV count=1`, no ASan reports).

This closes the W1 limit "no SIP/tport `ws-binding` call path". It does **not**
reach rung 5: no chosen pointer, marker execution, command or observed
attacker-driven side effect beyond a crash. Rung 4's byte-level metadata and
object-data conclusions still come from the layout harness
(`reports/sofiasip2shell-real-layout.md`), not from this ASan run.

## Method

`lab/sofiasip2shell/libbuild/live/live_ws_tport.c` is linked against the same
full `autogen/configure/make` static libraries used by
`lab/sofiasip2shell/libbuild/RESULT.md`; it adds no library source changes.
Its parent process:

1. `su_init()`, `su_root_create()`, `tport_tcreate()` with a minimal
   `tport_stack_class_t`, then `tport_tbind()` with `tpn_proto = "ws"`,
   `tpn_host = "127.0.0.1"`, `TPTAG_SERVER(1)` and transports `{"ws", NULL}`.
2. forks an attacker client that connects to the bound loopback port, sends
   a real HTTP upgrade (`GET / HTTP/1.1`, `Upgrade: websocket`,
   `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`), waits for the server's
   real `101 Switching Protocols`, and only then writes a masked 64-bit-length
   BINARY frame with mask `41 5a 42 43`.
3. runs `su_root_step()` until the client exits. The library's epoll wakeup
   path (`tport_base_wakeup` -> `tport_recv_event` -> `tport_recv_data`) calls
   `tport_recv_stream_ws`, which calls `ws_read_frame`.

Build and runs:

```
bash lab/sofiasip2shell/libbuild/live/build_and_run.sh v17 'v1.13.17' 18857
bash lab/sofiasip2shell/libbuild/live/build_and_run.sh v18 'v1.13.18' 18858
```

Per-case command, stdout, stderr and rc are in
`lab/sofiasip2shell/libbuild/evidence/v{17,18}-live-{full,short}.*`.

## Observations

| case | rc | observation |
|---|---|---|
| `v17-live-full` (65544) | 1 | ASan `WRITE of size 1`, 0 bytes after a 65544-byte region; stack `ws_raw_read ws.c:427` <- `ws_read_frame ws.c:1073` <- `tport_recv_stream_ws tport_type_ws.c:217`; allocation from `realloc` at `ws.c:1057` via the same tport call chain |
| `v17-live-short` (65520) | 0 | `CLIENT_UPGRADE_101`, `TPORT_RECV count=1`, `SERVER_DONE ... ERRORS=0`, no ASan report |
| `v18-live-full` (65544) | 0 | same upgrade and `TPORT_RECV count=1`, no ASan report |
| `v18-live-short` (65520) | 0 | same, no ASan report |

The client's `CLIENT_UPGRADE_101` line proves the HTTP 101 was actually issued
by `ws_handshake()` inside the library before frame bytes were sent; waiting
for it avoids mixing the upgrade request and the frame in the same
`ws_handshake()` read buffer.

The 65544-byte payload was chosen to cross the 65536-byte initial `ws_init`
bbuffer and exercise the real `ws.c:1057` realloc branch, matching the
`plain-v17-realloc` layout case. ASan's allocator reallocated to exactly
65544 bytes, so its first report is the terminator write at `ws.c:427`, not
the XOR loop. The layout harness's plain build is what measures the XOR
bytes' final offsets on glibc's natural usable-size padding.


## Plain (non-ASan) live tport: natural glibc abort and byte readback

Full non-ASan `autogen/configure/make` builds of both tags were exported from
the pinned commit hashes into `libbuild/pins/v17plain` and `v18plain`
(`ws.c` SHA-256 `90ef747f…` / `7c0b8b55…`); build logs are in
`libbuild/evidence/v{17,18}plain-{autogen,configure,make}.log`. The same live
driver was rebuilt without ASan with `SAN=plain`:

```
SAN=plain bash lab/sofiasip2shell/libbuild/live/build_and_run.sh v17plain 'v1.13.17-plain' 18859
SAN=plain bash lab/sofiasip2shell/libbuild/live/build_and_run.sh v18plain 'v1.13.18-plain' 18860
```

| case | rc | observation |
|---|---|---|
| `v17plain-live-plain-full` | 134 | `TPORT_RECV count=1`, then glibc `corrupted size vs. prev_size` (SIGABRT) |
| `v17plain-live-plain-short` | 0 | `TPORT_RECV count=1`, clean |
| `v18plain-live-plain-full` | 0 | `TPORT_RECV count=1`, clean |
| `v18plain-live-plain-short` | 0 | `TPORT_RECV count=1`, clean |

`libbuild/live/victim_preload.c` plus `run_victim.sh` add an `LD_PRELOAD`
`realloc` shim that records the next chunk's size field when the pinned
`ws.c:1057` realloc occurs, and the driver reads it back in the tport receive
callback. On v1.13.17 full (`v17plain-live-victim-full`, rc 134):

```
NEXT_SIZE_BEFORE=1101000000000000 NEXT_SIZE_AFTER=005b4243415a4243
LIVE_META_DELTA_BAD=0
corrupted size vs. prev_size
```

Bytes 1..5 equal `before ^ mask[k%4]` for mask `415a4243`; byte 0 is the
terminating NUL. The fixed pin produces no such readback and stays clean.
The shim's separate 128-byte object landed 312 bytes past the buffer
(`VICTIM_OFF=65856`), so its `0xC3` data was untouched — an honest negative
about placement inside this tport allocation order, not a contradiction of
the layout harness's controlled adjacent-object cases.

**Why this does not continue to rung 5.** The first byte of the adjacent
`size` field is overwritten by the terminator (0x00 in the realloc case,
even `0xd0` in the 65527 case). That clears the `PREV_INUSE` bit before any
later allocator operation; glibc detects it and aborts
(`corrupted size vs. prev_size`, or `malloc(): corrupted top size` in the
layout harness). No useful fake-chunk state, overlapping allocation or
pointer value was measured, so no exploitation mechanics were built on this
path. This is a host-specific glibc consumer check, not a claim about other
allocators or builds.

## Honest grade and limits

- **Rung 1/2/3**: confirmed through a real loopback WS SIP tport, live HTTP
  101 upgrade, attacker-written wire frame, and the library's own receive
  event loop. Vulnerable/fixed and full/short controls are clean as labeled.
- **Rung 4**: the plain live tport shows the natural glibc abort and a
  byte-exact chosen-delta write to the next chunk's size field from the
  library's own receive path. Byte placement into a live neighbour's *data*
  is still carried by the layout harness's controlled geometries.
- **Rung 5**: not attempted, not implied. The measured corruption clears
  `PREV_INUSE` and glibc aborts at the next allocator operation; no benign
  command, marker or pointer control was achieved.
- The test app binds a raw `ws` tport with a trivial stack class; it does not
  build a full SIP dialog, SDP, authentication, or FreeSWITCH. It uses a
  forked client in the same process tree, both constrained to 127.0.0.1.
- The parent's `su_root_step()` polling loop is a lab harness driver, not a
  production SIP server; its exit is not itself security impact.

## W5: identity of the physical live neighbour (2026-11-23)

The plain live lane previously knew only that the chunk after the frame
buffer had size `0x111` and that `LD_PRELOAD`'s own 128-byte victim landed
312 bytes away. This wake identifies the real neighbour with a bounded
allocation-tracker shim, `lab/sofiasip2shell/libbuild/live/neighbor_probe.c`,
driven by `run_neighbor_probe.sh` on the unmodified plain v17 live driver
and fresh loopback ports 18871/18872. The shim interposes
`malloc`/`calloc`/`realloc` through glibc's `__libc_*` entry points, records
each allocation's caller and size, and on the pinned `ws.c:1057`
`realloc(..., 65544)` looks for the allocation whose user pointer is
`r+65552` — the neighbour whose size field starts at `r+65544`.

Full case (`lab/sofiasip2shell/libbuild/evidence/w5/v17plain-neighbor-full.*`,
rc 134): `NEIGHBOR_FOUND=1`, neighbour allocation size 264, caller
symbolized with `addr2line` as `timers_alloc` at pinned
`su/su_timer.c:201`. The bbuffer callers resolve to `ws_init` at
`ws.c:744` (original 65536-byte allocation) and `ws_read_frame` at
`ws.c:1057` (the realloc), confirming the library's own path. Raw neighbour
bytes are `NEIGHBOR_FIRST8=1e00000000000000`: the first word is `0x1e`
(30), not a pointer. `NEXT_SIZE_BEFORE=0000000000000111`, followed by the
same `corrupted size vs. prev_size` abort and `TPORT_RECV count=1`. The
65520-byte short control (`v17plain-neighbor-short.*`, rc 0) never fires the
realloc probe, reaches `TPORT_RECV count=1` and stays clean.

Source-bound layout: `HEAP_BODIES` at `su/sofia-sip/heap.h:162-198` defines
the 264-byte control block as `{size_t _size; size_t _used;
su_timer_t *_heap[2];}` with `_size = 32 - _offset = 30` at
`heap.h:167-169`; `timers_alloc` is its realloc callback at
`su_timer.c:196-204`. `struct su_timer_s` at `su_timer.c:159-170` puts
`sut_wakeup` well past the first words. The probe reads `NEIGHBOR_FIRST8`
at realloc time, before the frame write; combined with W2's measured realloc
extent (5/6 bytes), that write reaches the low bytes of `_size`. The timer
pointers and the callback are out of reach.

This is a **measured negative at the live-process scope**, not a new rung-4
positive and not rung 5: no pointer, callback, marker, command or side
effect was obtained. The mask is still repeating-XOR and requires heap-byte
knowledge; the neighbour chunk's size is corrupted by the same write and
glibc aborts before any timer-heap use. Enlarging `_size` would additionally
require enough queued timers for `_used` to approach `_size`, which was
neither measured nor claimed. Independent witness replay (W143) **ESTABLISHED**
the identity measurement at this labeled scope: clean `git archive 709a34c`,
hash-checked pins, three runs (full rc 134 with matching neighbour fields,
short rc 0, port-shifted structurally identical), all caller offsets symbolized
to the pinned sources, no counterexample and no grade change.

## W11: second-order timer-heap write from corrupted `_size` (2026-11-23)

W8's wall left one question open: the live neighbour's `_size` is in the
5/6-byte XOR reach, but source alone did not indicate a secondary execution
path. W11 measures it in the live plain tport. Three new source files under
`lab/sofiasip2shell/libbuild/live/` implement it:
`live_ws_timers.c` (proven live driver plus timer setup and readback),
`timer_probe.c` (LD_PRELOAD shim exporting the neighbour pointer and its
allocation size), and `run_timer_probe.sh` (build and four loopback cases).
Evidence is in `lab/sofiasip2shell/libbuild/evidence/w11/`.

The driver pre-queues 30 long-lived timers on the root task before the
upgrade, so the timer heap array is live and at its initial 30-slot capacity.
A tport-internal timer then resizes that array to 528 bytes (63 slots) between
setup and frame; the shim confirms the array is the physical neighbour of the
reallocated 65544-byte frame buffer (`TIMER_Q_PTR == SHIM_NEIGHBOR`, `DELTA=0`)
and symbolizes its caller to pinned `timers_alloc` at `su_timer.c:201`.

Vulnerable full case (`v17plain-full`, ports 18901 and replay 19011, rc 134):
`TIMER_Q_BEFORE size=99236347796094 used=30 boundary_off=528`. The size is
`0x005a4143425a7e` — the original 63 (`0x3f`) XORed with repeating mask
`41 5a 42 43` over six bytes, i.e. an attacker-chosen inflation to a huge
capacity. The receive callback then performs 35 `su_timer_set()` calls through
the library's own `timers_add()` (`TIMER_ADDS n=35 last_rc=0`, `_used`
30 -> 65). All 35 pass the corrupted capacity check; the final one writes at
array index 65, exactly 0 bytes past the 528-byte allocation. Readback at
`heap+528` changes from `0000000000000000` to a live `su_timer_t *`
(`00005f910e67bf10`, replay `00006459a72d1f60`); the following chunk's size
word at `heap+536` stays `0x21`. The process then aborts with
`corrupted size vs. prev_size`.

Controls: v1.13.17 with the 65520-byte short frame (rc 0) never fires the
realloc probe, keeps `_size=63`, and makes only two in-bounds adds; both
v1.13.18 full and short cases (rc 0) are identical to the short control.
The port-shifted vulnerable replay reproduces every field structurally.

This is a **rung-4 observation, not rung 5 and now witness-backed at the
labeled live plain v17 tport scope**. The write value is a heap pointer to a
timer object, not an attacker-chosen address or payload; it lands in the next
chunk's `prev_size`, and glibc's abort is still driven by the header corrupted
by the original frame write. No callback, callable field, marker or command
was obtained. It requires a timer-heavy live application with the measured
neighbour geometry and does not change the lane's overall grade.

Witness #2735 (W164) replayed commit `cbda94a` from a clean `git archive` into
`/tmp/w164-sofia`: the three new sources hash-matched (`0fcae2b1` / `2271f532`
/ `9781c174`) and both pinned `ws.c` matched the report (`v17plain`
`90ef747f…`, `v18plain` `7c0b8b55…`). BUILD LIMIT: the pins are gitignored, so
the witness rebuilt the shim and both drivers from committed sources with
committed flags but linked the provisioned pinned static `.a` libraries;
sofia-sip was not rebuilt from scratch. On fresh loopback ports 19101-19104
the whole matrix reproduced: v17-full rc 134 with `TIMER_Q_PTR ==
SHIM_NEIGHBOR`, `DELTA=0`, 528-byte neighbour, caller symbolized to pinned
`timers_alloc su_timer.c:201`, `_size=99236347796094` (`0x5a4143425a7e`),
`_used` 30 -> 65 over 35 adds, `heap+528` `0` -> live timer pointer,
`heap+536` still `0x21`, glibc `corrupted size vs. prev_size`; the short and
both v18 cases rc 0 with `_size=63` and two in-bounds adds. All six stderr
logs (four author cases plus two port-shifted replays) were normalized-
identical. As a causal variation the witness changed only `mask4[0]` `0x41` ->
`0x51` and rebuilt: the full case still rc 134 with the same 35 adds and OOB
write, while `_size` moved to `0x5a5143425a6e` — exactly the predicted XOR
over the six reachable bytes. The corrupted capacity therefore tracks
attacker wire bytes, not a harness constant. The witness also checked that
the committed no-timer and W5 full evidence abort with the same `corrupted
size vs. prev_size`, confirming the second-order write is real but is not the
abort cause, as this report states. Verdict **ESTABLISHED at the labeled
scope**: no counterexample, no grade change, rung 5 still UNKNOWN.

## W14: deeper second-order writes into live chunks (2026-11-23)

W11 stopped after 35 adds, writing one live timer pointer at exactly the
array boundary. The corrupted `_size` is `0x005a4143425a7e` (about 2.7e13),
so the capacity check imposes no practical bound. W14 asks how far the
library's own `su_timer_set()` calls will write once that check is passed,
and which live object lies in the path. Three new sources under
`lab/sofiasip2shell/libbuild/live/` extend W11 without changing its committed
files: `live_ws_timers_deep.c` adds `SIA_DEEP_EXTRA` (extra adds beyond W11's
stop) and a 16-qword tail snapshot; `timer_probe_deep.c` logs allocations in
the next 640 bytes after the timer array; `run_deep_probe.sh` builds both and
runs four cases. Evidence is in `libbuild/evidence/w14/`.

Vulnerable full case (`SIA_DEEP_EXTRA=60`, port 19301, rc 134): the shim again
identifies the physical neighbour as the 528-byte `timers_alloc` array
(`su_timer.c:201`, `DELTA=0`); the 19-byte allocation at `neighbor+544` is
`sub_alloc` at `su_alloc.c:500`. The receive callback performs 95 timer adds
(`_used` 30 -> 125) and overwrites **16 consecutive qwords at array offsets
520 through +640** with live timer pointers spaced `0x50` bytes apart. Before
the adds, `+536` was the next chunk's `size` word `0x21`, `+544` and `+552`
held the 19-byte string's data (`ws\0.127.0` / `.0.1363\0`), `+568` was
`0x391`, `+576` was `0x388`, and `+584` held an existing heap pointer. After
the adds all 16 qwords are `0x57f945423f10 + 0x50*k`. The process then aborts
with `corrupted size vs. prev_size`.

Controls: v1.13.17 with 65520-byte payload and both v1.13.18 cases (ports
19302-19304, rc 0) keep `_size=63`, make only two in-bounds adds, and change
only the two in-bounds array slots at `+256`/`+264`; their chunk headers and
the following object stay intact. A port-shifted replay (19311-19314) with
the same sources reproduced every field structurally: 95 adds, the same
16-pointer run, the same controls.

**Grade unchanged: rung 4, author-observed pending witness replay.** This is
a larger second-order write than W11 — the library writes live timer pointers
through a neighbouring 19-byte live object and several chunk headers, not
just one boundary slot — but the values are heap pointers, not attacker-chosen
bytes or addresses. The overwritten object was symbolized to a generic string
allocation; no callback, callable field, marker or command was reached, and
the glibc abort still follows from corrupted allocator headers. It does not
support a rung-5 claim.
