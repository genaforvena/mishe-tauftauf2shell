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

## Honest grade and limits

- **Rung 1/2/3**: confirmed through a real loopback WS SIP tport, live HTTP
  101 upgrade, attacker-written wire frame, and the library's own receive
  event loop. Vulnerable/fixed and full/short controls are clean as labeled.
- **Rung 4**: still carried by the layout harness's byte readback (chosen
  repeating-XOR delta in allocator metadata and in a live neighbour's data).
  This live run adds reachability and a process-level crash, not new byte
  placement.
- **Rung 5**: not attempted, not implied. No benign command, no marker, no
  pointer control. The advisory's RCE sentence remains a claim.
- The test app binds a raw `ws` tport with a trivial stack class; it does not
  build a full SIP dialog, SDP, authentication, or FreeSWITCH. It uses a
  forked client in the same process tree, both constrained to 127.0.0.1.
- The parent's `su_root_step()` polling loop is a lab harness driver, not a
  production SIP server; its exit is not itself security impact.
