# rabbitmqc2shell — socket-fed consumer experiment (CVE-2026-61547)

Date: 2026-11-21 ~13:45Z. Lane: `lab/rabbitmqc2shell/`. This report extends
`reports/frontier-rabbitmqc2shell.md`; it does not replace the witness-verified
frontier evidence. All testing stayed on local `AF_UNIX` sockets inside this
plant; no broker, TCP listener or external host was contacted.

Witness W74 independently replayed this claim and returned ESTABLISHED AS
CLAIMED; see the witness replay section at the end of this report.

## Question and design

Frontier left one open question: does an untrusted body arriving over a socket
reach the vulnerable serialization copy unchanged inside a *service process*,
and what real heap object sits past the outbound frame buffer?

`service.c` binds an `AF_UNIX` stream socket under `/tmp`, accepts one
connection, reads a 4-byte big-endian length and then exactly that many body
bytes, and passes the received bytes as `frame.payload.body_fragment` to
`amqp_send_frame()` on a pinned, verbatim v0.16.0 `amqp_connection_state_t`.
The only library setup is a local `AF_UNIX` socketpair with its write end shut
down so the post-copy send returns without a broker. **No library source is
copied, patched or interposed** in the plain and ASan service builds. The
client is a separate process that generates and sends the body.

A debug variant adds a 512-byte live heap sentinel after connection creation
so gdb can inspect a real glibc neighbour. A second debug variant models a
service with a reusable 200000-byte receive buffer: the socket declares a
65600-byte body (still 64 bytes past the 65536-byte frame buffer) while the
larger allocation preserves the heap layout observed with 200000-byte bodies.
This also keeps the whole `memcpy` inside the heap mapping.

## Observed results

Reproduce with `bash lab/rabbitmqc2shell/run.sh /tmp/rmq2-service-final`:
**8 PASS / 0 FAIL rc 0**, six source pins OK, determinism digest
`f8efc860e75e8cc0035c4957b2208928a74403da44e4f198ed757e3f2fd4209d`.
A clean-output-directory build gave the same digest. Artifacts and logs live
in `/tmp/rmq2-service-final/` (gitignored).

1. **Socket-fed ASan write, library allocator.** Service log:
   `service: received len=200000 first=5a last=5a`, then
   `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 200000`,
   `0 bytes after 65536-byte region`, frames `amqp_frame_to_bytes
   amqp_connection.c:467` ← `amqp_send_frame_inner :548` ← `amqp_send_frame
   :531`; allocation via `amqp_tune_connection :140` ← `amqp_new_connection
   :53`; `run_service service.c:88`. Service process rc 1. No harness
   allocator interposer in this build.

2. **Real heap neighbour under gdb (unsanitized, no interposer).** With a
   200000-byte `0xa5` body, the `memcpy` destination was `outbound + 7` and
   `state->socket` was exactly `outbound + 65552` (from frame 2,
   `amqp_send_frame_inner`). Before the copy:
   `outbound+65544` = `0x21` (live 32-byte chunk), and the 8 bytes at
   `outbound+65552` = `0x55555556fc20`, which gdb resolved to
   `<amqp_tcp_socket_class>`. After the copy: neighbour `prev_size` and
   `size` = `0xa5a5a5a5a5a5a5a5`, and the pointer field = `0xa5a5...`.
   Addresses vary with ASLR; the offsets and byte values are the evidence.
   The 200000-byte `memcpy` then faults partway through in
   `__memcpy_avx_unaligned_erms` when it runs off the heap mapping — that
   path does **not** reach the send call.

3. **Chosen bytes steer a live vtable and execute a benign marker.** With
   the reusable-buffer model and a 65600-byte body, `state->socket->klass`
   was `0x4141414141414141` at the `amqp_socket_send` breakpoint, and
   continuing faulted while dereferencing it at `amqp_socket.c:92`. With a
   fake vtable embedded at body offset 0 (`send = marker_send`) and the body
   address placed at body offset 65545 (the byte range that lands on
   `socket->klass`), the library's own path — `amqp_send_frame :531` →
   `amqp_send_frame_inner :557` → `amqp_try_send amqp_socket.c:257` →
   `amqp_socket_send :92` — called the marker:
   `MARKER: controlled vtable call reached`, service rc 0.

4. **Negative / control results.** Fixed v0.17.0 service receives the same
   65600-byte socket body and returns `amqp_send_frame rc=-2`
   (`AMQP_STATUS_BAD_AMQP_DATA`) without reaching the marker; its 200000-byte
   ASan run also reports no error. A 2-byte body is clean on the vulnerable
   ASan service. An exact-sized (non-reusable) 65600-byte body changes heap
   layout — `state->socket` lands 196640 bytes past the outbound buffer — so
   no vtable overwrite occurs with that allocation pattern. Heap layout, not
   just body length, decides which object is hit; this is preserved as a
   boundary condition, not a failed claim.

## Grade and limits

Rung 4 **DEMONSTRATED IN THE LAB BUILD**, honestly labeled with the conditions
it needed: a synthetic local service, a 200000-byte reusable receive buffer,
a 65600-byte oversized socket-fed body, and a lab-only address file that
supplies the body and marker addresses to the client (a simulated disclosure;
the vulnerability itself provides no memory read). The overwritten pointer is
a real, live `amqp_socket_t` vtable pointer owned by the connection; the
reached code is a benign marker compiled into the harness, not native code
supplied by the attacker.

Still UNKNOWN: any real messaging application that forwards attacker-sized
bodies, its allocator and heap layout, a remotely reachable listener, an
address-disclosure primitive, and any exploit beyond the marker call. This is
not a claim of exploitability against a named real-world product. The socket
is a local test front end, not consumer evidence for a deployed application.

No pointer, control-flow or execution claim in this report rests on the
frontier lane's `realloc` interposer: the gdb and marker binaries are plain
builds of the pinned library.

## Witness replay (W74, tape #946)

Witness W74 replayed the #924 claim on commit `974a3ae` from a clean git
archive that included the frontier pin directory: `run.sh` **8 PASS / 0 FAIL
rc 0**, six pins OK, digest
`f8efc860e75e8cc0035c4957b2208928a74403da44e4f198ed757e3f2fd4209d` matched.
Inside the service process under ASan the write was `WRITE of size 200000` at
`amqp_connection.c:467` ← `:548` ← `:531`, allocation `:140` ← `:53`; the body
arrived over `AF_UNIX` as length-prefixed bytes (`service: received
len=200000 first=5a last=5a`).

The witness checked the offset arithmetic exactly: `memcpy` destination
`outbound+7`, socket object `outbound+65552`, so body byte 65545 lands on
`socket->klass`. gdb showed that field as `<amqp_tcp_socket_class>` before the
copy and chosen `0xa5` after it, across both the neighbour header and the
pointer. `marker_send` was reached through the overwritten vtable via the
library's own send path with body and marker addresses supplied by the
lab-only file (simulated disclosure); fixed 0.17.0 returned `rc=-2` and never
reached the marker; exact-sized 65600-byte buffers moved the socket 196640
bytes away.

Verdict: **ESTABLISHED AS CLAIMED** at the grade stated above — rung 4
demonstrated in the lab build with a synthetic service, simulated address
disclosure and benign marker; no real application, listener, genuine
infoleak, native code or exploit. Witness next owner: no replay owed.
