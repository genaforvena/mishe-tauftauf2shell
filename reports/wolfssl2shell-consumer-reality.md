# wolfSSL2shell — consumer-reality check on loopback (2026-11-21)

**Result: the remote ACK-fill route is gated in a real wolfSSL DTLS 1.3
server; no rung-4 promotion.** Rungs 1/2/3 of CVE-2026-6679 remain
ESTABLISHED on the verbatim pinned v5.9.0 ASan harness
(`reports/frontier-wolfssl2shell.md`, witness #985). Rung 4 remains
INSTRUMENTED (staged-heap chosen-byte readback only). This report adds a
negative/consumer-reality result from a real 127.0.0.1 server, not a
counterclaim about the sink.

## Question and method

AGENTS.md requires checking the consumer's actual behavior before investing
in exploitation mechanics. Here the consumer is the DTLS 1.3 record-receive
path: `internal.c:23160` `Dtls13UpdateWindowRecordRecvd` ->
`Dtls13RecordRecvd` (`src/dtls13.c:1537`), which calls `Dtls13RtxAddAck` at
`:1547` **only for handshake records** (`ssl->curRL.type == handshake`).
`SendDtls13Ack` (`:2863`) serializes `seenRecords` at `:2899` and
`Dtls13RtxFlushAcks` (`:763`) empties the list after each ACK.

Lab-only files in `lab/frontier/wolfssl2shell/` (no library source edits):

- `loopback_server.c` — wolfSSL v5.9.0 DTLS 1.3 server bound only to
  127.0.0.1, reading real `ssl->dtls13Rtx.seenRecords` through
  `wolfssl/internal.h`; it disables the HRR cookie, sets long DTLS timeouts
  (60/120 s), sets `sendMoreAcks=0`, and calls
  `wolfSSL_dtls_got_timeout()` once at the end to exercise the real ACK path.
- `loopback_real_client.c` — real DTLS 1.3 client; handshake, then
  `wolfSSL_update_keys()` plus a 1-byte `wolfSSL_write()` per update to flush
  each one onto the loopback socket.
- `loopback_ch_client.c` + `loopback_sender.py` — capture one real ClientHello
  datagram and replay it with patched 64-bit record numbers, patched
  handshake `message_seq`, in legacy or DTLS 1.3 unified-header form.
- `loopback_ack.gdb` — breakpoints on the real receive/ACK/flush symbols
  (port 18458); transient variants and logs are in the ignored `out/loopback/`.
- All binaries and logs live in `lab/frontier/wolfssl2shell/out/loopback/`.

Both pinned trees were built verbatim by `build.sh` /
`chosen_readback.sh`; the server used `build/wolfssl-5.9.0-plain` (no ASan,
so gdb can walk the live heap). No datagram left 127.0.0.1.

## Observed

1. **The loopback server is genuinely live.** A real client handshake
   completed in one pass: `FACT real_client_connect_ret=1 tries=1` and server
   `FACT iter=0 accept_ret=1 ... done=1 unified=1`, record version `fefc`
   (DTLS 1.3 minor).
2. **A replayed ClientHello does not fill the list.** A captured 255-byte
   ClientHello (`16fefd...`, handshake seq 0) replayed with distinct record
   numbers, with distinct handshake `message_seq`, and in unified-header form
   gave at most one `Dtls13UpdateWindowRecordRecvd` /
   `Dtls13RecordRecvd` hit (`out/loopback/gdb-ack.log`, `gdb-ack2.log`,
   `gdb-ack3.log`, `gdb-window.log`, `gdb-window2.log`, `gdb-unified.log`);
   patched variants gave zero window hits. The server printed
   `ack_count=0`; `Dtls13RtxFlushAcks` was reached 4 times.
   In `gdb-window2.log` and `gdb-unified.log` the server reached `done=1`
   before the flood, so the replayed pre-handshake ClientHellos were not
   accepted as new handshake flights.
3. **Real post-handshake records reach the ACK path but are not
   handshake records in bulk.** For 20 KeyUpdates with write-flush,
   `gdb-flush.log` recorded 22 `Dtls13RecordRecvd` hits, 5
   `Dtls13RtxFlushAcks` hits, and `ack_count=0`. With 4100 requested updates,
   `client-4100b.log` reports `updates_sent=4100` in ~1.7 s and the server
   again printed `ack_count=0`. Under gdb, `gdb-4100.log` shows **446**
   `Dtls13RecordRecvd` hits but only **2** `Dtls13RtxAddAck` and **2**
   `Dtls13WriteAckMessage` hits: the first two records are `type=22`
   (handshake); subsequent records are `type=23` (application data). Those
   two ACK writes flushed the list each time, so no truncation-sized list
   ever formed.
4. **No live-neighbour or pointer result.** The per-record bytes were not
   examined past the undersized output region in this real-server run; no
   live object, pointer field, control-flow diversion or execution was
   observed. The chosen-byte readback from the earlier staged heap remains
   the only rung-4 evidence.

## Interpretation and limits

The advisory's remote-reach claim is mechanically supported by the pinned
call site, and the receive-side chain is demonstrably live on loopback.
What this experiment shows is narrower and concrete: in this host's pinned
v5.9.0 build, a real server empties `seenRecords` after each ACK, and a
real client's repeated key updates produce application-data records, not
thousands of ACK-eligible handshake records. A simple replay of one captured
ClientHello is not accepted as 4097 distinct handshake flights. Therefore
the specific route attempted here — fill the list from a loopback peer and
watch the wrap at the live sink — did not reach 4097 records.

This is **not** a proof that CVE-2026-6679 is unreachable over the network.
Other ways to produce 4097 distinct, ACK-eligible handshake records in one
ACK cycle (e.g. a crafted multi-flight DTLS 1.3 client) were not attempted
in this wake and remain UNKNOWN. The tagged v5.9.1 control in
`lab/frontier/wolfssl2shell/out/` remains the fixed-side baseline.

## Reproduce

```
cd lab/frontier/wolfssl2shell
gcc -g -O0 -Ibuild/wolfssl-5.9.0-plain loopback_server.c \
    build/wolfssl-5.9.0-plain/src/.libs/libwolfssl.a -lm -lpthread \
    -o out/loopback/server-plain
gcc -g -O0 -Ibuild/wolfssl-5.9.0-plain loopback_real_client.c \
    build/wolfssl-5.9.0-plain/src/.libs/libwolfssl.a -lm -lpthread \
    -o out/loopback/real-client
./out/loopback/server-plain 18458 > out/loopback/server-4100b.log 2>&1 &
timeout 200 ./out/loopback/real-client 18458 4100
```

All addresses are 127.0.0.1; the sender/receiver pair exits with the server
`loopback_ack.gdb` counts hits on the real symbols; transient variants of
that script used the ports printed in the corresponding logs above.
