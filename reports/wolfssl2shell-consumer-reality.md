# wolfSSL2shell — consumer-reality check on loopback (2026-11-21)

**Result: rung 4 is now ESTABLISHED for availability impact on a live
loopback wolfSSL DTLS 1.3 server, under explicit lab preconditions; code
execution remains UNKNOWN.** Rungs 1/2/3 of CVE-2026-6679 stay ESTABLISHED
on the verbatim pinned v5.9.0 ASan harness
(`reports/frontier-wolfssl2shell.md`, witnesses #985 and #1080). The natural
fill route hits only the heap top chunk (fifth wake below), but a lab-only
pre-grown output buffer — modelling a server that has already sent a flight
— puts the overflowing ACK write across the live `seenRecords` nodes:
sender-chosen record-number bytes overwrite a live node's glibc chunk size
and `next` pointer, and the real `Dtls13RtxFlushAcks` free path aborts with
`double free or corruption (out)` (sixth wake below). This is a
chosen-byte-in-live-object, symbolized, loopback-only result; no pointer
diversion to attacker code, control-flow hijack or execution was observed.

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

## Second wake: same-socket injection attempt (2026-11-21, 17:0xZ)

The first wake's replay used a fresh UDP socket per flood, so a different
source port was one possible explanation for `ack_count=0`. That sender
artifact is now excluded, and a stronger negative result recorded.

New lab-only files: `loopback_flood.py` (one connected UDP socket sends a
captured ClientHello plus copies with distinct 64-bit record numbers),
`loopback_inject_client.c` (wolfSSL IO-send callback injects forged handshake
records on the real client's own fd immediately after the real ClientHello),
`loopback_flood_test.py` (time-bounded orchestrator). `loopback_server.c`
gained a timeout argument and a 0.5 s monitoring thread; no pinned library
source was edited. All addresses 127.0.0.1.

Observed with `out/loopback/server-plain` (v5.9.0):

1. **Datagrams arrive.** `strace-inject.log` shows 11 `recvfrom` calls on
   the connected socket: the real ClientHello (record seq 0) plus 10 forged
   copies (seq 1–10), all from the client's single source port. The
   different-source-port explanation is therefore eliminated.
2. **Forged records are dropped before the ACK chain.** Under gdb
   (`gdb-inject10.log`) a 10-record injection produced exactly one
   `Dtls13CheckWindow`, one `Dtls13RecordRecvd`, one `Dtls13RtxAddAck` and
   four `Dtls13RtxFlushAcks` hits; none of the forged records reached
   `Dtls13CheckWindow`. A companion trace (`gdb-drop-diag.log`) counted 2
   `Dtls13CheckWindow` and 10 `DropAndRestartProcessReply` hits, with **no**
   `HandleDTLSDecryptFailed` hit. The live monitor stayed at `ack_count=0`,
   `done=1`, `state=10` for the full 4097-record injection. Symbolized
   cause of the drops beyond `DropAndRestartProcessReply` is UNKNOWN; the
   timing coincides with the server's switch from plaintext ClientHello
   records to encrypted handshake keys after its first reply.
3. **Plaintext-epoch extension attempt failed.** Rewriting every cipher
   suite in the captured ClientHello to `0x0000` (`ch-nosuite.bin`) to keep
   the server in plaintext epoch 0 after entering stateful mode left the
   server at `state=0`, `ack_count=0` for a 21-datagram flood
   (`nosuite-server.log`); that ClientHello never reached the stateful
   transition. `WOLFSSL_DTLS_CH_FRAG` is not defined in the pinned build's
   `wolfssl/options.h`, so fragmented-ClientHello filling is unavailable.

Grades are unchanged: rungs 1/2/3 ESTABLISHED on the verbatim pinned ASan
harness; rung 4 INSTRUMENTED (staged-heap chosen-byte readback only). No
live-neighbour overwrite, pointer control, control-flow diversion or
execution was observed. The remote fill route remains UNKNOWN, not
disproved: a crafted peer that produces thousands of ACK-eligible
handshake records within one plaintext epoch was not demonstrated here.

Reproduce the second-wake probes (all loopback only):

```
cd lab/frontier/wolfssl2shell
# same-socket replay; server prints ack_count via its monitor thread
./out/loopback/server-plain 18480 1 > out/loopback/replay-server.log 2>&1 &
python3 loopback_flood.py out/loopback/ch.bin 18480 20
# same-flight injection from the real client's fd
./out/loopback/server-plain 18481 1 > out/loopback/inject-server.log 2>&1 &
./out/loopback/inject-client 18481 4097
# unsupported-cipher variant (cipher-suite bytes 63..116 of ch.bin -> 0)
python3 -c 'b=bytearray(open("out/loopback/ch.bin","rb").read()); \
[b.__setitem__(i,0) for i in range(63,117)]; \
open("out/loopback/ch-nosuite.bin","wb").write(b)'
python3 loopback_flood.py out/loopback/ch-nosuite.bin 18482 20
```

The library trees, the ASan harness and the v5.9.1 control were untouched.

## Third wake: structural ACK-flush ceiling (2026-11-21, 17:4xZ)

A source read of the pinned v5.9.0 `src/dtls13.c` explains both prior
negative results mechanically. `Dtls13WriteAckMessage` (the vulnerable
serialization, called at `:2899`) is always followed by
`Dtls13RtxFlushAcks` (`:2930`), which frees every `seenRecords` node and
sets the list to NULL (`:775-783`). The overflow therefore requires 4097
distinct ACK-eligible handshake records to accumulate **between two
flushes**. Four pinned triggers start a flush:

1. `Dtls13MsgWasProcessed` (`:336-347`) sets `sendAcks =
   Dtls13RtxMsgNeedsAck(ssl, hs)`. On a server that helper returns 1 for
   `finished` (`:324-325`), `session_ticket` and `key_update` (`:330-331`).
   Each such message is self-flushing via `Dtls13DoScheduledWork` (`:2709`)
   -> `SendDtls13Ack`. This matches the observed 2 AddAck / 2 WriteAck / 2
   flush under the KeyUpdate flood and the ACK at the end of the real
   handshake (`finished`).
2. Retransmission (`:901-910`): `peer_handshake_number < expected` sets
   `retransmit = 1` and, when `seenRecords != NULL`, `sendAcks = 1`.
3. Disruption (`:930-934`): `dtls13SendMoreAcks && Dtls13DetectDisruption`
   sets `sendAcks = 1`. The lab server sets `sendMoreAcks = 0`, so this
   trigger is disabled there.
4. Fast timeout (`Dtls13RtxTimeout`, `:2742-2748`): any timeout with a
   non-empty list and (`serverState >= SERVER_HELLO_COMPLETE` or a seen
   unified header) calls `SendDtls13Ack` directly.

Structural consequence: a real client's post-handshake records are
application data (outer type 23, never added) or self-flushing KeyUpdates,
and forged plaintext records after the server's first flight are dropped
at the epoch switch. None of the demonstrated loopback routes can hold 4097
handshake records in one ACK cycle. This is a property of the pinned
consumer, not of the sink: rungs 1/2/3 remain ESTABLISHED on the harness,
where `Dtls13RtxAddAck` is driven directly and each insert is real.

Still UNKNOWN: a peer that delivers 4097 distinct handshake records inside
one epoch with no intervening finish/key-update/retransmission/timeout
flush (e.g. a crafted multi-fragment client flight before any key switch,
or a large in-order flight received within one fast-timeout interval). Not
demonstrated here and not disproved. No live-neighbour overwrite, pointer
control, control-flow diversion or execution was observed, so rung 4 stays
INSTRUMENTED. Grades unchanged. Pinned library trees untouched; all
addresses loopback; tagged v5.9.1 (128-record cap) remains the fixed-side
baseline.

## Fourth wake: live server reaches the wrap point (2026-11-21, 18:1xZ)

The earlier negatives came from the *flights* tried, not from the sink.
A new route fills `seenRecords` from raw network datagrams in a real
127.0.0.1 wolfSSL DTLS 1.3 server and reaches the vulnerable serializer.

### Route and lab preconditions

`Dtls13RecordRecvd` (`src/dtls13.c:1537`) runs at the record layer via
`Dtls13UpdateWindowRecordRecvd` (`src/internal.c:19322`), before the
handshake layer parses the message. A plaintext handshake record carrying
an *incomplete* ClientHello fragment (message_seq 0, fragment_offset 0,
fragment_length 4 < message_length 1024) is ignored by
`Dtls13AcceptFragmented` (`:1658`, returns 0 because
`WOLFSSL_DTLS_CH_FRAG` is absent), so there is no ServerHello, no epoch
switch and no ACK flush — yet the record's epoch/seq is still inserted into
`seenRecords` by `Dtls13RtxAddAck`. Sending 4097 such records with distinct
record numbers fills the list to 4097.

Two lab-only wrapper preconditions are explicit and must not be hidden:
`early13` sets `ssl->options.tls1_3 = 1` so `wolfSSL_accept()` enters the
TLS 1.3 path from the first call (a real server reaches that state after
version negotiation with a complete ClientHello, which also switches
epoch); `unified_seen` sets `ssl->options.seenUnifiedHdr = 1`, the second
gate in `Dtls13RtxTimeout` (`:2740`) without which no ACK is sent. A single
unified-header datagram from the peer does set this flag (observed:
`got_timeout_ret=1` in `out/loopback/frag-mixed.log`), but it also poisons
later legacy-record processing, so the wrapper sets it here. No pinned
library source was edited. Pacing is required: an unpaced 4097-datagram
flood reached only 2657 inserts, while 200-1200 us pacing reached 4097.

The reverse order was also tried: fill the list first, then replay one real
unified-header ClientHello from the peer (`frag-peerunified.log`,
`frag-peerunified2.log`). It did not reach the sink: ASan stayed clean and
the live count peaked at 3991/3983, below the wrap point. The wrapper-set
`unified_seen` therefore remains part of the demonstrated conditions.

### Observations (all 127.0.0.1, logs in `out/loopback/`)

1. **The list fills from the wire.** 20 fragments → `ack_count=20`
   (`frag-early13.log`). 4097 paced fragments → `ack_count=4097`,
   `state=0 done=0`, no intervening flush (`frag-4097-paced.log`,
   `frag-asan-4097b.log`).
2. **ASan fires at the real sink, with symbolized frames**
   (`frag-asan-gate2.log`): `WRITE of size 8 at c64toa misc.c:1010` ←
   `Dtls13WriteAckMessage dtls13.c:2604` ← `SendDtls13Ack :2899` ←
   `Dtls13RtxTimeout :2748` ← `wolfSSLReceive internal.c:11132` ←
   `GetInputData :22186` ← `DoProcessReplyEx :22728` ← `wolfSSL_accept_TLSv13
   tls13.c:14783` ← `wolfSSL_accept ssl.c:6756` ← `main`. The write is 0
   bytes after a 31-byte region `[0x503000031900,0x50300003191f)` allocated
   by `GrowOutputBuffer internal.c:11415` ← `CheckAvailableSize :11581` ←
   `Dtls13WriteAckMessage :2588`.
3. **Chosen bytes from the network land past the region**
   (`chosen-live2-gdb.log`, `chosen-live4-gdb.log`, plain build under gdb).
   Sender record numbers started at `0x424242420000`; at the first OOB
   record the breakpoint at `dtls13.c:2607` shows
   `output=0x55555564b210`, `region_end=0x55555564b22f` and, at
   `0x55555564b237`, bytes `00 00 42 42 42 42 00 01` — the network-chosen
   seq of the second record. The adjacent glibc chunk's size field at
   `0x55555564b230` is zeroed by the epoch write. The same symbolized frame
   chain (frames 0-5) is present.
4. **Fixed control holds.** The tagged v5.9.1 ASan server
   (`server-fixed-asan`, `frag-fixed-asan.log`) given the identical 4097
   fragments caps `ack_count` at 128 (DTLS13_ACK_MAX_RECORDS) and reports
   zero ASan errors.

### Grade disposition

Rungs 1/2/3 remain ESTABLISHED on the harness and are now additionally
ESTABLISHED on a live loopback server driven by network-fed records with
symbolized frames. Rung 4 is still labelled INSTRUMENTED: the chosen-byte
write is now observed on the live path, but the bytes land in heap slack /
the next malloc chunk's metadata, and no specific live neighbour object or
pointer field, control-flow diversion or execution was identified. The
remaining gap is a grooming step that places a chosen live object or
pointer at the overwritten offsets, not another fill route. The two lab
flags above are part of the conditions and are reported as such.

Reproduce (all loopback):

```
cd lab/frontier/wolfssl2shell
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
    -Ibuild/wolfssl-5.9.0-stable loopback_server.c \
    build/wolfssl-5.9.0-stable/src/.libs/libwolfssl.a -lm -lpthread \
    -o out/loopback/server-asan
ASAN_OPTIONS=detect_leaks=0 ./out/loopback/server-asan 18516 1 1 1 \
    > out/loopback/frag-asan-gate2.log 2>&1 &
python3 loopback_frag_sender.py 18516 4097 0 1024 800 legacy 424242420000
```

## Fifth wake: the overflow path is wilderness, not a live object (2026-11-21, 18:4xZ)

Question: with the fill route solved, can a chosen live object or pointer be
placed at the overwritten offsets? Answer from the live plain build: **no,
not in this route** — the 65,552-byte overwrite lands entirely in the glibc
top chunk, because the ACK output buffer is the last live allocation before
the sink. This is a structural ceiling on the demonstrated route, not a
claim that CVE-2026-6679 is unexploitable by some other fill route.

Method: `groom_inspect.gdb` breaks at `dtls13.c:2604` on the first epoch
write past `output + headerLength + 2 + msgSz`, dumps live object addresses,
1024 bytes past the region, the neighbouring glibc chunk headers and
`info proc mappings`, then breaks at `:2613` after the full loop. Server:
plain (non-ASan) `server-plain`, port 18630, 4097 paced fragments at 1200 us.
All addresses 127.0.0.1; full log `out/loopback/groom-inspect.log`.

Observed:

1. `output=0x55555564b210`, `region_end=0x55555564b22f`, `msgSz=16`,
   `headerLength=13`. Live objects are all *below* the output buffer:
   `ssl=0x555555628620`, `ctx=0x5555556272c0`,
   `inputBuffer.buffer=0x55555562aa50`,
   `seenRecords=0x55555562b1f0`, encryption epochs `0x555555628c28`,
   `rtxRecords=NULL`. `seenRecords` nodes are 0x20 apart and
   `0x62b1f0 + 4097*0x20 = 0x64b210` exactly: the output buffer is the very
   next allocation after the last inserted record number.
2. The chunk header immediately after the output buffer is at
   `0x55555564b230` with `size=0x1ddd1`. `info proc mappings` gives the heap
   as `[0x555555627000,0x555555669000)`; `0x669000 - 0x64b230 = 0x1ddd0`.
   That chunk is the **top chunk** (wilderness), not a live object. The 1024
   bytes past the region are all zero before the write — no allocated chunk,
   no tcache/fastbin `fd`/`bk`, no pointer to corrupt.
3. After the loop, `ackMessage=0x55555565b22f` (65,552 bytes past the start)
   and the region reads as the attacker's repeating pattern
   (`0x0000000000000000` epoch, `0x0100000000000000`,
   `0x0200000000000000`, ... sequence). All 65,552 controlled bytes land in
   unallocated top memory; `0x64b22f + 65552 = 0x65b22f` is still below the
   heap end `0x669000`.
4. The adjacent top-chunk size field at `0x55555564b238` is attacker-writable
   (7 bytes from the sequence value, 1 from the next epoch value), but this
   host is glibc 2.39: its `sysmalloc`/top-size sanity checks rule out the
   classic House-of-Force follow-up. A plain run to completion
   (`out/loopback/groom-plain-post.log`) exited 0 with no malloc/abort — no
   consumer allocates from the corrupted top after the write.

Interpretation: the fill route requires the incomplete-ClientHello path,
which suppresses the handshake, all ACK flushes and every prior output
write. `CheckAvailableSize` therefore grows the output buffer at `:2588`
immediately before the write loop, so it is always the last live chunk and
the overflow has no live neighbour to hit. Nothing allocates between the
grow and the write, and the receiver is single-threaded, so network-driven
grooming cannot insert a victim there. A live-pointer overwrite would need
the output buffer to be a pre-existing large allocation with live chunks
after it (the state of a real server after a completed handshake); producing
4097 ACK-eligible records in that state remains UNKNOWN — KeyUpdates
self-flush and post-handshake plaintext records are dropped at the epoch
switch, as recorded above. Rung 4 stays INSTRUMENTED; rungs 1/2/3 are
unchanged. Tagged v5.9.1 (128-record cap) remains the fixed control.

Reproduce (all loopback, no pinned source edits):

```
cd lab/frontier/wolfssl2shell
gdb -q -batch -x groom_inspect.gdb ./out/loopback/server-plain \
    > out/loopback/groom-inspect.log 2>&1 &
sleep 2
python3 loopback_frag_sender.py 18630 4097 0 1024 1200
```

## Sixth wake: chosen bytes in a live node, real cleanup abort (2026-11-21, 18:5xZ)

The fifth-wake ceiling applies to the *natural* fill route, where the output
buffer is grown at the sink and is the last live chunk. A lab-only variant
reaches the live objects. `loopback_server.c` gained an optional sixth
argument `pregrow`: before the flood it calls `CheckAvailableSize(ssl, 64)`,
modelling a real server whose output buffer already exists because it has
sent a flight. No pinned library source was edited. `CheckAvailableSize`
then does not grow the buffer at `:2588`, so the 4097 `seenRecords` nodes
are allocated *after* it, inside the 65,552-byte overflow path.

Preconditions, reported with the result: `early13`, `unified_seen`,
`pregrow=64`, epoch 0, 4097 paced fragments (1200 us), loopback only. Epoch
is not attacker-chosen in this route: sending epoch `0x4242` kept
`ack_count=0` (`groom-abort2-gdb.log`), so the chosen bytes come from the
64-bit record *sequence number*.

Observed:

1. Gdb at `dtls13.c:2613` after the write (plain build, `groom-victim2.gdb`
   running `18633 60 1 1 64`): `output=0x55555562a930`,
   `ackMessage=0x55555563a94f`, `seenRecords=0x55555562b240`. The corrected
   dump (`out/loopback/groom-victim2-corrected.log`) shows the live head
   node's glibc chunk header: `prev_size` at `0x55555562b230` is
   `0x0000000000000000` and its size field at `0x55555562b238` is
   `0x008f000000000000` (originally `0x21`). Its `next` pointer at
   `0x55555562b250` is `0x0000000000000000` (originally the address of the
   next node). Neighbouring node size fields carry the same sender-derived
   pattern (`0x0090000000000000` at `0x55555562b248`, `0x0091000000000000`
   at `0x55555562b258`, and so on). The write cursor reaches these live
   fields with the full symbolized frame chain
   `Dtls13WriteAckMessage dtls13.c:2613` ← `SendDtls13Ack :2899` ←
   `Dtls13RtxTimeout :2748` ← `wolfSSLReceive internal.c:11132` ←
   `wolfSSL_accept_TLSv13 tls13.c:14783`.
   Correction from witness replay #1104: the earlier dump in
   `out/loopback/groom-victim2.log` reported `0x0078000000000000` at
   `0x55555562b238`. That byte came from an unrelated slab region at
   `0x55555562b0c8`, not from the head node: the old expression
   `x/8gx ssl->dtls13Rtx.seenRecords - 16` was interpreted as a display
   offset from `head` rather than byte arithmetic on `head`. The script now
   uses `x/8gx ((char*)ssl->dtls13Rtx.seenRecords - 16)` and prints the
   head's `prev_size`/`size` directly; the old log is retained as the
   original observation. This is a citation correction only: the overwrite,
   sender-chosen bytes and abort below are unchanged.
2. Without gdb, the same live server aborts: `out/loopback/groom-plain-crash.log`
   shows 4097 ACK records then `double free or corruption (out)`, server
   exit code 134 (SIGABRT). Under gdb (`groom_abort.gdb`,
   `out/loopback/groom-abort-gdb.log`) the symbolized chain is
   `malloc_printerr` ← `_int_free_merge_chunk(p=0x55555562b230,
   size=40250921669623808)` ← `_int_free` ← `__GI___libc_free` ←
   `wolfSSL_Free wolfcrypt/src/memory.c:449` ←
   `Dtls13RtxFlushAcks dtls13.c:780` ← `SendDtls13Ack :2930` ←
   `Dtls13RtxTimeout :2748` ← `wolfSSLReceive internal.c:11132` ←
   `GetInputData :22186` ← `DoProcessReplyEx :22728` ←
   `wolfSSL_accept_TLSv13 tls13.c:14783`. The abort is in the real ACK
   cleanup, entered from the record receive path, not in lab instrumentation.
3. The aborting size is sender-chosen. With `seq_base=0` the free size is
   `0x008f000000000000` (143 << 48, where 143 is a chosen record number);
   with `seq_base=0x1000` (`run_groom_seqbase.sh`,
   `out/loopback/groom-abort3-gdb.log`) it is `0x008f100000000000` — the
   chosen `0x10` byte appears in the size argument. Same frames and same
   chunk `0x55555562b230` in both runs.
4. Fixed control: the tagged v5.9.1 server built from the same wrapper with
   `pregrow=64` and the identical 4097 fragments
   (`out/loopback/groom-fixed-control.log`) reported no abort and zero ASan
   reports across 184 monitor samples; the known 128-record cap applies.
   The run was stopped at the harness timeout while still looping, so this
   control is bounded to that observation window, not a full server exit.

Grade disposition: rung 4 moves from INSTRUMENTED to **ESTABLISHED for
availability impact** — chosen record-number bytes at chosen offsets in a
live heap object, symbolized frames, and a deterministic server abort on a
loopback socket. This matches the advisory's `VA:H`. It does **not**
establish pointer diversion, arbitrary write or execution: the `next`
pointer was overwritten with a chosen value but the flush traverses only
one node before the abort, and no fake-chunk or tcache follow-up was
demonstrated. Those remain UNKNOWN. All four lab preconditions above are
part of the demonstrated conditions; early13 and unified_seen were already
reported in the fourth wake, and pregrow models a post-flight server.

Reproduce (all loopback, no pinned source edits):

```
cd lab/frontier/wolfssl2shell
gcc -g -O0 -Ibuild/wolfssl-5.9.0-plain loopback_server.c \
    build/wolfssl-5.9.0-plain/src/.libs/libwolfssl.a -lm -lpthread \
    -o out/loopback/server-groom
gdb -q -batch -x groom_abort.gdb ./out/loopback/server-groom \
    > out/loopback/groom-abort-gdb.log 2>&1 &
sleep 2
python3 loopback_frag_sender.py 18635 4097 0 1024 1200
```

## Seventh wake: pointer-control ceiling at the live free site (2026-11-21, 19:2xZ)

The sixth-wake result left two open questions: does the overwritten `next`
pointer ever become non-NULL, and can the overwritten chunk size be made a
valid glibc size so the real cleanup completes instead of aborting? Both were
tested at the live free site, loopback only, with no pinned library edits.

Probe: `groom_size.gdb` breaks at the real `XFREE` in `Dtls13RtxFlushAcks`
(`dtls13.c:780`) and prints the node being freed, its `next`, and the chunk
size field at `rn - 8`. `run_groom_size.sh PORT SEQ_BASE_HEX LOG` runs the
plain build with `pregrow=64`, `early13`, `unified_seen` and 4097 paced
fragments (1200 us), varying only the sender's 48-bit `seq_base`.

Observed (logs in `out/loopback/`):

1. Control, `seq_base=0` (`groom-size-control.log`): `rn=0x55555562b240`,
   `next=(nil)`, `list=(nil)`, size field at `0x55555562b238` =
   `0x008f000000000000`. Cleanup aborts: `double free or corruption (out)`
   from `_int_free_merge_chunk`. This reproduces the sixth-wake result with
   the new breakpoint.
2. Chosen size, `seq_base=0x20ffffffff71` (`groom-size-21.log`): same node
   and same `next=(nil)`; the size field becomes `0x0000000000002100` —
   256 bytes, 16-byte aligned, i.e. a *plausible* glibc chunk size chosen by
   wire bytes. Cleanup still aborts, now with `double free or corruption
   (!prev)`. The neighbouring qwords at `0x55555562b230/240/248` are
   `0`, `0`, `0x0001000000002100`: chosen bytes also reach the node's data,
   but the `next` field stays zero.
3. Across three sender bases (`0`, `0x1000` in the sixth wake, and
   `0x20ffffffff71` here) every overwritten size field has its low byte
   zero (PREV_INUSE clear) and every observed node `next` field is NULL.
   The sender sends a 48-bit sequence number, so the bytes feeding the size
   field's low byte and `next` are structurally zero on this host; epoch is
   not attacker-chosen here (sixth wake, `groom-abort2-gdb.log`). This is a
   measured ceiling on this build, not a claim about other heap layouts or
   64-bit sequence support.

Disposition: rung 4 stays **ESTABLISHED for availability impact** — nothing
here weakens the chosen-byte overwrite or the deterministic abort. Rung 5
stays **UNKNOWN** and is now bounded on this build: no non-NULL `next` was
observed, no tcache insertion or subsequent allocation was reached, and even
an aligned chosen size forces glibc into backward-consolidation checks
against an also-corrupted neighbour, so cleanup aborts. No pointer
diversion, arbitrary write, benign marker call or execution was observed.
The tagged v5.9.1 control from the sixth wake (128-record cap, no abort)
still applies; the fixed code rejects the list before this loop regardless
of `seq_base`.

Reproduce, all loopback:

```
cd lab/frontier/wolfssl2shell
bash run_groom_size.sh 18644 0 out/loopback/groom-size-control.log
bash run_groom_size.sh 18645 20ffffffff71 out/loopback/groom-size-21.log
```

