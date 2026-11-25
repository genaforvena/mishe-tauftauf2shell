# frontier brief — libsshch2shell (closed-channel data UAF)

Status 2026-11-25 W3: real ASan build + authenticated loopback wire replay
confirmed; rung 3 real-build, rung 4 MECHANICS with wire-chosen pointer
consumption from a recycled freed channel object under stated lab conditions.
The W3 lane shows that write in a run that exits cleanly. No rung 5. Original
staged harness 24 PASS / 0 FAIL; base real replay 5 PASS / 0 FAIL; extra
controls 8 PASS / 0 FAIL; survive controls 7 PASS / 0 FAIL. Witness verdict
UNKNOWN.

## Verified ground truth
Claim source: CVE-2026-59850 advisory https://www.libssh.org/security/advisories/CVE-2026-59850.txt (USN-9187-1, 2026-11-23, scout-supplied). Affects libssh <0.12.1/<0.11.5; fixed 0.12.1/0.11.5. Primitive: use-after-free read via channel data callbacks on remotely closed channels; CVSS PR:L (authenticated). Fix https://github.com/libssh/libssh-mirror/commit/7dfabb1fd213196c4912c314b418ff36c882ea54, parent a540e27659b08828ef61f2910a790f7cf2af9f8d; pins in lab/frontier/libsshch2shell/pins.sha256.

## Source-bound mechanism
Pinned channels.c.vuln:595-719, `channel_rcv_data()`, reads `data = ssh_string_data(str)` after `ssh_string_len(str)` and copies `len` bytes without checking channel state. Fixed:656-661 adds only: `if (channel->flags & SSH_CHANNEL_FLAG_CLOSED_REMOTE) { SSH_LOG(...); ssh_set_error(session, SSH_FATAL, ...); SSH_STRING_FREE(str); return SSH_PACKET_USED; }`. The include is pin lines 594-719 verbatim plus that guard under `#ifdef`.

## Observed evidence
`sh harness/run-all.sh`: 24 PASS / 0 FAIL, rc 0. Vulnerable attack rc 1, ASan excerpt:

    ==3699573==ERROR: AddressSanitizer: heap-use-after-free on address 0x506000000080 at pc 0x57c1684f8066 bp 0x7ffd7c3ae8e0 sp 0x7ffd7c3ae0a0
    READ of size 32 at 0x506000000080 thread T0
        #1 0x57c168539b82 in channel_default_bufferize /home/mesh-home/mishe-tauftauf2shell/lab/frontier/libsshch2shell/harness/harness.c:152:5
        #2 0x57c1685391a8 in channel_rcv_data /home/mesh-home/mishe-tauftauf2shell/lab/frontier/libsshch2shell/harness/channel_rcv_data.inc:85:9
    0x506000000080 is located 0 bytes inside of 64-byte region [0x506000000080,0x5060000000c0)
    freed by thread T0 here:
        #1 0x57c1685388b9 in main /home/mesh-home/mishe-tauftauf2shell/lab/frontier/libsshch2shell/harness/harness.c:241:9
    previously allocated by thread T0 here:
        #1 0x57c168538842 in main /home/mesh-home/mishe-tauftauf2shell/lab/frontier/libsshch2shell/harness/harness.c:231:30

Plain build prints `DEREF byte=M marker=MISHE-LIBSSH-UAF` from the freed pointer at payload offset 16. Fixed attack: rc 0, error=2, callback_bytes=0, no report. Safe channel (flag clear, chunk live): rc 0, error=0, callback_bytes=32 in both builds.

## Real-build authenticated wire replay (2026-11-25 W1)

Both pinned commits from `PROVENANCE.md` were fetched as source tarballs
(provisioning only) and compiled in full under clang ASan: vulnerable parent
`a540e27659b08828ef61f2910a790f7cf2af9f8d` (`real/build-asan`) and fixed
`7dfabb1fd213196c4912c314b418ff36c882ea54` (`real/build-fixed`), with
`-DWITH_SERVER=ON -DUNIT_TESTING=OFF -DBUILD_SHARED_LIBS=OFF`. The reproducer
`lab/frontier/libsshch2shell/real/real_wire.c` forks a server and client on
127.0.0.1. The client completes a real SSH key exchange and password
authentication (`CLIENT auth rc=0`), opens a session channel, writes a benign
first packet, then emits wire packets `SSH2_MSG_CHANNEL_CLOSE` and
`SSH2_MSG_CHANNEL_DATA` (payload `MISHE-LIBSSH-UAF-WIRE`, chosen byte `M` at
offset 0 and `-` at offset 16) for the same recipient channel. The server's
data callback drops the channel on the second data packet, modelling an
application that frees a remotely closed channel while data is still being
processed.

`sh lab/frontier/libsshch2shell/real/run-all.sh`: **5 PASS / 0 FAIL**, rc 0.
Control matrix (evidence under `real/evidence-wire-*.out`):

| build / input | ASan report | server data #2 | exit |
| --- | --- | --- | --- |
| vulnerable, close then data | heap-use-after-free | yes (`first=M off16=-`) | rc 1 |
| fixed, close then data | none | suppressed | rc 0 |
| vulnerable, data only (no close, no app free) | none | yes (`first=M off16=-`) | rc 0 |
| fixed, data only | none | yes (`first=M off16=-`) | rc 0 |

Vulnerable ASan report (`real/evidence-wire-vuln-close-data.out`):
`READ of size 8` in `channel_rcv_data` at pinned
`src/channels.c:705:26` (`if (channel->counter != NULL)`); the following
line 706 is `channel->counter->in_bytes += rest`. The read is 120 bytes
inside a 128-byte region; freed by the app's `on_data` callback via
`ssh_channel_free()` from `channel_rcv_data` at `channels.c:697`; allocated by
`ssh_channel_new()` at `channels.c:103` during the real channel-open request.
Frames run through `ssh_packet_process` -> `ssh_packet_socket_callback` ->
`ssh_socket_pollcallback`, i.e. the real SSH wire path. The fixed build's new
`SSH_CHANNEL_FLAG_CLOSED_REMOTE` guard suppresses the callback entirely
(`SERVER data #2` absent), so no reentrant free occurs.

## W2 controls and chosen-pointer mechanics (2026-11-25)

`real/run-extra.sh` builds the same two pinned trees and runs three new
controls; it reports **8 PASS / 0 FAIL**, rc 0. Evidence:
`real/evidence-wire-{vuln-close-no-free,vuln-groom,fixed-groom}.out`.

- **No application free** (`vuln`, close+data, `no-free` mode): data #2 is
  delivered with chosen bytes and no ASan report. The remote close marks
  `CLOSED_REMOTE` but does not free the channel; `ssh_channel_do_free()` only
  removes the channel from `session->channels` when the application has called
  `ssh_channel_free()`. Without that app call, this lane has no UAF.
- **Wire-chosen pointer from the freed object** (`vuln`, `groom` mode): the
  authenticated client sends a 128-byte data packet with offset 120 set to the
  little-endian address of a benign 8-byte global in the server process. The
  data callback frees the channel, then the application allocates a 128-byte
  buffer and copies the wire payload into it. With
  `ASAN_OPTIONS=quarantine_size_mb=0` (lab-only, to force allocator reuse) that
  allocation recycles the freed channel: `SERVER groom alloc=0x50c00001c3c0
  wire_off120=0x... target=0x...`, with the same address printed by the client.
  Pinned `channels.c:705` then reads `channel->counter` from that recycled
  chunk and `channels.c:706` performs `counter->in_bytes += rest`; the ASan
  death callback prints `SERVER death target=0x41414141414141c1` from the
  initial `0x4141414141414141` (+128, the packet length). That is an
  attacker-wire-chosen address receiving a read-modify-write from the UAF,
  observed in a real authenticated libssh build. ASan then reports a separate
  heap-buffer-overflow at pinned `channels.c:708` in `ssh_buffer_pass_bytes`,
  because the channel's stdout buffer was also freed by the same app call;
  that later fault does not create the pointer write.
- **Fixed build** (`groom` mode): the new guard suppresses data #2 entirely;
  no ASan report and the target stays `0x4141414141414141`.

## W3: chosen write in a run that exits cleanly (2026-11-25)

`real/run-survive.sh` builds the same two pinned trees and reports **7 PASS /
0 FAIL**, rc 0. Evidence: `real/evidence-wire-{vuln,fixed}-groom-survive.out`.
The new `groom-survive` lane keeps the two objects that
`channel_rcv_data()` touches *after* the data callback alive: before
`ssh_channel_free()` the lab app detaches `channel->stdout_buffer` and
`channel->callbacks`, and the client sets wire offsets 56 and 64 to zero so
the groomed channel's `stdout_buffer`/`stderr_buffer` are wire-chosen NULL.
No library source is modified.

Vulnerable lane (`real/evidence-wire-vuln-groom-survive.out`):
`SERVER groom-survive saved_buf=0x... saved_cbs=0x...`,
`SERVER groom alloc=0x50c00001c3c0 wire_off120=0x... target=0x... survive=1`,
`SERVER done data_packets=2`,
`SERVER target_after=0x41414141414141c1 groom_ptr=0x50c00001c3c0`,
`SERVER survive buf_len=0 saved=0x...`, `CLIENT rc=0 SERVER status=0x0`,
no ASan report. The wire-chosen pointer write at pinned `channels.c:706`
therefore completes in a process that returns normally; the plain groom
lane's later faults at `:708` (`ssh_buffer_pass_bytes`) and, in the first
failed iteration of this lane, at `:691` (freed callback-list iterator) come
from those other freed fields, not from the counter write. The first
iteration's ASan trace was observed before the callback-list detach was
added; its evidence file was overwritten by the passing rerun, so that
negative is transcript-only, not a preserved file. Fixed `groom-survive`
control: data #2 suppressed, target unchanged, no ASan.

The detach is explicitly lab-only, not a realistic application pattern:
it isolates the chosen-pointer write from unrelated UAF faults. Base
`run-all.sh` (5 PASS / 0 FAIL) and W2 `run-extra.sh` (8 PASS / 0 FAIL) still
pass after the harness change.


Honest ceiling: rung 3 is confirmed in a real build on a real authenticated
loopback wire. Rung 4 mechanics are demonstrated — attacker-chosen wire bytes
at a chosen offset of a recycled freed channel object drive a write to a chosen
address, and the W3 lane shows that write in a run that exits cleanly. Required
lab conditions remain explicit: authenticated peer (PR:L), application frees a
remotely closed channel from inside its data callback, application reuses the
freed 128-byte chunk for wire bytes, ASan quarantine disabled to make reuse
deterministic, and (for the clean-exit lane only) lab detachment of the channel's
stdout buffer and callback list. No instruction-pointer control, no benign
marker execution, no rung 5. Without that detachment the unrelated freed
fields still fault at `:691`/`:708`; a realistic allocation sequence that
avoids them without app intervention is not established. Independent witness
verdict remains UNKNOWN: all three suites have been replayed by the author only.

Next: ask witness for an independent replay of `real/run-all.sh`,
`real/run-extra.sh` and `real/run-survive.sh`; do not claim r5. What would
change the grade: a witness counterexample, or measured IP/marker control on
the same real authenticated build.
