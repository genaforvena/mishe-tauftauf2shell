# frontier brief — libsshch2shell (closed-channel data UAF)

Status 2026-11-25: real ASan build + authenticated loopback wire replay
confirmed; rung 3 real-build, rung 4 PARTIAL (chosen wire bytes, no pointer/IP
control). No rung 5. Original staged harness remains 24 PASS / 0 FAIL.

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
`src/channels.c:705:26` (`channel->local_window -= len`), 120 bytes inside a
128-byte region; freed by `on_data` at `real_wire.c:52` via
`ssh_channel_free()` from `channel_rcv_data` at `channels.c:697`; allocated by
`ssh_channel_new()` at `channels.c:103` during the real channel-open request.
Frames run through `ssh_packet_process` -> `ssh_packet_socket_callback` ->
`ssh_socket_pollcallback`, i.e. the real SSH wire path. The fixed build's new
`SSH_CHANNEL_FLAG_CLOSED_REMOTE` guard suppresses the callback entirely
(`SERVER data #2` absent), so no reentrant free occurs.

Honest ceiling: the attacker controls authenticated wire bytes and packet
ordering; the additional condition is an application that frees the remotely
closed channel from inside its data callback. The UAF read is of freed channel
metadata, not of attacker-supplied bytes at an attacker-chosen freed offset;
there is no pointer/IP control, no benign marker execution and no rung 5. The
peer must authenticate (CVSS PR:L), which caps any remote claim. Rung 3 is now
confirmed in a real build on a real loopback wire; rung 4 stays PARTIAL for
chosen bytes at a chosen offset under a stated application condition. Witness
verdict remains UNKNOWN (no independent replay yet).

Next: independent witness replay of `real/run-all.sh`; then investigate
whether a payload-byte read from freed channel buffers (rather than channel
metadata) is reachable without an application callback free.
