# frontier brief — libsshch2shell (closed-channel data UAF)

Status 2026-11-25: STAGED locally; rung 3 ASan plus rung 4 PARTIAL. No rung 5.

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

## Feasibility and next experiment
Rung 3: ASan read in pinned verbatim callback. Rung 4 PARTIAL: chosen bytes at a chosen offset; authenticated peer required. No real SSH build, wire packet, pointer/IP control, command execution or rung 5. Next: build pinned 0.12.1 parent under ASan, set CLOSED_REMOTE, send a real SSH2_MSG_CHANNEL_DATA on an authenticated loopback session, and check guard suppression before any reentrant free.
