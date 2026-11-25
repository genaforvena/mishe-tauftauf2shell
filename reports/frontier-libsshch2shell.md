# frontier brief — libsshch2shell (closed-channel data UAF)

Status 2026-11-25 W5: independent witness verdict #4161 (W214) is ESTABLISHED
AS LABELED for the five unmodified real-build suites replayed from a clean
archive of `c5ece2a9` — rung 3 on a real authenticated loopback wire, rung 4
mechanics, and rung 5 MECHANICS only, NOT ESTABLISHED as remote execution.
No contradiction, no grade change, no NIT; PR:L and the lab-only detach, malloc
reuse and trampoline conditions stand. Staged harness 24 PASS / 0 FAIL; real
suites base 5/0, extra 8/0, survive 7/0, call 9/0, exec 8/0, all rc 0.

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

Bounded negative (mode removed, transcript-only): a `groom-rebuild` variant
tried to avoid the detach by allocating fresh replacement objects for the
freed stdout buffer and callback-list iterator after the channel free. The
new objects did not land at the old addresses (`SERVER rebuild buf_old=0x...
buf_new=0x... buf_match=0 it_old=0x... it_new=0x... it_match=0`); ASan still
faulted at pinned `channels.c:708` while the death callback still showed the
chosen-pointer write (`target=0x41414141414141c1`). The experimental mode
and its throwaway evidence file were removed. A clean-exit lane without app
detachment is therefore not established.

The detach is explicitly lab-only, not a realistic application pattern:
it isolates the chosen-pointer write from unrelated UAF faults. Base
`run-all.sh` (5 PASS / 0 FAIL) and W2 `run-extra.sh` (8 PASS / 0 FAIL) still
pass after the harness change.

Clean-archive receipt: source and scripts extracted from `git archive HEAD`
into a throwaway directory, with symlinks to the same lab's prebuilt ASan
libs, mirror trees and hostkey (the archive does not contain those build
artifacts). All three suites replayed there at 06:03Z: `run-all.sh` 5 PASS /
0 FAIL, `run-extra.sh` 8 PASS / 0 FAIL, `run-survive.sh` 7 PASS / 0 FAIL.
This checks committed harness text, not a rebuild of libssh from the archive.

## W4: wire-chosen indirect call and command execution (2026-11-25)

`real/run-call.sh` reports **9 PASS / 0 FAIL**; `real/run-exec.sh` reports
**8 PASS / 0 FAIL**. Neither library source nor the pinned commits were
changed; the extra lanes extend only `real/real_wire.c`.

**Indirect call.** With the W3 detaches in place, the lab app keeps the
channel's first callback-list node alive and redirects its `next` pointer to
an app-owned fake `ssh_iterator` whose `data` is a fake
`ssh_channel_callbacks_struct`. Wire offset 112 chooses that structure's
`channel_data_function`; the pinned iterator at `channels.c:691-697` then
calls the chosen address with the session, channel, buffer and userdata.
Vulnerable evidence `real/evidence-wire-vuln-groom-call.out`:
`CLIENT sent call fn=0x... bad=0`,
`SERVER call fake_cbs=0x50e0000003c0 node=0x502000006f50
fn=0x... first=0x502000006f70`,
`SERVER MARKER called len=0 hits=1`, `SERVER done data_packets=2
marker_hits=1`, `SERVER target_after=0x41414141414141c1`,
`CLIENT rc=0 SERVER status=0x0`, no ASan. The marker sees `len=0` because the
first callback's 128-byte return was consumed from the detached buffer by
`ssh_buffer_pass_bytes` at `channels.c:708` before the second callback ran.
The chosen code address is ASLR-dependent; reruns of the same lane print
different values, so it is redacted here as elsewhere in this report.
Invalid-pointer control `real/evidence-wire-vuln-groom-call-bad.out` sends
`fn=0x4141414141414141` and faults exactly at the indirect call:
`ERROR: AddressSanitizer: SEGV ... channels.c:697:16 in channel_rcv_data`,
no marker, `SERVER status=0x100`. Fixed `groom-call` suppresses data #2 and
the call entirely.

**Wire-borne command.** In `groom-exec` mode the wire carries
`touch evidence-wire-vuln-groom-exec.marker` at offset 0 and the
`exec_trampoline` address at offset 112; the fake callback's `userdata` points
at the groomed chunk, so the command string is read from wire-carried bytes in
the server process. Vulnerable evidence
`real/evidence-wire-vuln-groom-exec.out`:
`CLIENT sent exec cmd=touch evidence-wire-vuln-groom-exec.marker fn=0x...`,
`SERVER EXEC trampoline cmd=touch evidence-wire-vuln-groom-exec.marker`,
`SERVER EXEC rc=0`, `SERVER done data_packets=2`, the chosen-pointer write,
clean exit and no ASan. The file existed and was renamed to
`real/evidence-wire-exec-sideeffect.kept` before the controls ran. Fixed
`groom-exec` has no data #2, no trampoline call, no file and an unchanged
target; vulnerable `groom-call` (marker function, no command) also leaves no
file. The chosen callee is therefore wire-selected, not a harness default.


Clean-archive receipt (commit `c5ece2a9`, 2026-11-25 06:25Z): source and
scripts from `git archive c5ece2a9 lab/frontier/libsshch2shell` extracted to
a throwaway directory, with symlinks to this lab's prebuilt ASan libs, both
pinned mirror trees and the hostkey (the archive carries no build artifacts).
All five suites replayed there: base 5 PASS / 0 FAIL, extra 8/0, survive 7/0,
call 9/0, exec 8/0; the exec lane again printed the trampoline command and
the call lane again printed the benign marker. This checks committed harness
text, not a rebuild of libssh from the archive.

Honest ceiling: rung 3 is confirmed in a real build on a real authenticated
loopback wire. Rung 4 mechanics are demonstrated — attacker-chosen wire bytes
at chosen offsets of a recycled freed channel object drive a write to a chosen
address, select an indirect callee, and execute a benign in-process marker.
The command lane is **rung 5 MECHANICS only**, witness-replayed and accepted
as labeled but NOT ESTABLISHED as remote execution: a wire-borne string is
executed by a lab trampoline in the live server process, not by a real
application callback pattern. Required lab conditions remain explicit:
authenticated peer (PR:L),
application frees a remotely closed channel from inside its data callback,
application reuses the freed 128-byte chunk for wire bytes, ASan quarantine
disabled, W3/W4 detachment of the channel's stdout buffer and callback list,
and app-owned fake callback objects for the call lanes. ASLR was not disabled;
the client chose current process addresses in the forked peer. No persistent
shell, no remote command service, no IP hijack beyond the chosen callback
slot. Without the detachment the unrelated freed fields still fault at
`:691`/`:708`; a realistic allocation sequence that avoids them without app
intervention is not established.

## Witness verdict (2026-11-25 06:41Z, tape #4161 / W214)

Independent replay of the W4 offer (#4157, covering W2 #4127 and W3 #4145):
**ESTABLISHED AS LABELED**, no contradiction, no grade change, NO full r5.
The witness replayed the five unmodified real-build suites from a clean git
archive of `c5ece2a9`: `run-all.sh` 5 PASS / 0 FAIL, `run-extra.sh` 8/0,
`run-survive.sh` 7/0, `run-call.sh` 9/0, `run-exec.sh` 8/0, all rc 0. It checked
the pins (vulnerable `channels.c` b015a334..., fixed b320a326...), the three
sinks verbatim (`channels.c:697` indirect call, `:705` counter read, `:706`
`in_bytes += rest`) and that the fixed delta is the single vendor
`CLOSED_REMOTE` guard at `:653-660`.

In the raw `groom-exec` evidence the witness confirmed the touch command at
wire offset 0, the trampoline address at offset 112,
`SERVER EXEC trampoline cmd=touch evidence-wire-vuln-groom-exec.marker`,
`SERVER EXEC rc=0`, `target_after=0x41414141414141c1`,
`CLIENT rc=0 SERVER status=0x0`, no ASan, and a created 0600 zero-byte marker
file. The fixed lane made no call, created no file and left the target intact.
Its bad-pointer counterexample (`fn=0x4141414141414141`) faulted at
`channels.c:697:16` with no marker, confirming the callee is wire-supplied.

Accepted ceiling, exactly as reported above: PR:L authenticated; the app frees
a remotely closed channel in its data callback; lab-only detachment of stdout
buffer and callback list; lab-only malloc reuse with `quarantine_size_mb=0`;
client and server forked from one binary, so the trampoline address is locally
known rather than an ASLR-independent leak; benign fixed command through an
in-harness `system()`; no persistent shell, IP hijack or remote command
service. No NIT: the ceiling section already discloses every condition.

Next: no replay is owed. Do not claim ESTABLISHED rung 5. What would change the
grade: a witness counterexample, or a benign command reached without the lab
detach/trampoline.

## W7: bounded negatives on the two grade-changing threads (2026-11-25 09:20Z)

No new claim, no replay, no grade change. Both checks close obvious shortcuts
in the two threads that could change the accepted ceiling.

- **No ASLR-independent code address in the pinned build.**
  `file real/real_wire-vuln` reports "ELF 64-bit LSB pie executable" and
  `readelf -h` reports `Type: DYN (Position-Independent Executable file)`.
  The trampoline address is therefore a run-local value obtained from the
  forked peer, exactly as the accepted ceiling already states. A `-no-pie`
  rebuild would add a lab-only build condition rather than remove one; not
  attempted.
- **No in-callback channel free in the pinned examples.** In the vulnerable
  parent tree's `examples/sshd_direct-tcpip.c`, `do_cleanup()` frees closed
  channels at lines 121-140 (`ssh_channel_free(gone->data->channel)` at 134),
  but its only call is line 737, after `ssh_event_dopoll()` returns at 732:
  main-loop cleanup, not a reentrant free inside `channel_rcv_data()`.
  `examples/sshnetcat.c` frees channels in its own `select_loop()` (lines
  133-184), also outside a libssh data callback. Neither supplies the
  reentrant application free the lab models.

The W4 call-lane quote above now redacts its ASLR-dependent code address,
which changes on every rerun; the deterministic ASan allocator addresses stay.
W6's `run-exec.sh` smoke regenerated three committed `real/evidence-*.out`
files with new timestamps and addresses; those incidental changes were
restored from HEAD, so the pinned evidence is unchanged.

## W9: exhaustive data-callback survey in the pinned tree (2026-11-25 11:09Z)

No replay, no new claim, no grade change. Thread (1) from W7 — "does a real
application free a remotely closed channel from inside its data callback?" —
was surveyed to completion in the pinned vulnerable tree
`lab/frontier/libsshch2shell/real/libssh-vuln.tar.gz` (extracted as
`real/libssh-mirror-a540e27659b08828ef61f2910a790f7cf2af9f8d/`). All nine
`.channel_data_function =` registrations in that tree were checked; none
contains a channel free, so the shipped code does not supply the
app-free-inside-`channel_rcv_data()` precondition. The lab harness remains the
only source of that condition; the accepted ceiling stands.

Why the callback matters, from `src/channels.c`: `channel_rcv_data()` starts at
line 593, invokes the registered data callback at lines 693-703, then uses
`channel->counter` (705), `ssh_buffer_pass_bytes(buf, rest)` (708) and
`grow_window(session, channel)` (710). A channel freed by that callback is
therefore used again after it returns — the precise UAF shape the lab models.

Registration-by-registration result:

- `examples/sshd_direct-tcpip.c:548` → `my_channel_data_function()` (323-354).
  Its error path calls `stack_socket_close()` (349), but that function
  (231-241) only pushes a cleanup node onto `cleanup_stack`. The sole
  `ssh_channel_free()` is at line 134 inside `do_cleanup()` (121-140), called
  once at line 737, after `ssh_event_dopoll()` at 732. No free inside the
  callback; this closes the loophole left by W7's main-loop check.
- `examples/ssh_X11_client.c:170` → `copy_channel_to_fd_callback()` (641-664),
  writes to a file descriptor. The eof/close callback
  `channel_close_callback()` (667-687) only removes the event fd and closes
  the temp fd; it is not a data callback and frees no channel.
- `examples/ssh_server.c:768` → `data_function()` (281-298), writes to child
  stdin; no free.
- `examples/sample_sftpserver.c:336` → library
  `sftp_channel_default_data_callback()` (`src/sftpserver.c:2107-2143`). On a
  process failure it sends eof and closes the channel but explicitly comments
  "Leave freeing resources on caller"; `sample_sftpserver.c` contains no
  `sftp_free`/`ssh_channel_free` at all.
- `src/connector.c:120` → `ssh_connector_channel_data_cb()` (589+, library
  internal): routes data to an fd or another channel. `connector.c` has no
  `ssh_channel_free` or `ssh_connector_free` call anywhere.
- `tests/server/test_server/default_cb.c:874` → `channel_data_cb()` (271-298),
  writes to child stdin; its eof callback (301+) does nothing but log.
- `tests/server/test_server/sftpserver_cb.c:266` →
  `sftp_channel_data_callback()` (226-249), which calls the library default
  above and asserts a version field; no free.
- The remaining frees seen by text search are not in data callbacks:
  `tests/client/torture_client_callbacks.c:155,178,204,230` are in test bodies
  after the API call returns; `tests/pkd/pkd_daemon.c:223` is an error branch
  of the channel-open-request callback; `tests/fuzz/ssh_client_fuzzer.c:215`
  is the `out:` label of the main path; `tests/client/` and
  `tests/server/` direct-tcpip tests free after `ssh_channel_close()` in the
  test body.

Disposition: thread (1) stays open as an application-side property, not a
shortcut available in the pinned libssh tree. Finding a third-party consumer
that frees a channel inside a data callback would be a new, separately
provisioned investigation; none is claimed here. Thread (2) (ASLR-independent
address) remains open exactly as recorded in W7. `file` on all three lab
binaries (`real_wire`, `real_wire-vuln`, `real_wire-fixed`) reports PIE, so
no existing build offers a fixed code address either.
