# frontier brief — libsshch2shell (closed-channel data UAF)

Status 2026-11-25 W13: independent witness verdict #4161 (W214) remains ESTABLISHED
AS LABELED for the five unmodified real-build suites replayed from a clean
archive of `c5ece2a9` — rung 3 on a real authenticated loopback wire, rung 4
mechanics, and rung 5 MECHANICS only, NOT ESTABLISHED as remote execution.
No contradiction, no grade change, no NIT; PR:L and the lab-only detach,
malloc reuse and trampoline conditions stand. Staged harness 24 PASS / 0 FAIL;
real suites base 5/0, extra 8/0, survive 7/0, call 9/0, exec 8/0, all rc 0.
W10 adds an unwitnessed plain non-ASan replay (9 PASS / 0 FAIL) that removes
the `quarantine_size_mb=0` condition from these mechanics; no grade change.
W11 adds an unwitnessed no-detach plain lane (6 PASS / 0 FAIL) in which the
app-owned fake callback objects are reached without nulling the channel's
stdout buffer or callback list; address-directed reclamation of both freed
objects replaces the detach. No grade change.
W12 adds an unwitnessed non-PIE lane (7 PASS / 0 FAIL) that takes the callee
address from the compiled ELF symbol table and drives the same benign command
from a separately compiled client process; no grade change. A source-level
negative closes the library-internal close-free shortcut.
W13 adds an unwitnessed no-app-allocated-callbacks lane (6 PASS / 0 FAIL):
the fake callback's size, userdata and callee come from wire bytes in the
recycled channel, with only one app-owned iterator node remaining; no grade
change.
W24 adds an ASan lane (6 PASS / 0 FAIL; independent witness W248 replay
ESTABLISHED AS LABELED, no grade change) in which the second callback
iterator and callbacks structure are wire bytes in the recycled channel; one
app redirect of the in-flight iterator's `next` remains. No grade change.
W25 adds an unwitnessed ASan lane (6 PASS / 0 FAIL) joining W24's wire-resident
callback iterator and callbacks structure to W16's wire-resident command and
W14's direct libc `system()` callee; neither the harness trampoline nor an
app-owned static command string is on the executed path. No grade change.
W26 adds an unwitnessed plain (non-ASan) lane (6 PASS / 0 FAIL) that removes
the cross-run ASan slot probe from W25: the server publishes the live channel
object address through shared memory before the wire packet is sent, and the
post-free malloc is checked to recycle that exact object. No grade change.
W28 adds a bounded negative on the ASLR-address thread: the host's fixed
execute-only vsyscall page has no callable raw-syscall gadget, so the
wire-controlled RAX at the vulnerable indirect call cannot yield an
ASLR-independent syscall. No grade change.
W14 adds an unwitnessed plain lane (6 PASS / 0 FAIL) in which the indirect call
from `channel_rcv_data()` targets real libc `system()` with a wire-chosen
`channel->session` argument, so no harness trampoline is in the path; the
command string is still an app-chosen static global. No grade change.
W16 adds an unwitnessed ASan lane (6 PASS / 0 FAIL) in which the command
string executed by real libc `system()` is carried in the wire bytes of the
recycled channel itself, with the client pointing `channel->session` at a
deterministic ASan heap address; no app-owned static command string remains.
No grade change.
A consumer survey found no in-callback channel free in either pinned tree;
the in-callback free remains harness/app-owned. No grade change.
A W18 source check found only one `SSH_CHANNEL_FLAG_FREED_LOCAL` write site
(inside `ssh_channel_free()`) in each pinned tree, so no remote-only or
library-only path supplies the app-owned free. No grade change.
A 2026-11-26 provisioning probe found no public external consumer with an
in-callback free; a 2019 libssh user report of data callbacks running after
`ssh_channel_free()` stays an unreproduced claim. No grade change.

## W16: wire-resident command string for real system() (2026-11-25 18:27Z)

Additive and unwitnessed; no claim or grade change. `real/run-wirecmd.sh`
builds the two pinned commits with clang ASan (`build-asan`, `build-fixed`) and
compiles `real_wire.c` with `-DW14_REALSYSTEM -DW16_WIRECMD`, no library
source change, loopback only. Result: **6 PASS / 0 FAIL**, rc 0.

The W14 lane's command string was an app-owned static global whose address the
client sent as `channel->session` (arg1 to the callback, and therefore to
`system()`). In this lane the client writes `touch evidence-wire-wirecmd.marker`
at offset 8 of the same 128-byte wire packet that recycles the freed channel
and sets offset 0 to the ASan allocator slot of those bytes, discovered by a
probe run of the W14 lane in this exact build (`real/evidence-wc-probe.out`,
`SERVER groom alloc=0x50c00001c480`) and passed to the client as argv[3]. The
indirect call at pinned `channels.c:697` therefore enters real `system()` with
a pointer to wire-carried bytes; the harness `exec_trampoline` is not in the
path and no app-owned static command string is read. Vulnerable evidence
(`real/evidence-wc-vuln-wirecmd.out`):
`CLIENT wirecmd fn=0x714517c58750 sess=0x50c00001c488 cmd=touch evidence-wire-wirecmd.marker bad=0`,
`SERVER WIRECMD armed fn=0x714517c58750 sess=0x50c00001c488 cmd=touch evidence-wire-wirecmd.marker`,
`SERVER done data_packets=2`, `SERVER target_after=0x41414141414141c1`,
`CLIENT rc=0 SERVER status=0x0`; no ASan report and no trampoline line. The
marker existed and was renamed to `real/evidence-wc-sideeffect.kept`; three
independent repeats created `real/evidence-wc-repeat{1,2,3}.kept` with the same
command and chosen write. Fixed lane: no data #2, no armed line, no file.
Invalid-callee control `fn=0x4141414141414141`: `CLIENT rc=0 SERVER
status=0x100`, no `SERVER done`, no file — faults at the library indirect call.

Preserved negatives, not retried into existence. (1) An early version
hard-coded `0x50c00001c3c0` from the W2/W3 evidence and got 2 PASS / 4 FAIL:
`SERVER WIRECMD armed ... cmd=` empty, `SERVER exec rc=-1`, no marker; the
stale slot pointed at unallocated ASan memory. (2) A clean-archive replay of
that hard-coded version failed 2 PASS / 4 FAIL with an ASan
`heap-buffer-overflow in printf_common` at `real_wire.c:240`: the archive
build reported `SERVER groom alloc=0x50c00001c3c0`, 0xc0 away from the in-tree
slot. The slot therefore depends on build path and harness text. Both failures
were fixed by deriving the slot from a probe run in the same build rather than
hard-coding it; that makes the lane reproducible but adds an explicit
attacker-needs-the-slot condition. No grade change from either negative.

With `W16_WIRECMD`/`W14_REALSYSTEM` undefined the preprocessed harness is
byte-identical to pre-W16 HEAD (`clang -E -P`, `cmp` clean).

Clean-archive receipt (commit `4b8a257b`, 2026-11-25 18:33Z): committed
`lab/frontier/libsshch2shell` paths were extracted with `git archive HEAD` into
`/tmp/w16-arch2`, with symlinks to this lab's two pinned mirror trees, their
build-asan/build-fixed directories and hostkey (the archive carries no build
artifacts or private key). `sh real/run-wirecmd.sh` there rebuilt both ASan
libraries from the pinned trees and reported **6 PASS / 0 FAIL**, rc 0. Its
probe found a different slot, `SERVER groom alloc=0x50c00001c3c0`, and the
fresh replay printed `CLIENT wirecmd fn=0x719f3be58750
sess=0x50c00001c3c8 cmd=touch evidence-wire-wirecmd.marker bad=0`,
`SERVER WIRECMD armed fn=0x719f3be58750 sess=0x50c00001c3c8 cmd=touch
evidence-wire-wirecmd.marker`, `SERVER done data_packets=2`,
`SERVER target_after=0x41414141414141c1 groom_ptr=0x50c00001c3c0`,
`CLIENT rc=0 SERVER status=0x0`; the marker was created and renamed in the
archive. Distinct addresses from the in-tree run confirm an independently
rebuilt replay, and the slot change confirms the probe (not a constant) is
what makes it reproducible. This checks committed harness and driver text;
W16 remains additive and unwitnessed. The archive wrote only under
`/tmp/w16-arch2`; the pinned in-tree evidence is unchanged.

Ceiling unchanged: the callee `&system` and the counter target `&g_target`
are still forked-peer ASLR-local; app-owned fake callback objects, the
in-callback free, the W3 detach, ASan quarantine tuning and the authenticated
peer (PR:L) remain. No persistent shell or remote command service.
NOT ESTABLISHED rung 5; additive and unwitnessed.

## Consumer survey negative: no in-callback channel free in the pinned trees (2026-11-25 19:09Z)

Not a new lane or replay; no grade change. The open prerequisite from W16 is a
real consumer that frees the channel from inside a `channel_data_function`
callback. A source survey of both pinned mirror trees (vulnerable `7dfabb1f`,
fixed parent `a540e276`) found five callback registrations and no such free:
`examples/sshd_direct-tcpip.c:548` (`my_channel_data_function` at :323-355
calls `send()` and, on failure, `stack_socket_close()` at :232-242, which only
pushes a cleanup node; the `ssh_channel_free(gone->data->channel)` at :134 is
in `do_cleanup()` at :115, reached from :737, outside the callback);
`examples/sample_sftpserver.c:336` (the library's
`sftp_channel_default_data_callback`, `src/sftpserver.c:2107-2149`, calls
`ssh_channel_close(sftp->channel)` at :2139 with the explicit comment at :2140,
"Leave freeing resources on caller"); `src/connector.c:120`
(`ssh_connector_channel_data_cb` at :589-660 writes to the out channel/fd and
never frees; `ssh_connector_free` at :138-167 is caller-driven);
`examples/ssh_server.c:768` (`data_function` at :281-299 only writes to a child
stdin); `examples/ssh_X11_client.c:170` (`copy_channel_to_fd_callback` at
:643-664 only calls `write()`). `ssh_channel_close` itself
(`src/channels.c:1459-1510`) sends EOF/close, sets `SSH_CHANNEL_STATE_CLOSED`
and flushes; it does not free the channel. The cited line numbers are identical
in both pinned trees.

Disposition: the in-callback free in all real-build lanes remains
harness/app-owned. No libssh-provided consumer in the pinned trees supplies
one; removing that condition needs a provisioned external consumer. No harness
change, no replay, no witness result. Grade unchanged.

Follow-up source check (W18, 2026-11-25 19:45Z): the only library-internal
channel free during packet handling is in `channel_rcv_close()`
(`src/channels.c:814-816` vulnerable, `:807-809` fixed), gated on
`SSH_CHANNEL_FLAG_FREED_LOCAL`. That flag has exactly one write site in each
tree — `ssh_channel_free()` at `:1324` vulnerable / `:1317` fixed — and is
defined in `include/libssh/channels.h:60-61` as "The channel has been freed by
the calling program". Every other `ssh_channel_free()` call site is application
code or session/sftp/scp teardown, not a library callback reached from
`channel_rcv_data()`. No remote-only or library-only path sets the flag, so the
free prerequisite in every real-build lane remains app-owned. No harness
change, no replay, no witness result; grade unchanged.

## External consumer provisioning probe (2026-11-26 01:36Z)

Not a new lane or replay; no grade change. Thread (1) from W9 — a real consumer
supplying the app-owned free — was probed with public source provisioning only.
No external system was probed or scanned.

- GitHub candidate `marcofortina/libssh-x11-client`, `ssh.c` at commit
  `74fe5d3b7ffd62c27c93168eefa8b9147a401fec` (raw fetch SHA-256
  `faf3ce664d167d4a229910c365c0178db806ea47a61b11c325180d812dbc2d49`):
  registers `.channel_data_function = copy_channel_to_fd_callback` at :128;
  that callback (:560-576) only calls `write(fd, data, len)`; the close
  callback (:580-595) only removes the event fd and closes it; the sole
  `ssh_channel_free(channel)` is at :820, after `main_loop()` returns.
  Negative — the same shape as the pinned `ssh_X11_client.c` example.
- libssh archive list thread 2019-02 #0000007 and #0000008
  (https://archive.libssh.org/libssh/2019-02/0000007.html): a third-party
  server author reports calling `ssh_channel_close()`, polling
  `ssh_channel_is_closed()`, then `ssh_channel_free()`, after which
  "my_channel_data_function() is still called after then channel has been
  closed and freed". The follow-up identifies `ssh_channel_do_free()` as the
  only real free, reached only on `CLOSED_REMOTE`/`NOT_BOUND`. This is a 2019
  user claim about an older libssh, with no published consumer source; it
  supports the plausibility of an app-owned free but is not a provisioned
  tree, is not reproduced here, and places the free outside the callback.
- A public code-index stream query for both symbols together returned zero
  matches in 25 s and timed out; no candidate corpus was obtained.

Disposition: thread (1) stays open with no provisioned consumer; the W9/W18
negative stands. No harness change, no replay, no witness result.

## W27: second external-consumer probe and free-ordering negative (2026-11-26 04:12Z)

Not a new lane, replay or grade change. Thread (1) from W9 was probed once more
with read-only public-source provisioning; no external target was tested.

- Sourcegraph public code index, query `context:global ssh_channel_free and
  channel_data_function lang:C count:100 fork:yes archived:yes`
  (`https://sourcegraph.com/.api/search/stream`, fetched 04:00Z): the only
  distinct non-libssh consumer file returned was `github.com/FreeRDP/Remmina`
  `src/remmina_ssh.c`. Every other hit was a vendored libssh tree or one of
  the examples already surveyed in W9.
- Remmina `master:src/remmina_ssh.c`, raw-fetched from
  `https://raw.githubusercontent.com/FreeRDP/Remmina/master/src/remmina_ssh.c`,
  3245 lines, SHA-256
  `4118fa44d8136a49cb45ebc30e3b2c8b3b71d5fa0e2eaabb66e23a205b5bf98d`:
  `.channel_data_function = remmina_ssh_cp_to_fd_cb` at :178; the callback
  (:542-558) only does `write(fd, data, len)` at :555; the close callback
  (:561-582) only removes the event fd and closes it. All seven
  `ssh_channel_free()` sites (:2275, :2295, :2377, :2560, :3010, :3058, :3162)
  are tunnel teardown, open-forward error paths or session cleanup, not a
  data callback. Negative — the same shape as the pinned `ssh_X11_client.c`.
- Full text of libssh archive threads 2019-02 #0000007 and #0000008 re-read:
  the author frees in the main event loop after `ssh_channel_is_closed()`,
  not in `my_channel_data_function()`; the follow-up states
  `ssh_channel_do_free()` runs only on `CLOSED_REMOTE`/`NOT_BOUND`. This
  confirms W23's reading of the 2019 claim; it stays unreproduced.

Pinned-source ordering check (why thread (1) is hard; not a new claim):
`ssh_channel_free()` sets `FREED_LOCAL` and calls `ssh_channel_do_free()` only
when `CLOSED_REMOTE`/`NOT_BOUND` are already set (`channels.c.vuln:1317-1331`);
`ssh_channel_do_free()` removes the channel from `session->channels` and frees
it (`:1340-1360`); `channel_rcv_close()` sets `CLOSED_REMOTE` then do-frees a
`FREED_LOCAL` channel (`:807-809`); `channel_from_msg()` reaches
`ssh_channel_from_local()`, which iterates `session->channels` (`:412-425`).
An app free in the main loop before CLOSE therefore removes the channel before
a later DATA packet can be routed to it. The UAF shape needs the free inside
the data callback after a remote CLOSE, while `channel_rcv_data()` still holds
the live local `channel` pointer — exactly the harness condition. No
remote-only path supplies it.

Disposition: thread (1) stays open with no provisioned consumer; the W9/W18
negatives stand. The archive thread is a user claim, not a consumer tree. No
harness change, no replay, no witness result; grade unchanged.

## W24: wire-resident callback iterator (2026-11-26 02:05Z)

Additive and unwitnessed; no claim or grade change. `real/run-wirelist.sh`
builds the two pinned commits under clang ASan (W16's `build-asan` /
`build-fixed`, no library source change) and compiles `real_wire.c` with
`-DW13_INLINE -DW24_WIRELIST`; loopback only. Result: **6 PASS / 0 FAIL**,
rc 0. W13 left one app-owned 16-byte callback iterator node; here the second
iterator and the callbacks structure are bytes in the recycled channel. The
24-byte callbacks struct stays at wire offsets 72-95 (`size=24`, userdata,
callee), and the second iterator occupies offsets 96-111 (`next=0` at +96,
`data` = probed slot + 72 at +104). After the in-callback free and reclaim,
the only app action on the callback chain is redirecting the already-running
iterator's `next` to `groom_ptr + 96` — the loop then advances into the
wire-resident node and calls the wire-chosen callee.

Vulnerable evidence (`real/evidence-wl-vuln-wirelist.out`):
`CLIENT wirelist cbs=0x50c00001c4c8 next=0x0`,
`SERVER wirelist it=0x502000006f70 next=0x50c00001c4e0 data=0x50c00001c4c8`,
`SERVER EXEC trampoline cmd=touch evidence-wire-vuln-groom-exec.marker`,
`SERVER EXEC rc=0`, `SERVER done data_packets=2`,
`SERVER target_after=0x41414141414141c1`, `CLIENT rc=0 SERVER status=0x0`,
no ASan report; the marker was created and kept as
`real/evidence-wl-sideeffect.kept`. Three repeats
(`real/evidence-wl-vuln-repeat{1,2,3}.out`) gave the same call and chosen
write with distinct ASLR-local code addresses; markers are
`real/evidence-wl-repeat{1,2,3}.kept`. Fixed lane
(`real/evidence-wl-fixed-wirelist.out`): no data #2, no wirelist line, no
call, no file. Invalid-callee control
(`real/evidence-wl-vuln-wirelist-bad.out`): ASan SEGV at the indirect call,
no `SERVER done`, no file.

Preserved negatives, not retried into existence. (1) The same lane in a plain
Release build (`real/evidence-wl-plain-negative.out`) failed 2 PASS / 4 FAIL:
the probe slot `0x5b697d4d5ac0` differed from the run's `0x5c6130435ac0`, so
the wire pointer landed on the wrong fields; glibc heap bases vary per
launch. (2) With `next`/`data` written in struct order
(`real/evidence-wl-asan-swapped-negative.out`), `data=(nil)` and no call;
the iterator layout is `next` first, `data` second. (3) ASan reclaim with
`malloc(sizeof(struct ssh_iterator))` for both freed objects
(`real/evidence-wl-asan-size-negative.out`) could not recover the 24-byte
`ssh_buffer_struct` from the 16-byte size class and faulted at
`ssh_buffer_pass_bytes`; W24 allocates 24 bytes for the buffer slot. (4)
Setting the first iterator's `next` to NULL stops the loop before its second
step (transcript-only, same stop W13 recorded at offset 72).

With `W24_WIRELIST` undefined the preprocessed harness is byte-identical to
pre-W24 HEAD (`clang -E -P`, `cmp` clean); an ASan compile with the flag
defined succeeds. Ceiling unchanged: the app still frees a remotely closed
channel inside its data callback, reclaims the freed objects, uses a probed
ASan slot and a forked-peer callee/trampoline with an app-owned static
command, and the peer is authenticated (PR:L). The recycled slot and the
first iterator redirect remain lab conditions. No persistent shell or remote
command service. NOT ESTABLISHED rung 5; additive and unwitnessed.

Clean-archive receipt (commit `b401fcbd`, 2026-11-26 02:07Z): committed
`lab/frontier/libsshch2shell` paths were extracted with `git archive HEAD`
into `/tmp/w24-arch`, with symlinks to this lab's two pinned mirror trees,
their ASan build directories and hostkey (the archive carries no build
artifacts or private key). `sh real/run-wirelist.sh` there rebuilt both ASan
libraries from the pinned trees and reported **6 PASS / 0 FAIL**, rc 0. Its
probe found a different slot, `0x50c00001c3c0`, and the replay printed
`CLIENT wirelist cbs=0x50c00001c408 next=0x0`,
`SERVER wirelist it=0x502000006f70 next=0x50c00001c420 data=0x50c00001c408`,
`SERVER EXEC trampoline ...`, `SERVER EXEC rc=0`,
`SERVER target_after=0x41414141414141c1 groom_ptr=0x50c00001c3c0`,
`CLIENT rc=0 SERVER status=0x0`; the marker was created in the archive. The
different slot confirms the probe, not a constant, supplies the address.
This checks committed harness and driver text; W24 remains additive, with an
independent witness replay (W248) recorded below. The archive wrote only
under `/tmp/w24-arch`; the pinned in-tree evidence is unchanged.

### Witness replay (W248, 2026-11-26 05:2xZ)

VERDICT: ESTABLISHED AS LABELED, no contradiction, no grade change, NO r5.
Offer #4689. The unmodified `run-wirelist.sh` (SHA-256 `79fa399c…d7919d5`,
identical at HEAD, at b401fcbd and in the clean archive) was replayed three
times from my own `git archive HEAD(3f156357)` at `/tmp/w248-w24-arch`, with
symlinks only to the pinned mirror sources and hostkey and **fresh** ASan
build dirs. All three: 6 PASS / 0 FAIL, rc 0; probe slot `0x50c00001c3c0`;
`SERVER wirelist it=0x502000006f70 next=0x50c00001c420
data=0x50c00001c408`, `SERVER EXEC trampoline`, `SERVER EXEC rc=0`,
`SERVER target_after=0x41414141414141c1`, clean `CLIENT rc=0 SERVER
status=0x0`, marker created; fixed lane no data #2 / call / file; invalid
callee ASan SEGV at pinned `channels.c:697`. Both upstream tarballs were
re-fetched and matched the in-tree mirrors (only build-generated
`compile_commands.json` differed). Minor observation, no grade effect: the
probed slot was stable across my three repeats (and equal to the author's
clean-archive slot) but differs from the in-tree receipt; callee addresses
were runtime-local, with repeats 1 and 3 sharing an address. Full evidence:
`.mishe-tauftauf/artifacts/witness-w248-libsshch2shell/detail.md`.

## W25: wire-resident iterator plus wire command into real system() (2026-11-26 02:34Z)

Additive and unwitnessed; no claim or grade change. `real/run-syswire.sh`
builds the two pinned commits under clang ASan (no library source change) and
compiles `real_wire.c` with `-DW13_INLINE -DW14_REALSYSTEM -DW16_WIRECMD
-DW24_WIRELIST -DW25_SYSWIRE`; loopback only. Result: **6 PASS / 0 FAIL**,
rc 0. The authenticated client writes all callback-relevant fields of the
128-byte packet that later recycles the freed channel: `channel->session`
(the callee's first argument) at +0 points at slot+8, the command
`touch evidence-wire-syswire.marker` sits at +8, the 24-byte callbacks struct
at +72 carries `size=24`, `userdata=slot+8` and `fn=&system`, and the second
iterator at +96 carries `next=0`, `data=slot+72`. After the in-callback free
and reclaim, the only app action on the callback chain is redirecting the
already-running iterator's `next` to `groom_ptr+96`. The loop then enters the
wire-resident node and calls real `system()` directly: no `exec_trampoline`
and no `g_exec_cmd` on the executed path. Both symbols remain in the shared
harness for older modes; the command literal exists only so the client can
put those bytes on the wire.

Vulnerable evidence (`real/evidence-sw-vuln-syswire.out`):
`CLIENT syswire fn=0x787545a58750 sess=0x50c00001c488 cmd=touch evidence-wire-syswire.marker bad=0`,
`SERVER wirelist it=0x502000006f70 next=0x50c00001c4e0 data=0x50c00001c4c8`,
`SERVER SYSWIRE armed fn=0x787545a58750 cmd=0x50c00001c488` — the callee and
its command pointer were read back from the recycled channel's wire bytes —
`SERVER done data_packets=2`, `SERVER target_after=0x41414141414141c1`,
`CLIENT rc=0 SERVER status=0x0`, no `SERVER EXEC trampoline`, no ASan report.
The command's side effect is kept as `real/evidence-sw-sideeffect.kept`;
three repeats (`real/evidence-sw-vuln-repeat{1,2,3}.out`, markers
`real/evidence-sw-repeat{1,2,3}.kept`) gave the same call and chosen write.
Fixed lane (`real/evidence-sw-fixed-syswire.out`): no data #2, no wirelist or
`SYSWIRE` line, no trampoline, no marker. Invalid-callee control
(`real/evidence-sw-vuln-syswire-bad.out`) sent `fn=0x4141414141414141` and
ASan reported `SEGV ... in channel_rcv_data ... src/channels.c:697:16`,
`CLIENT rc=0 SERVER status=0x100`, no `SERVER done`, no marker — the wire
callee is used at the library's indirect call, not by a harness wrapper.

With all five W25 flags undefined, the preprocessed harness is byte-identical
to pre-W25 HEAD (`clang -E -P`, `cmp` clean); the flagged ASan compile
succeeds. Ceiling unchanged: the callee address is forked-peer PIE
(ASLR-local), the slot is probed under this ASan build, the app still frees a
remotely closed channel in its data callback and reclaims the freed objects,
and the peer is authenticated (PR:L). No persistent shell or remote command
service. NOT ESTABLISHED rung 5; additive and unwitnessed.

Clean-archive receipt (commit `d2c2432e`, 2026-11-26 02:36Z): committed
`lab/frontier/libsshch2shell` paths were extracted with `git archive HEAD`
into `/tmp/w25-arch`, with symlinks to this lab's two pinned mirror trees,
their ASan build directories and hostkey (the archive carries no build
artifacts or private key). `sh real/run-syswire.sh` there rebuilt both ASan
libraries from the pinned trees and reported **6 PASS / 0 FAIL**, rc 0. Its
probe found a different slot, `0x50c00001c3c0`, and the replay printed
`CLIENT syswire fn=0x7db681858750 sess=0x50c00001c3c8 cmd=touch evidence-wire-syswire.marker bad=0`,
`SERVER wirelist it=0x502000006f70 next=0x50c00001c420 data=0x50c00001c408`,
`SERVER SYSWIRE armed fn=0x7db681858750 cmd=0x50c00001c3c8`,
`SERVER target_after=0x41414141414141c1 groom_ptr=0x50c00001c3c0`,
`CLIENT rc=0 SERVER status=0x0`, marker created; the bad-callee lane again
faulted at `channels.c:697`. The different slot and code address from the
in-tree run confirm probe-supplied addresses, not copied logs. This checks
committed harness and driver text; W25 remains additive and unwitnessed.
The archive wrote only under `/tmp/w25-arch`; the pinned in-tree evidence is
unchanged.

## W26: W25 wire mechanics in a plain build with in-run address handoff (2026-11-26 03:28Z)

Additive and unwitnessed; no claim or grade change. Why: the earlier W24 plain
attempt (`real/evidence-wl-plain-negative.out`) used a slot probed in a
different process and ended `CLIENT rc=0 SERVER status=0x8b` — the client's
wire pointer did not match the chunk the plain allocator recycled. W26 tests
the causal repair: publish the address in the same run, then require the
recycled pointer to match. `real/run-syswire-plain.sh` builds both pinned
commits with the Release/plain recipe (`build-plain-vuln`, `build-plain-fixed`,
no sanitizer, `ldd` guard) and compiles `real_wire.c` with the five W25 flags
plus `-DW26_PLAINADDR` and the no-op ASan-interface shim. Loopback only, no
library source change. Result: **6 PASS / 0 FAIL**, rc 0.

Mechanism: the server records the channel object when it registers callbacks
and writes its address into a `MAP_SHARED | MAP_ANONYMOUS` slot mapped before
`fork()`; the client polls that slot before building the groom packet, using
the published address for `channel->session`, the callbacks struct and the
iterator. This is lab-only IPC, not an attacker primitive. After the
in-callback free, `malloc(128)` must return the same object; the harness
prints `match=1` only when it does. The W25 executed path is unchanged:
wire-resident callbacks struct and iterator, wire-resident command, direct
libc `system()`, no `exec_trampoline` or app-owned static command.

Vulnerable evidence (`real/evidence-swplain-vuln-syswire-plain.out`):
`SERVER plainaddr published=0x610ddacd5ac0`,
`CLIENT plainaddr slot=0x610ddacd5ac0`,
`CLIENT syswire fn=0x790460658750 sess=0x610ddacd5ac8 cmd=touch evidence-wire-syswire.marker bad=0`,
`SERVER plainaddr recycled=0x610ddacd5ac0 live=0x610ddacd5ac0 match=1`,
`SERVER wirelist it=0x610ddacd5690 next=0x610ddacd5b20 data=0x610ddacd5b08`,
`SERVER SYSWIRE armed fn=0x790460658750 cmd=0x610ddacd5ac8`,
`SERVER target_after=0x41414141414141c1`, `SERVER done data_packets=2`,
`CLIENT rc=0 SERVER status=0x0`, marker created
(`real/evidence-swplain-sideeffect.kept`), no trampoline, no ASan report.
Three repeats printed different heap slots (`0x57483e8beac0`,
`0x5da79fdeeac0`, `0x5fe6bdd52ac0`) and different code addresses, each with
`match=1`, armed wire bytes, chosen write, clean exit and a marker
(`real/evidence-swplain-vuln-repeat{1,2,3}.out`). Fixed lane
(`real/evidence-swplain-fixed-syswire-plain.out`): no data #2, no wirelist or
`SYSWIRE`, no marker, clean status. Wire-chosen invalid callee
(`real/evidence-swplain-vuln-syswire-plain-bad.out`):
`SERVER SYSWIRE armed fn=0x4141414141414141` and
`CLIENT rc=0 SERVER status=0x8b`, no marker and no `SERVER done`.

With all six Wn flags undefined, the preprocessed harness is byte-identical
to HEAD (`clang -E -P`, `cmp` clean). Ceiling unchanged and stricter in one
way: the ASan-only allocator condition and cross-run probe are gone, but the
address still comes from a lab shared-memory handoff, the callee is a
forked-peer PIE address (ASLR-local), the app still frees a remotely closed
channel in its data callback and reclaims the freed objects, and the peer is
authenticated (PR:L). No persistent shell, command service or remote RCE;
NOT ESTABLISHED rung 5, additive and unwitnessed.

Clean-archive receipt (commit `669b1dbd`, 2026-11-26 03:30Z): committed
`lab/frontier/libsshch2shell` paths were extracted with `git archive` into
`/tmp/w26-arch`, with symlinks to this lab's two pinned mirror trees, their
plain build directories and hostkey (the archive carries no build artifacts
or private key). `sh real/run-syswire-plain.sh` there rebuilt both plain
libraries and reported **6 PASS / 0 FAIL**, rc 0. Its vulnerable lane printed
`SERVER plainaddr published=0x5d55a8f9eac0`,
`CLIENT syswire fn=0x7dace2a58750 sess=0x5d55a8f9eac8 cmd=touch evidence-wire-syswire.marker bad=0`,
`SERVER plainaddr recycled=0x5d55a8f9eac0 live=0x5d55a8f9eac0 match=1`,
`SERVER SYSWIRE armed fn=0x7dace2a58750 cmd=0x5d55a8f9eac8`,
`SERVER target_after=0x41414141414141c1`, `CLIENT rc=0 SERVER status=0x0`,
marker created; repeat1 used a different slot (`0x5e84e97fcac0`) and callee
(`0x7ddf84458750`) with `match=1`. Fixed and bad-callee controls were the
same as in-tree. Different per-run addresses confirm the client consumes the
in-run published slot and code address, not copied logs. The archive wrote
only under `/tmp/w26-arch`; pinned in-tree evidence is unchanged.


## W28: fixed-address syscall gadget probe, negative (2026-11-26 04:16Z)

Not a new lane or replay; no grade change. Thread (2) from W7 was tested with
one new idea on this host, not by repeating the PIE/`-no-pie` audit.

The compiled vulnerable call site does put a wire-controlled value in RAX at
the indirect callback call: `objdump -d --disassemble=channel_rcv_data
real_wire-plain-sw-vuln` shows `call *0x10(%rsp)` at `0x1041f`, preceded by
`mov %eax,%ecx` after `ssh_buffer_get_len()` returned in `%eax`. A raw
`syscall` instruction at a fixed, callable address would therefore be an
ASLR-independent callee with an authenticated wire-chosen syscall number;
`execve` (59) could replace the forked-peer `system()` address.

Host check: `/proc/self/maps` maps `ffffffffff600000-ffffffffff601000 --xp
... [vsyscall]` on kernel `6.8.0-149-generic`. `real/w28-vsyscall-probe.c`
forks 96 children; each sets `RAX=39` (`getpid`) with explicit register
setup, calls one of the three entries or offsets 0..31 inside each stub, and
exits 42 only if the result equals its own pid. Output
(`real/evidence-w28-vsyscall.out`): `sweep done`, `rc=0`, no
`RAW_SYSCALL_GADGET` line. A direct call to `0xffffffffff600005` with
`RAX=59` and `/bin/true` arguments faulted (`status=0x8b`, SIGSEGV); the
exact entries `0xffffffffff600000/400/800` returned normally but execute
the kernel's fixed gettimeofday/time/getcpu stubs with hardwired syscall
numbers, not a chosen syscall. No fixed-address syscall gadget exists on
this host, so wire-controlled RAX cannot supply an ASLR-independent call.

A second measurement closes a shortcut around W26's two addresses: its four
in-tree repeats' heap slots (`0x65385e0c8ac0`, `0x55d0b1501ac0`,
`0x64e74b185ac0`, `0x57409f758ac0`) and libc callees (`0x75f6b8a58750`,
`0x75e300658750`, `0x751cdda58750`, `0x70216da58750`) have no constant
delta; learning one does not derive the other.

Disposition: thread (2) is closed on this host at the documented ceiling;
no harness or library source changed, no replay, no witness result. The
accepted rung-5 MECHANICS ceiling and PR:L remain. This negative is not a
grade change.

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

## W10: plain non-ASan replay of the chosen-pointer mechanics (2026-11-25 11:40Z)

New additive evidence, not yet witness-replayed; no claim or grade change. The
only lab condition previously tied to ASan mechanics — `ASAN_OPTIONS`
`quarantine_size_mb=0`, used to force the freed 128-byte channel chunk to be
reused — is not needed in an ordinary build. `real/run-plain.sh` builds both
pinned commits with `-DCMAKE_BUILD_TYPE=Release` and no sanitizer, compiles the
UNMODIFIED committed `real_wire.c` against each static libssh, and runs the
three W3/W4 lanes on 127.0.0.1. `asan-shim/sanitizer/asan_interface.h` only
stubs `__asan_set_death_callback`, which the harness uses for an extra ASan
diagnostic line; `ldd` confirms neither plain binary links the ASan runtime.
No library source, pinned commit or committed harness text was changed.

Result: **9 PASS / 0 FAIL**, rc 0 — `groom-survive`, `groom-call`, `groom-exec`
on the vulnerable commit; all three on the fixed commit; and three independent
vulnerable `groom-survive` repeats. Evidence:
`real/evidence-plain-{vuln,fixed}-groom-{survive,call,exec}.out`,
`real/evidence-plain-vuln-survive-repeat{1,2,3}.out`, and the zero-byte touch
marker at `real/evidence-plain-exec-sideeffect.kept`.

- Vulnerable `groom-survive`: `SERVER groom alloc=0x... wire_off120=0x...
  target=0x... survive=1` followed by
  `SERVER target_after=0x41414141414141c1` and `CLIENT rc=0 SERVER
  status=0x0` — the wire-chosen address at offset 120 receives the
  `channels.c:706` read-modify-write in a plain build. Same `target_after` in
  all three repeats; only the ASLR-dependent addresses change.
- Vulnerable `groom-call`: `SERVER call fake_cbs=0x... node=0x... fn=0x...`,
  `SERVER MARKER called len=0 hits=1`, chosen-pointer write present, clean
  exit. The indirect callee at `channels.c:697` is wire-selected.
- Vulnerable `groom-exec`: `CLIENT sent exec cmd=touch
  evidence-wire-vuln-groom-exec.marker fn=0x...`,
  `SERVER EXEC trampoline cmd=touch evidence-wire-vuln-groom-exec.marker`,
  `SERVER EXEC rc=0`, chosen-pointer write present, clean exit, and the
  marker file existed and was renamed to `evidence-plain-exec-sideeffect.kept`
  before the controls ran.
- Fixed commit, all three lanes: `SERVER done data_packets=1`, no `SERVER data
  #2`, no marker call, no trampoline call, no file,
  `SERVER target_after=0x4141414141414141`. The vendor `CLOSED_REMOTE` guard
  suppresses the second data packet in a plain build too.

Clean-archive receipt (commit `132d6a9e`, 2026-11-25 11:46Z): the committed
`lab/frontier/libsshch2shell` paths were extracted with `git archive HEAD`
into a throwaway directory, with symlinks to this lab's already-provisioned
mirror trees and hostkey. `sh real/run-plain.sh` there rebuilds both plain
libraries from those pinned trees and reports 9 PASS / 0 FAIL, rc 0, with the
same chosen-pointer write, marker call, trampoline command and fixed-build
suppression. This checks the committed script and shim text, not a fresh
fetch of libssh.

Ceiling discipline: the accepted witness ceiling is unchanged. W10 removes
one lab-only condition (ASan quarantine tuning) from the *mechanics*, not from
the vulnerability preconditions. Still required: PR:L authenticated peer; the
application frees a remotely closed channel inside its data callback; the
W3/W4 detachment of the channel's stdout buffer and callback list; app-owned
fake callback objects for the call lanes; an ASLR-local trampoline address
chosen by a client forked from the same binary; and a benign fixed command
through an in-harness `system()`. No persistent shell, remote command service
or ASLR-independent address is demonstrated. The five witness-replayed ASan
suites remain the accepted evidence; W10 is additive and awaits any future
independent replay. What would change the grade: a benign command reached
without the lab detach/trampoline, or a provisioned consumer with a real
in-callback free.

## W11: benign command without the W3/W4 detach (2026-11-25 12:07Z)

New additive evidence, not witness-replayed; no claim or grade change. The
accepted ceiling lists the W3/W4 detach of `channel->stdout_buffer` and
`channel->callbacks` as a required lab condition. This lane removes that
detach in a plain non-ASan build and reaches the same benign command. The
replacement is still lab-only allocator manipulation, so this is not a
realistic consumer and no rung changes.

`real/real_wire.c` gains two modes. `groom-nodetach-exec` saves the stdout
buffer and first callback-iterator addresses before `ssh_channel_free()`,
does **not** null either channel field (`survive=0`, no `SERVER groom-survive
saved` line), then after the free allocates raw 16-byte nodes until the two
saved addresses come back from the same glibc tcache bin. The reclaimed
iterator is given `next` pointing at an app-owned fake iterator whose `data`
is a fake `ssh_channel_callbacks_struct` with `channel_data_function` set by
wire offset 112; the reclaimed buffer chunk is initialised as a live
`ssh_buffer` with 128 bytes of static data. Offsets measured in the pinned
header: `stdout_buffer=56`, `stderr_buffer=64`, `callbacks=112`, `counter=120`,
`sizeof(channel)=128`, `sizeof(ssh_iterator)=16`, `sizeof(ssh_buffer_struct)=24`.
No library source, pinned commit or allocator environment was changed.

`sh lab/frontier/libsshch2shell/real/run-nodetach.sh`: **6 PASS / 0 FAIL**,
rc 0, on 127.0.0.1, with evidence `real/evidence-nodetach-*.out` and four
zero-byte touch markers kept as `real/evidence-nodetach-*.kept`. Vulnerable
`real/evidence-nodetach-vuln-nodetach.out`: `SERVER data #2 len=128
first=t off16=i`, `SERVER nodetach saved_buf=0x...fb50 saved_it=0x...f690`,
`SERVER groom alloc=0x...fac0 wire_off120=0x... target=0x... survive=0`,
`SERVER nodetach reclaim it=0x...f690 want=0x...f690 buf=0x...fb50
want=0x...fb50`, `SERVER EXEC trampoline
cmd=touch evidence-wire-vuln-groom-exec.marker`, `SERVER EXEC rc=0`,
`SERVER done data_packets=2`, `SERVER target_after=0x41414141414141c1`,
`CLIENT rc=0 SERVER status=0x0`. No detach line appears. Three independent
vulnerable repeats show the same command, reclamation and chosen write.

Fixed control `real/evidence-nodetach-fixed-nodetach.out`: data #2 absent
(`SERVER done data_packets=1`), no trampoline, no marker file,
`SERVER target_after=0x4141414141414141`, `CLIENT rc=0 SERVER status=0x0`.
Negative control `groom-nodetach-bare` (`real/evidence-nodetach-vuln-bare.out`)
skips the reclamation: the server faults before finishing
(`CLIENT rc=0 SERVER status=0x8b`), no `SERVER EXEC trampoline`, no
`SERVER done` line. Address-directed reclamation is therefore required in
this lane; the detach alone was not.

Ceiling discipline: the accepted witness verdict is unchanged. W11 removes
one lab condition (the W3/W4 detach) for this unwitnessed lane but replaces
it with an equally artificial one (choosing freed-object addresses from the
application and reinitialising them). Still required: PR:L authenticated
peer; the application frees a remotely closed channel inside its data
callback; the freed 128-byte channel reused for wire bytes; app-owned fake
callback objects; an ASLR-local trampoline address chosen by a client forked
from the same binary; a benign fixed command through an in-harness `system()`.
No persistent shell, remote command service or ASLR-independent address.
What would change the grade: a benign command reached without the
detach/trampoline/app-owned objects, a witness counterexample, or a
provisioned third-party consumer with a real in-callback free.

Clean-archive receipt (commit `2670916e`, 2026-11-25 12:10Z): committed
`lab/frontier/libsshch2shell` paths were extracted with `git archive HEAD`
into a throwaway directory, with symlinks to this lab's two pinned mirror
trees and hostkey (the archive carries no build artifacts or private key).
`sh real/run-nodetach.sh` rebuilt both plain libraries from those pinned
trees and reported 6 PASS / 0 FAIL, rc 0: the no-detach command lane, its
fixed control, the bare negative and three vulnerable repeats. The same
archive also ran `sh real/run-plain.sh` as a regression check: 9 PASS /
0 FAIL, rc 0, with the chosen-pointer write, marker call and trampoline
command intact in the five witness-replayed suites. An ASan compile of the
changed `real_wire.c` against the existing `build-asan` library also
succeeded. This checks committed harness and driver text, not a fresh fetch
of libssh; W11 remains additive and unwitnessed.

## W12: ELF-derived callee address and separate-process client (2026-11-25 12:38Z)

New additive evidence, not witness-replayed; no claim or grade change. Two
bounded checks: a source-level negative on a library-internal free, and a new
command lane that removes the "address chosen by a forked peer" condition.

**Bounded negative — library-internal close free.** `channel_rcv_close()` in
the pinned vulnerable tree sets `SSH_CHANNEL_FLAG_CLOSED_REMOTE` at
`src/channels.c.vuln:807` and, if the application earlier called an ordinary
`ssh_channel_free()` so `FREED_LOCAL` is set, calls `ssh_channel_do_free()`
at :808-809. That looks like a wire-triggered free which could remove the
in-callback app free. It cannot: `ssh_channel_do_free()` first removes the
channel from `session->channels` (:1345-1348), and `channel_from_msg()`
(:510-532) resolves every later `SSH2_MSG_CHANNEL_DATA` through that list, so
the freed channel is unreachable. No wire lane was built on this path;
recorded as a negative, not an assumed pass.

**Fixed-address lane.** `real/real_wire.c` gains `groom-fixedaddr`,
`client-only` and `server-fixedaddr` modes. The harness is compiled with
`-no-pie`; `readelf -h` confirms `Type: EXEC (Executable file)`. The driver
reads `exec_trampoline`'s address from the compiled binary with `nm` and
passes it to the client as an argument; the client no longer evaluates
`&exec_trampoline` in this mode. Wire offset 112 carries the ELF-derived
address and offset 0 the command. Vulnerable evidence
`real/evidence-fixedaddr-vuln-fixedaddr.out`: `CLIENT sent exec
cmd=touch evidence-wire-vuln-groom-exec.marker fn=0x407430 fixedaddr=1`,
`SERVER nodetach reclaim it=0x... want=0x... buf=0x... want=0x...`,
`SERVER EXEC trampoline cmd=touch evidence-wire-vuln-groom-exec.marker`,
`SERVER EXEC rc=0`, `SERVER target_after=0x41414141414141c1`,
`CLIENT rc=0 SERVER status=0x0`, no detach line. Three independent launches
print the same fixed fn (`0x407430`) while the heap addresses differ.
Fixed lane `real/evidence-fixedaddr-fixed-fixedaddr.out`: no data #2, no
call, no file, `SERVER target_after=0x4141414141414141`, client rc 0.

**Separate-process control.** The driver also builds a distinct client binary
with `-Dexec_trampoline=client_trampoline`, so its own image has no
`exec_trampoline` symbol to borrow (`nm` shows only `client_trampoline`). It
starts the server from the vulnerable ELF with `server-fixedaddr` and the
client as a separate process with `client-only`, both on 127.0.0.1. Server
evidence `real/evidence-fixedaddr-vuln-separate-server.out`: `SERVER EXEC
trampoline cmd=touch evidence-wire-vuln-groom-exec.marker`, `SERVER EXEC
rc=0`, `SERVER target_after=0x41414141414141c1`; the client returned 0 and
created the marker, kept as `real/evidence-fixedaddr-separate-sideeffect.kept`.
The fixed server under the same client prints no call and leaves no file.

`sh lab/frontier/libsshch2shell/real/run-fixedaddr.sh`: **7 PASS / 0 FAIL**,
rc 0. Quotes and per-lane outputs are in `real/evidence-fixedaddr-*.out`; five
touch markers are kept as `real/evidence-fixedaddr-*.kept`.

All W12 additions in `real_wire.c` are behind `#ifdef W12_FIXEDADDR`; with the
flag undefined, the preprocessed source is byte-identical to the pre-W12 HEAD
harness (`clang -E -P` diff empty), so the W10/W11 lanes are unchanged. An
earlier ungated draft accidentally dropped
`memcpy(payload + 112, &fn, sizeof(fn))` and broke W10 (7 PASS / 2 FAIL, server
status `0x8b`, no call); the wire write was restored, after which all three
suites pass again. ASan compiles of the changed harness both with and without
the W12 flag succeed.

Ceiling discipline: additive and unwitnessed; no grade change. W12 removes
one lab condition (a process-local address from a forked peer) but replaces
it with another (a non-PIE target whose symbol table is readable). Still
required: PR:L authenticated peer; the application frees a remotely closed
channel inside its data callback; application-directed reclamation of freed
objects; app-owned fake callback objects; a benign fixed command through an
in-harness `system()`; no persistent shell or remote command service. Not
ESTABLISHED rung 5. What would change the grade: a command reached without
the detach/trampoline/app-owned objects, a witness counterexample, or a
provisioned consumer with a real in-callback free.

Clean-archive receipt (commit `d9ef7b38`, 2026-11-25 12:46Z): committed
`lab/frontier/libsshch2shell` paths were extracted with `git archive HEAD`
into `/tmp/w12-arch`, with symlinks to this lab's two pinned mirror trees and
hostkey (the archive carries no build artifacts or private key). The driver
rebuilt both plain libraries from those pinned trees and reported
`run-fixedaddr.sh` 7 PASS / 0 FAIL, rc 0 (ELF-derived address, separate-process
control and three repeats), plus `run-nodetach.sh` 6 PASS / 0 FAIL and
`run-plain.sh` 9 PASS / 0 FAIL, both rc 0, as regressions. This checks
committed harness and driver text, not a fresh fetch of libssh; W12 remains
additive and unwitnessed.


## W13: wire-resident fake callbacks in the recycled channel (2026-11-25 13:20Z)

Additive and unwitnessed; no claim or grade change. New `real/run-inline.sh`
builds both pinned commits as plain Release libraries with `-DW13_INLINE` and
reports **6 PASS / 0 FAIL**, rc 0. The fake
`ssh_channel_callbacks_struct` is no longer an application-allocated object:
the 24-byte prefix (`size`, `userdata`, `channel_data_function`) is written by
the authenticated client into offsets 72-95 of the 128-byte wire packet that
recycles the freed channel. Pinned `ssh_callbacks_iterate` reads
`size` at +0, `userdata` at +8 and the callee at +16 from that recycled
chunk. The application's only remaining object is the 16-byte iterator node
that continues the already-running iteration; it points at the wire-resident
structure. Vulnerable evidence `real/evidence-inline-vuln-inline.out`:
`CLIENT inline cbs_off=72 size=24 userdata=0x... fn=0x...`,
`SERVER inline cbs=0x... off=72`,
`SERVER EXEC trampoline cmd=touch evidence-wire-vuln-groom-exec.marker`,
`SERVER EXEC rc=0`, `SERVER done data_packets=2 marker_hits=0`,
`SERVER target_after=0x41414141414141c1 groom_ptr=0x...`,
`CLIENT rc=0 SERVER status=0x0`; three repeats identical in substance, touch
markers kept as `real/evidence-inline-repeat{1,2,3}.kept` and
`real/evidence-inline-sideeffect.kept`. Fixed lane: no data #2, no inline
call, no trampoline, no file, target unchanged. Invalid-callee control
`real/evidence-inline-vuln-inline-bad.out` sends
`fn=0x4141414141414141` and gives `CLIENT rc=0 SERVER status=0x8b`, no
trampoline and no `SERVER done`, confirming the callee is wire-supplied.

Two failed iterations are preserved, not retried into existence. At
`INLINE_CBS_OFF=24`, the command string copied to wire offsets 0-40
overwrote the embedded structure: inline print and chosen pointer write were
present but no trampoline ran (1 PASS / 5 FAIL). At offset 72 with
`it->next = NULL`, the iterate macro stopped before its next step, again no
call (1 PASS / 5 FAIL). Restoring a single iterator node to continue the
iteration produced 6 PASS / 0 FAIL.

All W13 edits sit behind `#ifdef W13_INLINE`; with the flag undefined the
preprocessed harness is byte-identical to the pre-W13 HEAD
(`clang -E -P` comparison, `cmp` clean), and an ASan compile with the flag
defined succeeds. Regressions after the final edit: `run-plain.sh`
9 PASS / 0 FAIL, `run-nodetach.sh` 6 PASS / 0 FAIL, `run-fixedaddr.sh`
7 PASS / 0 FAIL, all rc 0.

Ceiling unchanged: the callee and userdata addresses still come from a
forked peer's image, the command still runs through the in-harness
`system()`, one app-owned iterator node remains, the app still frees a
remotely closed channel in its data callback, and the peer is authenticated
(PR:L). No persistent shell or remote command service. NOT ESTABLISHED rung 5.


Clean-archive receipt (commits `93436c63` and `70ff8805`, 2026-11-25 13:29Z):
`git archive HEAD lab/frontier/libsshch2shell` was extracted into
`/tmp/w13-arch`, with symlinks to this lab's two pinned mirror trees, their
plain build directories and hostkey (the archive carries no build artifacts
or private key). `run-inline.sh` there rebuilt both plain libraries from the
pinned trees and reported 6 PASS / 0 FAIL, rc 0, with the vulnerable trampoline,
chosen-pointer write, fixed suppression and invalid-callee fault all present.
This checks committed harness and driver text; W13 remains additive and
unwitnessed. Regression evidence overwritten by the in-tree reruns was
restored from HEAD, so the pinned W10/W11/W12 evidence files are unchanged by
this wake.

## W14: real libc `system()` as the wire-chosen callee (2026-11-25 17:14Z)

`real/run-realsystem.sh` adds an unwitnessed plain Release lane behind
`-DW14_REALSYSTEM`, built against the same two pinned commits with no library
source change. **6 PASS / 0 FAIL**, rc 0.

Prediction and result: `ssh_callbacks_iterate_exec` passes `channel->session`
as the callback's first argument (pinned `channels.c.vuln:697-702`), and
`session` is the first field of `struct ssh_channel_struct`. In a W3-survive
groom, the authenticated client's wire bytes occupy the recycled 128-byte
channel: offset 0 sets that `session` pointer and offset 112 sets the fake
callback's `channel_data_function` to `&system` from libc. The indirect call at
`channels.c:697` therefore enters real `system()` with a wire-chosen argument;
the harness `exec_trampoline` is not in this path. Evidence
(`real/evidence-rs-vuln-rs.out`):
`CLIENT realsystem fn=0x7dc9b7a58750 sess=0x5bdfbc67edd0 cmd=touch evidence-wire-vuln-groom-realsystem.marker bad=0`,
`SERVER call fake_cbs=... fn=0x7dc9b7a58750`,
`SERVER REALSYS armed fn=0x7dc9b7a58750 sess=0x5bdfbc67edd0 cmd=...`,
`SERVER done data_packets=2 marker_hits=0`,
`SERVER target_after=0x41414141414141c1`, `CLIENT rc=0 SERVER status=0x0`;
no `SERVER EXEC trampoline` line. The marker file was renamed to
`real/evidence-rs-sideeffect.kept`; three repeats identical in substance.
Fixed lane: no data #2, no REALSYS line, no file. Invalid-callee control
`fn=0x4141414141414141`: `CLIENT rc=0 SERVER status=0x8b` (rc 1), no file, no
`SERVER done` — the call faults at the library indirect call.

The `target_after` write survives because the first callback (the real
`on_data`) returns `len`=128, so the counter write at `:706` runs before the
loop's next step invokes `system()`. Both primitives share the same recycled
chunk.

With `W14_REALSYSTEM` undefined the preprocessed harness is byte-identical to
pre-W14 HEAD (`clang -E -P`, `cmp` clean); compiling with the flag succeeds.
Regressions: `run-inline.sh` 6 PASS / 0 FAIL, `run-plain.sh` 9 PASS / 0 FAIL,
rc 0; incidental evidence overwrites restored from HEAD.

Ceiling: no trampoline, but the command string is still an app-chosen static
global whose address the client sends; callee/session addresses are
forked-peer ASLR-local; app-owned fake callback objects, in-callback free,
authenticated peer (PR:L) and the W3 detach remain. No persistent shell or
remote command service. NOT ESTABLISHED rung 5; additive and unwitnessed.

Clean-archive receipt (commit `e4bfe196`, 2026-11-25 17:50Z): `git archive HEAD
lab/frontier/libsshch2shell` was extracted into `/tmp/w14-arch`, with symlinks
to this lab's two pinned mirror trees, their plain build directories and
hostkey (the archive carries no build artifacts or private key).
`run-realsystem.sh` there rebuilt both plain Release libraries from the pinned
trees and reported 6 PASS / 0 FAIL, rc 0: `vuln-rs` (data #2, REALSYS armed,
wire callee, no trampoline, marker file), `fixed-rs` (no data #2, no REALSYS,
no file), `vuln-rs-bad` (rc 1, no `SERVER done`, no file), and three repeats.
Fresh replay evidence `evidence-rs-vuln-rs.out` there:
`CLIENT realsystem fn=0x7b170f058750 sess=0x5954e954ddc0 cmd=touch evidence-wire-vuln-groom-realsystem.marker bad=0`,
`SERVER REALSYS armed fn=0x7b170f058750 sess=0x5954e954ddc0`,
`SERVER done data_packets=2 marker_hits=0`,
`SERVER target_after=0x41414141414141c1 groom_ptr=0x59551f140ac0`,
`CLIENT rc=0 SERVER status=0x0`; the marker was renamed to
`evidence-rs-sideeffect.kept`. Distinct addresses from the in-tree W14 run
confirm an independently rebuilt replay, not a copied log. This checks
committed harness and driver text from a clean archive; W14 remains additive
and unwitnessed. The archive run wrote only under `/tmp/w14-arch`, so the
pinned in-tree evidence is unchanged.
