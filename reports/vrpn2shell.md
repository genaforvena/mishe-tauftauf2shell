# vrpn2shell — CVE-2026-123200 wire rung 3 and a plain-build rung-4 boundary

Status 2026-11-22 ~03:45Z, author observation (W5). Wire rung 3 is OBSERVED on
the live pinned 07.36 ASan server through both description handlers and, since
W3, from a wire-supplied negative index. Plain-build wire input demonstrably
changes a saved return address (W1/W2) and, at index -8, zeroes the low byte of
a live `endpoint` object pointer that is dereferenced immediately afterwards,
without touching saved frame state. The attacker chooses the **offset** of a
fixed NUL byte, not the byte value. No command side effect, no chosen-byte
control, no rung 5. Witness replay of W1/W2 (#1261) is pending; W3 is
author-only. Nothing here is ESTABLISHED.

## Claim and pins

- CVE-2026-123200 (CNA VulnCheck), CWE-787, pre-auth network write.
- Vulnerable: tag `v07.36`, commit `79deb000cc0b47ae49a80c92c78167c02d8a04d8`.
- Fixed control: commit `0da5b0b71e06e8c318a4e674c84caee12251a782`, which clamps
  the index with `min(i, sizeof(name) - 1)`. No released fixed version exists to
  name (W5 lookup: upstream tags and published releases stop at v07.36; the
  fix commits are untagged). The pinned fixed commit is the control.
- Sources and digests: `lab/frontier/vrpn2shell/PROVENANCE.md`; upstream release
  lookup: `lab/frontier/vrpn2shell/UPSTREAM-RELEASE-LOOKUP.md`.
- Compiler: `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, x86-64, Linux 6.8.
  ASLR on; addresses below differ between runs, offsets and low bytes do not.
- All tests on 127.0.0.1 ports 13901-13906 against processes started by this
  plant. No external system was contacted with a probe.

## The negative result that was a harness bug

Frontier preserved a wire ASan sweep over indices -256..160 with no report and
attributed it to a different live frame layout. That attribution is refuted.

- Pinned `getOneTCPMessage()` (`vrpn_Connection.C:4163-4245`) reads `header[5]`
  (20 bytes) plus 4 alignment bytes, then `payload_len = len - 24`.
- Pinned `marshall_message()` (`:4377-4458`) writes six int32 fields
  (len, tv_sec, tv_usec, sender, type, seqNo) into that 24-byte region and copies
  the payload at byte 24.
- The committed `wire_inject.py` and `sweep.py` wrote six int32 **plus four extra
  NUL bytes** before the payload. The server therefore saw
  `p.buffer = [0,0,0,0][index]` and evaluated `i = ntohl(*p.buffer) == 0` for
  every supplied index. No out-of-range index ever reached the write site.
- Both scripts now send a 24-byte header. Hashes and the superseded hash are in
  `PROVENANCE.md`. The direct-call harness was unaffected: it builds `p` in
  memory.

## Wire rung 3 — live ASan server

Reproduce with `bash lab/frontier/vrpn2shell/probe-gdb.sh <outdir> 13901 100`
(server: `build-asan-07.36/server_src/vrpn_server`).

`out-probe-gdb-100/gdb.log` records, at a breakpoint immediately before the
write (`vrpn_Connection.C:4554`):

```
WRITE_SITE_HIT i=100 &sender_name=0x7ffff5181770 dest=0x7ffff51817d4 payload_len=8
0x531000014960: 0x00 0x00 0x00 0x64
==3069725==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1 at 0x7ffff51817d4
    #0 handle_sender_message  vrpn_Connection.C:4554
    #1 doSystemCallbacksFor   vrpn_Connection.C:1446
    #2 doSystemCallbacksFor   vrpn_Connection.C:1424
    #3 vrpn_Endpoint::dispatch vrpn_Connection.C:4331
    #4 getOneTCPMessage        vrpn_Connection.C:4239
    #5 handle_tcp_messages     vrpn_Connection.C:3561
    #6 vrpn_Endpoint_IP::mainloop :3056
    #7 vrpn_Connection_IP::mainloop :6120
    #8 main /server_src/vrpn.C:304
Address ... is located in stack of thread T0 at offset 212 in frame
  [112, 212) 'sender_name' (line 4537) <== access at offset 212 overflows
```

This is a real TCP message into a plant-started server, dispatching through the
real stack to the vulnerable write. Wire rung 3 is OBSERVED, not inferred.

## Plain-build layout map

Reproduce with `BIN=.../build-plain-07.36/server_src/vrpn_server bash
lab/frontier/vrpn2shell/probe-gdb.sh <outdir> 13904 100` (no sanitizer,
`-DCMAKE_BUILD_TYPE=Debug`, stack protector active).

`out-plain-wire-100/gdb.log`:

```
WRITE_SITE_HIT i=100 &sender_name=0x7fffffffd820 dest=0x7fffffffd884
Stack level 0, frame at 0x7fffffffd8a0
  rbp at 0x7fffffffd890, rip at 0x7fffffffd898
&local_id=0x7fffffffd810  &endpoint=0x7fffffffd818
&sender_name=0x7fffffffd820  &sender_name[100]=0x7fffffffd884
0x7fffffffd880: 0x0000000000000000  0xe133928ec0e0e800
```

Relative to `sender_name`: bytes 100-103 are padding; the stack canary occupies
104-111, saved rbp 112-119, saved rip 120-127. The ASan build places a redzone
at 100+, which is why the same index faults there.

## Rung-4 boundary — saved return address changed from wire input

Reproduce with `bash lab/frontier/vrpn2shell/probe-plain-rip.sh <outdir> 13905
120`.

`out-plain-rip-120/gdb.log`:

```
PRE  i=120 dest=0x7fffffffd988 canary=0x42861e88d6684700
     saved_rbp=0x7fffffffd9f0 saved_rip=0x555555596d88
POST i=120 dest=0x7fffffffd988 canary=0x42861e88d6684700
     saved_rbp=0x7fffffffd9f0 saved_rip=0x555555596d00
Program received signal SIGILL, Illegal instruction.
0x0000555555596d00 in vrpn_TypeDispatcher::doSystemCallbacksFor ... :1436
```

The NUL written at the attacker-chosen offset 120 zeroes the low byte of the
saved return address; execution resumes at the modified address and faults.
The canary and saved rbp are untouched, so this is a control-flow modification,
not a stack-canary abort. Fixed byte, chosen offset, layout-specific to this
compiler/build — no claim of arbitrary control or code execution.

## Controls

- Short input, live ASan server, index 4 (`out-probe-gdb-4/gdb.log`):
  `i=4`, destination inside `sender_name`, no ASan report.
- Fixed commit, live ASan server, index 100 (`out-fixed-wire-100/gdb.log`):
  `i=100` reaches the handler, write site at fixed `:4558`, no ASan report.
- Fixed commit, plain server, index 120 (`out-plain-fixed-rip-120/gdb.log`):
  `PRE` and `POST` saved_rip both `0x555555596d86`; no signal. The clamp reduces
  the write to `sender_name[99]` in-frame.
- Vulnerable direct-call ASan harness results (`out-direct-01/`) and the
  earlier `out-control-fixed/` remain as admission evidence.

## Second sink — TYPE_DESCRIPTION, wire rung 3 and rung 4 (W2, 2026-11-22 ~02:25Z)

The pinned handler for VRPN message type -2 has the same unchecked index on a
second 100-byte stack array: `strncpy(type_name, p.buffer + 4, ...)`, then
`i = ntohl(*(const vrpn_int32 *)p.buffer)` and `type_name[i] = '\0'`
(`vrpn-07.36/vrpn_Connection.C:4476-4482`). The fixed commit clamps at
`vrpn-fixed/vrpn_Connection.C:4486`. `wire_inject.py --msgtype -2` sends the
same 24-byte header with type -2; `--msgtype -1` remains the default, so the
W1 sender-sink replay commands are unchanged.

- Live ASan server, real loopback TCP index 100, port 13911
  (`out-type-asan-100/gdb.log`): `WRITE_SITE_HIT i=100 &type_name=...070
  dest=...0d4`, `type=-2`, frames `getOneTCPMessage:4239` → `dispatch:4331` →
  `doSystemCallbacksFor:1424/1446` → `handle_type_message:4482`, ASan
  `stack-buffer-overflow WRITE of size 1` with `sender_name`-equivalent shadow
  frame `[112, 212) 'type_name'` and access at offset 212.
- Short input, same build, index 4 (`out-type-asan-4/gdb.log`): `i=4`, in-frame
  destination, no ASan report.
- Fixed commit, same wire input, index 100 at fixed `:4486`
  (`out-type-fixed-100/gdb.log`): `i=100` reaches the clamped write, no ASan
  report.
- Plain g++ 13.3.0 `-O0` server, index 120, port 13914
  (`out-type-plain-rip-120/gdb.log`): `PRE saved_rip=0x555555596d88`,
  `POST saved_rip=0x555555596d00` (low byte zeroed), then SIGILL at
  `0x5555555596d00`. Same offset-to-saved-rip mapping as the sender sink.
- Plain fixed-commit server, index 120 (`out-type-plain-fixed-rip-120/gdb.log`):
  `PRE`/`POST saved_rip` both `0x555555596d86`, no signal.

Reproduce with `VAR=type_name LINE=4482 MSGTYPE=-2 bash
lab/frontier/vrpn2shell/probe-gdb.sh <outdir> <port> 100` and
`VAR=type_name MSGTYPE=-2 LINE_PRE=4482 LINE_POST=4484 bash
lab/frontier/vrpn2shell/probe-plain-rip.sh <outdir> <port> 120`. Both scripts
default to the original sender sink and message type, so old commands still
work. This is a second pre-auth wire path to the same rung-4 boundary, still
with a fixed NUL, no chosen byte and no command side effect.

## Negative wire indices — pointer landing without saved-state damage (W3, 2026-11-22 ~02:56Z)

Frontier's negative sweep predates the 24-byte framing fix and never reached
`i`; no negative index had been exercised over the wire. `wire_inject.py` packs
a signed int32 and vulnerable `sender_name[i] = '\0'` has no lower bound (the
check at `:4541` caps only payload_len). Reused `probe-gdb.sh` and added
`probe-frame-write.sh`, which prints `&p`, `&p.buffer`, `&endpoint` and the byte
at the destination immediately before and after the write.

- ASan v07.36, index -8, port 13915 (`out-w3-endpoint-8-asan/gdb.log`):
  `sender_name` at `0x7ffff5184670`, write at `...4668` (array-8), shadow
  `[f2]` poisoned in the left redzone. ASan `stack-buffer-overflow WRITE of
  size 1` at `:4554`, frames `getOneTCPMessage:4239` → `dispatch:4331` →
  `doSystemCallbacksFor:1446` → handler. Same rung-3 class as the positive
  indices, now from a wire-supplied negative index.
- Plain g++ 13.3.0 `-O0`, index -8, port 13914 (`out-w3-endpoint-8/gdb.log`):
  the layout differs from ASan — `&endpoint` is `sender_name - 8`, while `&p`
  is `sender_name + 128`. PRE `endpoint=0x5555556f3220`, byte at dest `0x20`;
  POST `endpoint=0x5555556f3200`, byte `0x00`. saved_rip `0x555555596d88`
  unchanged and the PRE/POST frame dumps differ only in that byte. Execution
  then faults at `vrpn_TypeDispatcher::getSenderID:1131` with
  `this=0x5555556f1150`, read through the corrupted
  `endpoint->d_dispatcher` — SIGSEGV, with no saved-frame damage.
- The landing is build-specific: in this plain build `&endpoint =
  sender_name-8`, `&p.payload_len = sender_name+152`, `&p.buffer =
  sender_name+160`. Index -48 (`out-w3-neg-ptr-48b/gdb.log`) hit a byte already
  `0x00` (no-op); index -64 in the ASan build (`out-w3-neg-asan-64/gdb.log`)
  hit `p.msg_time` with no ASan report and no effect. The pointer landing is a
  property of this plain build on this host, not of the source primitive.
- Fixed-commit controls at the same wire index -8: ASan at fixed `:4558`
  (`out-w3-endpoint-8-fixed-asan/gdb.log`) reaches the clamped write with no
  ASan report; plain at fixed `:4558`/`:4560`
  (`out-w3-endpoint-8-fixed2/gdb.log`) leaves canary, saved_rbp and saved_rip
  unchanged and survives. The fixed handler declares `i` as `vrpn_uint32` and
  clamps with `min(i, sizeof(sender_name)-1)`, so -8 writes
  `sender_name[99]`.

Reproduce with `bash lab/frontier/vrpn2shell/probe-frame-write.sh <out> <port>
-8` (plain default) and `BIN=lab/frontier/vrpn2shell/build-asan-07.36/server_src/vrpn_server
...` for ASan; the fixed control uses `BIN=...build-plain-fixed/server_src/vrpn_server
LINE_PRE=4558 LINE_POST=4560 bash lab/frontier/vrpn2shell/probe-plain-rip.sh
<out> <port> -8`. Honest rung: a wire-chosen offset deterministically zeroes
the low byte of a live object pointer that is used immediately afterwards; no
chosen byte value, no arbitrary destination, no command side effect, no rung 5.
W3 is author-only until replayed.

## Clean rebuild self-replay (W4, 2026-11-22 ~03:26Z)

The W2 and W3 raw logs are now committed alongside the older W1 evidence, and
the script digests in `PROVENANCE.md` were corrected — the committed W2
`--msgtype` / env-override edits had left the recorded hashes stale.

To test whether the wire result depends on stale build state, both servers were
rebuilt from the pinned sources in NEW directories (`build-replay-w4`,
`build-replay-fixed-w4`; exact CMake commands and build logs in
`PROVENANCE.md`) and probed on fresh loopback ports:

- Vulnerable plain rebuild, port 13931, index -8
  (`out-w4-rebuild-neg8/gdb.log`): `&endpoint = sender_name - 8`; endpoint
  `0x5555556f3220` → `0x5555556f3200` (byte `0x20` → `0x00`), saved rip
  `0x555555596d88` unchanged, then SIGSEGV at `getSenderID:1131`. Same offsets
  and low byte as the original W3 build.
- Fixed-commit rebuild, port 13932, index -8
  (`out-w4-rebuild-fixed-neg8/gdb.log`): clamped write, canary / saved rbp /
  saved rip unchanged, no signal.

This is author self-replay: it shows the committed scripts and pinned sources
reproduce the rung-4 boundary from a clean build. It is NOT an independent
witness verdict; the replay request #1261/#1271 is still open. No chosen byte,
no command side effect, no rung 5.

## Released fixed version — authoritative negative (W5, 2026-11-22 ~03:44Z)

The charter and W1-W4 left the released fixed version UNKNOWN because the two
pinned fix commits do not name a release. A read-only metadata lookup now
resolves that into a precise negative: upstream `git ls-remote --tags` has 35
refs and no 07.37/07.38/07.39 tag; the GitHub releases API lists v07.36
(published 2025-06-28) as the newest release; the v07.39 tarball URL is 404;
the clamp commit `0da5b0b71e06` and cookie bump `c893b583d928` are both
untagged commits dated 2026-10-22. `07.39` is the version *string* written by
the second commit, not a released version. Exact commands and output:
`lab/frontier/vrpn2shell/UPSTREAM-RELEASE-LOOKUP.md`.

No build, control or rung claim changes: the fixed control stays the pinned
commit tarball, and the released fixed version remains UNKNOWN because no
fixed release exists. This is reference provisioning, not a target probe.

## Limits and next work

- Witness replay of the wire rung-3 and rung-4 runs is required before any
  published ESTABLISHED claim. All raw W1-W4 logs are committed; the rebuild
  commands in `PROVENANCE.md` let a fresh context reproduce both builds, and
  the probe scripts take a `BIN` override and fresh ports. Replay request
  #1261/#1271 is still open (W105 deferred it behind other targets).
- A NUL at 104-111 corrupts the stack canary (expected abort); 112-119 lands on
  saved rbp; 120+ on saved rip. Those ranges are specific to g++ 13.3.0 Debug
  `-O0` on this host and must be re-measured on any other build.
- Rung 5 is out of reach on this evidence: no chosen byte, no benign command
  side effect, no reuse of a long-lived service. The class boundary also stands:
  this is a pre-auth network server library, not a web-facing server.
- No fixed release exists upstream as of 2026-11-22 (W5); the fixed commit is
  the only fixed control. Do not infer that 07.37-07.39 are released fixes.
