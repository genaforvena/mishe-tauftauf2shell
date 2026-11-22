# vrpn2shell — CVE-2026-123200 wire rung 3 and a plain-build rung-4 boundary

Status 2026-11-22 ~02:25Z, author observation (W2). Wire rung 3 is OBSERVED on
the live pinned 07.36 ASan server through **both** description handlers, and
plain-build wire input demonstrably changes a saved return address and
redirects control through both. Rung 4 is claimed only at that honest boundary:
the attacker chooses the **offset** of a fixed NUL byte, not the byte value. No
command side effect, no chosen-byte control, no rung 5. Witness replay of the
wire limbs (W1 and W2) is pending, so nothing here is ESTABLISHED.

## Claim and pins

- CVE-2026-123200 (CNA VulnCheck), CWE-787, pre-auth network write.
- Vulnerable: tag `v07.36`, commit `79deb000cc0b47ae49a80c92c78167c02d8a04d8`.
- Fixed control: commit `0da5b0b71e06e8c318a4e674c84caee12251a782`, which clamps
  the index with `min(i, sizeof(name) - 1)`. The precise released fixed version
  is UNKNOWN from the fetched commits; the fixed commit is the control.
- Sources and digests: `lab/frontier/vrpn2shell/PROVENANCE.md`.
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

## Limits and next work

- Witness replay of the wire rung-3 and rung-4 runs is required before any
  published ESTABLISHED claim. Ask the witness to reuse the committed scripts
  with fresh ports.
- A NUL at 104-111 corrupts the stack canary (expected abort); 112-119 lands on
  saved rbp; 120+ on saved rip. Those ranges are specific to g++ 13.3.0 Debug
  `-O0` on this host and must be re-measured on any other build.
- Rung 5 is out of reach on this evidence: no chosen byte, no benign command
  side effect, no reuse of a long-lived service. The class boundary also stands:
  this is a pre-auth network server library, not a web-facing server.
- The precise released fixed version remains UNKNOWN; only the fixed commit is
  a control.
