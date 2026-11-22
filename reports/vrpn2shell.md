# vrpn2shell — CVE-2026-123200 wire rung 3 and a plain-build rung-4 boundary

Status 2026-11-22 ~05:38Z, author observation (W7). Wire rung 3 is OBSERVED on
the live pinned 07.36 ASan server through both description handlers and, since
W3, from a wire-supplied negative index; W7 extends it to an optimized (-O2)
build. Plain-build wire input demonstrably changes a saved return address
(W1/W2) and, at index -8, zeroes the low byte of a live `endpoint` object
pointer that is dereferenced immediately afterwards, without touching saved
frame state. W6 confirms the debugger-free consequence on one Debug -O0 build:
a single pre-auth TCP message deterministically kills the stock plain server
(SIGSEGV or SIGILL). W7 measures the limit: on a stock RelWithDebInfo (-O2)
build the same WRITE still fires under ASan, but the plain process survives
both indices, so the DoS is layout-specific, not build-independent. The
attacker chooses the **offset** of a fixed NUL byte, not the byte value. No
command side effect, no chosen-byte control, no rung 5. Witness replay of
W1/W2 (#1261) is pending; W3, W6 and W7 are author-only. Nothing here is
ESTABLISHED.

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
  Host `randomize_va_space=2`. The gdb probe scripts do not override gdb's
  default address-randomization setting, and the absolute addresses they logged
  are identical across runs; offsets and low bytes are the invariant. W6's
  functional runs recorded exit status, not addresses.
- All tests on 127.0.0.1 ports 13901-13967 against processes started by this
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

Geometry from `out-plain-wire-100/gdb.log`: bytes 100-103 are padding, the
stack canary occupies 104-111, saved rbp 112-119, saved rip 120-127. Only the
120+ landing has a write-site log; the 104-119 consequences are inference from
these addresses, not observed NUL landings. The ASan build places a redzone at
100+, which is why the same index faults there.

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

Parsing note for fixed-commit raw logs: `dest=` in the probe output is
`&name[raw_wire_index]` computed by the probe, not the address the clamped
commit writes. The fixed source clamps to `name[99]`; no far write occurred.

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

## Debugger-free functional consequence — pre-auth remote DoS (W6, 2026-11-22 ~04:26Z)

Every W1-W5 rung-4 readback ran under gdb breakpoints. The causal question for
this wake was whether the same wire input faults an otherwise untouched server
process. New `lab/frontier/vrpn2shell/probe-func-dos.sh` starts a stock plain
server (no gdb, no sanitizer, no instrumentation), sends exactly one
description message with the corrected 24-byte framing, records the server
PID's exit status two seconds later, and then kills surviving controls for
cleanup. Each run records the binary SHA-256, port, index, message type and
status in `out-w6-func-*/meta.txt`; raw server stdout/stderr and client output
are in the same directory.

Vulnerable binary `build-plain-07.36/server_src/vrpn_server`
(SHA-256 `5cf4945768615a55da3401c7608f4223dd1f8f04fb89f2387f6ff6c22340bd74`);
fixed control `build-replay-fixed-w4/server_src/vrpn_server`
(SHA-256 `15111740fd68868c49569570f1f283d4f801e7a4cfd9c988c94497e0c4b791fa`).
Every `out-w6-func-*/meta.txt` records which binary it ran; the vulnerable SHA
belongs to the original plain build, not to the W4 rebuild (whose binary hash
is `4e462ace33fa1de028b9de25a7474f24e00e72392e235f9166e2e93fe53060a9`).
Host `randomize_va_space=2` throughout; no per-run addresses were recorded.

| Sink | Index | Build | Port | Result |
| --- | --- | --- | --- | --- |
| SENDER_DESCRIPTION | -8 | vulnerable | 13941 | DEAD, exit 139 (SIGSEGV, core dumped) |
| SENDER_DESCRIPTION | -8 | vulnerable, repeat | 13945 | DEAD, exit 139 (SIGSEGV, core dumped) |
| SENDER_DESCRIPTION | 120 | vulnerable | 13944 | DEAD, exit 132 (SIGILL, core dumped) |
| SENDER_DESCRIPTION | 4 | vulnerable | 13942 | ALIVE after message |
| SENDER_DESCRIPTION | -8 | fixed commit | 13943 | ALIVE after message |
| TYPE_DESCRIPTION | -8 | vulnerable | 13948 | DEAD, exit 139 (SIGSEGV, core dumped) |
| TYPE_DESCRIPTION | 120 | vulnerable | 13946 | DEAD, exit 132 (SIGILL, core dumped) |
| TYPE_DESCRIPTION | 120 | fixed commit | 13947 | ALIVE after message |

Signals match the gdb mechanics: W3's zeroed `endpoint` low byte becomes a
SIGSEGV on the next `getSenderID` dereference; W1/W2's zeroed saved-rip low byte
becomes SIGILL at the redirected address. Two different wire message types,
two landing classes, deterministic across a repeat run under host ASLR (no
addresses were captured in the W6 runs). A short in-frame index and the clamped
fixed commit survive the identical wire path.

Scope of the claim: a deterministic **pre-auth remote denial of service** on
this plant's plain g++ 13.3.0 `Debug -O0` build, both sinks, on loopback.
`ALIVE` means the process was still running two seconds after the message;
those controls were then killed by the probe for cleanup. No debugger was
attached in any W6 run. This is not chosen-byte control, not pointer control
beyond the observed low-byte zeroing, not a benign command side effect, and
not rung 5. Layout-specific, author-only, and not yet replayed by the witness.

Reproduce any row from the repo root, e.g.:
`bash lab/frontier/vrpn2shell/probe-func-dos.sh <out> 13941 -8`;
`BIN=lab/frontier/vrpn2shell/build-replay-fixed-w4/server_src/vrpn_server bash
lab/frontier/vrpn2shell/probe-func-dos.sh <out> 13943 -8`;
`MSGTYPE=-2 bash lab/frontier/vrpn2shell/probe-func-dos.sh <out> 13946 120`.
Use fresh ports when replaying.


## Optimized build — rung 3 holds, DoS does not transfer (W7, 2026-11-22 ~05:38Z)

The limits section named the only unmeasured build claim: W6's debugger-free
DoS was observed on one plain g++ 13.3.0 `Debug -O0` build. This wake built the
same pinned `v07.36` source with `-DCMAKE_BUILD_TYPE=RelWithDebInfo` in a NEW
directory (`build-opt-07.36`; CMake flags `-fPIC -O2 -g -DNDEBUG`, exact
commands and logs in `PROVENANCE.md`) and replayed the same wire path on fresh
ports.

| Sink | Index | Build | Port | Result |
| --- | --- | --- | --- | --- |
| SENDER_DESCRIPTION | -8 | vulnerable, -O2 plain | 13951 | ALIVE after message |
| TYPE_DESCRIPTION | 120 | vulnerable, -O2 plain | 13952 | ALIVE after message |
| SENDER_DESCRIPTION | -8 | vulnerable, -O2 ASan | 13961 | DEAD, exit 134; ASan `stack-buffer-overflow WRITE of size 1`, `vrpn_Connection.C:4554` |
| SENDER_DESCRIPTION | 100 | vulnerable, -O2 ASan | 13962 | DEAD, exit 134; same ASan WRITE at `:4554` |
| SENDER_DESCRIPTION | 4 | vulnerable, -O2 ASan | 13963 | ALIVE, no ASan report |
| SENDER_DESCRIPTION | -8 | fixed commit, -O2 ASan | 13964 | ALIVE, 0 ASan errors |
| SENDER_DESCRIPTION | 100 | fixed commit, -O2 ASan | 13965 | ALIVE, 0 ASan errors |
| SENDER_DESCRIPTION | -8 | fixed commit, -O2 plain | 13966 | ALIVE after message |
| TYPE_DESCRIPTION | 120 | fixed commit, -O2 plain | 13967 | ALIVE after message |

Binaries: vulnerable -O2 plain `build-opt-07.36/server_src/vrpn_server`
(SHA-256 `bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`);
vulnerable -O2 ASan `build-opt-asan-07.36/server_src/vrpn_server`
(`cbf89fd73c87d81b3ca8e16ebb7ce0ed849fd84756390bf9c9fb33d7ef4402e2`);
fixed -O2 ASan `build-opt-asan-fixed/server_src/vrpn_server`
(`d68a8ebc7b44a01c63ffc08dd57a7249576c331d145a8dcfec09af360dfa1d03`).
Full digests and per-run SHA are in `PROVENANCE.md` and each
`out-w7-*/meta.txt`.

The ASan rows are the control that makes the negative meaningful: the
unchecked NUL is still written from real loopback TCP input at `-O2` (wire
rung 3 holds), fixed and short-input controls are clean, yet the same offsets
in a stock optimized plain build do not fault. Optimization moves the frame
objects, so neither the W3 `endpoint` pointer landing nor the W1/W2 saved-rip
landing transfers. W7 therefore resolves the prior UNKNOWN into a measured
negative: **the remote DoS is a Debug -O0 layout effect on this host, not a
build-independent consequence of the bug.** No chosen byte, no command side
effect, no rung 5. Author-only, not witness-replayed.

The gdb frame probe does not work unchanged at `-O2`:
`probe-frame-write.sh` prints `&p`, which is not an lvalue once the by-value
`HANDLERPARAM` is optimized into registers, so the breakpoint command file
aborts (`out-w7-opt-frame-neg8/gdb.log`: `Can't take address of "p" which isn't
an lvalue`). No O2 frame geometry is claimed from that run.

## Limits and next work

- Witness replay of the wire rung-3, rung-4 and W6 functional runs is required
  before any published ESTABLISHED claim. All raw W1-W7 logs are committed; the
  rebuild commands in `PROVENANCE.md` let a fresh context reproduce every
  build variant, and the probe scripts take a `BIN` override and fresh ports.
  Replay request #1261/#1271 is still open (W105 deferred it behind other targets).
- Geometry predicts a NUL at 104-111 lands in the stack canary and at 112-119
  in saved rbp, but no committed log exercises an index in 104-119; those
  outcomes stay UNKNOWN until measured. Index 120+ landing on saved rip is
  logged. All ranges are specific to g++ 13.3.0 Debug `-O0` on this host and
  must be re-measured on any other build.
- W6's DoS is a measured **Debug -O0 layout effect**. W7 resolves the former
  optimized-build UNKNOWN into a negative: on `RelWithDebInfo` (`-O2`) the
  ASan WRITE still fires from the wire but the plain process survives -8 and
  120. Do not claim a build-independent DoS.
- Rung 5 is out of reach on this evidence: no chosen byte, no benign command
  side effect, no reuse of a long-lived service. The class boundary also stands:
  this is a pre-auth network server library, not a web-facing server.
- No fixed release exists upstream as of 2026-11-22 (W5); the fixed commit is
  the only fixed control. Do not infer that 07.37-07.39 are released fixes.
