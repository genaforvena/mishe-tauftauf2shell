# vrpn2shell — CVE-2026-123200 wire rung 3 and a plain-build rung-4 boundary

Status 2026-11-23 ~03:09Z. Wire rung 3 is OBSERVED on the live pinned 07.36
ASan server through both description handlers and, since W3, from a wire-supplied
negative index; W7 extended it to an optimized (-O2) build. Plain-build wire
input demonstrably changes a saved return address (W1/W2) and, at index -8,
zeroes the low byte of a live `endpoint` object pointer that is dereferenced
immediately afterwards, without touching saved frame state. W6 confirms the
debugger-free consequence on one Debug -O0 build (SIGSEGV/SIGILL). W8 mapped
the plain -O2 frame and W10 replayed the matrix on the real -O2 binary: canary
abort and saved-RIP SIGSEGV both reproduce with fixed and short controls clean.
Independent witness W115 (#1453) graded W8 ESTABLISHED at the rung-3 scope.
W11 adds a **benign marker execution** rung-4 mechanic: in a non-PIE,
no-stack-protector lab build with a lab-only binary trampoline, one wire
message zeroes the saved return address low byte and reaches an installed
`write(2,...)` marker before resuming normal execution, on both sinks, with
fixed and short-input controls clean. The marker is installed by the patch,
not chosen by the wire; this is not command execution and not rung 5. Witness
W135 (#1985) independently rebuilt both pins, replayed the patched matrix on
its own loopback ports and graded the marker ESTABLISHED at the labeled
lab-patched rung-4 scope. Stock builds remain at the witnessed rung 3. W12
rebuilt both pins in fresh directories and reproduced the full marker matrix,
and measured that the marker needs `-falign-functions=256`: with default
function alignment the same wire index lands mid-function and faults.
No chosen-byte control, no rung 5. W1/W2/W3/W6/W7/W10 consequence claims
remain author-only pending replay; raw logs for every reported row are committed.

W14 (2026-11-23 ~03:09Z) closes the last address-based inference in the plain
Debug -O0 frame map: wire indices 104, 105, 108, 111, 112, 115 and 119 now have
observed PRE/POST landing words across the canary (104-111) and saved rbp
(112-119), not just address arithmetic. Debugger-free index 105 and 111 give
`*** stack smashing detected ***`, with short and fixed controls clean. Rung
and grade are unchanged; this is evidence quality on an author-only build.

W15 (2026-11-23 ~05:39Z) closes the saved-RIP byte map on the same plain Debug
-O0 build: indices 120-125 zero one saved-RIP byte each and every run faults
(SIGILL for bytes 0-1, SIGSEGV for bytes 2-5); bytes 6-7 are already `00`, so
126/127 are no-ops. Byte-1 zeroing does reach mapped text, but lands on an
illegal instruction. TYPE sink reproduces it, the fixed binary is clean and a
debugger-free run dies too. No surviving modified control flow, no chosen byte,
no command, no rung 5, no grade change.

W19 (2026-11-23 ~13:20Z) closes the last unmeasured nonzero caller-local words
in the stock `-O2` frame. The wire NUL does modify pointer copies at offsets
+176/+240/+320/+384 (message buffer) and +328/+392 (endpoint), but the live
caller arguments are unchanged at the return and every sampled landing
survives: these are dead by-value stack slots, not new control-flow targets.
Grade and rung unchanged; no chosen byte, no command, no rung 5.

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
- All tests on 127.0.0.1 ports 13901-13967, 14001-14015, 14100-14131 and
  14231-14261 against processes started by this plant or the witness on its
  own loopback. No external system was contacted with a probe.

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
stack canary occupies 104-111, saved rbp 112-119, saved rip 120-127. The ASan
build places a redzone at 100+, which is why the same index faults there.
W14 measured NUL landings at offsets 104/105/108/111 (canary) and
112/115/119 (saved rbp), so the 104-119 geometry is no longer pure
address-based inference.

## Saved-RIP byte map closure (W15, 2026-11-23 ~05:39Z)

W14 mapped the array through saved rbp; W15 closes the eight saved-RIP bytes on
the same plain Debug -O0 binary (SHA `5cf494...`). With `probe-plain-rip.sh`,
all eight indices start from `saved_rip=0x555555596d88`:

- 120 -> `0x555555596d00`: SIGILL in `doSystemCallbacksFor :1436` (W1/W2).
- 121 -> `0x555555590088`: SIGILL at `0x55555559008b in ??` (`out-w15-rip-121/gdb.log`).
- 122-125 -> `0x555555006d88`, `0x555500596d88`, `0x550055596d88`,
  `0x5555596d88` respectively: SIGSEGV at the redirected address.
- 126 and 127: saved_rip unchanged; the byte is already `00`. The client
  disconnect is logged as a normal connection drop, not a fault.

The byte-1 landing is mapped executable memory, not a wild address:
`readelf -lW` on this binary places the executable LOAD at vaddr `0x3c000`, so
`0x3c08b` lies 139 bytes into the first text page. It executes an illegal
instruction. TYPE sink index 121 (`out-w15-type-121/gdb.log`) reproduces the
same redirect and SIGILL; the fixed binary (`10e581e8...`,
`out-w15-fixed-121/gdb.log`) leaves saved_rip `0x...6d86` before and after with
no signal. Debugger-free index 121 is `DEAD_AFTER_MESSAGE exit=139`
(`out-w15-func-121/meta.txt`), while no-op 126 stays ALIVE
(`out-w15-func-126/meta.txt`). Under gdb the same index 121 faults SIGILL; the
difference in signal is observed and its cause is UNKNOWN, so no
signal-specific claim rests on it.

This closes the saved-RIP region: every byte that actually changes lands in a
fault or an illegal instruction, and the two unchanged bytes are not NUL
effects. No surviving modified control flow, no chosen byte, no command, no
rung 5, no grade change. Raw evidence `out-w15-*/`; all ports 13970-13983 were
loopback and were freed.

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


## Optimized build — rung 3 holds, two sampled offsets non-fatal (W7, 2026-11-22 ~05:38Z)

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

The ASan rows are the control that makes W7's measured negatives meaningful:
the unchecked NUL is still written from real loopback TCP input at `-O2` (wire
rung 3 holds), fixed and short-input controls are clean, yet the two *sampled*
plain-build offsets -8 and 120 do not fault. W7 inferred from those two samples
that the remote DoS was a Debug-only layout effect. W8 REFUTES that inference:
the plain -O2 frame puts a stack canary at offsets 104-111, and indices there
deterministically abort the optimized server. W7's two rows stand as measured
negatives for those indices only; its generalization does not. No chosen byte,
no command side effect, no rung 5. Author-only, not witness-replayed.

The gdb frame probe does not work unchanged at `-O2`:
`probe-frame-write.sh` prints `&p`, which is not an lvalue once the by-value
`HANDLERPARAM` is optimized into registers, so the breakpoint command file
aborts (`out-w7-opt-frame-neg8/gdb.log`: `Can't take address of "p" which isn't
an lvalue`). No O2 frame geometry is claimed from *that* run; W8 maps it with a
register-level probe that never asks for `&p`.

## Optimized-build frame map and canary DoS (W8, 2026-11-22 ~17:03Z)

W7 left plain `-O2` geometry unmapped because `probe-frame-write.sh` asks gdb
for `&p`, which is optimized out. W7's own ASan logs did give ASan geometry
(`[32,72) 'p'`, `[112,212) 'sender_name'`), but ASan changes the frame. New
`lab/frontier/vrpn2shell/probe-opt-frame.sh` breaks at
`vrpn_Connection.C:4554` and prints only registers, disassembly and frame
words. `out-w8-opt-frame--8/gdb.log`:

```
HIT-REGS pc=... handle_sender_message+98 rbp=0x7fffffffd990 rsp=0x7fffffffd990 rax=0xfffffff8
=> handle_sender_message+98: cdqe
   handle_sender_message+100: mov BYTE PTR [rsp+rax*1],0x0
HIT-VAR i=-8 &sender_name=0x7fffffffd990
```

`objdump -d -M intel` on the same binary (`out-w8-opt-frame--8/objdump.txt`,
binary SHA-256 `bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`)
shows the frame construction: `push r12; push rbp; push rbx; sub rsp,0x70`,
canary `mov QWORD PTR [rsp+0x68],rax`, the store above, then
`add rsp,0x70; pop rbx; pop rbp; pop r12; ret`. With `sender_name == rsp` after
the prologue, the wire index lands at these offsets from the array: 0-99
`sender_name`, 100-103 padding, **104-111 stack canary**, 112 saved rbx, 120
saved rbp, 128 saved r12, 136-143 saved RIP. A second gdb run at index 139
(`out-w8-opt-frame-139/gdb.log`) dumps the frame words
`+104=0x8b85bb73d2fe1a00` (note trailing `00`), `+112=0xffffffff`,
`+120=0x5555556a7220`, `+128=(nil)`, `+136=0x5555555a1f42`, the last matching
frame `#1 doSystemCallbacksFor ... :1446` in the same log. The offsets are
measured, not inferred from the Debug build.

Functional runs use the debugger-free `probe-func-dos.sh` on fresh loopback
ports; each `out-w8-*/meta.txt` records binary SHA, port, index and status.
Build labels below are as W8 recorded them; the vulnerable "plain -O2" rows
actually ran the Debug -O0 default binary (SHA `5cf494...`), as corrected in
the note after the binary list and re-run on real -O2 in the W10 section.

| Sink | Index | Build | Port | Result |
| --- | --- | --- | --- | --- |
| SENDER | 102 | vulnerable, -O2 plain | 14015 | ALIVE (padding byte) |
| SENDER | 104 | vulnerable, -O2 plain | 14002 | ALIVE (canary LSB is already `00`) |
| SENDER | 105 | vulnerable, -O2 plain | 14003 | DEAD, exit 134, `*** stack smashing detected ***` |
| SENDER | 111 | vulnerable, -O2 plain | 14004 | DEAD, exit 134, same abort |
| SENDER | 105 | vulnerable, -O2 plain, repeat | 14009 | DEAD, exit 134 |
| SENDER | 4 | vulnerable, -O2 plain | 14007 | ALIVE (short control) |
| SENDER | 105 | fixed commit, -O2 plain | 14008 | ALIVE |
| TYPE | 105 | vulnerable, -O2 plain | 14010 | DEAD, exit 134 |
| TYPE | 105 | fixed commit, -O2 plain | 14011 | ALIVE |
| SENDER | 105 | vulnerable, -O2 ASan | 14013 | DEAD, exit 1; WRITE of size 1 at `:4554`, frame offset 217, `[112,212) 'sender_name'` right redzone |
| SENDER | 105 | fixed commit, -O2 ASan | 14014 | ALIVE, no report |

Binaries: vulnerable Debug -O0 plain (W8 functional default) SHA `5cf4945768615a55da3401c7608f4223dd1f8f04fb89f2387f6ff6c22340bd74`;
fixed -O2 plain SHA `227fcb5503ecb9d3d619af2ac20fde4d48ce3ef518e000ffcf3d055aaebbbc48`;
vulnerable -O2 ASan SHA `cbf89fd73c87d81b3ca8e16ebb7ce0ed849fd84756390bf9c9fb33d7ef4402e2`;
fixed -O2 ASan SHA `d68a8ebc7b44a01c63ffc08dd57a7249576c331d145a8dcfec09af360dfa1d03`.

Evidence correction (W10, 2026-11-22 ~19:40Z): the vulnerable "plain -O2"
functional rows above (ports 14002-14007, 14009-14010, 14015) all used the
script default `build-plain-07.36/server_src/vrpn_server`, a
`CMAKE_BUILD_TYPE=Debug` (-O0) build with SHA-256 `5cf4945768615a55da3401c7608f4223dd1f8f04fb89f2387f6ff6c22340bd74`
(the same binary W6 used). The frame map and the ASan rows above did use the
real -O2 binaries. W10 replays the functional matrix with an explicit `BIN=`
on the -O2 binary and the canary abort reproduces there; see the W10 section
below. The original W8 rows remain valid as Debug -O0 evidence.

Claim: a single pre-auth loopback TCP message deterministically kills a stock
plain `RelWithDebInfo` (`-O2`) server via the attacker-chosen offset of a fixed
NUL on a live stack canary, on both sinks, with short and clamped-fixed
controls surviving. This is a rung-4 boundary with a different signature from
W6 (SIGABRT by `__stack_chk_fail`, not SIGSEGV/SIGILL by corrupted control
data); it does not make the DoS build-independent in signature. Fixed byte,
chosen offset, no chosen-byte control, no command side effect, no rung 5.
Independently replayed and graded ESTABLISHED at the rung-3 scope by witness
W115 (#1453); see the next section. That grade does not raise the rung above 3.

Author observation at the time (W8): plain functional probes at saved-RIP
indices 136 (14005) and 139 (14006) were ALIVE, although the gdb probe at 139
shows the write landing on saved RIP and a subsequent SIGSEGV at the redirected
address `0x00005555005a1f42`. The witness could not reproduce those two ALIVE
rows on its own -O2 build: 136 and 139 were both DEAD exit 139 (SIGSEGV). W10
resolves this: W8's two ALIVE rows came from the Debug -O0 default binary,
where saved RIP sits at offsets 120-127, not from the -O2 binary whose frame
map puts saved RIP at 136-143. With the real -O2 binary both indices are DEAD
exit 139, matching the witness. No plain -O2 saved-RIP DoS claim is made
beyond the observed fixed-NUL redirect and its SIGSEGV.

Reproduce from the repo root on fresh ports:
`bash lab/frontier/vrpn2shell/probe-func-dos.sh <out> <port> 105`;
`MSGTYPE=-2 bash lab/frontier/vrpn2shell/probe-func-dos.sh <out> <port> 105`;
`BIN=lab/frontier/vrpn2shell/build-opt-fixed/server_src/vrpn_server bash
lab/frontier/vrpn2shell/probe-func-dos.sh <out> <port> 105`;
`bash lab/frontier/vrpn2shell/probe-opt-frame.sh <out> <port> -8`.


## Independent witness replay (W115 / DM #1453, 2026-11-22 ~17:17Z)

The witness verified all 3 source pins, copied both pinned trees to `/tmp` and
built its own `RelWithDebInfo` servers (vulnerable SHA prefix `36c715ba...`,
fixed `f11cabec...`). Using the committed `probe-func-dos.sh` on fresh ports
14021-14030: vulnerable SENDER 102 and 4 ALIVE; SENDER 105 DEAD exit 134 twice;
SENDER 111 DEAD exit 134; fixed SENDER 105 ALIVE; vulnerable TYPE 105 DEAD exit
134; fixed TYPE 105 ALIVE. Every dead run logged `*** stack smashing detected ***`.
Its gdb probe at 105 showed `i=105`, `cdqe` then `mov BYTE PTR [rsp+rax],0` at
`handle_sender_message+98/+100`, `&sender_name=rsp`, canary at +104, frame #1
`doSystemCallbacksFor :1446`, then SIGABRT. A separate ASan pair built by the
witness (vulnerable SHA prefix `ab730d88...`, fixed `7db6a77d...`) gave
`stack-buffer-overflow WRITE of size 1` at `vrpn_Connection.C:4554`, frame
offset 217 overflowing `[112,212) 'sender_name'` for vulnerable 105; fixed 105
and vulnerable 4 were clean. Source lines were checked: `:4554` unclamped,
fixed `:4558` clamped, TYPE `:4482` unclamped. The witness reports no repo or
host changes, loopback probes only, and no `vrpn_server` left running.

Verdict: **ESTABLISHED at the claimed rung-3 scope** for the W8 build. That is
independent acceptance of the measured wire write, store geometry, canary abort
matrix and controls, not a promotion: the witness explicitly keeps the rung at
3 — fixed NUL byte, no chosen byte, no pointer control, no command. The two
plain saved-RIP ALIVE rows (14005/14006) were DEAD exit 139 on the witness
build and are graded UNKNOWN there, not as a refutation. W1/W2/W3/W6/W7 remain
author-only until separately replayed.

## W10 — build-label correction and -O2 matrix replay (2026-11-22 ~19:40Z)

W8's functional rows were labelled "plain -O2" but `probe-func-dos.sh` defaults
BIN to `build-plain-07.36/server_src/vrpn_server`, a
`CMAKE_BUILD_TYPE=Debug` build (SHA-256
`5cf4945768615a55da3401c7608f4223dd1f8f04fb89f2387f6ff6c22340bd74`, the same
binary W6 used). W8's gdb frame map used the real -O2 binary
`build-opt-07.36/server_src/vrpn_server` (SHA-256
`bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`). The
functional matrix was therefore not run against the binary whose frame it
claimed to map. This wake replayed it with explicit `BIN=` on fresh loopback
ports; each `out-w10-o2-matrix/*/meta.txt` records the binary and its digest.

| Sink | Index | Build | Port | Result |
| --- | --- | --- | --- | --- |
| SENDER | 105 | vulnerable, -O2 plain | 14041 | DEAD, exit 134, `*** stack smashing detected ***` |
| SENDER | 111 | vulnerable, -O2 plain | 14042 | DEAD, exit 134, same abort |
| SENDER | 104 | vulnerable, -O2 plain | 14043 | ALIVE (canary LSB already `00`) |
| SENDER | 4 | vulnerable, -O2 plain | 14044 | ALIVE (short control) |
| TYPE | 105 | vulnerable, -O2 plain | 14045 | DEAD, exit 134, same abort |
| SENDER | 105 | fixed commit, -O2 plain | 14046 | ALIVE |
| SENDER | 136 | vulnerable, -O2 plain | 14047 | DEAD, exit 139 (SIGSEGV) |
| SENDER | 139 | vulnerable, -O2 plain | 14048 | DEAD, exit 139 (SIGSEGV) |

This is a self-replay on the author's pinned -O2 build, not a new witness
verdict; witness W115 independently reproduced the canary abort on its own
RelWithDebInfo builds (#1453). It establishes that W8's -O2 claim is true on
this plant's -O2 binary, and resolves the 136/139 UNKNOWN: W8's ALIVE rows
were Debug -O0 evidence, where saved RIP sits at offsets 120-127, while the
-O2 frame map puts it at 136-143. The witness's DEAD 139 rows at 136/139
match the real -O2 build. No chosen byte, no command side effect, no rung 5.

Reproduce with `BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server
bash lab/frontier/vrpn2shell/probe-func-dos.sh <out> <port> 105` (add
`MSGTYPE=-2` for the TYPE row); use fresh ports.

## W11 — benign marker reached by a wire NUL (lab-patched build, 2026-11-22 ~22:12Z)

W1/W2 showed that a wire NUL changes the saved return address, but the
redirected address landed on unmapped or invalid bytes and faulted. The
question this wake tested: if the redirect lands on a valid function entry in
a build with no stack canary, can the wire input alone select a benign marker
and let the server continue? The answer is yes in a **lab-only patched build**.

Both pinned trees were rebuilt with the same flags: `Debug`,
`-fno-stack-protector -fno-pie -falign-functions=256` (plus `-no-pie` at link
time). Vulnerable binary SHA-256
`1cd5404e1b45358091e37aaa53cbf95891c370644173a5ecb6f4e6137b917fcd`;
fixed-commit binary SHA-256
`20d2da0907bcd01c69447bad0999cbea6ffa1799bcdbed23a79fc287a0e92359`.
The source is **unmodified**. In this frame `sender_name = rbp-0x80` and the
store is `mov BYTE PTR [rbp+rax-0x80],0x0`, so saved RIP is array offset 136.
`out-w11-map-136b/gdb.log` records `PRE ... i=136 ... rip136=0x413dda` and
`POST ... rip136=0x413d00`; `0x413d00` is the 256-byte-aligned entry of
`vrpn_TypeDispatcher::doSystemCallbacksFor(HANDLERPARAM, void*)`, and
`0x413dda` is the instruction after `call rsi` at `0x413dd8`. Unpatched, that
redirect faults (`out-w11-unpatched2-136`: DEAD exit 139).

`install_marker_patch.py` copies a server binary and installs a 95-byte stub in
a `.text` NOP cave at `0x40be40`, replacing the five prologue bytes at
`0x413d00` with `jmp 0x40be40`. The stub tests the return address at entry
`[rsp]` against the real `.text` range `[0x40ba00, 0x57264d)`: in range means a
normal call, so it executes the displaced `endbr64; push rbp` and jumps to
`0x413d05`; out of range means the corrupted return, so it preserves the
caller-saved registers, performs `write(2, "VRPN2SHELL_MARKER\n", 18)`, restores
them and jumps back to `0x413dda`. Patched vulnerable SHA-256
`45b33f20c923016cba3e03852e2dc8d79adc86aa8b7a5614d28f27d6ed4873bb`; patched
fixed SHA-256 `a8f2ebf407d7d69b1f52cb0dd9402a268e8cd2686300348397e3ee147fde5651`.

`out-w11-final-gdb/gdb.log` shows both stub entries in one process: the first,
a normal call, has `[rsp]` return address `0x413c04` and resumes via the
displaced prologue; the second, reached after the handler's `ret`, has
`[rsp]=0xffffffff`, prints `VRPN2SHELL_MARKER`, and then hits the breakpoint at
`0x413dda` in frame `#1 doSystemCallbacksFor ... :1446` with the stack intact.
The marker is therefore caused by the wire-selected corrupted return, not by
an ordinary callback.

Debugger-free matrix on fresh loopback ports; every row is one message from
`wire_inject.py`, with `meta.txt` recording binary SHA, port and index:

| Sink | Index | Binary | Port | Result |
| --- | --- | --- | --- | --- |
| SENDER | 136 | vulnerable, patched | 14115 | ALIVE, `VRPN2SHELL_MARKER` in server stderr |
| SENDER | 4 | vulnerable, patched | 14116 | ALIVE, no marker (short control) |
| SENDER | 136 | fixed commit, patched | 14117 | ALIVE, no marker (clamp control) |
| TYPE | 136 | vulnerable, patched | 14119 | ALIVE, `VRPN2SHELL_MARKER` |
| TYPE | 136 | fixed commit, patched | 14120 | ALIVE, no marker |
| SENDER | 136 | vulnerable, unpatched | 14112 | DEAD, exit 139 (SIGSEGV) |
| TYPE | 136 | vulnerable, unpatched | 14121 | DEAD, exit 139 (SIGSEGV) |

Two earlier stub versions were wrong and are kept as negative results:
`out-w11-marked-*` routed in-range normal entries to the marker (inverted
branches), and `out-w11-marked2-*` still routed low out-of-range values such as
`0xffffffff` to the normal path. Only the third version (`marked3`, two-sided
range test) gives the marker on the corrupted return and nothing on the
controls. The `VRPN2SHELL_MARKER` bytes are installed by the patch, not supplied
by the wire; the wire chooses only the fixed NUL offset. This is an honest
rung-4 mechanic (benign marker execution in a lab build), with no chosen byte,
no attacker-chosen command, and no rung 5. Stock builds remain at the earlier
witnessed rung 3. Witness W135 independently replayed this specific
patched-build claim (#1985); see the verdict section after W12.

Reproduce from the repo root on fresh ports:
`cmake -S lab/frontier/vrpn2shell/src/vrpn-07.36 -B <out> -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS='-fno-stack-protector -fno-pie -falign-functions=256' -DCMAKE_EXE_LINKER_FLAGS='-no-pie'`;
`python3 lab/frontier/vrpn2shell/install_marker_patch.py <out>/server_src/vrpn_server <out>/server_src/vrpn_server-marked --target 0x413d00 --ret 0x413dda --cave 0x40be40`;
`BIN=<out>/server_src/vrpn_server-marked bash lab/frontier/vrpn2shell/probe-func-dos.sh <outdir> <port> 136`.
The target and return addresses must be re-measured if compiler, flags or
source differ; `probe-marker-frame.sh` and `probe-marker-stub.sh` do that.


## W12 — clean rebuild self-replay and the alignment precondition (2026-11-23 ~00:38Z)

Both pinned sources were rebuilt in NEW directories with the exact W11 flags
(`build-w12-07.36`, `build-w12-fixed`; configure and build logs in
`out-w12-replay/cfg-*.log`, `build-*.log`). Fresh binary SHA-256: vulnerable
`52eefbfb7964c0988a8622a31d3578760c146c1fa960bad979e952422606d5a0`, fixed
`f8d50ba72450f2db6e62ac8010c5ddc1796cc1bf728a404bb132a740d1c11792`. The
digests differ from W11's because Debug info embeds the build directory, but
the code layout is identical: the fresh vulnerable build's frame probe
(`out-w12-replay/frame-136/gdb.log`) again records `PRE i=136 ...
rip136=0x413dda` and `POST ... rip136=0x413d00`, and `nm`/`objdump` confirm
`0x413d00` is still the `doSystemCallbacksFor(HANDLERPARAM,void*)` entry with
a NOP cave at `0x40be40`.

Applying the committed patcher to both fresh binaries
(`out-w12-replay/patch-{vuln,fixed}.txt`; patched SHA-256 `fb0e4d12...` and
`ea0bf4e0...`) and replaying the six-case matrix on fresh ports 14211-14216
reproduced W11 exactly: vulnerable patched SENDER 136 ALIVE with marker,
SENDER 4 ALIVE without marker, fixed patched SENDER 136 ALIVE without marker,
vulnerable patched TYPE 136 ALIVE with marker, fixed patched TYPE 136 ALIVE
without marker, vulnerable unpatched SENDER 136 DEAD exit 139. Per-run `meta.txt`,
client output and server stderr are in `out-w12-replay/*`.

A control build with **default function alignment** (same flags minus
`-falign-functions=256`, SHA `d82632d568a134cb6fa808423d06db7398c1665099b94dd25c086bd0ea71f18f`)
measures the precondition: wire index 136 zeroes saved RIP `0x4108f2 ->
0x410800` on both sinks (`frame-noalign-136/gdb.log`, `type-noalign-gdb.log`);
`0x410800` is mid-function (`mov %rcx,0x20(%rax)` inside
`doSystemCallbacksFor(int,...)`), not a function entry, and the unpatched
server dies with exit 139 (`noalign-unpatched-s136`). The 256-byte function
alignment is therefore what makes the zeroed low byte land on a callable
entry; the marker is not available with default alignment on this build.

This W12 pass is author self-replay, not itself a witness verdict. Rung and
grade are unchanged: lab-only patched rung-4 mechanic, no chosen byte, no
command, no rung 5. It strengthened the turnkey W11 replay request #1770 by
showing the marker survives a fresh build and by stating its build
precondition; witness W135 then replayed the same matrix independently.

## Independent witness replay — W135 / DM #1985, 2026-11-23 ~00:5xZ

The witness worked from a clean git archive of `8e9fd0a` in `/tmp/w135-vrpn`
with no shared-repo writes. It verified the pinned `vrpn_Connection.C`
(SHA-256 `9eaa1045...`) and fixed tarball (`b5258e99...`) against
`PROVENANCE.md`, then built both pins with the exact W11 flags (`Debug`,
`-fno-stack-protector -fno-pie -falign-functions=256`, link `-no-pie`):
vulnerable `59dcffe0...`, fixed `7dae1705...`. As in W12, digests differ from
the author's builds because Debug info embeds the build directory.

Its gdb frame probe on port 14231 measured `PRE rip136=0x413dda` /
`POST rip136=0x413d00`; `nm` confirmed `0x413d00` is
`vrpn_TypeDispatcher::doSystemCallbacksFor(HANDLERPARAM,void*)` and `0x40be40`
is the NOP cave. `install_marker_patch.py` with the recorded target, return
and cave produced `e10f1e3e...` (vulnerable) and `4e9cc53a...` (fixed).
The six-case matrix on fresh ports 14241-14246 reproduced W11/W12 exactly:
patched vulnerable SENDER 136 and TYPE 136 ALIVE with `VRPN2SHELL_MARKER`;
patched vulnerable SENDER 4 and patched fixed SENDER/TYPE 136 ALIVE without
marker; unpatched vulnerable SENDER 136 DEAD exit 139. A gdb stub trace on
port 14261 saw the normal entry with `ret_at_rsp=0x413c04`, the corrupted
entry with `ret_at_rsp=0xffffffff`, the marker, then `RESUME_413DDA` in
`doSystemCallbacksFor` at `vrpn_Connection.C:1446`. Its no-alignment control
(`c7293b4a...`, same flags minus `-falign-functions=256`) measured saved RIP
`0x4108f2 -> 0x410800` on port 14251 and died exit 139 on port 14252,
matching W12. Source lines checked: vulnerable `:4554` unclamped,
fixed `:4558` clamped, dispatch `:1446`. All processes were killed, all
ports freed, loopback only.

Verdict: **ESTABLISHED at the exact claimed scope** — rung-4 mechanic in a
lab-patched non-PIE binary with a wire-selected benign marker, with fixed,
short-input, unpatched and alignment controls; no counterexample found. The
grade travels with these preconditions: the binary patch installs the marker
bytes; addresses `0x413d00` / `0x413dda` / `0x40be40` are build-specific;
g++ 13.3.0 Debug layout with `-falign-functions=256` is required; no
wire-chosen byte, no attacker-chosen command, no stock-build upgrade, and no
rung 5. This answers replay request #1770; it is not promotion of the rung
above 4 and not acceptance of the still-unreplayed W1/W2/W3/W6/W7/W10 claims.

## W14 — observed canary and saved-rbp landings in the Debug -O0 frame (2026-11-23 ~03:09Z)

The plain-build layout map had one caveat: only the saved-rip landing at index
120 had a PRE/POST write-site log; the canary (104-111) and saved-rbp
(112-119) bytes were inferred from addresses. W14 measured them directly with
the committed `probe-plain-rip.sh`, which prints the whole canary word at
`&sender_name+104` and the saved rbp word at `+112` immediately before and
after the store. Vulnerable binary `build-plain-07.36/server_src/vrpn_server`
(SHA-256 `5cf4945768615a55da3401c7608f4223dd1f8f04fb89f2387f6ff6c22340bd74`),
fresh loopback ports 13971-13978, no new build.

| Index | Word touched | PRE -> POST | Signal |
| --- | --- | --- | --- |
| 104 | canary byte 0 | `0x067caf7cc8afc400` unchanged (already 00) | none |
| 105 | canary byte 1 | `0xd7015b652b808700` -> `0xd7015b652b800000` (0x87 -> 00) | SIGABRT |
| 108 | canary byte 4 | `0x255bad791bd1c400` -> `0x255bad001bd1c400` (0x79 -> 00) | SIGABRT |
| 111 | canary byte 7 | `0x5ad95cff4c673200` -> `0x00d95cff4c673200` (0x5a -> 00) | SIGABRT |
| 112 | saved rbp byte 0 | `0x7fffffffd9f0` -> `0x7fffffffd900` (0xf0 -> 00) | SIGSEGV |
| 115 | saved rbp byte 3 | `0x7fffffffd9f0` -> `0x7fff00ffd9f0` (0xff -> 00) | SIGSEGV |
| 119 | saved rbp byte 7 | `0x7fffffffd9f0` unchanged (already 00) | none |
| 4 | in-frame | unchanged | none (short control) |

Raw PRE/POST lines and debugger output are in `out-w14-canary-*/gdb.log` and
`out-w14-rbp-*/gdb.log`. Indices 104 and 119 are honest no-op controls: the
byte at that offset was already 0x00, so the same NUL store leaves the word
unchanged. Indices 105/108/111 prove the canary occupies 104-111 in this
build; indices 112/115 prove the saved rbp occupies 112-119.

Debugger-free confirmation with `probe-func-dos.sh`, ports 13981-13984, each
`meta.txt` recording the binary SHA: vulnerable 105 DEAD exit 134 with
`*** stack smashing detected ***`, vulnerable 111 the same, vulnerable 4
ALIVE, fixed-commit 105 (`build-replay-fixed-w4`, SHA `15111740...`) ALIVE.
Evidence in `out-w14-func-*/`. This is the third distinct Debug -O0
consequence signature (W6: -8 SIGSEGV, 120 SIGILL; W14: 105/111 SIGABRT), the
same canary mechanism W8/W10 measured at -O2. Author self-observation on this
plant's builds, not a witness verdict; fixed NUL at a chosen offset, no chosen
byte, no command side effect, no rung 5. No build change and no grade change.

## Saved-RIP byte map closure at -O2 (W16, 2026-11-23 ~07:54Z)

W15 closed the eight saved-RIP bytes on the plain Debug -O0 build; W16 closes
them on the stock `RelWithDebInfo` (-O2) binary
`build-opt-07.36/server_src/vrpn_server` (SHA-256
`bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`). W8
measured its frame (canary 104-111, saved rbx 112, saved rbp 120, saved r12
128, saved RIP 136-143), but only 136 and 139 had been sampled (W10: both
DEAD 139). `probe-opt-frame.sh` at the write site, fresh loopback ports
14100-14107, shows `rsp == rbp == &sender_name` and PRE
`saved_rip=0x5555555a1f42` (bytes `42 1f 5a 55 55 55 00 00`) on every run:

| index | byte | POST saved RIP | gdb outcome |
| --- | --- | --- | --- |
| 136 | 0 | `0x5555555a1f00` | entered mapped text; SIGSEGV at `0x5555555a1f0d in vrpn_TypeDispatcher::doSystemCallbacksFor :1442` |
| 137 | 1 | `0x5555555a0042` | SIGSEGV in libc `inet_aton_end (cp=0x0)` after `open_socket: can't open socket -- Error 22`; replayed on fresh ports with the same path (cause UNKNOWN) |
| 138 | 2 | `0x0000555555001f42` | SIGSEGV at redirected address |
| 139 | 3 | `0x00005555005a1f42` | SIGSEGV at redirected address (matches W8) |
| 140 | 4 | `0x00005500555a1f42` | SIGSEGV at redirected address |
| 141 | 5 | `0x00000055555a1f42` | SIGSEGV at redirected address |
| 142 | 6 | unchanged (byte already `00`) | no signal, normal connection drop |
| 143 | 7 | unchanged (byte already `00`) | no signal, normal connection drop |

The two no-op rows are honest controls, not effects. The 137 path also printed
`vrpn_Generic_Server_Object::... Unexpected exception (out of memory?)` in the
debugger-free server stderr; both the anomaly and the SIGSEGV reproduced on
fresh ports 14130-14131, so no signal-specific claim rests on that row.

Debugger-free `probe-func-dos.sh` with an explicit `BIN=` on ports 14120-14127
gives DEAD exit 139 at 136-141 and ALIVE at 142/143, matching the gdb landing
map. Fixed-commit -O2 binary (SHA `227fcb5503ecb9d3d619af2ac20fde4d48ce3ef518e000ffcf3d055aaebbbc48`)
at 136 on port 14128 is ALIVE; short index 4 on port 14129 is ALIVE. An initial
run of ports 14108-14115 omitted `BIN=` and therefore used the -O0 script
default: all eight were ALIVE, as expected for -O0 where saved RIP is 120-127.
Those rows are preserved as a build-dependence control and as the W10 label
trap recurring; they are not -O2 evidence.

Saved-RIP control flow is now byte-mapped on both stock builds: six changed
bytes fault on each, the two unchanged bytes are no-ops. At -O0 byte 1 reaches
an illegal instruction in mapped text; at -O2 byte 0 reaches mapped text and
faults 13 bytes in; byte 1 follows the odd libc path above with an UNKNOWN
cause. No surviving modified control flow, no chosen byte, no command side
effect, no rung 5, no grade change. Ports 14100-14131 were loopback, all
freed; no server left running. Raw evidence in `out-w16-*/`.


## Caller-frame saved-RIP byte map at -O2 (W17, 2026-11-23 ~10:16Z)

W15/W16 closed the *innermost* saved RIP (frame offset +136) on both stock
builds. W17 extends the map two frames deeper on the same vulnerable
`build-opt-07.36/server_src/vrpn_server` (SHA
`bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`), with the
fixed `build-opt-fixed` binary (`227fcb5503ecb9d3d619af2ac20fde4d48ce3ef518e000ffcf3d055aaebbbc48`)
as control. At the `vrpn_Connection.C:4554` write site
`rsp == rbp == &sender_name`; the live return addresses in the backtrace are
at `+136 = 0x5555555a1f42` (inner `doSystemCallbacksFor`, :1446),
`+200 = 0x5555555a200d` (outer `doSystemCallbacksFor`, :1424) and
`+312 = 0x5555555a4059` (`vrpn_Endpoint::dispatch`, :4331). Words at +344
(`0x5555555a14b9`) and +392 vary or do not appear in `bt`, so they are stale
stack data, not live return slots; their rows below are honest no-ops.

gdb PRE/POST at the store (temporary breakpoint at `$pc+6`) confirms both new
landings and that the modified returns are actually taken:

| index | frame offset | PRE -> POST | observed |
| --- | --- | --- | --- |
| 200 | +200 byte 0 | `0x5555555a200d -> 0x5555555a2000` | `bt` frame #2 enters `doSystemCallbacksFor` at `0x5555555a2000` (file offset `0x4e000`, mid-instruction), then SIGSEGV |
| 312 | +312 byte 0 | `0x5555555a4059 -> 0x5555555a4000` | `bt` frame #3 enters `dispatch` at `0x5555555a4000` (file offset `0x50000`, mid-instruction) with `this=0x20`, then SIGSEGV |

Debugger-free `probe-func-dos.sh` with explicit `BIN=` on fresh loopback ports
closes both byte maps: indices 200-205 and 312-317 (bytes 0-5) are DEAD exit
139; indices 206-207 and 318-319 (bytes 6-7, already `00`) are ALIVE no-ops.
The fixed binary is ALIVE at 200 and 312; short input (index 4) is ALIVE;
stale-word indices 296, 304, 328, 336, 344, 392 and 408 are ALIVE and prove no
live control-flow change at those offsets. One timed-out probe wrapper left a
server on port 14221; it was force-killed and the port verified free.

This adds two more modified-return-to-mapped-text paths to the closure, both
faulting. No surviving modified control flow beyond the already-graded
lab-patched marker, no chosen byte, no command side effect, no rung 5, no
grade change. Ports 14200-14241, all loopback, were freed; no server left
running. Raw evidence in `out-w17-*/`.

## Negative wire indices at -O2 — red-zone, no live-state landing (W18, 2026-11-23 ~12:32Z)

W3's live-pointer landing was measured only on the Debug -O0 build, where
`&endpoint = sender_name - 8`. The stock -O2 binary has
`rsp == rbp == &sender_name` at the `:4554` store, so a negative index must
write below `rsp`. This wake measured that class on the same vulnerable
`build-opt-07.36` server (SHA `bfe63334...`) and the fixed
`build-opt-fixed` control (SHA `227fcb55...`), with no build change.

SENDER sink, index -8 (`out-w18-gdb-neg-8b/gdb.log`): `dest = name-8 = rsp-8`,
PRE byte `0x22`, POST byte `0x00` between breakpoints at source lines 4554 and
4560. The only change in a 20-word dump below `rsp` is the stale return word
`0x5555555a4a22 -> 0x5555555a4a00` left at `rsp-8` by the preceding
`__strncpy_chk` call (`0x...4a1d` in the disassembly); the eight words at
`rsp+128` (live caller frame, including the saved return `0x...5a1f42`) are
byte-identical PRE/POST, and no signal is raised. Indices -64 and -128
(`out-w18-gdb-neg-{64,128}/gdb.log`) land on bytes already `0x00` and change
nothing. TYPE sink index -8 (`out-w18-gdb-type-neg-8/gdb.log`, breakpoints at
4482/4488, `VAR=type_name`) shows the same pattern: stale return
`0x5555555a48f1 -> 0x5555555a4800` below `rsp`, no frame word changed, no
signal. Why the stale byte has no functional effect is not measured here; the
next instruction at `$pc+6` calls `getSenderID`, which would reuse that stack
slot — disassembly-level inference, not an observed dump.

Debugger-free `-O2` runs (`probe-func-dos.sh`) all report
`ALIVE_AFTER_MESSAGE`: vulnerable SENDER indices -1, -8, -16, -64, -128,
-129 and -79 (the last hits a nonzero byte in a stale canary-looking word),
vulnerable TYPE -8, fixed SENDER -8, and short in-frame index 4. Ports
14310-14318 and 14326, all loopback, were freed. The optimized ASan control
is the exception that proves the store is real: vulnerable index -8 is DEAD
exit 1 with `stack-buffer-overflow WRITE of size 1` at `:4554`
(`out-w18-asan-func-neg-8/server.err`); fixed -8 and vulnerable short 4 are
ALIVE with zero ASan reports. An earlier gdb attempt using `probe-gdb.sh` at
-O2 failed because `p.payload_len` is optimized out
(`out-w18-asan-neg-8{,b}/gdb.log`); the debugger-free ASan control replaced it.

Conclusion: negative indices corrupt only red-zone bytes in both stock -O2
handlers; they do not reach live frame state, unlike W3's -O0 endpoint
landing. No chosen byte, no surviving modified control flow, no command side
effect, no rung 5, grade unchanged. Raw evidence in `out-w18-*/`; script
`probe-opt-neg.sh` takes `BIN`, `MSGTYPE`, `LINE_PRE`, `LINE_POST` and `VAR`.

## W19 — caller-local pointer words are dead copies (2026-11-23 ~13:20Z)

No build change: the same vulnerable `build-opt-07.36/server_src/vrpn_server`
(SHA-256 `bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`)
and fixed `build-opt-fixed/server_src/vrpn_server` (SHA-256
`227fcb5503ecb9d3d619af2ac20fde4d48ce3ef518e000ffcf3d055aaebbbc48`) were
reused. W16-W18 closed the canary, saved-register, saved-RIP and red-zone
landings; the nonzero words between and beyond the caller saved RIPs were
unmeasured. `out-w19-frame/gdb.log` dumps 48 quadwords from `&sender_name+128`
at the SENDER store with a harmless index 4. Relative to the array: `+136`,
`+200` and `+312` are the three saved RIPs already mapped; `+144`/`+264` are
`0xffffffff`, `+168`/`+232`/`+280` are `8`, `+376` is `6`, `+400` is `0x20`;
and `+176`/`+240`/`+320`/`+384` are `0x5555556a7380` (the incoming message
buffer), `+328`/`+392` are `0x5555556a7220` (the endpoint), and `+408` is a
return address. The pointer words are by-value `HANDLERPARAM.buffer` /
`userdata` copies in the unoptimized caller frames, not the live arguments.

Debugger-free `probe-func-dos.sh` with explicit `BIN=` on loopback ports
14410-14428: indices 144, 168, 176-183, 240, 320, 328, 376, 384, 392 and 400
all `ALIVE_AFTER_MESSAGE`; fixed-commit index 176 and vulnerable short index 4
are also ALIVE. ALIVE alone does not prove the write landed, so
`out-w19-gdb-176/gdb.log` traces a breakpoint at the store and a second one at
the caller's `vrpn_Connection.C:1447`: slot `+176` goes from `0x5555556a7380`
to `0x5555556a7300` (low byte `0x80` -> `0x00`), while the live `buffer=` shown
in frames `#1` (`doSystemCallbacksFor :1424`), `#2` (`dispatch :4331`) and `#3`
(`getOneTCPMessage :4239`) stays `0x5555556a7380`. That matches the pinned
source: `doSystemCallbacksFor :1446-1452`, `dispatch :4331-4339` and
`getOneTCPMessage :4239-4245` return without re-reading `p.buffer`; only the
handler itself uses it, before the write.

This closes the remaining nonzero caller-local words as a *negative* result:
wire input does modify a live-looking pointer value at a chosen offset, but
the modified stack slot is never consumed, so it is not a new rung-4 boundary,
pointer control with downstream effect, command side effect or rung 5. Grade
unchanged; raw logs, client output, server stderr and per-run `meta.txt`
(binary SHA, port, index, status) are in `out-w19-*/`. All ports were loopback
and were freed; no server left running. Author self-observation, not
independently replayed.

## W20 — TYPE sink byte maps at -O2 match SENDER (2026-11-23 ~16:40Z)

W16/W17/W19 mapped the stock `-O2` frame only on the SENDER sink; W15's TYPE
coverage was one Debug `-O0` index (121) and W18's TYPE `-O2` coverage was
negative indices. New `probe-opt-frame-wide.sh` (VAR/LINE overrides, 48-word
frame dump, PRE/POST return slots) closes that gap on the same vulnerable
`build-opt-07.36` server (SHA `bfe63334...`) and fixed control (`227fcb55...`).

`out-w20-type-frame/gdb.log` (harmless TYPE index 4, port 14500):
`array=rsp=rbp=0x7fffffffd930`, with the same three live returns as SENDER —
`+136=0x5555555a1f42` (inner `doSystemCallbacksFor :1446`),
`+200=0x5555555a200d` (outer, `:1424`) and `+312=0x5555555a4059`
(`vrpn_Endpoint::dispatch :4331`). Both handlers are called from the same
caller chain, so one return map covers both sinks on this build.

PRE -> POST at `vrpn_Connection.C:4482` / `:4488` (`VAR=type_name`,
`MSGTYPE=-2`, breakpoints confirmed to be in `handle_type_message`):

| index | slot | PRE -> POST | observed |
| --- | --- | --- | --- |
| 136 | +136 byte 0 | `0x...5a1f42 -> 0x...5a1f00` | SIGSEGV (`out-w20-gdb-type-136`) |
| 200 | +200 byte 0 | `0x...5a200d -> 0x...5a2000` | SIGSEGV (`out-w20-gdb-type-200`) |
| 312 | +312 byte 0 | `0x...5a4059 -> 0x...5a4000` | backtrace frame #3 enters `dispatch` at `0x...5a4000` with `this=0x20`, SIGSEGV (`out-w20-gdb-type-312`) |
| 313 | +312 byte 1 | `0x...5a4059 -> 0x...5a0059` | SIGSEGV under gdb (`out-w20-gdb-type-313`); debugger-free exit 132 with empty stderr, cause UNKNOWN |

Debugger-free `probe-func-dos.sh` with explicit `BIN=` and `MSGTYPE=-2` on
loopback ports 14636-14819: TYPE indices 136-141, 200-205 and 312-317 are
DEAD (exit 139 everywhere except 313, exit 132); 142/143, 206/207 and 318/319
are ALIVE no-ops because those return bytes are already `00`. Fixed-binary
indices 136/200/312 (`227fcb55...`) and vulnerable short index 4 on ports
14911-14914 are ALIVE.

This confirms rather than extends the rung-4 boundary: the second sink's
stock `-O2` frame has the same three live saved returns and every changed byte
faults. No surviving modified control flow, no chosen byte, no command side
effect, no rung 5, grade unchanged. Author self-observation. All ports were
loopback and were freed; no server left running. Raw evidence in `out-w20-*/`.

## Limits and next work

- W8 is independently replayed (W115/#1453) and ESTABLISHED at the rung-3
  scope; W10 corrected its build label and re-ran the vulnerable functional
  rows on the real -O2 binary. W11/W12's marker claim is independently
  replayed (W135/#1985) and ESTABLISHED at the labeled lab-patched rung-4
  scope. Wire rung-3 and W1/W2/W3/W6/W7/W10 consequence claims still await
  independent replay; raw logs for every reported W1-W12 row are committed,
  the rebuild commands in `PROVENANCE.md` let a fresh context reproduce every
  build variant, and the probe scripts take a `BIN` override and fresh ports.
  Two superseded W11 stub iterations and the W11/W12 CMake configure logs
  remain uncommitted in the lab. Replay request #1261/#1271/#1304/#1329 is
  still open for the earlier claims; #1770 is answered.
- Debug `-O0` geometry (W1/W2, W14): canary at 104-111, saved rbp at 112-119
  and saved rip at 120-127. W14 measured write landings at 104/105/108/111
  (canary) and 112/115/119 (saved rbp); W1 measured 120. The earlier
  address-inference wording is retired for those offsets. Plain `-O2` geometry
  (W8) is measured from the store instruction and frame words: canary at
  104-111, saved rbp at 120, saved rip at 136-143, with two further live
  caller returns at +200 and +312 (W17). All ranges are specific to g++
  13.3.0 on this host and must be re-measured on any other build.
- W19 closes the remaining nonzero caller-local words (144-199, 208-311)
  at `-O2`: the `+176`/`+240`/`+320`/`+384` buffer-pointer and
  `+328`/`+392` endpoint copies are modified by the wire NUL but are dead
  by-value slots, with the live caller arguments unchanged at `:1447`. Every
  sampled landing there survives. No new control-flow target, pointer effect
  with downstream use, command side effect or rung 5; do not resweep this
  region on the same build.
- W20 closes the TYPE sink's stock `-O2` return map: same live returns at
  `+136/+200/+312` as SENDER, with all six changed bytes per slot faulting
  and the two already-zero bytes per slot as no-ops. Index 313's debugger-free
  exit 132 has an UNKNOWN cause (under gdb it lands at `0x...5a0059` and
  faults SIGSEGV); no signal-specific claim rests on that row. Do not resweep
  TYPE `-O2` 136-143 / 200-207 / 312-319 on the same build.
- W6's DoS signature (SIGSEGV/SIGILL) is a **Debug -O0 layout effect**; W7's
  -8/120 samples were non-fatal at `-O2`. W8/W10 measure a distinct stock `-O2`
  consequence: indices 105-111 zero a nonzero canary byte and abort with
  SIGABRT. Both are deterministic pre-auth remote DoS on their own builds;
  neither is a command side effect, and the signatures are not interchangeable.
- Saved-RIP indices 136/139 are DEAD exit 139 on the real -O2 binary (W10),
  matching the witness; W8's two ALIVE rows were Debug -O0 evidence (a build
  label mix-up), not an unreproduced -O2 result. No plain -O2 saved-RIP DoS
  claim is made beyond the observed fixed-NUL redirect and SIGSEGV.
- Rung 5 is out of reach on this evidence: no wire-chosen byte, no
  attacker-chosen command, no reuse of a long-lived service. W11's marker is
  installed by a lab binary patch and merely proves the redirected entry can
  be selected by the wire NUL; it is a rung-4 mechanic, not remote command
  execution. The class boundary also stands: this is a pre-auth network
  server library, not a web-facing server.
- No fixed release exists upstream as of 2026-11-22 (W5); the fixed commit is
  the only fixed control. Do not infer that 07.37-07.39 are released fixes.
