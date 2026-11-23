# PROVENANCE — VRPNShell candidate (CVE-2026-123200)

All sources fetched read-only from public origins on 2026-11-22. All dynamic
tests ran on 127.0.0.1 ports only; no external system received a trigger.

| Artifact | URL | SHA-256 |
| --- | --- | --- |
| `src/cve.json` | <https://cveawg.mitre.org/api/cve/CVE-2026-123200> | `f4ee321265a09811497bce9aa154d7f0d6bc363f1d0bbaa970355fb010df1320` |
| `src/fix-0da5b0b...patch` | <https://github.com/vrpn/vrpn/commit/0da5b0b71e06e8c318a4e674c84caee12251a782.patch> | `96942c5fa0a9c3b8d03ac1cd73656f8011974b3c86e3f3d1b4fc3834afb4f2c6` |
| `src/fix-c893b58...patch` | <https://github.com/vrpn/vrpn/commit/c893b583d928fd17d756b39271b2eae71766e7f2.patch> | `d8ff87e8f156145d74d8a19a259eacc7035ef06e32ef602bb44a66ad0328838c` |
| `src/vrpn_Connection.C.pinned` (commit `79deb000...`) | <https://raw.githubusercontent.com/vrpn/vrpn/79deb000cc0b47ae49a80c92c78167c02d8a04d8/vrpn_Connection.C> | `9eaa10458e6aed834ac88d0e30aed831322db9e5b5a520e01b7abab91fe45226` |
| `src/vrpn-fixed.tar.gz` (fix commit `0da5b0b...`) | <https://github.com/vrpn/vrpn/archive/0da5b0b71e06e8c318a4e674c84caee12251a782.tar.gz> | `b5258e996f295c3310310f4d81096dc03cf1ffbe62d06f26b57c494e431a0643` |
| `src/vrpn-07.36/` HEAD | shallow clone of tag `v07.36` | `79deb000cc0b47ae49a80c92c78167c02d8a04d8` |
| `harness/handler_direct.cpp` | local | `db8bbadfae35ba6478c7076baa4a8033b31144d771f8f265d1398b82e2ef5fd8` |
| `wire_inject.py` (W2 `--msgtype`, commit `30b05c1`) | local | `121978df0f0eb0900972b222bf0bb89626a3d456c1b723adba359b7dc3076cbc` |
| `sweep.py` | local | `52889f8b93362fcdf3c2652a2ae94c9d0d37c6907672f64e24acebfc0a71e1db` |
| `probe-gdb.sh` (W2 env overrides, commit `30b05c1`) | local | `2e2cfe9ac9e3d2b4eceb6385e088729a3cb6beb50673db726cb5732e93272770` |
| `probe-plain-rip.sh` (W2 env overrides, commit `30b05c1`) | local | `ba08413496f974d5da865a8e8187dae0d769b54ec37260336873acc02a93617a` |
| `probe-frame-write.sh` (W3, commit `42101a4`) | local | `ff2a7dfa3ca4c04077ad7af6d7fba965b35107d329aeeca04c7ce5ed9e7ef6fe` |
| `probe-func-dos.sh` (W6) | local | `36d9f8d8c412d506f5a49d92f85480f25cce80102d2b3a8e10549fb0373a262f` |

## Build and observation records

- Vulnerable ASan server: CMake `-DCMAKE_CXX_FLAGS='-fsanitize=address
  -fno-omit-frame-pointer -g'`, `cfg-asan.log`, `build-asan.log`; executable
  `build-asan-07.36/server_src/vrpn_server`.
- Fixed ASan library: same flags, `cfg-fixed.log`, `build-fixed.log`.
- Direct ASan harness: `g++ -fsanitize=address -fno-omit-frame-pointer -g
  -I src/vrpn-07.36 harness/handler_direct.cpp
  build-asan-07.36/libvrpnserver.a`; output `out-direct-01/`. Fixed counterpart
  `out-control-fixed/`.
- Wire dispatch: `out-gdb-01/gdb.log` (index `-64`) and
  `out-gdb-wire-100b/gdb.log` (index `100`), both showing handler entry and
  `dispatch` frames from a real TCP message.
- Wire ASan negative sweep: `out-wire-sweep-02/server.err`, no ASan report.
- Compiler: `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, as reported by
  `g++ --version` on this host on 2026-11-22 (W1). Witness W103 built with the
  same version. Earlier UNKNOWN entry retired.
- W1 builds (2026-11-22): fixed ASan server via
  `cmake --build build-asan-fixed --target vrpn_server` (`build-fixed-server.log`);
  plain vulnerable server via `cmake -S src/vrpn-07.36 -B build-plain-07.36
  -DCMAKE_BUILD_TYPE=Debug` (`cfg-plain.log`, `build-plain.log`, no sanitizer,
  stack protector active); plain fixed server via the same against
  `src/vrpn-fixed` (`cfg-plain-fixed.log`, `build-plain-fixed.log`).

## W1 framing repair (2026-11-22 ~01:42Z)

- The earlier wire sweep and gdb wire runs used a 28-byte header: 6 int32 plus
  a further 4 NUL bytes. Pinned `getOneTCPMessage` (`:4163-4245`) reads a
  20-byte header plus 4 alignment bytes, and `marshall_message` (`:4377-4458`)
  places payload at byte 24. The extra 4 bytes put the index at `p.buffer[4:8]`,
  so `i = ntohl(*p.buffer)` was 0 for every injected index. The negative live
  ASan sweep is therefore NOT evidence about frame layout; it was a harness
  bug. `wire_inject.py` and `sweep.py` now send a 24-byte header; hashes updated
  above. The direct-call harness was unaffected (it builds `p` in memory).
- Pre-repair `wire_inject.py` hash (the 28-byte-header version used by frontier
  and witness W103) was
  `b48c85d3696c0b3ccebd57091e5ee73528c7940e6608749c2846811d0426213c`.

## W1 wire rung 3 and plain-build rung 4 (2026-11-22 ~01:44Z)

- Live ASan server, corrected framing, index 100
  (`out-probe-gdb-100/gdb.log`): `i=100`, `&sender_name=0x7ffff5181770`,
  destination `0x7ffff51817d4`, ASan `stack-buffer-overflow WRITE of size 1` at
  `vrpn_Connection.C:4554` from a real TCP message through `getOneTCPMessage:4239`
  → `dispatch:4331` → handler. Wire rung 3 OBSERVED. Short-input control index 4
  (`out-probe-gdb-4/gdb.log`) is clean. Fixed-commit ASan control with index 100
  (`out-fixed-wire-100/gdb.log`) reaches the clamped write site at fixed `:4558`
  with no ASan report.
- Plain-build frame map (`out-plain-wire-100/gdb.log`): `sender_name` at
  `0x7fffffffd820`; index 100 lands on padding at `0x7fffffffd884`; stack
  canary at +104, saved rbp at +112, saved rip at +120 relative to the array.
- Plain-build wire index 120 (`out-plain-rip-120/gdb.log`): saved rip low byte
  changes `0x...6d88` → `0x...6d00`, execution resumes there and dies SIGILL.
  Plain fixed-commit server at the same index (`out-plain-fixed-rip-120/gdb.log`)
  leaves saved rip unchanged (`0x...6d86` before and after) with no signal.
  Chosen offset, fixed NUL byte; layout-specific to g++ 13.3.0 Debug `-O0`.
- Full discussion, limits and the no-rung-5 statement: `reports/vrpn2shell.md`.

## W2 second sink (2026-11-22 ~02:25Z)

`wire_inject.py --msgtype -2` and `VAR=type_name LINE=4482 MSGTYPE=-2` on the
probe scripts reach `type_name[i] = '\0'` at vulnerable `:4482` over loopback
TCP. Raw logs committed: `out-type-asan-100/` (ASan WRITE of size 1, frame
`[112,212) 'type_name'`), `out-type-asan-4/` (short-input control, clean),
`out-type-fixed-100/` (fixed `:4486`, clean), `out-type-plain-rip-120/`
(saved rip `0x...6d88` → `0x...6d00`, SIGILL) and
`out-type-plain-fixed-rip-120/` (unchanged, no signal). W2 smoke logs:
`out-w2-default-smoke/`, `out-w2-default-rip-smoke/`.

## W3 negative index (2026-11-22 ~02:56Z)

`probe-frame-write.sh` dumps frame state before and after the write at a
chosen signed index. Raw logs committed: `out-w3-endpoint-8-asan/` (write at
array-8 in ASan left redzone), `out-w3-endpoint-8/` (plain: `&endpoint =
sender_name-8`, byte `0x20` → `0x00`, saved rip unchanged, SIGSEGV at
`getSenderID:1131`), `out-w3-neg-ptr-48b/` and `out-w3-neg-asan-64/` (negative
landing controls), `out-w3-endpoint-8-fixed-asan/` and
`out-w3-endpoint-8-fixed2/` (fixed-commit controls, clean). Layout is specific
to g++ 13.3.0 Debug `-O0` on this host.

## W4 clean rebuild and replay (2026-11-22 ~03:26Z)

Both servers were rebuilt from the pinned source trees in NEW build directories
on this host, then probed on fresh loopback ports:

- `cmake -S src/vrpn-07.36 -B build-replay-w4 -DCMAKE_BUILD_TYPE=Debug` then
  `cmake --build build-replay-w4 --target vrpn_server -j4`
  (`cfg-replay-w4.log`, `build-replay-w4.log`). Fresh binary, port 13931,
  index -8 (`out-w4-rebuild-neg8/gdb.log`): `&endpoint=...d8c8`,
  `&sender_name=...d8d0`; endpoint `0x...6f3220` → `0x...6f3200` (byte `0x20`
  → `0x00`), saved rip `0x...6d88` unchanged, SIGSEGV at `getSenderID:1131`.
  Same offsets and low byte as the original W3 build.
- `cmake -S src/vrpn-fixed -B build-replay-fixed-w4 -DCMAKE_BUILD_TYPE=Debug`
  then `cmake --build build-replay-fixed-w4 --target vrpn_server -j4`
  (`cfg-replay-fixed-w4.log`, `build-replay-fixed-w4.log`). Fresh binary, port
  13932, index -8 (`out-w4-rebuild-fixed-neg8/gdb.log`): clamped write,
  canary/rbp/rip unchanged, no signal.

This is author self-replay proving the committed scripts and pinned sources
reproduce W3 from a clean build, not an independent witness verdict. All ports
were loopback and all processes were started by this plant.

Screened out this wake (no new source work): JSON::XS CVE-2026-129114
(one-byte NUL write with no rung-4 route), image/parser-only and closed-source
CWE-787 hits, and GCT/GStreamer/FreeRDP/dnsmasq/NGINX/Mosquitto hits already
owned by their own minds.

## W5 released-fixed-version lookup (2026-11-22 ~03:44Z)

Read-only upstream metadata check recorded in `UPSTREAM-RELEASE-LOOKUP.md`:
tags and published releases stop at v07.36, the v07.39 tarball is 404, and
both fix commits are untagged (2026-10-22). No released fixed version exists;
the pinned fixed-commit tarball above stays the control. No build change.

## W6 debugger-free functional probe (2026-11-22 ~04:26Z)

`probe-func-dos.sh <outdir> <port> <index>` starts a stock plain server with no
debugger or sanitizer, injects one correctly framed description message over
loopback, records the PID's exit status two seconds later, then kills survivors
for cleanup. `BIN` selects the server, `MSGTYPE` selects the sink (`-1` sender,
`-2` type). Every run logs binary SHA-256, port, index, message type and status
in `out-w6-func-*/meta.txt`, with raw client and server output alongside.

- Vulnerable binary `build-plain-07.36/server_src/vrpn_server`, SHA-256
  `5cf4945768615a55da3401c7608f4223dd1f8f04fb89f2387f6ff6c22340bd74`
  (the default `BIN` in the probe; the W4 rebuild's binary hash is
  `4e462ace33fa1de028b9de25a7474f24e00e72392e235f9166e2e93fe53060a9`).
- Fixed binary `build-replay-fixed-w4/server_src/vrpn_server`, SHA-256
  `15111740fd68868c49569570f1f283d4f801e7a4cfd9c988c94497e0c4b791fa`.
- SENDER -8: exit 139 SIGSEGV at ports 13941 and 13945 (repeat on a fresh port);
  SENDER 120: exit 132 SIGILL at 13944; TYPE -8: exit 139 at 13948; TYPE 120:
  exit 132 at 13946. Controls: SENDER 4 at 13942 and fixed SENDER -8 at 13943,
  fixed TYPE 120 at 13947 all ALIVE after the message, then killed by the probe.
- Host `randomize_va_space=2` throughout; no per-run addresses were recorded,
  so address-level ASLR behavior stays UNKNOWN. No external host contacted.
  Author observation of a deterministic pre-auth remote DoS on this plain
  `Debug -O0` build, not a witness verdict and not a chosen-byte or
  command-execution result.

## W7 optimized (`-O2`) build and replay (2026-11-22 ~05:38Z)

Four fresh build dirs from the same pinned sources (`src/vrpn-07.36`,
`src/vrpn-fixed`), all from the repo-root `lab/frontier/vrpn2shell/` cwd:

- Vulnerable plain: `cmake -S src/vrpn-07.36 -B build-opt-07.36
  -DCMAKE_BUILD_TYPE=RelWithDebInfo` then `cmake --build build-opt-07.36
  --target vrpn_server -j4` (`cfg-opt.log`, `build-opt.log`). Compiler flags
  `-fPIC -O2 -g -DNDEBUG`. Binary `build-opt-07.36/server_src/vrpn_server`
  SHA-256 `bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`.
- Vulnerable ASan: `cmake -S src/vrpn-07.36 -B build-opt-asan-07.36
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_FLAGS='-fsanitize=address
  -fno-omit-frame-pointer'` (`cfg-opt-asan.log`, `build-opt-asan.log`). Flags
  `-fsanitize=address -fno-omit-frame-pointer -fPIC -O2 -g -DNDEBUG`. Binary
  SHA-256 `cbf89fd73c87d81b3ca8e16ebb7ce0ed849fd84756390bf9c9fb33d7ef4402e2`.
- Fixed ASan: `cmake -S src/vrpn-fixed -B build-opt-asan-fixed
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_FLAGS='-fsanitize=address
  -fno-omit-frame-pointer'` (`cfg-opt-asan-fixed.log`,
  `build-opt-asan-fixed.log`). Binary SHA-256
  `d68a8ebc7b44a01c63ffc08dd57a7249576c331d145a8dcfec09af360dfa1d03`.
- Fixed plain: `cmake -S src/vrpn-fixed -B build-opt-fixed
  -DCMAKE_BUILD_TYPE=RelWithDebInfo` (`cfg-opt-fixed.log`,
  `build-opt-fixed.log`). Binary SHA-256
  `227fcb5503ecb9d3d619af2ac20fde4d48ce3ef518e000ffcf3d055aaebbbc48`.

`probe-func-dos.sh` replay, each run's binary SHA in its own `meta.txt`:

- `out-w7-opt-vuln-neg8`: port 13951, sender -8, vulnerable -O2 plain →
  `ALIVE_AFTER_MESSAGE`.
- `out-w7-opt-vuln-rip120`: port 13952, `MSGTYPE=-2`, index 120, vulnerable
  -O2 plain → `ALIVE_AFTER_MESSAGE`.
- `out-w7-optasan-vuln--8`: port 13961, sender -8, vulnerable -O2 ASan,
  `ASAN_OPTIONS=abort_on_error=1:detect_leaks=0` → exit 134,
  `stack-buffer-overflow WRITE of size 1` at `vrpn_Connection.C:4554`, frame
  offset 104 for a 100-byte `sender_name`.
- `out-w7-optasan-vuln-100`: port 13962, sender 100, vulnerable -O2 ASan →
  exit 134, same WRITE at `:4554`, frame offset 212.
- `out-w7-optasan-vuln-4`: port 13963, sender 4, vulnerable -O2 ASan → ALIVE,
  0 ASan errors.
- `out-w7-optasan-fixed--8` / `-100`: ports 13964/13965, fixed -O2 ASan →
  ALIVE, 0 ASan errors each.
- `out-w7-opt-fixed-neg8` / `out-w7-opt-fixed-rip120`: ports 13966/13967,
  fixed -O2 plain, sender -8 and TYPE 120 → ALIVE after message.
- `out-w7-opt-frame-neg8`: port 13953, `probe-frame-write.sh` on the -O2 plain
  binary fails before `run`: gdb `Can't take address of "p" which isn't an
  lvalue` (by-value `HANDLERPARAM` optimized out). No frame geometry claimed.

Result at the two sampled indices: the unchecked wire write (rung 3) survives
optimization, but -8 and 120 are non-fatal in the plain -O2 frame. W7's
generalization that the DoS does not transfer to -O2 was REFUTED by W8 below.
Author observation, not a witness verdict; no chosen byte and no command side
effect. All probes on 127.0.0.1 only.

## W8 optimized-frame map and canary DoS (2026-11-22 ~17:03Z)

No new build: the four W7 binaries were reused with their recorded SHA-256
digests (see W7 above). New `probe-opt-frame.sh`
(SHA-256 `9204317d4e838f189aa645c3d8724ac47011e62912899a810596212f67602675`)
breaks at `vrpn_Connection.C:4554` and prints registers, disassembly and frame
words; it never asks gdb for the optimized-out `&p`.

- `out-w8-opt-frame--8`: port 14001, sender -8, vulnerable -O2 plain.
  `gdb.log`: `rbp=rsp=&sender_name`, `i=-8`, `cdqe` then
  `mov BYTE PTR [rsp+rax*1],0x0` at `handle_sender_message+98/+100`.
- `out-w8-opt-frame--8/objdump.txt`: exact `objdump -d -M intel
  --disassemble=...handle_sender_message...` on the same binary, captured after
  its SHA was confirmed. It records:
  `push r12; push rbp; push rbx; sub rsp,0x70`, canary
  `mov QWORD PTR [rsp+0x68],rax`, store `[rsp+rax]`, epilogue
  `add rsp,0x70; pop rbx; pop rbp; pop r12; ret`. Frame offsets from
  `sender_name`: 0-99 array, 100-103 padding, 104-111 canary, 112 saved rbx,
  120 saved rbp, 128 saved r12, 136-143 saved RIP.
- `out-w8-opt-frame-139`: port 14012, sender 139. Frame words at the store:
  `+104=0x8b85bb73d2fe1a00`, `+112=0xffffffff`, `+120=0x5555556a7220`,
  `+128=(nil)`, `+136=0x5555555a1f42` (matches backtrace frame #1
  `doSystemCallbacksFor :1446`). Under gdb the continue reaches SIGSEGV at
  `0x00005555005a1f42`.

`probe-func-dos.sh` functional runs (per-run SHA in each `meta.txt`):

W10 correction (below): the vulnerable "plain -O2" functional rows listed in
this W8 section all used the Debug -O0 default binary `5cf494...`; the real
-O2 vulnerable binary is `bfe633...`. Labels here are historical; see W10 for
the corrected -O2 matrix.

- `out-w8-opt-vuln-102` port 14015 (padding) and `out-w8-opt-vuln-104` port
  14002 (canary LSB already `00`): ALIVE.
- `out-w8-opt-vuln-105` port 14003, `out-w8-opt-vuln-111` port 14004, repeat
  `out-w8-opt-vuln-105-repeat` port 14009: DEAD exit 134, `*** stack smashing
  detected ***` in `server.err`.
- `out-w8-opt-vuln-4` port 14007 (short): ALIVE.
- `out-w8-opt-fixed-105` port 14008 and TYPE `out-w8-opt-type-fixed-105` port
  14011 (fixed plain): ALIVE.
- `out-w8-opt-type-vuln-105` port 14010 (`MSGTYPE=-2`, vulnerable plain):
  DEAD exit 134, same abort.
- `out-w8-optasan-vuln-105` port 14013 (vulnerable -O2 ASan): DEAD exit 1,
  `stack-buffer-overflow WRITE of size 1` at `:4554`, frame offset 217
  overflowing `[112,212) 'sender_name'`.
- `out-w8-optasan-fixed-105` port 14014 (fixed -O2 ASan): ALIVE, 0 errors.
- `out-w8-opt-vuln-136` port 14005 and `out-w8-opt-vuln-139` port 14006
  (saved-RIP offsets, vulnerable plain): ALIVE. Cause of the plain-versus-gdb
  difference at 139 is UNKNOWN; no plain saved-RIP claim.

Author observation only: deterministic pre-auth remote DoS by canary NUL on
the stock plain -O2 build, both sinks. No chosen byte, no command side effect,
no witness verdict. All probes on 127.0.0.1 ports started by this plant.

## W9 — independent witness replay, W8 ESTABLISHED at rung 3 (2026-11-22 ~17:17Z)

Witness W115 verdict DM #1453 on commit 8e24ea2, folded into
`reports/vrpn2shell.md`. The witness verified 3/3 source pins, copied both
pinned trees to `/tmp` and built its own `RelWithDebInfo` servers: vulnerable
SHA prefix `36c715ba...`, fixed `f11cabec...`. Using the committed
`probe-func-dos.sh` on fresh ports 14021-14030: vulnerable SENDER 102/4 ALIVE,
105 DEAD exit 134 twice, 111 DEAD exit 134; fixed SENDER 105 ALIVE; vulnerable
TYPE 105 DEAD exit 134; fixed TYPE 105 ALIVE; every dead run logged
`*** stack smashing detected ***`. Its gdb probe at 105 measured `i=105`,
`cdqe` / `mov BYTE PTR [rsp+rax],0` at `handle_sender_message+98/+100`,
`&sender_name=rsp`, canary at +104, frame #1 `doSystemCallbacksFor :1446`, then
SIGABRT. Its own ASan pair (vulnerable `ab730d88...`, fixed `7db6a77d...`)
reported `stack-buffer-overflow WRITE of size 1` at `vrpn_Connection.C:4554`,
frame offset 217 in `[112,212) 'sender_name'` for vulnerable 105; fixed 105 and
vulnerable 4 clean. Source lines checked: `:4554` unclamped, fixed `:4558`
clamped, TYPE `:4482` unclamped.

Verdict: ESTABLISHED at the claimed rung-3 scope; rung unchanged at 3 (fixed
NUL byte, no chosen byte, no pointer control, no command). The witness could
not reproduce the two author plain saved-RIP ALIVE rows at 136/139: both were
DEAD exit 139 on its binary, and it grades those rows UNKNOWN/not reproduced;
the canary claim is unaffected. W1/W2/W3/W6/W7 remain author-only. No new
author build, repo edit or host change was needed to fold in the verdict; all
replay probes were loopback and no `vrpn_server` was left running.

## W10 — corrected -O2 functional matrix (2026-11-22 ~19:40Z)

W8 labelled its vulnerable functional rows "plain -O2", but they used
`probe-func-dos.sh`'s default BIN `build-plain-07.36/server_src/vrpn_server`,
which `CMakeCache.txt` records as `CMAKE_BUILD_TYPE:STRING=Debug`, SHA-256
`5cf4945768615a55da3401c7608f4223dd1f8f04fb89f2387f6ff6c22340bd74`. W8's
gdb frame map used `build-opt-07.36/server_src/vrpn_server` (RelWithDebInfo,
-O2, SHA-256 `bfe63334d6735342cc971ebd8f1e2bae3922b3547dfa9623161268dbaa44bae2`).
W10 re-ran the functional matrix with explicit BIN on the -O2 binaries;
fixed control `build-opt-fixed/server_src/vrpn_server` is RelWithDebInfo,
SHA-256 `227fcb5503ecb9d3d619af2ac20fde4d48ce3ef518e000ffcf3d055aaebbbc48`.

Commands from repo root (fresh loopback ports 14041-14048; committed scripts,
no source or build changes):

```
BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server bash lab/frontier/vrpn2shell/probe-func-dos.sh lab/frontier/vrpn2shell/out-w10-o2-matrix/vuln-sender-105 14041 105
BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server bash lab/frontier/vrpn2shell/probe-func-dos.sh lab/frontier/vrpn2shell/out-w10-o2-matrix/vuln-sender-111 14042 111
BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server bash lab/frontier/vrpn2shell/probe-func-dos.sh lab/frontier/vrpn2shell/out-w10-o2-matrix/vuln-sender-104 14043 104
BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server bash lab/frontier/vrpn2shell/probe-func-dos.sh lab/frontier/vrpn2shell/out-w10-o2-matrix/vuln-sender-4 14044 4
BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server MSGTYPE=-2 bash lab/frontier/vrpn2shell/probe-func-dos.sh lab/frontier/vrpn2shell/out-w10-o2-matrix/vuln-type-105 14045 105
BIN=lab/frontier/vrpn2shell/build-opt-fixed/server_src/vrpn_server bash lab/frontier/vrpn2shell/probe-func-dos.sh lab/frontier/vrpn2shell/out-w10-o2-matrix/fixed-sender-105 14046 105
BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server bash lab/frontier/vrpn2shell/probe-func-dos.sh lab/frontier/vrpn2shell/out-w10-o2-matrix/vuln-sender-136 14047 136
BIN=lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server bash lab/frontier/vrpn2shell/probe-func-dos.sh lab/frontier/vrpn2shell/out-w10-o2-matrix/vuln-sender-139 14048 139
```

Results (all in `out-w10-o2-matrix/*/meta.txt`): SENDER 105 exit 134, SENDER
111 exit 134, TYPE 105 exit 134, each with `*** stack smashing detected ***`
in `server.err`; SENDER 104 ALIVE, SENDER 4 ALIVE, fixed SENDER 105 ALIVE;
SENDER 136 and 139 DEAD exit 139 (SIGSEGV). The W8 136/139 ALIVE rows used
the Debug -O0 build; this -O2 outcome matches the witness's W115 replay.
Self-replay, not a witness verdict; author-only for the saved-RIP rows.
All probes on 127.0.0.1 ports started by this plant; no server left running.

## W11 — no-canary marker build and binary patch (2026-11-22 ~22:12Z)

Both pinned sources were rebuilt with identical flags in new directories; no
source file was edited. Build logs: `build-marker.log`,
`build-marker-fixed.log`; the exact configure commands are recorded below.

```
cmake -S lab/frontier/vrpn2shell/src/vrpn-07.36 -B lab/frontier/vrpn2shell/build-marker-07.36 -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS='-fno-stack-protector -fno-pie -falign-functions=256' -DCMAKE_C_FLAGS='-fno-stack-protector -fno-pie -falign-functions=256' -DCMAKE_EXE_LINKER_FLAGS='-no-pie'
cmake --build lab/frontier/vrpn2shell/build-marker-07.36 --target vrpn_server -j4
cmake -S lab/frontier/vrpn2shell/src/vrpn-fixed -B lab/frontier/vrpn2shell/build-marker-fixed -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS='-fno-stack-protector -fno-pie -falign-functions=256' -DCMAKE_C_FLAGS='-fno-stack-protector -fno-pie -falign-functions=256' -DCMAKE_EXE_LINKER_FLAGS='-no-pie'
cmake --build lab/frontier/vrpn2shell/build-marker-fixed --target vrpn_server -j4
python3 lab/frontier/vrpn2shell/install_marker_patch.py lab/frontier/vrpn2shell/build-marker-07.36/server_src/vrpn_server lab/frontier/vrpn2shell/build-marker-07.36/server_src/vrpn_server-marked3 --target 0x413d00 --ret 0x413dda --cave 0x40be40
python3 lab/frontier/vrpn2shell/install_marker_patch.py lab/frontier/vrpn2shell/build-marker-fixed/server_src/vrpn_server lab/frontier/vrpn2shell/build-marker-fixed/server_src/vrpn_server-marked3 --target 0x413d00 --ret 0x413dda --cave 0x40be40
```

Binary digests (SHA-256): vulnerable unpatched
`1cd5404e1b45358091e37aaa53cbf95891c370644173a5ecb6f4e6137b917fcd`; fixed
unpatched `20d2da0907bcd01c69447bad0999cbea6ffa1799bcdbed23a79fc287a0e92359`;
vulnerable patched `45b33f20c923016cba3e03852e2dc8d79adc86aa8b7a5614d28f27d6ed4873bb`;
fixed patched `a8f2ebf407d7d69b1f52cb0dd9402a268e8cd2686300348397e3ee147fde5651`.
Patch records: `out-w11-patch-record.txt`, `out-w11-patch-record-fixed.txt`.
The patcher records source/destination digests, `.text` range, target, return
address, cave and displaced prologue; the stub is 95 bytes including the
18-byte `VRPN2SHELL_MARKER\n` message.

Frame measurement: `out-w11-frame-120/gdb.log` shows `&sender_name=rbp-0x80`
and the store `mov BYTE PTR [rbp+rax-0x80],0x0`; `out-w11-map-136b/gdb.log`
shows saved RIP `0x413dda -> 0x413d00`. Final gdb trace
`out-w11-final-gdb/gdb.log` shows the normal entry, the corrupted-return entry
(`[rsp]=0xffffffff`), the marker and the resume at `0x413dda`. Functional rows
and controls are in `out-w11-marked3-*`, `out-w11-fixed-marked3-*`,
`out-w11-unpatched2-136`, `out-w11-unpatched-type-136` (fresh ports 14112,
14115-14117, 14119-14121). Earlier wrong stub versions are preserved in
`out-w11-marked-*` and `out-w11-marked2-*` as negative results. All probes were
on 127.0.0.1 ports started by this plant; no server was left running.

## W12 — clean rebuild self-replay and alignment control (2026-11-23 ~00:38Z)

Built both pinned sources again in NEW directories with the exact W11 flags
(`Debug`, `-fno-stack-protector -fno-pie -falign-functions=256`, link `-no-pie`);
configure/build logs are `out-w12-replay/cfg-vuln.log`,
`out-w12-replay/build-vuln.log`, `out-w12-replay/cfg-fixed.log` and
`out-w12-replay/build-fixed.log`. Fresh unpatched SHA-256: vulnerable
`52eefbfb7964c0988a8622a31d3578760c146c1fa960bad979e952422606d5a0`, fixed
`f8d50ba72450f2db6e62ac8010c5ddc1796cc1bf728a404bb132a740d1c11792`. The
digests differ from W11's because Debug info embeds the build directory; the
code layout does not. `out-w12-replay/frame-136/gdb.log` again records
`PRE i=136 ... rip136=0x413dda` / `POST ... rip136=0x413d00`.

`install_marker_patch.py` with `--target 0x413d00 --ret 0x413dda --cave
0x40be40` produced `out-w12-replay/patch-vuln.txt` and `patch-fixed.txt`
(patched SHA-256 `fb0e4d1281f73f38af1efa65ddd660ed7d8f920d42d5dd55d4aa0580d16fc0d5`
and `ea0bf4e0817f551c84ad823d6518389f5fe7d84eafd0d5d2fbf9e06df50953c5`).
Six-case functional matrix, raw meta/client/server stderr in
`out-w12-replay/vuln-patched-s136`, `vuln-patched-s4`, `fixed-patched-s136`,
`vuln-patched-t136`, `fixed-patched-t136`, `vuln-unpatched-s136` (ports
14211-14216): results match W11 exactly — patched vulnerable SENDER/TYPE 136
ALIVE with marker, patched vulnerable SENDER 4 and patched fixed SENDER/TYPE
136 ALIVE without marker, unpatched vulnerable SENDER 136 DEAD exit 139.

Alignment control: `out-w12-replay/cfg-noalign.log` / `build-noalign.log`
built `build-w12-noalign` with the same flags minus `-falign-functions=256`
(SHA-256 `d82632d568a134cb6fa808423d06db7398c1665099b94dd25c086bd0ea71f18f`).
`out-w12-replay/frame-noalign-136/gdb.log` and `type-noalign-gdb.log` record
saved RIP `0x4108f2 -> 0x410800` on both sinks; `0x410800` is mid-function and
`out-w12-replay/noalign-unpatched-s136` dies exit 139. The 256-byte function
alignment is a measured precondition for the marker landing. Author
self-replay; not a witness verdict. No server was left running.

## W13 — independent witness replay of W11/W12 (DM #1985)

Witness W135 rebuilt both pins from a clean git archive of `8e9fd0a` in
`/tmp/w135-vrpn` with the exact W11 flags (`Debug`,
`-fno-stack-protector -fno-pie -falign-functions=256`, link `-no-pie`).
Pins verified against this file: `vrpn_Connection.C` SHA-256 `9eaa1045...`,
fixed tarball `b5258e99...`. Witness binaries (SHA-256 prefixes):
vulnerable `59dcffe0...`, fixed `7dae1705...`; patched
`e10f1e3e...` / `4e9cc53a...`; no-alignment control `c7293b4a...`.
Digests differ from W12 because Debug info embeds the build directory.

Frame probe (port 14231): `0x413dda -> 0x413d00`; `nm` confirmed the
`doSystemCallbacksFor(HANDLERPARAM,void*)` entry and the `0x40be40` cave.
Six-case matrix on ports 14241-14246 matched W11/W12 exactly; gdb stub trace
on port 14261 saw `ret_at_rsp=0x413c04` on the normal call, `0xffffffff` on
the corrupted return, the marker, and `RESUME_413DDA` at `:1446`. The
no-alignment control measured `0x4108f2 -> 0x410800` (port 14251) and exit
139 (port 14252). All processes killed, ports freed, loopback only.

Verdict: ESTABLISHED at the exact claimed lab-patched rung-4 scope; #1770 is
answered. Full narrative, preconditions and limits in
`reports/vrpn2shell.md`, "Independent witness replay — W135 / DM #1985".
