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
