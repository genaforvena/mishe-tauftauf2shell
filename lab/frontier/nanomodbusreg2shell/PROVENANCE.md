# PROVENANCE — nanomodbusreg2shell

All fetching was read-only provisioning from public GitHub pages/refs; no
external host was probed. All execution is local, with the malicious server
bound to 127.0.0.1 only.

## Claim source

- GitHub advisory GHSA-5hc8-p74q-47pp / CVE-2026-29972, published 2026-05-08,
  High, CWE-121: nanoMODBUS through v1.22.0,
  `recv_read_registers_res()` writes server-response registers into the
  caller's buffer using the response `byte_count` before validating it
  against the requested quantity; a malicious Modbus TCP server can send
  `byte_count=250` and up to 248 attacker-controlled bytes past the caller's
  buffer. Advisory and PoC gist read from GitHub on 2026-11-27.
- Affected tag v1.22.0 `035b8d596a954c2dd4bc40e3fa28a7cb2a8c0ec1`; fixed tag
  v1.22.1 `11317b18a60f7b21583d909ba8201686a1b21fc3`; fix commit
  `a3a67f7bc1a06a5697d06772cf5f4386a32e37be` ("validate registers_bytes
  before write"), merged as `11317b1`. The one-hunk diff moves
  `registers_bytes != quantity * 2` from after the store loop to before
  `recv(nmbs, registers_bytes)`.

## Pinned bytes

`git clone` into `/tmp/nm-screen` was used only to read tags and export exact
files into `src/`; that clone is not part of the lab tree. `SHA256SUMS`
covers 11 files (six pinned upstream files plus five harness files). The
upstream files are verbatim tag bytes; `src/fix.patch` is the verbatim
`git diff v1.22.0 v1.22.1 -- nanomodbus.c` output.

| file | SHA-256 | source |
| --- | --- | --- |
| `src/nanomodbus-v1.22.0.c` | `d2df601955ce57a4c6935c3d9fc2f2e3f46b988ece617bca8755b19e7ec68295` | tag v1.22.0 `nanomodbus.c` |
| `src/nanomodbus-v1.22.1.c` | `7311e21369f7213e4af010071e7dda1b48cac4495bf5e06c4fb380681e514675` | tag v1.22.1 `nanomodbus.c` |
| `src/nanomodbus.h` | `6b75b40173719698ee6da46fb563ac29f567fd6a0e2902f576eeff9d08c8a828` | tag v1.22.0, unchanged in v1.22.1 |
| `src/platform.h` | `c1a630041514bc414fc48e9b6ca32ff7c0cafb9e9cf7482802116c9783f9d880` | tag v1.22.0 `examples/linux/platform.h`, unmodified |
| `src/client-tcp.c` | `1d42989f05d086235146779bc55991f50349701b9b374655827a7b80a2045593` | tag v1.22.0 `examples/linux/client-tcp.c`, unmodified |
| `src/fix.patch` | `bbbdaba26cec88582d239887634afba875e3542e4cb7d3d918436fb6644bbb01` | upstream diff |

## Harness disclosure

- `harness/server.py` is a loopback-only malicious Modbus TCP server. It
  answers FC15/FC1/FC16 normally, then answers FC3 with
  `byte_count=NMBS_COUNT` (250 for attack, 4 for safe) and chosen register
  bytes. `NMBS_MEM_HEX` supplies an exact desired in-memory byte image; the
  server performs the per-register big-endian-to-host swap so the chosen
  bytes land in memory in the stated order. No external address is used.
- `harness/client-wire.c` is a minimal caller, not an upstream file. It uses
  the unmodified `src/platform.h` Linux TCP read/write callbacks and the
  pinned library verbatim; it connects to the loopback server, creates a
  real `nmbs_t` client, and calls `nmbs_read_holding_registers(...,2,regs)`.
  `regs[2]` lives in a small `read_two()` frame so the 250-byte write can
  reach that frame's saved return address. `marker()` is an unreferenced
  lab function used only as a chosen control-flow destination; it writes
  `BENIGN_MARKER` to fd 1 and exits. No shell command is executed.
- `harness/replay.py` merely spawns the server and client (or GDB), saves
  logs in `evidence/`, and prints two stable tokens. It chooses a free
  loopback port for each arm; ports and PIDs are excluded from the summary.
- `harness/gdb-layout.cmd` and `harness/gdb-savedrip.cmd` are read-only
  observers (breakpoint, `info frame`, register/bt reads); they write no
  memory.
- `harness/run-all.sh` rebuilds four binaries from the pinned sources with
  gcc `-g -O0`, checks 11 pins and 17 stable tokens, and prints
  `RUN_ALL_OK 17 PASS / 0 FAIL` plus a SHA-256 over the token list only.

## Build conditions and controls

- ASan arms: `-fsanitize=address -fno-omit-frame-pointer`.
- Plain control arm: `-fno-stack-protector -U_FORTIFY_SOURCE
  -D_FORTIFY_SOURCE=0 -no-pie`. ASLR was left at host default; the marker
  payload uses the address of `marker` in that build, read with `nm -n` at
  replay time. No debugger write is used.
- Vulnerable caller: v1.22.0 with `byte_count=250`. Fixed control: v1.22.1
  with the same payload (rejects before the store). Safe input control:
  v1.22.0 with `byte_count=4`.
- Negative preserved: the unmodified upstream example client's `main()`
  frame is large (its `mem[1024]` etc.); GDB measurement put `r_regs` at
  `0x7fffffffde48` and the saved RIP at `0x7fffffffe168`, a gap of 800
  bytes, so the 250-byte write corrupts only that frame and does not reach
  its saved RIP. That is why the minimal caller exists; the real wire and
  library are the same.
  Evidence: `evidence/gdb-layout.client.out`.

## Observed evidence (author run 2026-11-27 16:2xZ)

- `evidence/example-asan-attack.client.out`: ASan `stack-buffer-overflow`,
  `WRITE of size 2` at `nanomodbus-v1.22.0.c:603`, called from unmodified
  `client-tcp.c:83` after four normal Modbus responses on a real TCP socket.
- `evidence/min-asan-attack.client.out`: same sink,
  `read_two harness/client-wire.c`; destination `regs[2]` (4 bytes).
- `evidence/min-fixed-attack.client.out` and
  `evidence/min-fixed-marker.client.out`: `READ_RC -2 REG0 0000 REG1 0000`,
  no ASan, no `BENIGN_MARKER`.
- `evidence/min-asan-safe.client.out`: `REG0 4141 REG1 4141`, no ASan.
- `evidence/min-plain-rip.client.out`: SIGSEGV and an unwind whose frames
  above the caller are `0x4343434343434343` (chosen wire bytes).
- `evidence/min-plain-marker.client.out`: `BENIGN_MARKER` — chosen wire
  bytes redirected execution to the chosen function address in a live
  loopback-fed client process.
- `sh harness/run-all.sh`: 11/11 pins, 17 checks OK, 0 fail, summary SHA-256
  `c8489055177859c647d4718101f1feaf61dc20a7d2e6e2dfa04dcc6b33ea909d`.
