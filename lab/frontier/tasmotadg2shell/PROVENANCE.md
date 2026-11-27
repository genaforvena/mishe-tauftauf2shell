# tasmotadg2shell — provenance and evidence ledger (W380, 2026-11-27)

## Claim and pins

- CVE-2026-119756, published 2026-11-09T17:28:33Z, CNA VulnCheck, CWE-805.
  Claim: Tasmota through 16.0.0, `SendReceiveDeviceGroupMessage()` heap OOB
  write via crafted Device Groups UDP messages on port 4447; unauthenticated
  LAN attacker drives `log_remaining` negative past a `malloc(512)` log buffer.
  https://api.osv.dev/v1/vulns/CVE-2026-119756
  https://nvd.nist.gov/vuln/detail/CVE-2026-119756
- Upstream fix commit `e97e1e4f7e319a55caa1613aef1f25fc81bdb554`
  ("Fix security issue", 2026-11-06T14:13:11Z), parent
  `1cb7ebcafb0b79f1836d0e9948275f78abc17d7b`.
  https://github.com/arendst/Tasmota/commit/e97e1e4f7e319a55caa1613aef1f25fc81bdb554
- Fetched source: shallow GitHub archive of the parent commit, SHA-256
  `fac737b021be11447ac711183adcdf86c53833985fdde2e413c14237d6b6abda`
  (`src/tasmota-pinned.tar.gz`); single raw file at the parent, SHA-256
  `70cde08eadecda129ab24c7c4369c5c742e873c4da56585b6ca7cd18bc463904`
  (`src/support_device_groups.vuln.ino`); single raw file at the fix commit,
  SHA-256 `5ad5c1d9c34b8b2a300eb0aff76f09fc8ce8b5ba6b24536b695ea7f14024648b`
  (`src/support_device_groups.fixed.ino`). Pinned DGR constants read from
  `tasmota/include/tasmota.h` at the parent commit (`src/Tasmota-.../tasmota/include/tasmota.h`).
- Exact fix hunk (verbatim from the commit API): initial `sprintf` becomes
  `snprintf_P(log_buffer, 512, ...)`, all four item-path `snprintf` calls
  become `snprintf_P`, the `'*'` write is wrapped in `if (log_remaining > 1) {
  // Fix GHSA-g56h-hfr6-x2v9`, and `*log_ptr++ = 0` becomes `*log_ptr = 0`.

## Source-bound mechanism

`SendReceiveDeviceGroupMessage()` allocates `char * log_buffer = (char *)malloc(512)`
at pinned line 236, sets `log_ptr = log_buffer + log_length` and
`log_remaining = 512 - log_length` at 238-239. Each item logging call at pinned
lines 345, 371, 378 and 383 returns the *would-be* length; lines 346-347 and
389-390 advance `log_ptr` and decrement `log_remaining` by that value without a
floor. With enough items `log_remaining` goes negative and the next `snprintf`
size argument is converted to a huge `size_t`, so the write at the advanced
`log_ptr` leaves the 512-byte heap block. Lines 409-410 write `'*'` unchecked;
line 454 writes the terminating NUL unchecked.

Real wire caller: pinned `DeviceGroupsLoop()` lines 921-929 reads a UDP packet
into `uint8_t packet_buffer[512]`, checks the `TASMOTA_DGR` prefix and calls
`ProcessDeviceGroupMessage()` at lines 862-900; that function creates a member
from the UDP source IP and calls the sink at line 899.

## Harness

`harness/build.sh` extracts the exact function body between
`void SendReceiveDeviceGroupMessage(` and the next top-level function from each
pinned `.ino` (pinned lines 214-491 vulnerable, 214-493 fixed), prepends
`harness/shim.h` and appends either `harness/main.cpp` (direct sink call) or
`harness/main_wire.cpp` + the pinned `ProcessDeviceGroupMessage()` body. The
shim defines only the Tasmota/Arduino symbols the extracted functions need; DGR
enum values are copied from the pinned `tasmota/include/tasmota.h`. The wire
shim (`-DUSE_SHIM_LOOPBACK_UDP`) opens a real UDP socket bound to
127.0.0.1:4447; the driver sends the crafted packet to that address and runs
the pinned receive function. No external host or non-loopback address is used.

Extracted body SHA-256: vulnerable `9cd947adca616f371b1993166ba0ef2d04ff8d3d4fe87707477aba3e4cdefbef`;
fixed `90bb4a6a12d6e4012d0261a37a94701d53120c421789d743a82ddef773a636c9`.
The fixed commit contains an upstream typo `snprintf-p(` at line 383 which
cannot compile; `build.sh` applies exactly one token repair,
`snprintf-p(` -> `snprintf_P(`, to the extracted fixed body only, recorded in
`harness/gen/typo-repair.txt`. This repair is isolated and does not touch the
sink lines under test.

Commands:
```
bash harness/build.sh
bash harness/run-all.sh
```
`run-all.sh` checks the two source pins and 17 behavioral cases; final result
`RUN_ALL_OK 18 PASS / 0 FAIL`. Its logs are in `harness/evidence/run-all/`.
Clean-archive replay at commit `b05c1126`: `git archive --format=tar HEAD
lab/frontier/tasmotadg2shell` extracted to a fresh `/tmp` directory, then
unmodified `build.sh` (`BUILD_OK`) and `run-all.sh` (`RUN_ALL_OK 18 PASS /
0 FAIL`). No local-only file outside the archive is needed to replay.

## Observations (host ASan, GCC 13.3.0, -O0 -g)

Message shape: `"TASMOTA_DGRg\0"` + 16-bit sequence + 16-bit flags, then N
8-bit `DGR_ITEM_LIGHT_BRI` items (id 5, value 0x43), then one
`DGR_ITEM_COMMAND` item (id 193) with an 8-byte attacker-chosen `0x44`
string, then EOL. Delivered both by direct call and over loopback UDP.

- N=1 (safe): both arms, direct and wire, rc 0, `log_len=61`, no ASan report.
- N=62: both arms clean. N=63 direct/wire vulnerable: ASan `WRITE of size 1`
  at `main*.vuln.cpp:242` (pinned line 454, final NUL), address `buf+512`.
  Fixed arm N=63: rc 0, `log_len=511` — the added NUL/star guards hold here.
- N=64 vulnerable: ASan `WRITE of size 1` at `main.vuln.cpp:197` (pinned line
  409, `'*'`); fixed arm faults at `main.fixed.cpp:244` (pinned line 456,
  `AddLogData()` reading the already-corrupted log buffer).
- N=65 direct and wire, both vulnerable and fixed: ASan `WRITE of size 11`
  at `main*.{vuln,fixed}.cpp:166` (pinned line 378, the `%s` item log),
  starting at `buf+515`. **The fix commit does not close this path in the
  host build**: `snprintf_P(..., log_remaining, ...)` still receives a
  negative size and writes past the buffer. Preserved as a negative result
  against the advisory's "fixed" claim; not generalized to ESP newlib
  behavior, which was not built here.
- Plain-build GDB at the store (N=65, after 65 item hits): `log_ptr-log_buffer
  = 515`, `log_remaining = -3`, `log_length = 10`, `item = 193`; memory at
  `log_buffer+512..+524` is `00 00 00 27 44 44 44 44 44 44 44 44 00`.
  The eight wire-supplied `0x44` bytes land at heap offsets 516..523, chosen
  by the packet's string content; the offset is chosen by the item count.
  Same readback in vulnerable direct, vulnerable wire and fixed direct arms.

Evidence pins (PID lines stripped where present):
- `harness/evidence/wire-vuln-asan-n63.txt` normalized
  `d5e26e015826164471aa6e7edc61eabc6b0333d69a554af30da0f8f6c464ddae`
- `harness/evidence/wire-vuln-asan-n65.txt` normalized
  `5318653cba9c53d4243adc330db1fbd77a6b2530038144de6dd195b71665edad`
- `harness/evidence/wire-fixed-asan-n63.txt`
  `4fe4d70c9b099818d8d17f85a4b2e1211d878e88c0ffcb91da0f481fe21c7374`
- `harness/evidence/wire-fixed-asan-n65.txt` normalized
  `69e249e44f495ae35f20bd469cf965e2e74d36851abb84b8427e67101b62d21e`
- `harness/evidence/wire-gdb-chosen-vuln-n65.txt`
  `657c7a806e56e436d873d4e2faf2edf2930cccb147617c2c050cee09902eff98`

Heap addresses and PIDs in raw logs are volatile; the reproducible checks are
the source functions, commands, item counts, fault lines and readback bytes.

## Limits

Harness is a host shim, not an ESP8266/ESP32 firmware build. No firmware
image, device boot, native code execution, ASLR state or shell side effect was
measured. The fix commit is on a branch diverged from `master` (compare API:
337 ahead / 70 behind); `master` at this commit still contains the vulnerable
`sprintf`/unbounded tail, so a released fixed version is UNKNOWN from these
observations. `GHSA-g56h-hfr6-x2v9` named in the fix comment is not a public
GitHub advisory via the API at the time of this wake; its relationship to
CVE-2026-119756 is UNKNOWN.
