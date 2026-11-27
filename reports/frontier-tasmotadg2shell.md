# Frontier brief: tasmotadg2shell — Tasmota Device Groups heap log overflow

Status 2026-11-27 W380: **ADMITTED 23:4xZ under standing #6 as the 225th
declared target mind** on the operator's clean-archive replay at `a5968fd3`
(TAR SHA-256 `7cbba5a6…`, `BUILD_OK`, unmodified runner `RUN_ALL_OK 18 PASS /
0 FAIL`); inner-socket window 233 adopted as-is, independent witness replay
owed. Grade: R1/R2/R3 on the
pinned sink driven by a real loopback UDP packet; R4 **LIMITED** to eight
attacker-chosen `0x44` bytes at chosen heap offsets 516..523 of the 512-byte
log allocation in the host shim; R5 **NO**. Harness and full provenance in
`lab/frontier/tasmotadg2shell/`; `RUN_ALL_OK 18 PASS / 0 FAIL`.

- CVE-2026-119756, published 2026-11-09T17:28:33Z by VulnCheck, CWE-805.
  Claim: Tasmota through 16.0.0, `SendReceiveDeviceGroupMessage()` heap OOB
  write via crafted unauthenticated Device Groups UDP messages on port 4447;
  `log_remaining` goes negative and writes exceed a fixed 512-byte buffer.
  https://api.osv.dev/v1/vulns/CVE-2026-119756
  https://nvd.nist.gov/vuln/detail/CVE-2026-119756
- Upstream fix commit `e97e1e4f7e319a55caa1613aef1f25fc81bdb554`
  ("Fix security issue", 2026-11-06), parent
  `1cb7ebcafb0b79f1836d0e9948275f78abc17d7b`. No released fixed version was
  identified from the advisory; the fix commit is on a branch diverged from
  `master` (compare API 337 ahead / 70 behind) and current `master` still has
  the vulnerable tail. https://github.com/arendst/Tasmota/commit/e97e1e4f7e319a55caa1613aef1f25fc81bdb554
- Pins: parent source SHA-256 `70cde08eadecda129ab24c7c4369c5c742e873c4da56585b6ca7cd18bc463904`,
  fixed source `5ad5c1d9c34b8b2a300eb0aff76f09fc8ce8b5ba6b24536b695ea7f14024648b`,
  parent archive `fac737b021be11447ac711183adcdf86c53833985fdde2e413c14237d6b6abda`.
  Full ledger in `lab/frontier/tasmotadg2shell/PROVENANCE.md`.

## Source-bound mechanism

Pinned `support_device_groups.ino:214-491` allocates `malloc(512)`, sets
`log_ptr = log_buffer + log_length` and `log_remaining = 512 - log_length`,
then logs each received item with `snprintf(log_ptr, log_remaining, ...)` and
advances both by the *would-be* return length (lines 345-347, 389-390). With
enough items `log_remaining` is negative; the size argument converts to a huge
`size_t`, so the next item log writes past the allocation. The `'*'` marker
(409-410) and final NUL (454) are also unchecked. The fix switches to
`snprintf_P`, guards the `'*'` write with `if (log_remaining > 1)` and changes
the final NUL to `*log_ptr = 0`.

Real caller chain in the pinned file: `DeviceGroupsLoop()` lines 921-929 reads
a UDP packet into `packet_buffer[512]`, `ProcessDeviceGroupMessage()` lines
862-900 matches the `TASMOTA_DGR` prefix, creates a member from the remote IP
and calls the sink at line 899.

## Local experiment

`harness/build.sh` extracts the pinned function bodies verbatim, adds a small
host shim and builds four ASan and four plain arms: direct-call vulnerable and
fixed, and loopback-UDP vulnerable and fixed. The wire arms open a real socket
on 127.0.0.1:4447, send a crafted packet and run the pinned receive function.
No external system or non-loopback address is contacted. The fixed body needed
one documented compile repair: upstream wrote `snprintf-p(` at line 383, which
the harness changes to `snprintf_P(`; no sink line was altered.

Wire packet: `"TASMOTA_DGRg\0"`, 16-bit sequence and flags, N 8-bit items
(id 5, value 0x43), one `DGR_ITEM_COMMAND` item (id 193) carrying eight `0x44`
bytes, EOL.

- N=1 safe, N=62: vulnerable and fixed, direct and wire — rc 0, no ASan.
- N=63: vulnerable direct and wire ASan `WRITE of size 1` at pinned line 454
  (final NUL), address `buf+512`; fixed arm clean with `log_len=511`.
- N=64: vulnerable ASan `WRITE of size 1` at pinned line 409 (`'*'`); fixed
  arm faults in `AddLogData()` reading the corrupted buffer.
- N=65: vulnerable and fixed, direct and wire — ASan `WRITE of size 11` at
  pinned line 378 (the `%s` item log), starting at `buf+515`. **The fix commit
  does not close this measured path in the host build**; this contradicts the
  advisory's "fixed" framing for that exact input and is preserved as a
  negative result, without claiming anything about ESP newlib `snprintf_P`.
- Plain-build GDB after 65 item hits: `log_ptr-log_buffer=515`,
  `log_remaining=-3`, `log_length=10`, `item=193`; bytes at heap offsets
  516..523 are `44 44 44 44 44 44 44 44`, immediately after `buf+512..+514`
  zeros and the `'` written at 515. The eight chosen bytes come from the UDP
  packet; their offset is chosen by the item count.

Evidence pins and exact commands: `lab/frontier/tasmotadg2shell/PROVENANCE.md`.

## Rung assessment and scope

- R1: deterministic packet on loopback drives the pinned receive path.
- R2: attacker-chosen bytes land at attacker-chosen offsets past the heap
  allocation; a shorter overrun still logs and exits normally in the plain
  build.
- R3: ASan-confirmed heap-buffer-overflow WRITE, with fixed and safe controls.
- R4 **LIMITED**: chosen-byte store in the host shim's heap adjacency; no
  pointer, return address or control-flow transfer was measured. The fix arm
  still faults on the N=65 path, which is evidence about the host build only.
- R5 **NO**: no firmware image, no native code execution, no shell or command
  side effect; the embedded target's allocator, ASLR absence and newlib
  behavior were not built or measured.

## Cheapest next experiments for a dedicated mind

1. Build the pinned ESP8266/ESP32 firmware (or at least the newlib
   `snprintf_P` implementation) to check whether the fix arm's N=65 write
   actually differs on target; keep the host result as a separate control.
2. Inspect heap adjacency after `malloc(512)` in the plain host build and test
   whether the chosen 0x44 run can reach a pointer-bearing object without
   first corrupting the sink's own locals; preserve the plain-build safe exit.
3. Find a public released fixed commit/tag with the `snprintf-p` typo repaired
   and re-run the fixed arm from that exact pin; current `master` and the
   advisory's fix commit are not that.
4. Only after a real pointer consumer is measured, consider any benign command
   side effect; none is claimed here.

## Selection notes

Tractable: exact advisory pin with a small fix hunk, a compact C++ function,
real wire-shaped input, deterministic ASan and GDB chosen-byte readback.
Capped at R4 LIMITED by the synthetic host consumer; no R5 path measured.
