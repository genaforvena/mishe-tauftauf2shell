# frontier brief — snap7shell (CVE-2026-131848)

## Ground truth

- Claim: Snap7 through 1.4.3 contains an out-of-bounds write in
  `TSnap7MicroClient::opReadMultiVars()`; a malicious or impersonated PLC can
  answer a normal `Cli_ReadMultiVars()` request with a server-supplied
  `DataLength`, writing up to 65535 bytes into each caller-owned item buffer.
- Sources: VulnCheck advisory 2026-11-17 (CVE-2026-131848, CWE-787, CVSS 4.0
  8.3 `AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H`), GHSA-xr6p-cjp3-pvwg,
  NVD 2026-11-18, upstream issue `davenardella/snap7#32` (open, 2026-08-01,
  reporters Mayur Agnihotri and Shukhratbek Uraiimov). All read-only.
- Affected: snap7 <= 1.4.3, including pinned commit `30f37da`. No upstream fix
  or patched release identified; issue is open.
- Primitive claimed: network-facing write into an application buffer, size from
  a single 16-bit response field; the caller's `Item->Amount` is not consulted.

## Source-bound mechanism

At pinned `src/core/s7_micro_client.cpp:400` the reply's item **count** is
checked (`ItemCount != ItemsCount`). Inside the loop at 405-429 each item's
`ReturnCode==0xFF` leads to `Slice = SwapWord(ResData[c]->DataLength)` (413);
non-octet/real/bit transports take `Slice >>= 3` (416). Then line 418:
`memcpy(Item->pdata, ResData[c]->Data, Slice)` — no bound against
`Item->Amount`, the receive size (`IsoSize`), or the caller's allocation.
`Offset += 4 + Slice` (427) uses the same unvalidated value, so later item
headers are also read past the 4096-byte `PDU.Payload`.

The reporter's fix bounds `Slice` by `MaxRecv` (bytes actually received minus
headers and offset) and `MaxDest = Item->Amount * DataSizeByte(Item->WordLen)`,
returning `errCliInvalidPlcAnswer` on violation. That patch is the fixed
control here; it is not a vendor release.

## Local experiment

`lab/frontier/snap7shell/`: pinned v1.4.3 tarball, two source trees (vulnerable
and fixed), an ISO test double, and a harness that calls the public
`TSnap7MicroClient::ReadMultiVars()` API. The test double injects the malicious
ReadVar answer directly into `PDU.Payload`, bypassing socket I/O but leaving
the vulnerable `memcpy` and the entire public call path unchanged.

- Rung 1: deterministic with declared length `0xffff`; no timing or state.
- Rung 2: `Slice=65535` against an `Amount=1` caller allocation of 1 byte.
- Rung 3: ASan `WRITE of size 65535`, 0 bytes after the 1-byte heap region,
  frame `opReadMultiVars() s7_micro_client.cpp:418` -> `PerformOperation()` ->
  `ReadMultiVars()`; rc 1.
- Byte control: declared length `0x20` into a 48-byte buffer writes `0x48` at
  offsets 16 and 31, canary at 32 untouched. Fixed control rejects both cases
  with `errCliInvalidPlcAnswer` (`rc=8388608`), ASan-clean; safe declared length
  1 is clean on both libraries. `sh run-all.sh` -> 13 PASS / 0 FAIL.

Exact pins, patch hashes, commands and limits: `lab/frontier/snap7shell/PROVENANCE.md`.

## Rung-4 feasibility and ceiling

Rung 3 is confirmed in the real pinned library through the public API. Rung 4
is PARTIAL: server-derived bytes at chosen offsets in a minimal harness, with
the response synthesized in-process. No wire replay, no COTP/S7 handshake, no
real PLC, no pointer/IP/command control, no allocator-metadata corruption, no
independent witness verdict, no rung 5. The wire position is plausible from
the advisory but untested here — an honest UNKNOWN, not a pass.

## Cheapest next experiment

Stand up a loopback-only S7 responder (real snap7 server behind a rewriting
proxy, or a minimal COTP/S7 responder) so `Cli_Connect()` +
`Cli_ReadMultiVars()` receives the crafted DataLength from 127.0.0.1 instead
of a test double; then rerun the same ASan and canary checks with fixed and
safe-input controls. If that reproduces, request independent witness replay
before any stronger claim.
