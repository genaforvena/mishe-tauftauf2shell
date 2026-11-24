# PROVENANCE — snap7shell lab (CVE-2026-131848)

All artifacts under `lab/frontier/snap7shell/`. Advisory pages and the upstream
issue were fetched read-only; no external probes. All test traffic is absent:
the ISO exchange is replaced by an in-process test double (see limits).

## Pins

- Vulnerable source: `davenardella/snap7` commit
  `30f37da3114024a71ba93f7fd855c680b97a406f` (version 1.4.3), fetched as
  `https://github.com/davenardella/snap7/archive/30f37da3114024a71ba93f7fd855c680b97a406f.tar.gz`,
  saved as `snap7-30f37da.tar.gz`, sha256
  `2840d50a833d928e5175b8ccc5383fae0fcc3e826c07e60b2b4190a30c613c36`.
- Pristine `src/core/s7_micro_client.cpp` sha256
  `d42d94c458b6534a1070ee5506ce3f784be3af5bb91de4f88ea4f9dea7c0c486`.
- Advisory: CVE-2026-131848 / GHSA-xr6p-cjp3-pvwg, VulnCheck 2026-11-17, NVD
  2026-11-18. CWE-787; CVSS 4.0 8.3
  `AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H`. Affects snap7 <= 1.4.3; no
  upstream fix or patched version identified (issue #32 open, 2026-08-01).
- Upstream report: `davenardella/snap7#32`, with source-bound mechanism, fix
  suggestion and a non-published loopback reproducer description.

## Patches and harness

- `isotcp-testdouble.patch` (sha256
  `a27bcf0a743ac386b6e73e3d1e3a19e044b26134923be92e1fa5eebf7572c590`)
  replaces only `TIsoTcpSocket::isoExchangeBuffer()` in `src/core/s7_isotcp.cpp`
  with a test double that writes a malicious PLC ReadVar answer into
  `PDU.Payload`: `ReturnCode=0xff`, `TransportSize=TS_ResOctet`,
  `DataLength` from the harness, 64 bytes of `0x48`. It bypasses socket I/O and
  negotiation; the harness sets `PDULength = 960`, the normal negotiated size.
  All other upstream bytes, including the `memcpy` in `opReadMultiVars`, are
  unchanged (vulnerable `s7_micro_client.cpp` sha matches pristine above).
- `fix-readmultivars.patch` (sha256
  `9b6a828f4c0152d0216c1976fe29dd2c021c571188b0b7f60c5af2788205ae08`)
  adds issue #32's `MaxRecv`/`MaxDest` bounds before the `memcpy` in a
  byte-for-byte copy of the tree; patched `s7_micro_client.cpp` sha256
  `9c70dc45b868dd9a6976849f43f7f806b42415c8547e7f9cf49fa81f2fda4048`.
  Both trees' patched `s7_isotcp.cpp` sha256
  `7abdea86847e985d3865c2d7087358de6672fd80ffd75610214017ff4a905d8e`.
- `harness.cpp` (sha256
  `1a180203958dd0ec4bf85546b6a07fdfe62aad5610ad16e00da7e562db8183d7`)
  calls the public `TSnap7MicroClient::ReadMultiVars()` with one item,
  `Amount=1`, `pdata` a heap buffer sized 1 byte (`asan`/`safe`) or 48 bytes
  with a canary at offset 32 (`bytes`). `protected` is made public only to set
  the negotiated `PDULength`; no private method is called directly.
- `sh bootstrap.sh` re-extracts both trees from the pinned tarball, applies the
  patches and compiles: `g++ -std=c++11 -fsanitize=address
  -fno-omit-frame-pointer -g -O0 -I src-$v/src/core -I src-$v/src/lib
  -I src-$v/src/sys harness.cpp src-$v/src/core/*.cpp src-$v/src/lib/*.cpp
  src-$v/src/sys/*.cpp -lpthread -o $v` for `v` in `vuln fixed`.
  Generated trees and binaries are gitignored.

## Observed bytes (2026-11-24T11:21Z)

- `./vuln asan`: ASan `heap-buffer-overflow`, `WRITE of size 65535`, 0 bytes
  after the 1-byte caller allocation. Frames: `memcpy` ->
  `TSnap7MicroClient::opReadMultiVars()` at `s7_micro_client.cpp:418` ->
  `PerformOperation()` -> `ReadMultiVars()` -> harness. rc 1.
- Clean-archive replay (2026-11-24T11:28Z): `git archive 3b74492
  lab/frontier/snap7shell` extracted to `/tmp/w203-snap7`, then
  `sh bootstrap.sh && sh run-all.sh` -> 13 PASS / 0 FAIL, rc 0, log
  `clean-replay.log`. The original tree was untouched.
- `./vuln bytes`: declared 32 bytes, `byte16=0x48 byte31=0x48 canary32=0xab`:
  server-derived bytes land at caller-chosen offsets; canary just past the
  declared copy is intact. rc 0.
- `./vuln safe`: declared length 1 into 1 byte, rc 0, no ASan report.
- `./fixed asan` and `./fixed bytes`: rc 0 with `rc=8388608`
  (`errCliInvalidPlcAnswer`), no ASan report, canary and bytes unchanged.
- `sh run-all.sh` -> 13 PASS / 0 FAIL, rc 0, log `replay.log`.

## Known limits / negatives

- The response is injected in-process by a test double, not delivered by a
  malicious PLC over TCP; no wire replay, no real COTP/S7 handshake, no
  authenticated PLC. The public client API and the vulnerable memcpy are real.
- Chosen bytes come from the test double's fill byte, not from a crafted
  network packet. This is rung 3 in the real library and rung 4 PARTIAL
  (chosen bytes/offsets) in a minimal harness; no pointer, IP or command
  control; no rung 5.
- No upstream patch or fixed release exists; the fixed control is the
  reporter's suggested bound patch, not a vendor release.
- Independent witness (2026-11-24, DM #3582): clean archive of commit
  `3b74492`, tarball/patch/harness hashes matched, `sh bootstrap.sh` then
  `sh run-all.sh` -> 13 PASS / 0 FAIL. Raw ASan `WRITE of size 65535`,
  0 bytes after the 1-byte region, frames `opReadMultiVars()`
  `s7_micro_client.cpp:418` -> `PerformOperation()` -> `ReadMultiVars()` ->
  harness; vuln bytes `byte16=0x48 byte31=0x48 canary32=0xab`; fixed rejected
  both attack lengths with rc=8388608. Steering harness against the rebuilt
  trees: declared 16 / fill 0x5a wrote bytes 0..15=0x5a, byte16=0xab;
  declared 48 / fill 0x7e wrote bytes 0..47=0x7e, byte48=0xab. Verdict
  ESTABLISHED AS LABELED: rung 3 real library, rung 4 PARTIAL; no wire,
  pointer/IP/command or r5.
