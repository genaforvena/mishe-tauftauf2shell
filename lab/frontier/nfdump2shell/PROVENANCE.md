# PROVENANCE — nfdump2shell staged evidence

All source was fetched read-only from `github.com/phaag/nfdump` on
2026-11-25 during frontier W234. No external target was probed; all
execution was local under `lab/frontier/nfdump2shell/`.

## Pins

| artifact | origin | SHA-256 |
| --- | --- | --- |
| `pins/nfd_raw-parent.c` | raw `src/netflow/nfd_raw.c` @ `8a00543aa5c7b25b7d3f7642fdf306fd9979f237` | `f946944aa4c65085af96dc56fb622e40fd4eb8c3662e8ba7f2336a9377f92869` |
| `pins/nfd_raw-fixed.c` | raw `src/netflow/nfd_raw.c` @ `32b9cbe7f17e099d59fc5eac71c84c6c6f051fa5` | `b6fbdd91fbac138ec1eac2c2becabcf82a59b9f46249979027cf086ceaa650ea` |
| `pins/nfxV3-parent.c` | raw `src/libnffile/nfxV3.c` @ parent | `408cbbc8859d62fe1002817d73c5b08800caa4640e107843af16a34de44ad0ae` |
| `pins/nfxV3-fixed.c` | raw `src/libnffile/nfxV3.c` @ fix | `d94b82d3d2a295c6692d3f03fc5b0ee06eb5f621ba7dcb6dcae1b3ef85cdf77e` |
| `pins/nfxV3.h` | raw `src/libnffile/nfxV3.h` @ parent | `84a6832819dc88ac988cf6518c37a083611c63a58c0fbea3b16f6f8ddf874247` |
| `pins/nfd_raw.h` | raw `src/netflow/nfd_raw.h` @ parent | `530d8851e3b1d9293fe484366e2694202fedbf4d165e62ddff29713666407efa` |
| `pins/nffile.h` | raw `src/libnffile/nffile.h` @ parent | `0e9573c595b546918355917c1278f5a1ae8a7c0b1f24da601a5c2b8d9402f870` |
| `pins/nffile_inline-parent.c` | raw `src/inline/nffile_inline.c` @ parent | `6a4c26fb91e603e3e83994b297d347a006a1c8f47a751d4c729f0fd222924c6e` |
| `pins/verify-parent.inc` | verbatim `sed -n 495,550p pins/nfxV3-parent.c` | `c020fe80a020eba2035b2a629f9437611d087c1ca9567c4911538ab9decf51d6` |
| `pins/verify-fixed.inc` | verbatim `sed -n 495,556p pins/nfxV3-fixed.c` | `0f66f0a3eb2b8cd4125c200d3875c564a66a6ce2147771b360342c56e8db0e16` |
| `pins/process-parent.inc` | verbatim `sed -n 136,320p pins/nfd_raw-parent.c` | `5c8857c7c6fd1b4ebc3af9ffea78e58f7b4e6fa8a6523a8c2a85982be4dd8cdb` |
| `pins/process-fixed.inc` | verbatim `sed -n 139,328p pins/nfd_raw-fixed.c` | `73473a1a48ad7ecfc2da0e8003f0c544861e450d14ea9c1a57baafb81f62a24c` |
| `harness/driver.c` | local harness | `96eb5fb9d2c59513b2a1136f69812c756c70f97821aff8def181fe2ea6f40a2d` |
| `run-all.sh` | local runner | `84daa3b2728fb8e9ab3053eff10de1b657e99cac21970e566c3a5f95c9851f19` |

Upstream fix patch: <https://github.com/phaag/nfdump/commit/32b9cbe7f17e099d59fc5eac71c84c6c6f051fa5.patch>

The GHSA id `GHSA-gpgq-hv9x-7mqj` came from this plant's scout/wall; both
`https://github.com/advisories/GHSA-gpgq-hv9x-7mqj` and the GitHub advisory
API returned HTTP 404 on 2026-11-25. No CVE id is claimed here. The fix
commit message is the verified ground truth for the primitive.

## What is pinned verbatim and what is a stand-in

Verbatim: the whole `nfxV3.h` struct/table/definitions, `VerifyV3Record()`
from both commits, `GetExtension()` + `Process_nfd()` from the parent,
`ScanExtensions()` + `Process_nfd()` from the fix. The `.inc` files are
byte-identical line ranges of the pinned sources (hashes above).

Stand-ins: `config.h` (empty) and `id.h` (`V3Record 11` copied from pinned
`src/libnffile/id.h`), `LogError`/`LogInfo`/`dbg_printf`, `getExporter()`,
`WriteBlock()`, `MetricExporterID()`, `UpdateMetric()`, `flow_record_short()`,
`ntohll()`, the output data block and stat record. The attack packet and
`FlowSource_t.received` are built in `harness/driver.c`.

## Commands and observed output

```
bash lab/frontier/nfdump2shell/run-all.sh
TOTAL: 10 PASS / 0 FAIL
```

W235 added `run-witness.sh` (commit `4545c7ef`), a one-command offline
replay that rehashes eight pins, reruns `run-all.sh` and checks the ASan,
fixed, safe and canary evidence:

```
bash lab/frontier/nfdump2shell/run-witness.sh
22 PASS lines / 0 FAIL, rc 0, WITNESS REPLAY PASS
git archive 4545c7ef lab/frontier/nfdump2shell | tar -x -C /tmp/w235-nfdump-clean
bash /tmp/w235-nfdump-clean/lab/frontier/nfdump2shell/run-witness.sh
22 PASS lines / 0 FAIL, rc 0, WITNESS REPLAY PASS
```

The clean-archive run rebuilt every binary from the pinned bytes in a
directory with no prior `harness/out/`; no generated evidence was copied.

GCC ASan (`harness/out/vuln-asan-attack.log`):

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 8 at 0x504000000040 thread T0
    #0 Process_nfd harness/../pins/process-parent.inc:121
    #1 main harness/driver.c:214
0x504000000040 is located 0 bytes after 48-byte region
allocated by malloc at harness/driver.c:148
SUMMARY: AddressSanitizer: heap-buffer-overflow ... Process_nfd
```

Clang ASan reports the same WRITE of size 8. The fixed build rejects the
short element (`Process_nfd: Corrupt nfd record: expected 1 records,
processd: 0`) and is ASan-clean; both vulnerable and fixed builds are clean
for the full 52-byte extension and for a record with no elements.

Plain vulnerable build with a 16-byte trailing canary region

(`harness/out/vuln-plain-attack-canary.log`):

```
ELEM_LEN=20 REC_SIZE=32 TOTAL=48
EXGENERICFLOW_SIZE=52 OFF_MSEC_RECEIVED=16
EXPECTED_BYTES=9b50351f49010000
CANARY_AFTER=9b50351f49010000
```

The written value is the harness-chosen `msecReceived` derived from
`fs.received` (`tv_sec=0x54415554`, `tv_usec=123000`); it is not
attacker-chosen on the wire. The fixed plain build leaves the canary at
`5a5a5a5a5a5a5a5a`.

## Receive-buffer shape: adjacent V3 record header (W281)

`harness/adjacent.c` (local, new) includes `driver.c` with `main` renamed so
it reuses the same stand-ins and verbatim pins, then calls pinned
`Process_nfd()` on a two-record datagram held in a 64 KiB buffer — the real
collector caller shape, not the exact 48-byte allocation. `run-adjacent.sh`
rebuilds vulnerable and fixed binaries and asserts **12 PASS / 0 FAIL**.
No socket, daemon or command is used; the no-wire/no-command ceiling stands.

With a 20-byte truncated EXgenericFlow element, `STORE_OFF=48` equals
`R2_OFF=48`: the 8-byte `msecReceived` store lands on the next record's
12-byte header (`harness/out/adjacent-vuln-attack.log`):

```
R2_HDR_BEFORE=0b00400001000000
R2_HDR_AFTER=9b50351f49010000
R2_TYPE=20635 R2_SIZE=7989 R2_NUMELEM=329
BLOCK_SIZE=40 NUM_RECORDS=1 FLOWS=1
```

The chosen header corrupts record 2's `type`/`size`/`numElements`, and
pinned `Process_nfd()` then rejects it (`record size error`, 1 of 2 records
processed). Safe full-element input leaves the header at
`0b00400001000000` and processes both records; the fixed build rejects the
short element and processes neither. ASan does not fire in this shape:
the store stays inside the 64 KiB allocation — the ASan finding is specific
to the exact-allocation harness, while the corruption of a live record
header is visible in the faithful receive-buffer shape.

`MODE=icmp` demonstrates charter action 3. The truncated element's
`EXgenericFlow` view starts 32 bytes before record 2's payload, so its
`srcPort` (offset 40), `dstPort` (42) and `proto` (44) alias record 2's
chosen bytes at `p2+8`, `p2+10` and `p2+12`. With `proto=IPPROTO_ICMP`,
the pinned swap copies chosen bytes past the element
(`harness/out/adjacent-vuln-icmp.log`):

```
P2_BYTES_BEFORE=dead5a5a01000000
P2_BYTES_AFTER=0000adde01000000
```

The 8-byte value remains collector-time-derived; only the 4 ICMP-swap bytes
are packet-chosen. No pointer-bearing object or command is involved. A live
loopback collector was later built and driven (section below); this harness
result alone does not establish wire reachability.

Trace hashes that include PID/address/path are deliberately not used as
evidence; line numbers in `.inc` excerpts are relative to the excerpt, the
pinned source line numbers are recorded in the excerpt commands above.

## Live pinned collector on loopback (2026-11-26)

New local files, with SHA-256:

| artifact | SHA-256 |
| --- | --- |
| `build-wire.sh` | `ce85d3f64832cafd3ef98f5e06288c69b27cedf5578ec34790fed082b332845b` |
| `run-wire.sh` | `841565f6efa8a26adf7f4eed1e39746e9e3d04e21603e87ee28952b8cdbca18c` |
| `harness/wire_send.py` | `c4dd969505eee3399928a11030c513f69cc0f76684c21b1be6eb12fdc0ff7ae2` |

`build-wire.sh` fetches two source tarballs from `github.com/phaag/nfdump`
(provisioning only; no probes) and verifies the exact commit bytes:

```
nfdump-8a00543a.tar.gz
  970247fa1b7deae56ee9ff09ebe8ec5e6c86adef9b5f82c7f2fd67754c29c827
nfdump-32b9cbe7.tar.gz
  61c92342d19469a4ee46810953741e48ebc4cce2ad3a5cb369feca2b1dbc81f2
```

It runs `autogen.sh`, then out-of-tree `configure --enable-devel` and `make`
for four pairs: vulnerable/fixed × ASan/plain. VPATH builds need the generated
`vcs_track.h`, `filter.h` and `ipconv.h` seeded into the build/source
directories; `build-wire.sh` does that before the second `make`.

`run-wire.sh` starts each collector as
`nfcapd -4 -b 127.0.0.1 -p PORT -M DIR/flows -t 5 -v 3`, sends one datagram
with `python3 harness/wire_send.py PORT MODE`, stops it with SIGTERM and
reads the renamed capture with `nfdump -r CAP -o 'fmt:%ts|%sp|%dp|%pr|%pkt|%byt'`.
Ports 10081–10086 are used sequentially on 127.0.0.1 only. Evidence lives in
`harness/out/wire/` (ASan) and `harness/out/wire-plain/` (plain).

```
bash lab/frontier/nfdump2shell/run-wire.sh
TOTAL: 13 PASS / 0 FAIL
V_BUILD=src/build-vuln-plain/src F_BUILD=src/build-fixed-plain/src \
  WIRE_OUT=harness/out/wire-plain bash run-wire.sh
TOTAL: 13 PASS / 0 FAIL
```

Observed (values differ between runs because the store is wall-clock derived):

```
vuln-attack   Process_nfd: record size error. Size v3header: 6274 > size left: 64
              Summary: total flows: 1, total bytes: 1
vuln-safe     Summary: total flows: 2, total bytes: 680, total packets: 8
vuln-icmp     Process_nfd: record size error …
              Summary: total flows: 1
vuln-single   Summary: total flows: 1 (fields read stale bytes past packet)
fixed-attack  Process_nfd: Corrupt nfd record: expected 2 records, processd: 0
              Summary: total flows: 0
fixed-safe    Summary: total flows: 2, total bytes: 680
```

No `ERROR: AddressSanitizer` line appears in any live daemon log: `nfcapd`
receives into `malloc(NETWORK_INPUT_BUFF_SIZE)` (65535 bytes,
`src/collector/nfnet.h:49`), so the 8-byte store stays inside the allocation.
The live object overlapped is the *next V3 record's 12-byte header* in the
same datagram; `Process_nfd()` rejects the corrupted record and the final
capture contains one flow instead of two. The written value comes from
`fs.received` (`gettimeofday()` immediately before dispatch in
`src/nfcapd/nfcapd.c:436-461`), not from the packet.

Negative result (preserved): an alias shape with a 4-byte element in a
16-byte record passes the pinned verifier and puts the store inside the
following, still structurally valid record's payload; it was sent live in
`alias-icmp`/`alias-tcp` variants with distinctive `inPackets` bytes. No
chosen-byte write into a processed record was observed: `Process_nfd()`
`memcpy`s each record to the output block *before* applying
`msecReceived`/ICMP mutations, and `nfdump` rejects the aliased record with
`Record: 2 Time error - last < first`. The csv line carried the pre-swap
value. That experiment was removed from the shipped runner; it is recorded
here only as a failed hypothesis, not evidence.

Wire reachability is now ESTABLISHED at the harness level (real loopback
socket, real pinned collector, vulnerable/fixed/safe controls). No pointer,
command or r5 claim is made. The live result awaits independent witness replay.
