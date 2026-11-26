# CVE-2026-121510 transport reachability (loopback-only, 2026-11-26)

All sockets bound to `127.0.0.1`; all ports unique and `>= 24000` (24010–24069).
No off-loopback traffic. Each case starts its own pinned daemon, sends the wire
bytes, captures stdout+stderr, and terminates the daemon. `rc = -6` is SIGABRT
from `abort_on_error=1`. `ASan` below means the log contains
`SUMMARY: AddressSanitizer: heap-buffer-overflow components/bundle6/reports.c:439 in record_parser_read_byte`.
Every per-case `.json` records the exact daemon `cmd`, `rc`, frame sizes and log path.

Builds (relative to `lab/frontier/ud3tn2shell/`):

- `vuln` = `src/ud3tn-v0.15.1/build/posix/ud3tn` (ASan)
- `fixed` = `src/ud3tn-v0.15.2/build/posix/ud3tn` (ASan)
- `plain` binary exists but was not used for these ASan measurements.

Runner: `transport_probe.py` (uses unmodified `harness/wire_trigger.py` and
`harness/gdb_probe.py`). BPv7 wire input: `make_bpv7_admin.py`.

## Main observations

| # | Transport / framing | Build | Input | rc | ASan at reports.c:439 | Log |
|---|---------------------|-------|-------|----|-----------------------|-----|
| 1 | MTCP, CBOR byte-string | vuln | BPv6 `eid_len=0`, marker 0x41, count 64, PoC default seq byte 0x00 | -6 | **yes** | `baseline/vuln-trigger-41.log` |
| 2 | MTCP, CBOR byte-string | vuln | BPv6 `eid_len=0`, marker 0x5A, count 64, PoC default seq byte 0x00 | -6 | **yes** | `baseline/vuln-chosen-5a.log` |
| 3 | MTCP, CBOR byte-string | vuln | BPv6 `eid_len=8` (safe control) | 0 | no | `baseline/vuln-safe-eid8.log` |
| 4 | MTCP, CBOR byte-string | fixed | BPv6 `eid_len=0` (build control) | 0 | no | `baseline/fixed-trigger-41.log` |
| 5 | SMTCP (passive), CBOR byte-string | vuln | BPv6 `eid_len=0`, seq 1 | -6 | **yes** | `smtcp-vuln-eid0.log` |
| 6 | SMTCP | fixed | BPv6 `eid_len=0`, seq 4 | 0 | no | `smtcp-fixed-eid0.log` |
| 7 | SMTCP | vuln | BPv6 `eid_len=8`, seq 6 | 0 | no | `smtcp-vuln-eid8.log` |
| 8 | SMTCP | vuln | BPv6 `eid_len=0`, seq 1..127 repeated (127 frames) | -6 | **yes** | `smtcp-r127.log` |
| 9 | TCPCLv3, DATA_SEGMENT `0x13 <SDNV len> <raw bundle>` after contact header | vuln | BPv6 `eid_len=0`, seq 3 | -6 | **yes** | `tcpclv3-vuln-eid0b.log` |
| 10 | TCPCLv3 | fixed | BPv6 `eid_len=0`, seq 5 | 0 | no | `tcpclv3-fixed-eid0.log` |
| 11 | TCPCLv3 | vuln | BPv6 `eid_len=8`, seq 7 | 0 | no | `tcpclv3-vuln-eid8.log` |
| 12 | TCPCLv3 | vuln | BPv6 `eid_len=0`, seq 1..127 repeated | -6 | **yes** | `tcpcl-r127.log` |
| 13 | TCPSPP (passive, APID 1), SPP-framed bundle | vuln | BPv6 `eid_len=0`, seq 9 | -6 | **yes** | `spp-vuln-eid0.log` |
| 14 | TCPSPP | fixed | BPv6 `eid_len=0`, seq 10 | 0 | no | `spp-fixed-eid0.log` |
| 15 | TCPSPP | vuln | BPv6 `eid_len=8`, seq 11 | 0 | no | `spp-vuln-eid8.log` |
| 16 | MTCP listener, raw bundle with **no** CBOR framing | vuln | BPv6 `eid_len=0`, seq 12 | 0 | no | `mtcp-raw-neg.log` |
| 17 | MTCP listener, ION-STCP-style 4-byte length prefix | vuln | BPv6 `eid_len=0`, seq 8 | 0 | no | `mtcp-stcp4-framing-neg.log` |
| 18 | TCPCLv3, malformed segment (CBOR header left inside payload) | vuln | BPv6 `eid_len=0`, seq 2 | 0 | no | `tcpclv3-vuln-eid0.log` |
| 19 | MTCP, CBOR | vuln | BPv7 status report, subject EID `[1,""]` (zero length) | 0 | no | `bpv7-zero-vuln-mtcp.log` |
| 20 | MTCP, CBOR | fixed | BPv7 `[1,""]` | 0 | no | `bpv7-zero-fixed-mtcp.log` |
| 21 | TCPCLv3 | vuln | BPv7 `[1,""]` | 0 | no | `bpv7-zero-vuln-tcpcl.log` |
| 22 | TCPSPP | vuln | BPv7 `[1,""]` | 0 | no | `bpv7-zero-vuln-spp.log` |
| 23 | TCPSPP | fixed | BPv7 `[1,""]` | 0 | no | `bpv7-zero-fixed-spp.log` |
| 24 | MTCP, CBOR | vuln | BPv7 subject EID `[1,0]` (dtn:none) | 0 | no | `bpv7-null-vuln-mtcp.log` |
| 25 | MTCP, CBOR | vuln | BPv7 subject EID `[1,"//attacker.dtn/"]` | 0 | no | `bpv7-normal-vuln-mtcp.log` |

Notes on specific cases:

- Cases 5 and 9 prove delivery over SMTCP and TCPCLv3. TCPCLv3 logs show
  `TCPCLv3: Handshake performed with "<incoming>", reports EID "dtn://attacker.dtn/"`
  before the ASan report, so the bundle was accepted on that CLA.
- Case 13 proves delivery over SPP framing. Its frame was
  `08 01 c0 00 00 a1 1c <4-byte seconds> <155-byte BPv6 bundle> 00 00`;
  the two CRC bytes are not verified by this RX parser
  (`components/cla/posix/cla_tcpspp.c:136-166`).
- Cases 16 and 17 are deliberate negatives: the same PoC bundle on a
  TCP socket without the framing each CLA expects is not dispatched to
  `bundle6_parser`. The ION-STCP 4-byte framing is a compile-time option
  defaulting to 0 (`include/cla/posix/cla_mtcp.h:18-21`) in the pinned builds.
- Case 18 is an invalid first attempt (payload accidentally included MTCP's
  CBOR header); it produced a clean handshake and rc 0, confirming the
  framing matters. Case 9 is the corrected, valid TCPCLv3 trigger.
- An earlier long-label SMTCP repeat run
  (`smtcp-vuln-repeat-seq1-127.log`, port 24034) is **invalid/excluded**: the
  daemon exited before listening because the AAP socket path exceeded
  `sun_path` (108 bytes); it is not a transport observation. The valid
  repeat runs are cases 8 and 12, whose bundles have refreshed timestamps
  and sequences 1..127.
- Cases 19–25: the BPv7 zero-EID bundle *did* reach admin-record handling —
  cases 19, 20, 21, 22 and 23 log
  `BundleProcessor: Received administrative record we cannot parse, discarding.`
  — yet neither ASan build reported a heap overflow. Case 24 (valid null EID)
  and case 25 (valid normal EID) likewise produced rc 0 and no ASan.

## Source findings

- BPv6 sink, `src/ud3tn-v0.15.1/components/bundle6/reports.c:422-444`: the
  source-EID length is read into `record_bundle_source_str_length`;
  `malloc(length + 1)` and `bytes_remaining = length` are set at 429–434;
  `RP_EXPECT_BUNDLE_SOURCE_EID` decrements `bytes_remaining` and writes
  `record_bundle_source_str[current_index++]` at 437–439 with no zero-length
  guard. With length 0, `bytes_remaining` wraps and the remaining admin bytes
  are written past a 1-byte allocation. Fixed build
  `src/ud3tn-v0.15.2/components/bundle6/reports.c:435-437` rejects
  `bytes_remaining == 0` before entering that state.
- BPv7 parser has **no analogous malloc-and-decrement sink**:
  `src/ud3tn-v0.15.1/components/bundle7/reports.c:344-356` parses the
  report's source EID through `bundle7_eid_parse_cbor` into a `struct eid`;
  `:427-487` handles the status report; `:600-652` handles BPDU records;
  `:655-688` is the entry point. EID parsing
  (`components/bundle7/eid.c:26-104`, `:107-174`, `:257-273`) allocates
  `malloc(4 + SSP_length + 1)` and copies the string once; for a zero-length
  `dtn` SSP it allocates 5 bytes and copies `"dtn:"` plus NUL. The
  `eid.c:87-90` validity check rejects an invalid resulting EID string,
  consistent with the observed `cannot parse` log. There is no length loop,
  decrement, or indexed write analogous to BPv6 `reports.c:437-441`.
- Framing/transport paths observed in source: MTCP
  `components/cla/posix/cla_mtcp.c:344-413`; SMTCP reuses the MTCP vtable
  (`components/cla/posix/cla_smtcp.c:77-100`); TCPCLv3
  `components/cla/posix/cla_tcpclv3.c:732-789` with segment parser
  `components/cla/posix/cla_tcpclv3_proto.c:74-128`; TCPSPP
  `components/cla/posix/cla_tcpspp.c:228-269`. Version selection for all of
  these is `components/cla/cla_contact_rx_task.c:118-145` (first byte 6 selects
  BPv6), so the same BPv6 admin-record sink is reachable regardless of CLA
  framing once a raw BPv6 bundle is delivered.

## Reproduction

From `/home/mesh-home/mishe-tauftauf2shell`:

```
# Baseline MTCP (four cases, harness helper)
python3 lab/frontier/ud3tn2shell/harness/wire_trigger.py \
  --src lab/frontier/ud3tn2shell/src \
  --outdir lab/frontier/ud3tn2shell/transport-w26/baseline \
  --vuln-port 24010 --fixed-port 24020

# One case with the generalized runner (repeat for the labels/ports in the table)
python3 lab/frontier/ud3tn2shell/transport-w26/transport_probe.py \
  --label <label> --build <vuln|fixed> --transport <mtcp|smtcp|tcpclv3|tcpspp|mtcp-stcp4|mtcp-raw> \
  --port <port> --eid-len <0|8> --seq <1..127> [--repeat 127]
```

Examples that produced ASan hits:

```
python3 lab/frontier/ud3tn2shell/transport-w26/transport_probe.py --label smtcp-vuln-eid0 --build vuln --transport smtcp --port 24031 --eid-len 0 --seq 1
python3 lab/frontier/ud3tn2shell/transport-w26/transport_probe.py --label tcpclv3-vuln-eid0b --build vuln --transport tcpclv3 --port 24042 --eid-len 0 --seq 3
python3 lab/frontier/ud3tn2shell/transport-w26/transport_probe.py --label spp-vuln-eid0 --build vuln --transport tcpspp --port 24051 --eid-len 0 --seq 9
```

BPv7 wire inputs and one case:

```
python3 lab/frontier/ud3tn2shell/transport-w26/make_bpv7_admin.py --out lab/frontier/ud3tn2shell/transport-w26/bpv7-zero-eid.bin --eid zero --seq 1
python3 lab/frontier/ud3tn2shell/transport-w26/transport_probe.py --label bpv7-zero-vuln-mtcp --build vuln --transport mtcp --port 24061 --wire-file lab/frontier/ud3tn2shell/transport-w26/bpv7-zero-eid.bin
```

Each daemon was launched with `-b 6 -e dtn://ud3tn.dtn/ -c <CLA>:127.0.0.1,<port>[,...] -s <label>.aap.sock -S <label>.aap2.sock -L 4` and
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1`; the exact command is in
each `<label>.json` (`cmd` field).

## Honest conclusion and limits

- The BPv6 trigger is **not specific to CBOR-framed MTCP**. With correct CLA
  framing it was reproduced on SMTCP, TCPCLv3, and SPP-framed TCPSPP on the
  ASan v0.15.1 build; the v0.15.2 ASan build and the `eid_len=8` safe input
  were clean on each of those transports.
- Without the framing expected by the listener (raw TCP bytes on MTCP, or a
  4-byte STCP length prefix on this default build), the observed result was
  no dispatch and no ASan hit. This is a negative observation about these
  exact inputs, not a claim about other framing variants.
- BPv7 admin records have no corresponding sink in the inspected source, and
  a zero-length subject-EID status report over MTCP, TCPCLv3 and SPP produced
  no ASan hit on either build; the v0.15.1 log confirms the admin parser was
  reached and rejected the record.
- Not exercised: the `bibe` CLA (requires AAP-level BPDU encapsulation and
  upper/lower node configuration) and the `sqlite` storage CLA (not a network
  ingress). No conclusion is claimed for those paths.
