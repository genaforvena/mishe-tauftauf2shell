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
| `harness/wire_send.py` | `6db336c599ad49089819adb5f02c4a8c38de50591b40807e23e73d31ebd0fe0c` |

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

The first clean-archive replay from commit `9fbeec88` returned
**3 PASS / 10 FAIL**: `build-wire.sh` did `cd .../src` before creating that
directory, so in an archive with no ignored `src/` the four builds landed at

the lab root and the runner could not find the collectors. The failure was
diagnosed from `harness/out/wire/vuln-attack/daemon.log`
(`nfcapd: No such file or directory`), not by weakening an assertion.
Commit `81e3cd8e` adds `mkdir -p .../src` plus an explicit post-build binary
check; the clean replay was repeated from that commit.

Correction (2026-11-26 20:31Z): this IPv4 bound does **not** cover IPv6.
On `::1` a UDP datagram may carry 65527 B, so the same terminal short element
puts the store at 65543..65550, past the allocation. The section below
measures that case live; the IPv4 `READ`-only result above stands unchanged.

Replay from `git archive 81e3cd8e lab/frontier/nfdump2shell` into
`/tmp/w-nfdump-wire-clean2`: `build-wire.sh` fetched and SHA-verified both
tarballs and built all four collector pairs, then `run-wire.sh` returned
**13 PASS / 0 FAIL** for the ASan builds and **13 PASS / 0 FAIL** for the
plain builds (`V_BUILD`/`F_BUILD`/`WIRE_OUT` overrides). `run-witness.sh`
from the first (faulty) clean archive still returned `WITNESS REPLAY PASS`
(22 PASS / 0 FAIL) and `run-adjacent.sh` 12 PASS / 0 FAIL — those runners do
not use the full collector builds.

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
command or r5 claim is made. The live-wire and boundary replays are still
owed; the later chosen-byte result was replayed independently by the
witness (W280, 2026-11-26 16:59Z, ESTABLISHED AS LABELED).

## Packet-chosen bytes in a processed live record (2026-11-26)

New local files, with SHA-256:

| artifact | SHA-256 |
| --- | --- |
| `run-alias.sh` | `c5f34ad5143ef26f5ad0d6e67369922d5ac6b83175b4affa5b711d3e8658a501` |
| `harness/alias_readback.py` | `65372e4da0df8d8737ee47b6e271b020f3e953f1537c26339dedb35ce20206b0` |
| `harness/wire_send.py` (alias modes added) | `6db336c599ad49089819adb5f02c4a8c38de50591b40807e23e73d31ebd0fe0c` |

`wire_send.py` gained `alias` and `alias-safe` modes. The alias datagram is
120 bytes: record 1 has a truncated EXgenericFlow (length 20) plus an
8-byte dummy element (type 42, below `MAXEXTENSIONS` 43), giving record 1
size 40; record 2 is a complete 52-byte element whose payload starts
`34 12 00 00 01` (chosen `srcPort`, zero `dstPort`, ICMP `proto` at offset 4
as seen by record 1). Record 1's `msecReceived` store lands on its own
dummy element, and the pinned ICMP swap writes `12 34` at record 2's
payload offset 2, which is copied and processed later in the same loop.

`run-alias.sh` starts `nfcapd -4 -b 127.0.0.1 -p 10101..10104 -M DIR/flows
-t 5`, sends one datagram, SIGTERMs the daemon and reads the capture.
`harness/alias_readback.py` finds record 2's
`0b004800020000000000000301003400` header/element prefix in the capture
(last match, to avoid a false match inside record 1) and prints the first
8 payload bytes. In-tree result: **11 PASS / 0 FAIL**.

```
vuln-alias-asan    REC2_MSECFIRST=0000123401000000  total flows: 2
vuln-alias-plain   REC2_MSECFIRST=0000123401000000  total flows: 2
vuln-alias-safe    REC2_MSECFIRST=3412000001000000  total flows: 2
fixed-alias        REC2_FOUND=0                     total flows: 0
```

With the ASan collector, `nfdump` shows the alias flow timestamp
`1970-03-01 19:42:42.176`; the safe control shows `1970-02-19
17:02:51.956`. The fixed collector logs `Corrupt nfd record: expected 2
records, processd: 0`. No `ERROR: AddressSanitizer` appears: the store is
inside the 65535-byte receive allocation. This is a packet-chosen 2-byte
write at a packet-chosen offset in a record the collector processed; it is
not a pointer, a command or r5. The earlier alias attempt remains a failed
hypothesis (header clobbered first), preserved above.

Clean-archive replay of commit `ca2bb2b0` into
`/tmp/w-nfdump-alias-clean` rebuilt all four collector pairs from the
SHA-verified tarballs and returned **11 PASS / 0 FAIL** for `run-alias.sh`,
**13 PASS / 0 FAIL** for `run-wire.sh` (ASan), **13 PASS / 0 FAIL** for the
plain `run-wire.sh` overrides, and `WITNESS REPLAY PASS` for
`run-witness.sh`. No generated evidence was copied into the archive and no
assertion was weakened.

Independent witness verdict: W280 (2026-11-26 16:59Z) replayed `run-alias.sh`
from `git archive ca2bb2b0` into `/tmp/w280-nfdump` and recorded ESTABLISHED
AS LABELED: all four collectors rebuilt, tarballs hashed, `11 PASS / 0 FAIL`,
the two chosen-byte readbacks and both flow counts reproduced. No rung 5.

Failed framing hypothesis (2026-11-26, not shipped): a 58-byte first record
(20-byte flow element plus a 26-byte dummy) was built to aim the pinned
ICMP swap at the second record's 2-byte `size` field, with the chosen bytes
in the first record's tail. The live collector reported `Next record -
type: 11, size: 64` for record 2 and wrote 2 flows: the short flow view's
`proto` byte reads the second record's size low byte (`0x40`, 64 decimal),
not its `numElements`, so the `IPPROTO_ICMP` branch never ran. Shifting the
first record to 56 bytes makes `proto` read `numElements` low (`01`), but
then the swap's source bytes are the fixed V3 record type (`0b 00`), so
there is no attacker-chosen size. The sender modes and runner were removed;
this is a negative result, not a claim.

## Receive-allocation boundary (2026-11-26)

`harness/wire_send.py` modes `edge` and `edge-safe` build maximum-size
65507-byte datagrams; `run-edge.sh` drives them against the live ASan
collector. `edge` ends with a 4-byte header-only EXgenericFlow element,
so `GetExtension()` returns `in_buff + 65507` and the pinned store lands
at 65523..65530 inside the 65535-byte `malloc` (`nfcapd.c:273`,
`nfnet.h:49`). In-tree result: **8 PASS / 0 FAIL**. Observed ASan report:
`heap-buffer-overflow`, `READ of size 1`, `nfd_raw.c:259:34 in
Process_nfd`. Safe control: 1 flow, no report. Fixed control: `Corrupt
nfd record`, no report. The in-tree `build-vuln-plain` directory is stale
ASan-instrumented (`config.log` CFLAGS contain `-fsanitize=address`), so
`run-edge.sh` does not assert on it; clean-archive builds use empty
CFLAGS. No write crosses the allocation, so this lane bounds rather than
advances the grade.

Witness replay of this boundary lane is still owed (tape #5680); the
in-tree and clean-archive author replays each returned 8 PASS / 0 FAIL.

## Chosen bytes in a processed record's V3 header (2026-11-26 18:15Z)

Additive files/hashes (`wire_send.py` and `alias_readback.py` gained
backward-compatible modes):

| artifact | SHA-256 |
| --- | --- |
| `run-hdr.sh` | `35281932abe4f11a2a37e057deb6f40e0eed10952369e53d52701f7175590d69` |
| `harness/wire_send.py` | `23f5a64c2a7347b7830a423e2f59ddb4f8a67cb2b4ef7a20fdb4d8f002177476` |
| `harness/alias_readback.py` | `ff3adf90f161c95201bbf164c7d3064cdbe952844e2f823e0e2fa2854bb2e5c2` |

`hdr` geometry: record 1 is 48 bytes (12-byte header + truncated 20-byte
EXgenericFlow + 16-byte dummy), so its flow view sees `srcPort` at
record1+56, `dstPort` at record1+58 and `proto` at record1+60. Record 2
starts at record1+48, so those offsets are its `exporterID` (8..9),
`flags`/`nfversion` (10..11) and element type (12). The element type low
byte is 1 (ICMP), which triggers the pinned swap: the chosen `exporterID`
wire bytes `03 ab` are written reversed as `ab 03` into record 2's
`flags`/`nfversion`, and `exporterID` is zeroed, all before record 2 is
verified, copied and written to the capture. Safe mode uses a complete
52-byte first element; fixed mode rejects the short element.

`run-hdr.sh` ports 10121..10124, **12 PASS / 0 FAIL** in-tree:

```
vuln-hdr-asan    REC2_EXPORTER=0000 REC2_FLAGS_NFVERSION=ab03  flows: 2
vuln-hdr-plain   REC2_EXPORTER=0000 REC2_FLAGS_NFVERSION=ab03  flows: 2
vuln-hdr-safe    REC2_EXPORTER=03ab REC2_FLAGS_NFVERSION=0003  flows: 2
fixed-hdr        REC2_FOUND=0                                 flows: 0
```

No ASan report (the store is inside the 65535-byte receive buffer); fixed
logs `Corrupt nfd record: expected 2 records, processd: 0`. Regression
after the sender refactor: `run-alias.sh` 11 PASS / 0 FAIL, `run-wire.sh`
13 PASS / 0 FAIL, `run-edge.sh` 8 PASS / 0 FAIL. This extends chosen-byte
control from a flow payload timestamp to a record header control field in
a live processed record; still no pointer, command or r5. Witness replay
is owed.

Clean-archive replay of commit `4c1fc9ee` into an empty
`/tmp/w-nfdump-hdr-clean` rebuilt all four collector pairs from the GitHub
tarballs verified against the pinned SHA-256 constants in `build-wire.sh`
(`BUILD_WIRE_OK`): `run-hdr.sh` returned **12 PASS / 0 FAIL**. The clean
readbacks and flow counts match the in-tree result above; no assertion was
weakened and no generated evidence was copied into the archive.

## Chosen byte decides record acceptance via the element type (2026-11-26 18:54Z)

Additive modes in `harness/wire_send.py` (`etype`, `etype-bad`, `etype-safe`)
and `harness/alias_readback.py` (`etype`); new runner `run-etype.sh`.
Hashes:

| artifact | SHA-256 |
| --- | --- |
| `run-etype.sh` | `c46660f65d5eb0c090467f8acf170a2719c735e54a2f241668ee2d6ec17c2ff3` |
| `harness/wire_send.py` | `9ea501252bbd3d1bd5b6b7b258b48adedb54a9cd2c0d3f2dd944dccf30266682` |
| `harness/alias_readback.py` | `542a34fb225936746662cdbbb14578c1911b1659c86fe78958c4cdb55fa3be07` |

Geometry: record 1 is 46 bytes (12-byte header + 20-byte truncated
EXgenericFlow + 14-byte dummy), so its 48-byte flow view starts at
record1+16 and sees `srcPort` at record2+10 (record 2 `flags`/`nfversion`),
`dstPort` at record2+12 (element type) and `proto` at record2+14 (element
length low byte, 1 = ICMP). When `Process_nfd()` handles record 1 the
pinned swap writes `nfversion`,`flags` byte-reversed into record 2's
element type and zeroes the source. Record 2's wire element type is 43
(`>= MAXEXTENSIONS`, rejected by `VerifyV3Record()`) in every case, so its
acceptance is decided solely by that crossing write. The declared element
length is 257 including its 4-byte header; record 2 size is 269.

`run-etype.sh` ports 10131..10135, **17 PASS / 0 FAIL** in-tree:

```
etype      flags/nfversion=0001 -> REC2_TYPE=0100 REC2_LENGTH=0101  flows: 2
etype-bad  flags/nfversion=002b -> REC2_FOUND=0, Corrupt nfd record    flows: 1
etype-safe complete first element, no crossing write -> REC2_FOUND=0   flows: 1
fixed      short element rejected -> Corrupt nfd record               flows: 0
```

The vulnerable ASan and plain collectors both write two flows with
`REC2_FLAGS_NFVERSION=0000` in the captured element header: the source
bytes were consumed by the crossing write. Changing the single chosen
`nfversion` byte from `01` to `2b` makes the same wire element type 43 and
the live collector rejects record 2 (`processd: 1`), leaving only record 1's
flow. The safe control keeps the same rejected wire type without a crossing
write and also yields one flow; the fixed build rejects the short element
and writes none. No ASan report (the store is inside the 65535-byte receive
buffer).

Caveat preserved: both the source (`flags`/`nfversion`) and the target
(element type) are fields on the attacker-supplied wire, so this shows a
parser decision made on bytes written across the truncated element's
boundary, **not** a capability gain over setting the element type directly.
No pointer-bearing object, benign marker or command side effect; the grade
stays rung 3 verbatim / rung 4 PARTIAL. An early shape with record size 273
(4 bytes too many) failed `VerifyV3Record()` with a 4-byte leftover and was
corrected; the failed intermediate is preserved here, not hidden.

Clean-archive receipt: `git archive cd47299c lab/frontier/nfdump2shell`
into an empty `/tmp/w-nfdump-etype-clean` rebuilt all four collector pairs
from the pinned GitHub tarballs verified against `build-wire.sh`
(`BUILD_WIRE_OK`, including `BUILT build-fixed-plain`), then
`bash run-etype.sh` returned **17 PASS / 0 FAIL** with the same capture
readbacks and flow counts as in-tree. No assertion weakened; no generated
evidence copied into the archive. Witness replay requested on the tape.

## Build-label correction and pointer-object boundary (2026-11-26 19:29Z)

Material correction to earlier full-collector "plain" labels. The pinned
`configure.ac:27-36` unconditionally appends
`-fno-omit-frame-pointer -fsanitize=address` when `--enable-devel` is set,
even when `CFLAGS` is empty. `build-wire.sh` had passed `--enable-devel`
for all four builds, so `build-vuln-plain` and `build-fixed-plain` were
ASan-instrumented too: their old `Makefile` had
`CFLAGS = ... -fsanitize=address ...,` and `nm` on the old
`build-vuln-plain/src/nfcapd/nfcapd` showed `T __asan_init` and
`T __asan_report_store8`, although `ldd` found no `libasan` (runtime linked
statically). The generated `harness/driver.c` "plain" binaries in
`run-all.sh` are a separate thing: compiled directly by `gcc` with no
sanitizer flag, genuinely uninstrumented.

`build-wire.sh` now configures plain builds with `--disable-devel` and
asserts the built ELF actually has (`asan`) or lacks (`plain`)
`__asan_init`; libtool shell wrappers are resolved to `.libs/` first, and a
non-ELF target fails the check. Both the true/false discrimination and
`BUILD_INSTRUMENTATION_OK` were observed. Fresh plain ELFs
(`src/build-vuln-plain/src/nfcapd/.libs/nfcapd`,
`src/build-fixed-plain/src/nfcapd/.libs/nfcapd`) have zero `__asan_init`
symbols and no `libasan` in `ldd`.

Consequence: earlier full-collector observations labeled "plain" were made
under ASan instrumentation. The observed chosen bytes and flow counts stand,
but the "without ASan" wording in `run-alias.sh`, `run-etype.sh` and
`run-hdr.sh` case labels described those builds wrongly until this fix. No
grade claim changes. After the rebuild: `run-all.sh` 10/0,
`run-adjacent.sh` 12/0, `run-alias.sh` 11/0, `run-etype.sh` 17/0,
`run-hdr.sh` 12/0, `run-edge.sh` 8/0, and `run-wire.sh` with genuine plain
builds 13/0. The genuine plain element-type case still reads
`REC2_FOUND=1 REC2_TYPE=0100 REC2_LENGTH=0101 REC2_FLAGS_NFVERSION=0000`
with two flows.

Pointer-object boundary: source inspection of the pinned tree found no
pointer field in the V3 wire records or extension structs written by
`Process_nfd()` (`pins/nfxV3.h:138-178` for `EXgenericFlow_t`,
`pins/nfxV3.h:787-790` for `record_map_t`, which belongs to the reader).
Pointer-bearing objects are separate allocations: `FlowSource_t` at
`src/collector/flowsource.h:45-63` holds `nffile`, `dataBlock`,
`exporters` and `last_exp`; `exporter_entry_t` is returned by
`getExporter()` and updated at `nfd_raw.c:169-174` and `:296`. GDB at the live
`Process_nfd()` breakpoint (`nfd_raw.c:157`, caller `nfcapd.c:461`) measured:

```
ASan build: in_buff=0x531000000800 fs=0x512000000340
            dataBlock=0x7fffef6d6800 nffile=0x50c0000001c0
Genuine plain ELF: in_buff=0x555555578240 fs=0x5555555882c0
            dataBlock=0x7ffff4e40010 nffile=0x555555588f40
```

In the plain allocator the 65535-byte `in_buff` chunk ends at
`in_buff+0x10010`; the following small chunk's user bytes at
`in_buff+0x10010` hold the source-ident string, and `fs` starts 0x80 bytes
later. Neither crossing write (8-byte store at element payload offset 16,
ICMP swap at `srcPort`/`dstPort`) reaches those bytes from a record inside
`in_buff`. An over-long element can make `GetExtension()` read past the
buffer (`nfd_raw.c:259` under the max-size `edge` shape), but that is a
read, not a chosen-pointer write. No pointer overwrite, marker or command
side effect was observed; grade stays rung 3 verbatim / rung 4 PARTIAL.

Clean-archive receipt for `ceb87a6e`: `git archive` of the committed lane
into an empty `/tmp/w-nfdump-plainfix-clean`, with only the two ignored
SHA-verified pinned tarballs copied into `src/`, rebuilt all four collectors
from scratch (`BUILT build-vuln-asan`, `BUILT build-fixed-asan`,
`BUILT build-vuln-plain`, `BUILT build-fixed-plain` followed by
`BUILD_INSTRUMENTATION_OK` and `BUILD_WIRE_OK`). On those fresh binaries:
`run-etype.sh` 17 PASS / 0 FAIL, `run-alias.sh` 11 PASS / 0 FAIL,
`run-hdr.sh` 12 PASS / 0 FAIL, `run-edge.sh` 8 PASS / 0 FAIL, and
`run-wire.sh` with `V_BUILD`/`F_BUILD` set to the genuine plain builds
13 PASS / 0 FAIL. No generated evidence was copied into the archive and no
assertion was weakened.

## Crossing-write bound on the live receive allocation (2026-11-26 19:47Z)

The direct route to a pointer-bearing object past `in_buff` is closed by
arithmetic and live observation, not by a harness-only assumption. Pinned
`EXgenericFlow_t` offsets (`pins/nfxV3.h:138-192`) put `msecReceived` at
element-header offset +20..27, `srcPort` at +44..45, `dstPort` at +46..47
and `proto` at +48. A valid IPv4 UDP datagram carries at most 65507 bytes,
and `nfcapd.c:273` receives into a 65535-byte `malloc`, so an element
header must start at E<=65503. The 8-byte store then ends at E+27<=65530,
five bytes inside the allocation. For the pinned ICMP swap to be triggered
by packet bytes, `proto` must satisfy E+48<=65506, which forces
`dstPort`<=65504, also inside. For `dstPort` to cross the allocation
(E+46>=65535), E>=65489 and `proto`>=65537: the trigger byte lies past both
the datagram and the allocation, so the swap cannot be wire-triggered into
that region.

GDB confirmation on the genuine uninstrumented ELF
(`src/build-vuln-plain/src/nfcapd/.libs/nfcapd`, `LD_LIBRARY_PATH` set to
`src/build-vuln-plain/src/libnffile/.libs`), break `nfd_raw.c:259`, live
`edge` datagram (`WIRE_LEN=65507`):

```
BP in_buff=0x555555578230 cnt=65507 fs=0x5555555882b0
in_buff+65528: 01 00 00 00 00 00 00 00
in_buff+65536: 00 00 00 00 00 00 00 00
in_buff+65544: 21 00 00 00 00 00 00 00
```

`genericFlow` is optimized out at `-O2`; from the shipped `edge_datagram()`
layout the element header sits at `in_buff+65503` and the flow view at
`in_buff+65507`, matching the ASan `READ of size 1` at `nfd_raw.c:259`
recorded by `run-edge.sh`. The `01` residue at +65528 is heap state, not a
wire-chosen trigger; no chosen write crossed the allocation. The temporary
GDB runner and log are under the ignored `harness/out/gdb-edge-swap*`;
they are not part of the replay. Grade unchanged: rung 3 verbatim / rung 4
PARTIAL, NO r5.

## Closure: the swap cannot set an accepted record size or element count (2026-11-26 20:11Z)

Pinned `recordHeaderV3_t` offsets are `type` +0..1, `size` +2..3,
`numElements` +4..5, `engineType`/`engineID` +6..7, `exporterID` +8..9,
`flags`/`nfversion` +10..11. From the truncated flow view (`srcPort` at
record1+56, `dstPort` +58, `proto` +60) the two framing targets are
structurally closed:

- record1 size 54 aims `dstPort` at record2 `numElements` (+4..5); `srcPort`
  then aliases record2 `size` (+2..3), and the pinned swap zeroes `srcPort`
  after copying. `VerifyV3Record()` sees size 0 and rejects.
- record1 size 56 aims `dstPort` at record2 `size` (+2..3); `srcPort` aliases
  record2 `type` (+0..1) and is zeroed, so verification rejects type != 11.

The already-shown `exporterID`, `flags`/`nfversion` and element-type lanes
are unaffected: there the zeroed source field is not needed for acceptance.

Live confirmation on the genuine uninstrumented plain collector, all on
loopback, with a throwaway generator (`/tmp/nfdump-ctl-probe.py`; not shipped):

```
attack  port 10143, 1351-byte datagram:
  record1 54 B (12 + truncated flow 20 + 22-byte dummy),
  record2 size 1281 (0x0501), numElements 261, engineType 1 (ICMP trigger)
  log: "Corrupt nfd record: expected 2 records, processd: 1"
  summary: "Flows: 1, Packets: 0, Bytes: 3096224743817216"
safe    port 10142, same valid record2 after a complete 52-byte record1:
  daemon summary "Flows: 2", no Corrupt line
fixed   port 10144, same attack datagram:
  log: "Corrupt nfd record: expected 2 records, processd: 0"
  summary: "Flows: 0"
```

The safe arm proves the 1281-byte / 261-element record2 is well formed; the
attack arm therefore fails because the swap zeroes its size. No pointer,
marker or command; grade unchanged: rung 3 verbatim / rung 4 PARTIAL, NO r5.
No stale collectors remained after the three cases.

## IPv6 allocation crossing: live WRITE and collector abort (2026-11-26 20:31Z)

New local files, with SHA-256:

| artifact | SHA-256 |
| --- | --- |
| `harness/wire_send.py` (IPv6 modes added) | `adcdf7f4576ff0cd83a624a4aacf0db0a16824a08f1cb9acf6cc8283e083ac44` |
| `run-v6edge.sh` | `013e2862226c243a164646bd2e93179a4926760e7964071439a4a6f67696509b` |

Pinned `configure.ac` builds the four collector pairs; no source changed.
`wire_send.py` gained `v6edge` / `v6edge-safe`, parameterising the existing
max-size datagram at 65527 B (16 B nfd header + 12 B record header + dummy
element + 4 B header-only EXgenericFlow). IPv4's 65507 B cap leaves the store
inside `in_buff`; IPv6's 65527 B cap moves `msecReceived` to 65543..65550,
eight bytes past the 65535-byte allocation at `nfcapd.c:273`.

```
bash lab/frontier/nfdump2shell/run-v6edge.sh
TOTAL: 17 PASS / 0 FAIL
```

Live ASan vulnerable collector (`harness/out/v6edge/v6-vuln-asan-attack/daemon.log`):

```
==936104==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 8 at 0x531000010807 thread T0
    #0 Process_nfd .../src/netflow/nfd_raw.c:256:39
    #1 run .../src/nfcapd/nfcapd.c:461:17
0x531000010807 is located 8 bytes after 65535-byte region
    [0x531000000800,0x5310000107ff)
allocated by thread T0 here:
    #1 run .../src/nfcapd/nfcapd.c:273:21
SUMMARY: AddressSanitizer: heap-buffer-overflow ... nfd_raw.c:256:39 in Process_nfd
```

The safe 65527 B complete-element datagram gives one flow with no report;
the fixed collector rejects the short element (`Corrupt nfd record:
expected 1 records, processd: 0`) with no report.

Genuine uninstrumented plain collector: the attack exits `rc=134` (SIGABRT)
at shutdown in three consecutive runs on loopback ports 10231-10233, with
glibc heap diagnostics `double free or corruption (!prev)` (two runs) and
`free(): invalid next size (normal)` (one run). The written 8 bytes are
collector-time derived, so which metadata word is hit varies between runs.
The same-size safe datagram and the fixed collector both exit `rc=0`, with
one clean flow and `Corrupt nfd record` respectively; no corruption message.
The runner asserts all six cases on ASan, genuine plain and fixed builds.

This is a live wire-triggered OOB **write** past the receive allocation and a
deterministic availability impact in the real collector, unlike the earlier
IPv4 `READ`-only boundary. It is still not a chosen written value, pointer
overwrite, benign marker or command: no r5. Grade: rung 3 confirmed in the
live process as well as the harness; rung 4 DEMONSTRATED for availability
(live daemon abort with vulnerable/fixed/safe controls) alongside the earlier
rung 4 PARTIAL chosen-byte field control.

Clean-archive replay: `git archive 59f81481 lab/frontier/nfdump2shell`
extracted into an empty `/tmp/w-nfdump-v6-clean`; `run-v6edge.sh`
self-provisioned both SHA-verified pinned tarballs and rebuilt all four
collector pairs (`BUILD_WIRE_OK`, `BUILD_INSTRUMENTATION_OK`). The runner
returned **17 PASS / 0 FAIL**, rc 0, with the same six cases: ASan WRITE-8
8 bytes past a 65535-byte region at `nfd_raw.c:256`; plain attack `rc=134`
with `free(): invalid next size (normal)`; safe and fixed `rc=0` with one
flow and `Corrupt nfd record` respectively. No generated evidence, build
directory or assertion was carried into the archive.

## Live heap target of the IPv6 store (2026-11-26 21:06Z)

New local file:

| artifact | SHA-256 |
| --- | --- |
| `run-v6heap.sh` | `71c3c69d593620e18a49bd4b34870c40844d61f5a46da6f86bf26a0308b83fce` |

The charter's open question — which live heap object the 8-byte store
overlaps — is measured in the genuine uninstrumented plain collector, not
in a harness. `run-v6heap.sh` starts `src/build-vuln-plain/src/nfcapd/.libs/nfcapd`
under GDB with a breakpoint at `nfd_raw.c:256`, sends the same 65527-byte
`v6edge` datagram on `::1`, and reads the malloc chunk metadata from the
running process. No source, packet or build is synthetic.

```
bash lab/frontier/nfdump2shell/run-v6heap.sh
TOTAL: 7 PASS / 0 FAIL

HEAPMAP in_buff=0x5555555781c0 chunk_size=65552 hdr_off=65536
        next_chunk=0x5555555881c0 target=0x5555555881c7
        target_off=7 size_field=33
0x5555555881d0:	"--1"
```

`in_buff` is the 65535-byte `malloc` at `nfcapd.c:273`, rounded to a 65552-byte
chunk. The next chunk header is exactly 65536 bytes later; its user data holds
the 32-byte source-ident chunk (`"--1"` here), followed by the `FlowSource_t`
chunk that holds `fs->nffile` and other pointers. The maximum IPv6 store
address is `in_buff+65543`, i.e. byte 7 of the next chunk header: it writes
one byte into the high byte of `prev_size` and seven bytes into the low bytes
of that chunk's `size` field (33, `0x21`, before the write). That is the
direct cause of the observed `free(): invalid next size (normal)` / `double
free or corruption (!prev)` abort. The abort message varies with the
collector-timestamp-derived value; the target word does not.

This measurement also closes the pointer-control route through this store:
the write offset is bounded by `cnt+16`, and a UDP datagram on `::1` cannot
exceed 65527 bytes, so the store cannot reach past `in_buff+65543` — seven
bytes into the next header, well short of any pointer-bearing field in the
following chunks. Value remains collector-time derived; no pointer, marker
or command. Grade unchanged: rung 3 live / rung 4 availability plus
chosen-byte PARTIAL, NO r5.
