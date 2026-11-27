# lwipmqtt2shell — status (admitted 2026-11-27 04:0xZ)

Staged by frontier W313 from CVE-2026-87121 / GHSA-h8q6-7rjx-3m2r (CWE-787,
CISA ICSA-26-265-01, CVSS v3.1 9.8 / v4.0 9.3). Vulnerable tag
`STABLE-2_2_1_RELEASE` is `77dcd25a72509eb83f72b033d219b1d40cd8eb95`; there is
no fixed upstream release as of 2026-11-27, so the fixed control is the
production hunk of upstream `68b2c1191886578d40342846db6ab9a0099c2f40`
applied to the vulnerable tree. The delta is a bounds check on
`client->msg_idx` in `src/apps/mqtt/mqtt.c:862`. Window 208 was adopted as-is
(panes %422/%423 dead=0, 209/209 unique registry names); operator clean-archive
replay and independent W314 witness replay are both done: **ESTABLISHED AS
LABELED** at the R2/R3/limited-R4 scope, no grade change, NO r5.

The harness runs the byte-unmodified public 2.7 KiB `mqtt_repro.c` (Savannah
bug 68590) directly into `mqtt_parse_incoming()` with a 200-byte pbuf of
`0xff`. Vulnerable pin: UBSan `array-bounds` rc 1,
`mqtt.c:862: runtime error: index 128 out of bounds for type 'u8_t [128]'`
under both gcc 13.3 and clang 18. Fixed pin with the same input: rc 0,
`msg_idx=128`, clean. Vulnerable pin with a 128-byte safe input: rc 0,
`msg_idx=128`, clean. Plain differential: vulnerable `msg_idx=200`, fixed `128`.

The published "ASan heap-buffer-overflow 72 bytes past `rx_buffer`" was **NOT
observed**: `rx_buffer[128]` is followed by `struct mqtt_ringbuf_t output`
inside `mqtt_client_s`, so the overrun is intra-object and heap ASan is silent
(vulnerable rc 0, `msg_idx=200`). The confirmed oracle is UBSan `array-bounds`.

Canary readback with `output.buf` prefilled `0xee`: vulnerable `0xff` input
changes 68/256 bytes, `put=get=65535`, first `ff ff ff ff`; `0x80` input
changes 68/256, `put=get=32896`, first `80 80 80 80`; fixed pin 0/256 changed,
`put=get=0`, first `ee ee ee ee`.

**Grade at handoff: R1 — / R2 ✓ / R3 ✓ (UBSan array-bounds, both compilers) /
R4 LIMITED (chosen bytes at chosen offsets in an adjacent live object, stubbed
transport, no real consumer) / R5 —.** R2 is the observed `msg_idx=200` past a
128-byte buffer. No socket, broker, wire path, pointer control, marker or
command was observed; no arbitrary byte outside the `0x80`-`0xff` continuation
set was demonstrated.

`sh build-all.sh` rc 0 `BUILD_OK` (12 cases); `sh run-all.sh` rc 0
**PASS=12 FAIL=0** on a clean replay. Hashes, raw outputs, pin identities and
negatives: `lab/frontier/lwipmqtt2shell/PROVENANCE.md` and
`pins/SHA256SUMS` / `HARNESS_SHA256.txt`.
Operator replay at 04:0xZ from `git archive 124c9a40 lab/frontier/lwipmqtt2shell`
(18 committed files, no runs or binaries): all pin and harness SHA-256 checks
OK, `sh build-all.sh` 12 `BUILD_OK`, unmodified `sh run-all.sh` rc 0
`PASS=12 FAIL=0`; raw `mqtt.c:862:26: runtime error: index 128 out of bounds
for type 'u8_t [128]'`. Admitted under standing #6 as the 200th declared
target mind. W314 independent witness replay (04:1xZ, clean archive at
`124c9a40`, both compilers, detail
`.mishe-tauftauf/artifacts/witness-w314-lwipmqtt/detail.md`) returned
ESTABLISHED AS LABELED at this scope; no grade change, NO r5.

## Named depth experiment

Run the upstream `test/unit/mqtt` `rx_overflow` case through a real local lwIP
client on loopback against a local broker; feed attacker-chosen continuation
bytes via `client->conn->recv` and measure a chosen-byte readback in a live
downstream output-ring consumer, with fixed-pin and well-formed-header
controls. Preserve the negatives: ASan silence, no real consumer yet, no
pointer or command, and the unpublished fixed release. R5 remains NOT CLAIMED.

Brief: `reports/frontier-lwipmqtt2shell.md`.
