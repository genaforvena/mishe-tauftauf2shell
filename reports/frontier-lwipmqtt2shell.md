# Frontier brief: lwipmqtt2shell — CVE-2026-87121 (lwIP MQTT rx_buffer overrun)

**Status: ADMITTED 2026-11-27 04:0xZ under standing #6 as the 200th declared
target mind; staged two-pane window 208 adopted as-is. Independent operator
clean-archive replay is done; independent witness replay is still owed. This
author report is not acceptance.**
Target slug `lwipmqtt2shell`; no prior charter, lab directory or window existed
at staging, and it is not in the frontier do-not-duplicate list. Grade at
handoff is recorded in `reports/lwipmqtt2shell-status.md` after local
observation, not inferred from advisory prose.

## Verified ground truth (sources read 2026-11-27)

- **Claim sources:** CISA ICSA-26-265-01
  `https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-01`, GHSA
  `GHSA-h8q6-7rjx-3m2r`, ByteRay BYTERAY-2026-0211, Savannah bug 68590, upstream
  fix `https://github.com/lwip-tcpip/lwip/commit/68b2c1191886578d40342846db6ab9a0099c2f40`
  and follow-up cap `576da61ccf2ede6db877f733ce2ef42cd3fdeb89`.
- **CVE / severity:** CVE-2026-87121, CWE-787, CVSS v3.1 9.8 / v4.0 9.3
  (Critical). Claim scope is the MQTT **client** parser: an attacker who
  controls or MitMs the broker can overrun the client's fixed header buffer
  before authentication. No listening socket or remote unauthenticated server
  path is claimed by this brief.
- **Versions and pins:** affected lwIP MQTT client 2.0.1-2.2.1; vulnerable tag
  `STABLE-2_2_1_RELEASE`, HEAD `77dcd25a72509eb83f72b033d219b1d40cd8eb95`.
  No fixed upstream release exists as of 2026-11-27 (2.2.2 planned); the fixed
  control is the production hunk of `68b2c119` applied to the vulnerable tree.
  CISA's cited `f89407ea` only changes a test `memset`, not production code.
- **Claimed primitive:** `mqtt_parse_incoming()` copies each incoming
  continuation byte into `client->rx_buffer[client->msg_idx++]` without an
  upper bound check. A 200-byte run drives `msg_idx` to 200 against a 128-byte
  buffer, a 72-byte overwrite into the adjacent output ring buffer. Published
  oracle: ASan heap-buffer-overflow, 1-byte write at `mqtt.c:862`, 72 bytes
  past `rx_buffer[128]`. Public reproducer: 2.7 KiB `mqtt_repro.c` at
  `https://file.savannah.nongnu.org/file/mqtt_repro.c?file_id=58860`, fed to a
  related public bug report.

## Source-bound mechanism (pinned bytes)

Vulnerable `src/apps/mqtt/mqtt.c:862` (verbatim):
`client->rx_buffer[client->msg_idx++] = b;`. In `struct mqtt_client_s`
(`src/include/lwip/apps/mqtt_priv.h:70-98`), `rx_buffer[128]` is followed by
`struct mqtt_ringbuf_t output`, so the write is **intra-object**: it lands in
`output.put`, `output.get` and `output.buf`, not past the allocation. The fix
wraps the store in `if (client->msg_idx < MQTT_VAR_HEADER_BUFFER_LEN) { ... }
else { return MQTT_CONNECT_DISCONNECTED; }`. The 400-byte upstream
`rx_overflow` regression test is in the same commit.

## Local observation (2026-11-27 W313, gcc 13.3 + clang 18)

`lab/frontier/lwipmqtt2shell/` builds the unmodified public reproducer against
both pin trees with `config/lwipopts.h` (`NO_SYS=1`, `LWIP_ALTCP=1`,
`MEM_LIBC_MALLOC=1`) and minimal libc-backed pbuf/mem stubs. `sh build-all.sh`
returned 12 `BUILD_OK`; `sh run-all.sh` rc 0 with **PASS=12 FAIL=0**.
- **Operator replay (04:0xZ):** clean `git archive 124c9a40
  lab/frontier/lwipmqtt2shell` (18 committed files, no runs or binaries);
  `pins/SHA256SUMS` and `HARNESS_SHA256.txt` all OK; `sh build-all.sh` 12
  `BUILD_OK`; unmodified `sh run-all.sh` rc 0 `PASS=12 FAIL=0`. Raw UBSan at
  `mqtt.c:862:26: runtime error: index 128 out of bounds for type 'u8_t [128]'`.

- **Primary oracle:** vulnerable pin rc 1 under `-fsanitize=bounds` in both
  compilers: `src/apps/mqtt/mqtt.c:862: runtime error: index 128 out of bounds
  for type 'u8_t [128]'`.
- **Fixed pin**, same 200-byte input: rc 0, `msg_idx=128`, no sanitizer report
  in either compiler. **Safe input** (128 bytes) on the vulnerable pin: rc 0,
  `msg_idx=128`, no sanitizer report.
- **ASan negative:** vulnerable rc 0, `msg_idx=200`, no AddressSanitizer report
  — the intra-object write is invisible to heap ASan. The published "ASan
  heap-buffer-overflow" oracle was **not observed** and is not claimed.
- **Chosen-byte readback:** with `output.buf` prefilled `0xee`, the vulnerable
  pin changes 68/256 bytes: `0xff` input gives `put=get=65535`, first bytes
  `ff ff ff ff`; `0x80` input gives `put=get=32896`, first bytes
  `80 80 80 80`. Fixed pin: 0/256 changed, `put=get=0`, first bytes `ee ee ee ee`.
- Plain differential: vulnerable `msg_idx=200`, fixed `msg_idx=128`.

Full hashes, raw outputs, source pin identities and all negatives:
`lab/frontier/lwipmqtt2shell/PROVENANCE.md`.

## Rung-4 feasibility and cheapest next experiment

R4 is **LIMITED**, not full: chosen continuation bytes (`0xff`, `0x80`) were
read back at chosen offsets in a live adjacent object (`output.put/get/buf`)
with a fixed-pin and safe-input control, entirely inside the standalone
harness with stubbed altcp transport. No real lwIP socket, broker, consumer,
pointer control, marker or command was observed, and no arbitrary byte outside
the continuation set (`0x80`-`0xff`) was demonstrated. R5 is NOT claimed.
The cheapest step toward full rung 4 is a real local lwIP client on loopback:
run the upstream `test/unit/mqtt` `rx_overflow` case against a local broker,
feed attacker-chosen continuation bytes through `client->conn->recv`, and
measure a chosen-byte readback in a live downstream output-ring consumer with
fixed-pin and well-formed-header controls. Preserve the negatives above.

## Screened alternatives this wake

Three scouts returned concrete recipes. NanoMQ GHSA-6w96-9qw7-m599 (REST API
`uri_param_parse` heap overflow, public `curl` PoC, ASan WRITE-2 at
`rest_api.c:538`) ranked second on impact but needs recursive submodules and a
heavier cmake build; its source clone timed out at 300 s. CPython bz2
CVE-2026-9669 has a 92-byte upstream test PoC and a vulnerable local 3.12.3,
but no published ASan oracle and needs instrumented libbz2; its impact is
DoS-only. fontconfig CVE-2026-34085 has a one-line fix and a published
`fc-cache` ASan WRITE-12 but needs a specific unattached SIL font. NSD
CVE-2026-12245 has no public PoC or oracle and is SCREENED OUT.
