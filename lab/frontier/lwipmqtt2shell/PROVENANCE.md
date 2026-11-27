# PROVENANCE — lwipmqtt2shell (CVE-2026-87121)

Staged by frontier in W313 (2026-11-27). Everything below is observed on the
pinned bytes in this directory; advisory claims are labeled as claims.

## Pins and provenance

- Vulnerable: lwIP `STABLE-2_2_1_RELEASE`, git HEAD
  `77dcd25a72509eb83f72b033d219b1d40cd8eb95`. `pins/lwip-2.2.1-vuln.tar.gz`
  SHA-256 `043787737450f541f65614e2ac8ecf7e6ba139e59650f9ad2bd73a3a1bd61693`.
- Fixed control: same source plus the production hunk of upstream commit
  `68b2c1191886578d40342846db6ab9a0099c2f40` ("mqtt: fix rx_buffer overrun",
  2026-08-31), applied with `git apply --exclude='test/*'`. No other source edit.
  `pins/lwip-2.2.1-fixed.tar.gz` SHA-256
  `b9c90d55a2cb75dab12229ceb444c47dda9948983191718af2231797667507c9`.
- Public reproducer: `pins/mqtt_repro.c`, 2724 bytes, SHA-256
  `84506cd1d30cdb14058a3be2ae1db546cc3df5fc4f3b13b06fbb5b44b66ff6c1`, fetched
  byte-unmodified from `https://file.savannah.nongnu.org/file/mqtt_repro.c?file_id=58860`
  (Savannah bug 68590). It defines altcp stubs and calls
  `mqtt_parse_incoming()` directly with a 200-byte `PBUF_RAM` pbuf of `0xff`.
- `pins/68b2c119.patch` SHA-256
  `32e46f0f275b39595a5df80e613fc3676e42b248acd60b9ed110b645addb098a`.
- Derived controls: `mqtt_repro_safe.c` (only `payload_len` 200 -> 128),
  `mqtt_canary.c` / `mqtt_canary80.c` (canary prefill of `output.buf` and
  post-parse readback; canary byte `0xff` / `0x80`). Full hashes in
  `pins/SHA256SUMS`; script/config hashes in `HARNESS_SHA256.txt`.

## Build

`sh build-all.sh` extracts both tarballs offline and builds 12 cases; no
network, checkout or prebuilt binary is used. gcc 13.3.0 and clang 18.1.3.
Oracle mode: `-fsanitize=bounds -fno-sanitize-recover=all -g -O1`. ASan mode:
`-fsanitize=address -fno-omit-frame-pointer -g -O1`. `config/lwipopts.h` sets
`NO_SYS=1`, `LWIP_ALTCP=1` (real altcp symbols for the PoC stubs),
`MEM_LIBC_MALLOC=1`, `MQTT=1`. `config/lwip_stubs.c` implements only the pbuf
and memory primitives the PoC reaches, on libc malloc, and `config/randstub.c`
supplies `lwip_port_rand`, `sys_timeout`, `sys_untimeout`.

## Observed (clean replay 2026-11-27 W313)

`sh build-all.sh` -> 12 `BUILD_OK`; `sh run-all.sh` -> **PASS=12 FAIL=0**, rc 0.

- Primary oracle, gcc and clang: vulnerable pin rc 1,
  `src/apps/mqtt/mqtt.c:862: runtime error: index 128 out of bounds for type
  'u8_t [128]'`. Raw sink line is the verbatim pinned
  `client->rx_buffer[client->msg_idx++] = b;`.
- Fixed pin, same 200-byte input: rc 0, `msg_idx=128`, no sanitizer report,
  both compilers. Vulnerable pin with the 128-byte safe input: rc 0,
  `msg_idx=128`, no sanitizer report.
- ASan negative: vulnerable pin rc 0, `msg_idx=200`, **no AddressSanitizer
  report** in either compiler — the overflow is intra-object (`output` ring
  follows `rx_buffer` inside `mqtt_client_s`), so heap ASan cannot see it.
- Plain differential: vulnerable `msg_idx=200`, fixed `msg_idx=128`, both rc 0.
- Canary (chosen-byte readback): vulnerable `0xff` input changes 68/256 bytes
  of `output.buf`, `put=get=65535`, first bytes `ff ff ff ff`; `0x80` input
  changes 68/256, `put=get=32896`, first bytes `80 80 80 80`. Fixed pin with
  `0xff`: 0/256 changed, `put=get=0`, first bytes `ee ee ee ee`.

## Negatives preserved

- The public "ASan heap-buffer-overflow, 72 bytes past `rx_buffer`" oracle was
  **not observed**: plain ASan is silent. The confirmed oracle is UBSan
  `array-bounds` at the raw sink.
- No full-program crash, socket, live broker, real consumer, wire path,
  arbitrary byte outside the `0x80`-`0xff` continuation set, pointer control,
  marker execution or command execution was observed.
- Upstream follow-up `576da61ccf2ede6db877f733ce2ef42cd3fdeb89` (MQTT 3.1.1
  Remaining-Length cap) is not applied to the fixed control.
- CISA's cited `f89407ea711879c04d91c92b35d67be78bbaf0f1` changes only a test
  `memset`, not production code; the production fix is `68b2c119`.
- ByteRay's published RCE claim is a screenshot with no exploit code; no RCE
  path was reproduced or claimed here.
