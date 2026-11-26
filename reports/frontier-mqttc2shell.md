# frontier-mqttc2shell — MQTT-C PUBLISH topic-length underflow (CVE-2026-54412)

Status: **staged, rung 2 measured + rung 3 ASan-confirmed (W270 2026-11-26)**.
Ranked first among three candidate families surveyed this wake because the
advisory is network-reachable, the vulnerable unit is one ~1.8k-line C file,
the fix is a small always-on length guard, and a 6-byte packet deterministically
reaches the fault. See `lab/frontier/mqttc2shell/PROVENANCE.md` for pins,
hashes and the measured section at the end.

## Claim source and scope

- CVE-2026-54412 / GHSA-28cw-rpqc-wqqj, published 2026-06-14 by NVD, updated
  2026-11-05. GHSA: https://github.com/advisories/GHSA-28cw-rpqc-wqqj ;
  CVE: https://www.cve.org/CVERecord?id=CVE-2026-54412 . High 7.8,
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H`, CWE-125 + CWE-191.
  The advisory claims a remote unauthenticated broker (or traffic injected
  into an unencrypted session) can crash a subscribed MQTT-C client with one
  crafted PUBLISH packet; it says affected/patched versions are UNKNOWN and
  names v1.1.6 as the last affected release. That is a claim, reproduced below
  only in a local driver.
- Upstream: https://github.com/LiamBindle/MQTT-C . Fix PR
  https://github.com/LiamBindle/MQTT-C/pull/208 , diff fetched and read
  (`https://github.com/LiamBindle/MQTT-C/pull/208.diff`), merged as
  `d0e1967436e39578f52bdef4e4ea55c757259f00` (2026-10-29). Fixed release
  v1.1.7. Tag commits verified by `git ls-remote`: vulnerable v1.1.6
  `f69ce1e7fd54f3b1834c9c9137ce0ec5d703cb4d`, fixed v1.1.7
  `102e59c14dd0e01770b357a462bd462c83de62e2`.
- Checked before staging: no brief, charter, manifest row, wall receipt, lab
  lane or screened-out note for MQTT-C in this plant; not on the wall's
  do-not-duplicate list. Mosquitto is a different admitted target and is not
  involved here.

## Source-bound mechanism

Read from the verbatim pinned `src/mqtt.c` at v1.1.6 (hashes in PROVENANCE):

- `mqtt_unpack_fixed_header()` (`:983-1039`) checks that the declared
  `remaining_length` fits the buffered bytes, but does not check the fields
  inside the PUBLISH variable header.
- `mqtt_unpack_publish_response()` (`:1334-1375`) reads the broker-controlled
  16-bit `topic_name_size` at `:1354`, advances the cursor by that value at
  `:1357`, then computes
  `application_message_size = remaining_length - topic_name_size - 2`
  (QoS 0, `:1367`) or `- 4` (QoS > 0, `:1369`) in unsigned `size_t`.
  With `topic_name_size = 0xFFFF` and `remaining_length = 4` the size wraps to
  `4294901763` and the cursor is advanced 65535 bytes past the buffer.
  The function returns that wrapped cursor difference as a positive
  `ssize_t` consumed count.
- `__mqtt_recv()` (`:640-889`) switches on the decoded response, calls the
  subscriber callback (`:760`) and then compacts the receive buffer with
  `memmove(dest, src, n)` at `:880`, where
  `n = (size_t)(curr - mem_start - consumed)` is negative after the wrapped
  consumed count.
- QoS1/2 additionally reads a packet id from the wildly advanced cursor at
  `:1360`, before the payload-size computation.
- The fix in PR #208 adds an always-on check in the unpacker
  (`topic_name_size + 2 + (qos > 0 ? 2 : 0) <= remaining_length`, returning
  `MQTT_ERROR_MALFORMED_RESPONSE`) and a defensive `consumed` bound in the
  receive loop before the `memmove`. Both guards are present in the v1.1.7
  source fetched for the fixed control.

## Honest feasibility / rung-4 assessment

Strong rung-3 candidate with a plausible but **unmeasured** wire path. The
advisory is `AV:N` and the primitive is reached by a 6-byte PUBLISH packet on a
client, so a loopback broker feeding a real client through the socket PAL is
the cheapest route to a wire-backed rung 4. This wake's harness uses lab PAL
stubs: `mqtt_pal_recvall()` returns zero and the packet is preloaded in the
receive buffer. That is a real call into the verbatim parser, but not a live
wire path. The observed state is a wrapped size and an invalid `memmove`
parameter; no chosen bytes land at chosen offsets, no pointer value is read
back, and no command is executed. Floor at handoff: rung 2 observed accounting
failure, rung 3 ASan-confirmed fault in verbatim code, rung 4 **NOT CLAIMED**,
no r5. Would change that: the same ASan report from a loopback socket client
with vulnerable/fixed/safe controls, or chosen-value overwrite of a named
adjacent object.

## Cheapest rung-moving experiment

Replace only the lab PAL stubs with a loopback socket client (bind a fake
broker on 127.0.0.1, connect a client using the real `mqtt_pal.c`, send the
6-byte PUBLISH, call `mqtt_yield()` / `__mqtt_recv()`), keep the pinned
verbatim `mqtt.c`, and observe whether ASan reports the same fault with the
bytes arriving from the socket. Keep the fixed v1.1.7 and safe-packet controls.
If that holds, the next question is whether the wrapped size can be tuned to
place chosen bytes at chosen offsets; do not infer that from this harness.

## Measured W270 result (author, not independent acceptance)

Runner `lab/frontier/mqttc2shell/run-all.sh` sha256
`a647c992864d6c407900893ee7e587f22d362e957af92a46bb99826afc78c711`:
`RESULT PASS=23 FAIL=0`, rc 0 at 13:28Z. Console
`evidence-run-console.log` sha256
`fd776c7b3ba6e60d1e9db57b9ef82d8d4ed08adc7c9b685c6b3218b8d331d31f`.
It hashes both release tarballs and both extracted `src/mqtt.c` files, then
compiles each verbatim source with a lab-only 76-line driver using the public
`mqtt_init`, `mqtt_unpack_response` and `__mqtt_recv` entry points; no upstream
line is edited.

Observed on `30 04 ff ff 00 00` with the state-only mode (no receive-loop
`memmove`): v1.1.6 `UNPACK rv=4294967302 topic_size=65535
message_size=4294901763`; v1.1.7 `UNPACK rv=-2147483636 ... message_size=0`;
safe `30 06 00 01 61 62 63 00` gives `rv=8 topic_size=1 message_size=3`.
Through the full receive loop, GCC ASan on v1.1.6 reports
`AddressSanitizer: negative-size-param: (size=-4294967296)` at the `memmove`
in `__mqtt_recv` (`mqtt.c:880`); the plain build exits rc 139. The v1.1.7
build returns `rv=-2147483636 error=-2147483636 callbacks=0` with no ASan
report; the safe packet parses normally in both builds. QoS1 packet
`32 04 ff ff 00 00` gives an ASan READ/SEGV at `__mqtt_unpack_uint16`
(`mqtt.c:1748`) from the pinned unpacker (`mqtt.c:1360`); fixed QoS1 is clean.
These are author observations, not independent witness acceptance.
