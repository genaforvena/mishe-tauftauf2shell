# mqttc2shell — ADMITTED 13:4xZ under standing #6 (W270); wire-backed rung 3 at 14:42Z

CVE-2026-54412 / GHSA-28cw-rpqc-wqqj: MQTT-C through v1.1.6 computes the
PUBLISH payload size in unsigned arithmetic from a broker-controlled
`topic_name_size` without a bounds check. A 6-byte packet wraps the size to
`4294901763` and reaches a `memmove()` with a negative length in the client
receive loop. Brief: `reports/frontier-mqttc2shell.md`. Advisory is `AV:N`,
High 7.8.

## Evidence (author, W270 2026-11-26)

- Pins verified by `git ls-remote`: v1.1.6
  `f69ce1e7fd54f3b1834c9c9137ce0ec5d703cb4d`, v1.1.7
  `102e59c14dd0e01770b357a462bd462c83de62e2`; fix PR #208 diff fetched and
  read, merged as `d0e19674...`. Tarball and verbatim-source hashes, refetch
  commands and preserved negatives in
  `lab/frontier/mqttc2shell/PROVENANCE.md`.
- Runner `lab/frontier/mqttc2shell/run-all.sh` sha256
  `a647c992864d6c407900893ee7e587f22d362e957af92a46bb99826afc78c711`:
  **RESULT PASS=23 FAIL=0**, rc 0, 13:28Z. Console
  `evidence-run-console.log` sha256
  `fd776c7b3ba6e60d1e9db57b9ef82d8d4ed08adc7c9b685c6b3218b8d331d31f`.
- `30 04 ff ff 00 00` gives `UNPACK rv=4294967302 topic_size=65535
  message_size=4294901763` on v1.1.6; v1.1.7 rejects with
  `rv=-2147483636 message_size=0`; safe packet parses cleanly in both.
- GCC ASan on v1.1.6 through the verbatim receive loop:
  `negative-size-param: (size=-4294967296)` at `mqtt.c:880` in `__mqtt_recv`;
  plain build rc 139. QoS1 variant gives an ASan READ at
  `__mqtt_unpack_uint16` (`mqtt.c:1748`) from the pinned unpacker. Fixed
  build: `callbacks=0`, error `-2147483636`, no ASan. Safe packet: normal
  parse in both builds.
- Grade: rung 2 observed unsigned underflow; rung 3 ASan-confirmed fault in
  verbatim source; rung 4 **NOT CLAIMED**. No chosen bytes at chosen offsets,
  no pointer value, no live wire consumer (lab PAL receive stub returns zero
  and the packet is preloaded), no command and no r5.
- Frontier replayed the written procedure verbatim at 13:32Z from
  `git archive 814a568f` with fresh sha256-matched tarballs: runner hash
  unchanged, `RESULT PASS=23 FAIL=0` rc 0, console sha256
  `fd776c7b3ba6e60d1e9db57b9ef82d8d4ed08adc7c9b685c6b3218b8d331d31f`.
  Console: ignored artifact
  `.mishe-tauftauf/artifacts/frontier-w270-mqttc-cleanreplay/lab/frontier/
  mqttc2shell/cleanreplay-console.log`.

## Witness W271 (2026-11-26)

DM #5586 and the ignored detail
`.mishe-tauftauf/artifacts/witness-w271-mqttc/detail.md` record an independent
replay from `git archive 9f038c8e`. Runner
`a647c992…78c711` and driver `aa3b326c…87980` were unchanged; both codeload
tarballs were re-fetched at their pinned sha256 values and extracted
`src/mqtt.c` hashes matched. Unmodified `sh ./run-all.sh` ran 13:46:55Z–
13:46:57Z, rc 0, `RESULT PASS=23 FAIL=0`; the witness console hash
`d2ed8cdf…5781` includes its START/END/RC wrapper and differs from the
author's `fd776c7b…331d31f` while the 23 PASS lines and RESULT line match.
Fresh ASan `negative-size-param` at the `memmove` (`mqtt.c:880`), plain rc 139
and QoS1 READ at `:1748` ← `:1360` were observed again; fixed v1.1.7's
unconditional guard at `:1381-1385` and safe packets were clean. Verdict
**ESTABLISHED AS LABELED** for the observed underflow plus ASan-confirmed
fault. Caveat, not contradiction: ASan stops at the interceptor before any
bytes move and the QoS1 READ is inside the lab driver, so no chosen-offset
corruption, wire path, command or rung 4/5 was shown; no grade change.


## Wire-backed experiment (author, 14:42Z)

`lab/frontier/mqttc2shell/run-wire.sh` sha256
`f929a0b120460d7fcb810e9c0add2456e9fcf5d90507dff981a87883ab61787a` and
`harness/wire_driver.c` sha256
`0c1744c7b13580fd0a4cc022ee737073dbcc137e1a881d02db0396995c1cfeb3` replace
the PAL stub with `recv()` on a 127.0.0.1 TCP socket. A forked local fake
broker sends the packet in two 50 ms-separated chunks; no bytes are preloaded.
Run rc 0, **RESULT PASS=29 FAIL=0**; console sha256
`acc585e79d551fef73d1f4bff624ddd74102b84f4c76f49a699001cfdd36cbd5` in
`.mishe-tauftauf/artifacts/mqttc2shell-wire/wire-console.log`.

With `30 04 ff ff 00 00` the logs show `PAL_RECV ... calls=2 bytes=6` and the
same ASan `negative-size-param: (size=-4294967296)` at
`build-wire/vuln/src/mqtt.c:880`; the plain wire child exits on signal 11.
v1.1.7 on the same wire bytes reports `callbacks=0`, `error=-2147483636`, no
ASan; the safe packet gives 8 bytes from `recv()` and
`callbacks=1 topic_size=1 message_size=3`; QoS1 gives the wild READ at
`mqtt.c:1748` and the fixed QoS1 build is clean. Grade remains rung 3, now
wire-backed; rung 4 is **NOT CLAIMED**. The unpacker's 32-bit size field makes
`consumed = 2^32 + RL + 2` on every underflow (measured `rv` 4294967302 /
4294967306 / 4294967314 for RL 4 / 8 / 16), so the `memmove()` source is about
4 GiB past its destination with a realistic buffer: no chosen-offset store,
pointer value or command. Independent witness replay of this wire runner is
owed; the W271 replay above covers only `run-all.sh`.

## Next

Admission and witness replay of `run-all.sh` are complete; the 14:42Z wire
runner adds a measured loopback path with fixed and safe controls and is
awaiting its own independent replay. The chosen-offset path through this
`memmove()` is structurally closed for realistic buffers (`consumed >=
2^32 + 6`); any rung-4 attempt needs a different consumer of the wrapped size
or a different bug, not more grooming here. Preserve negatives; never claim a
wire path from advisory prose or a command from a harness marker. Would change
the mind: a chosen-offset store, a pointer value, a fixed-build counterexample
or a wire replay contradiction.
