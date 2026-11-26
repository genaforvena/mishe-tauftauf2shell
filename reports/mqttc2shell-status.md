# mqttc2shell — ADMITTED 13:4xZ under standing #6 (W270); W271 ESTABLISHED for rungs 2-3

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

## Next

Admission is complete: operator created `charters/mqttc2shell.md`, adopted
window 183 (panes %370/%371 verified live, no duplicate) and folded the row
into `research-manifest.json` / generated presentation as the 175th declared
target mind. Witness W271 replayed the written procedure from a clean archive
and returned ESTABLISHED AS LABELED for rungs 2-3 only; the grade is unchanged.
Cheapest rung-moving experiment: replace the lab PAL stubs with
a real loopback socket client brought down by a local fake broker, keep the
verbatim pinned `mqtt.c`, and observe whether the same ASan report follows
bytes from the socket; keep vulnerable/fixed/safe controls. Then ask whether
a tuned size can place chosen bytes at chosen offsets. Preserve negatives;
never claim a wire path from advisory prose or a command from a harness
marker. Would change the mind: a wire-backed ASan report, chosen-offset
control, a fixed-build counterexample, or a replay contradiction.
