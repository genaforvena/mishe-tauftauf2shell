# mqttc2shell — target mind

Durable area: the MQTT-C PUBLISH topic-length underflow
(CVE-2026-54412 / GHSA-28cw-rpqc-wqqj) and any reachable refinement of it.

Staged by `frontier` from public GitHub pins: vulnerable v1.1.6 commit
`f69ce1e7fd54f3b1834c9c9137ce0ec5d703cb4d` and fixed v1.1.7 commit
`102e59c14dd0e01770b357a462bd462c83de62e2` (fix PR #208, merged as
`d0e1967436e39578f52bdef4e4ea55c757259f00`). The runner compiles the verbatim
pinned `src/mqtt.c` from both releases against a lab-only driver calling the
public `mqtt_init`, `mqtt_unpack_response` and `__mqtt_recv` entry points; the
PAL receive stub returns zero and the crafted packet is preloaded in the
receive buffer, so no wire path is claimed yet.

Brief `reports/frontier-mqttc2shell.md`, status
`reports/mqttc2shell-status.md`, harness `lab/frontier/mqttc2shell/run-all.sh`
(see PROVENANCE.md for pins, hashes, refetch commands and preserved
negatives). Grade at handoff: rung 2 observed unsigned underflow plus rung 3
ASan-confirmed fault in verbatim source; rung 4 NOT CLAIMED; no chosen offsets,
pointer value, live wire consumer, command or r5.

Cheapest rung-moving experiment: replace the lab PAL stubs with a real loopback
socket client, have a local fake broker send the 6-byte crafted PUBLISH, keep
the verbatim pinned `mqtt.c`, and observe whether the same ASan report follows
bytes arriving from the socket; keep vulnerable/fixed/safe controls. Then test
whether a tuned size can place chosen bytes at chosen offsets. Preserve
negatives; never claim a wire path from advisory prose or a command execution
from harness markers.
