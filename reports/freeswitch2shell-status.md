# Freeswitch2Shell status

Admitted 2026-11-20 ~17:52Z under standing approval #6. Dedicated two-pane
window and restorer registry entry are live; the charter, docs/task.md entry
and durable report were committed by the operator at 18:28Z. Wake trigger
units are owed from the person's full-flag sync. The operator reproduced the
harness in a throwaway copy at 18:28Z; the target mind still needs to re-run
it itself before treating any grade as its own.

## Target

FreeSWITCH `mod_xml_rpc` WebSocket extended-length heap overwrite,
CVE-2026-116785 / GHSA-jj89-q47c-gh94 (CWE-122/681/787, CVSS 3.1 9.1,
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`). Advisory boundary: affected
`<= 1.11.1`, fixed `>= 1.11.2`. Vulnerable parent `fbac12b451a1`, fix
`d557ca6d29e6da4f10824dc158100906a592b91a`. Config gate: `mod_xml_rpc` loaded
and `enable-websocket` set; both off by default, endpoint `http-port` 8080.

## Inherited, not yet re-run by this mind

- Length code 127 decodes 8 attacker bytes with a 32-bit `ntohl` into signed
  `int plen`; `FF FF FF FF` gives `plen=-1`, the signed guard passes with
  `need=-5`, and the unbounded copy writes all client bytes from `buffer+14`
  across `buffer[65536]`, `wbuffer[65536]` and the following handle fields.
- Operator reproduction 18:28Z (throwaway copy, pinned digests
  `7eeb5d26…` / `089d7e33…`) observed rungs 1/2 placement with 2928 OOB
  writes, an ASan `heap-buffer-overflow` `WRITE of size 132146` from
  `ws_raw_read`, and a chosen 8-byte value at
  `offsetof(wsh_t, ssl)=131112` executing a marker with `rc=42`; the fixed
  build rejects with `rc=-1009`. `run.sh` still prints `CHECKS FAILED`
  because its expected exit codes and literal byte patterns are stale after
  the source edit — quote individual observations with their digests, not
  the driver verdict. Full numbers in the brief's reproduction section.
- Live FreeSWITCH, WebSocket upgrade, real heap layout and network reachability
  are UNKNOWN. No off-loopback probe has been run.

## Open

- Re-run `bash lab/frontier/freeswitch2shell/run.sh` from clean HEAD and fix
  its stale exit-code and literal-pattern expectations so the driver reports
  PASS against the current pinned source.
- Verify the chosen-pointer offset against upstream `ws.h` on this host.
- Decide whether a loopback `mod_xml_rpc` build advances the network claim.
- Preserve controls and negatives; file a witness claim with digests.
