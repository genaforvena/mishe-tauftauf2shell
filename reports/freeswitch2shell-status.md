# Freeswitch2Shell status

Admitted 2026-11-20 ~17:52Z under standing approval #6. Dedicated two-pane
window (inner socket, window 17), restorer registry entry and charter are
live; the operator committed docs/task.md, this status and the durable brief
at 18:28Z. Wake trigger units are owed from the person's full-flag sync.
Frontier re-ran the repaired harness at 19:02Z from clean HEAD: `bash
lab/frontier/freeswitch2shell/run.sh` prints `ALL CHECKS PASS` with rc 0;
digests `75433b5d…` / `637cfa36…`.

## Target

FreeSWITCH `mod_xml_rpc` WebSocket extended-length heap overwrite,
CVE-2026-116785 / GHSA-jj89-q47c-gh94 (CWE-122/681/787, CVSS 3.1 9.1,
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`). Advisory boundary: affected
`<= 1.11.1`, fixed `>= 1.11.2`. Vulnerable parent `fbac12b451a1`, fix
`d557ca6d29e6da4f10824dc158100906a592b91a`. Config gate: `mod_xml_rpc` loaded
and `enable-websocket` set; both off by default, endpoint `http-port` 8080.

## Mechanism and reproduction

- Length code 127 decodes 8 attacker bytes with a 32-bit `ntohl` into signed
  `int plen`; `FF FF FF FF` gives `plen=-1`, the signed guard passes with
  `need=-5`, and the unbounded copy writes all client bytes from `buffer+14`
  across `buffer[65536]`, `wbuffer[65536]` and the following handle fields.
- Frontier re-run 19:02Z (pinned digests `75433b5d…` / `637cfa36…`, both in
  `logs/digests.txt` and the brief): rung 1 `plen=-1 need=-5 rplen=4
  guard_passed=1`, `oob_writes=1464 first_oob=65536 last_oob=66999`, C harness
  `RESULT=PASS`; rung 2 chosen patterns `dedfe0e1`/`cacbcccd` and
  `11121314`/`55565758` land at `wbuffer[0..3]` and `wbuffer[1024..1027]`;
  rung 3 ASan `heap-buffer-overflow`, `WRITE of size 132146`, `0 bytes after
  a 131136-byte region`, from `ws_raw_read`; rung 4 chosen value at
  `offsetof(wsh_t, ssl)=131112` executes the marker with rc 42. Fixed build
  rejects with `rc=-1009`; five repeat runs identical. Driver rc 0,
  `ALL CHECKS PASS`.
- The operator's earlier 18:28Z figure of 2928 OOB writes was double the real
  extent: `trace_copy()` underflowed on a zero-byte read past the buffer,
  counting 1464 phantom writes. The overwritten range 65536..66999 was always
  real. `mode_rung2()` also returned 1 on success because it ANDed subtest
  exit codes. Both defects and the stale grep literals were repaired; the
  operator's observation stands, its count and driver verdict do not.

## Open

- Verify the chosen-pointer offset against upstream `ws.h` on this host
  (harness diag: `offsetof(ssl)=131112`, buffer-relative 131104).
- Decide whether a loopback `mod_xml_rpc` build advances the network claim.
- Live FreeSWITCH, WebSocket upgrade, real heap layout and reachability stay
  UNKNOWN. No off-loopback probe has been run; preserve that boundary.
- Witness claim to file with the 19:02Z digests; author report is not
  independent acceptance.
