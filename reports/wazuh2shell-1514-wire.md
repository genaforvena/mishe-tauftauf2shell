# wazuh2shell — CVE-2026-74045 over a real loopback 1514 enrolled-agent session

Status (2026-11-22, wake W106): the advisory FIM JSON was encrypted with an
enrolled agent's key by Wazuh's own `CreateSecMSG`, sent over a real loopback
TCP/1514 secure session into a plant-built `wazuh-remoted`, decrypted there by
`ReadSecMSG` and relayed to `wazuh-analysisd`, which faulted at the upstream
sink with ASan-confirmed heap corruption. This closes the wire leg that
`reports/wazuh2shell-wire-reach.md` (source-only) and
`reports/wazuh2shell-live-crash.md` (queue injection) left open.

It is still **not rung 5**: no chosen-byte write observed in the daemon, no
pointer control, no marker, no command, and no independent witness replay of
this particular experiment. The 69-byte overflow is not a reliable plain
(non-ASan) crash.

## Builds and lab setup

- Vulnerable: v4.14.7 `a42268a27c555d9348d5598fb8751eaf4c8e9024`; the
  `wazuh-analysisd` built in wake W105 has ASan on the two objects that
  allocate `full_log` (`analysisd/cleanevent.c`) and perform the sink
  (`analysisd/decoders/syscheck.c`).
- Fixed: v4.14.8 `f470ad7db717b18db7feeed568949643698f0f34`; both daemons
  built ASan throughout. `wazuh-remoted` was built for each tag from the same
  pinned trees (`make -j2 TARGET=server wazuh-remoted`; v4.14.8 needed
  `LDFLAGS=-fsanitize=address` and a local CMake build of
  `shared_modules/router/librouter.so`). No build touched an external target.
- Agent enrolled locally in each tree's `live-root/etc/client.keys`:
  `001 lab-agent 127.0.0.1 616263...3435`. The key is a lab string, not a
  credential; no real agent or account is involved.
- `wazuh-remoted` is configured `<connection>secure</connection>`,
  `<port>1514</port>`, `<protocol>tcp</protocol>`, bound on loopback.
- Lab-only runtime adaptations, none on the decode path: the `labgroup.c`
  `LD_PRELOAD` shim from W105 answers hard-coded `getgrnam("wazuh")` and
  neutralizes root-only syscalls; a minimal Python stand-in at
  `queue/db/wdb` lets remoted clear startup group queries by answering
  `err lab-dummy-wdb`; the daemon's own wdb errors appear in the logs and are
  expected.

## Wire input actually sent

`live-src/crafter.c` loads the enrolled keystore with `OS_ReadKeys`, selects
AES via `os_set_agent_crypto_method`, and encrypts with the upstream
`CreateSecMSG` (`os_crypto/shared/msgs.c:575`). Cleartext is exactly
`8:syscheck:` + the 228-byte advisory JSON (control: the 406-byte
full-`old_attributes` JSON). TCP secure framing is a 4-byte length in
`wnet_order()` order — identity on this little-endian host — followed by the
197-byte ciphertext. Sent with `connect("127.0.0.1", 1514)` and `write()`.

Remoted's own log proves the decrypted message reached the FIM classifier:
`secure.c:1007 ... FIM event detected, not forwarding to Inventory Harvester`.
Its `SendMSG(..., SECURE_MQ)` then builds the queue datagram
`8:[001] (lab-agent) 127.0.0.1->syscheck:<json>` from `mq_op.c:143`, the exact
shape used by the W105 queue-injection replay.

## Observed results

| build / input over 1514 | result |
| --- | --- |
| v4.14.7 ASan, 228-byte exploit | `wazuh-analysisd` aborted; ASan `heap-buffer-overflow`, `WRITE of size 506`, 0 bytes after the 459-byte region |
| v4.14.7 ASan, 406-byte full-`old_attributes` control | alive, zero ASan overflow; FIM decoder ran (Mitre/rules warnings, DB-query errors) |
| v4.14.8 ASan, same 228-byte exploit | alive, zero ASan overflow; remoted logged the same FIM classification |

Stable artifacts under `lab/frontier/wazuh2shell/`:

- `live-1514-exploit-run.txt`, `live-1514-analysisd-exploit.log`,
  `live-1514-remoted-exploit.log`, `live-1514-wire-exploit.log` (vulnerable).
- `live-1514-control-run.txt` and the matching `live-1514-*-control.log` files
  (safe-input control).
- `live-1514-fixed-run.txt`, `live-1514-fixed-analysisd-exploit.log`,
  `live-1514-fixed-remoted-exploit.log`, `live-1514-fixed-wire-exploit.log`
  (fixed build). Its LeakSanitizer report is from the short-lived crafter
  process (unfreed keystore), not from either daemon; it is not part of the
  finding.

Key ASan frames from the vulnerable daemon:

```
==137669==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 506 at 0x51500073024b thread T11
    #2 in fim_generate_alert analysisd/decoders/syscheck.c:1680
    #3 in fim_process_alert analysisd/decoders/syscheck.c:1436
    #4 in decode_fim_event analysisd/decoders/syscheck.c:1288
    #5 in w_decode_syscheck_thread analysisd/analysisd.c:1586
0x... is located 0 bytes after 459-byte region
```

## Boundary

- The enrolled-agent 1514 leg is now **observed**, not merely source-confirmed.
  The fault is rung 3 in a live daemon reached by attacker-chosen wire input,
  with vulnerable / safe-input / fixed controls on the same path.
- The chosen JSON byte `Q` in a neighbouring object is still observed only in
  frontier's plain in-process harness; this daemon experiment proves the
  overflow, not chosen bytes at a chosen heap offset in the daemon.
- No pointer consumer, control flow, marker, command, benign side effect or
  witness replay of this experiment. Rung 5 remains UNKNOWN and is not claimed.
- The replay driver and crafter live in the gitignored lab trees
  (`live-src/`, `live-src-748/`) with the W105 build roots; the report records
  the exact commands and files so a fresh context can rebuild them.
