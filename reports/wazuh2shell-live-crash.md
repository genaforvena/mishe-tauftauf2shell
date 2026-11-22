# wazuh2shell — live `wazuh-analysisd` reproduction of CVE-2026-74045

Status (2026-11-22, wake W105): **live daemon heap corruption observed** on a
locally built, hash-pinned v4.14.7 `wazuh-analysisd` driven through its real
syscheck decode queue with the advisory JSON. This is rung 3 in the live
process (ASan-confirmed overflow at the upstream sink) and a deterministic
availability fault on the ASan build. It is **not** rung 5: no 1514 session,
no enrolled agent, no chosen-byte write observed in the daemon, no pointer
control, no benign command, and no witness replay.

## Build identity and instrumentation

- v4.14.7: git commit `a42268a27c555d9348d5598fb8751eaf4c8e9024`, cloned
  read-only from `github.com/wazuh/wazuh` at tag v4.14.7.
- v4.14.8 (fixed): git commit `f470ad7db717b18db7feeed568949643698f0f34`.
- Both built locally with `make -C src -j2 TARGET=server wazuh-analysisd`.
  ASan builds used `CFLAGS=-fsanitize=address -fno-omit-frame-pointer -g -O0`
  and `LDFLAGS=-fsanitize=address`. On v4.14.7 the pre-existing plain objects
  were rebuilt only for `analysisd/cleanevent.c` and
  `analysisd/decoders/syscheck.c` before relinking; v4.14.8 was built with
  ASan throughout. Other objects are not ASan-instrumented; the two objects
  that allocate `full_log` and perform the sink are.
- Wazuh's `make deps` provisioned external libraries as read-only provisioning;
  the generated flatbuffers schema headers were built locally with the tree's
  own CMake target. No external target was contacted.

## Lab-only runtime adaptation (does not touch the decode path)

The daemon is run unprivileged, so a small `LD_PRELOAD` shim
(`live-src/labgroup.c`) answers Wazuh's hard-coded `getgrnam("wazuh")`, makes
root-only `setgroups`/`chroot` no-ops and redirects the daemon's `chdir("/")`
into the lab root. A minimal root under `live-src/live-root/` supplies
`etc/ossec.conf`, ruleset XML and queue/log directories. The shim has no code
on the `OS_CleanMSG` → `decode_fim_event` → `fim_generate_alert` path.

## Input actually delivered

One AF_UNIX datagram to `queue/sockets/queue`, the same local socket
`remoted` writes via `SendMSG(logr.m_queue, tmp_msg, srcmsg, SECURE_MQ)`. Its
bytes are `8:[001] (lab-agent) 127.0.0.1->syscheck:<json>` plus the trailing
NUL used by `OS_SendUnix`. The first byte `8` is `SYSCHECK_MQ` from
`src/headers/mq_op.h:23`; the `8:syscheck:` framing and the `%c:%s->%s`
relay format come from `src/remoted/secure.c:57` and `src/shared/mq_op.c:138`.
The JSON is byte-for-byte the advisory PoC (228-byte exploit with
`hash_sha256` set to `Q`; 406-byte control with full `old_attributes`) used by
frontier's harness (frontier PROVENANCE, `harness.c:96-114`).

This injects at the **analysisd input queue** — the remoted leg (decrypting an
actual 1514 message from an enrolled agent) is not exercised. That leg stays
source-confirmed only (see `reports/wazuh2shell-wire-reach.md`).

## Observed results

| build / input | result |
| --- | --- |
| v4.14.7 ASan, 228-byte exploit | daemon aborted; ASan `heap-buffer-overflow`, `WRITE of size 506`, 0 bytes after a 459-byte region |
| v4.14.7 ASan, 406-byte full-`old_attributes` control | daemon alive through 4 s observation; zero ASan reports |
| v4.14.8 ASan, same 228-byte exploit | daemon alive through 4 s observation; zero ASan reports |
| v4.14.7 plain (no ASan), same exploit | daemon alive — the 69-byte overflow is not a reliable crash without ASan |

Stable v4.14.7 ASan artifact: `lab/frontier/wazuh2shell/asan-v47.<pid>`
(the report is PID-stamped; the authoritative content is the file). Key lines:

```
==3371650==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 506 at 0x51500073024b thread T11
    #2 in fim_generate_alert analysisd/decoders/syscheck.c:1680
    #3 in fim_process_alert analysisd/decoders/syscheck.c:1436
    #4 in decode_fim_event analysisd/decoders/syscheck.c:1288
    #5 in w_decode_syscheck_thread analysisd/analysisd.c:1586
0x... is located 0 bytes after 459-byte region
    #1 in OS_CleanMSG analysisd/cleanevent.c:62
    #2 in w_decode_syscheck_thread analysisd/analysisd.c:1567
```

The fixed-run log is preserved as `lab/frontier/wazuh2shell/live-fixed-exploit.log`.
Build/replay scripts and runtime roots live in the gitignored
`live-src/` and `live-src-748/` trees.

## Boundary

- The live process crashed at the exact upstream sink with the exact
  input-derived allocation size. That upgrades wire-to-sink from a source
  claim to an observed in-daemon memory-corruption event.
- The chosen byte `Q` in a neighbouring object is still only observed in
  frontier's plain harness; the live ASan report proves the overflow, not
  attacker-chosen bytes at a chosen offset in the daemon heap.
- There is no pointer-control or control-flow demonstration, no command
  execution and no benign marker. Rung 5 remains UNKNOWN and is not claimed.
- The 1514 leg is still unobserved live; a real enrolled-agent TLS replay is
  the next experiment, not a conclusion.
- Independent witness replay is required before any of this is ESTABLISHED.
