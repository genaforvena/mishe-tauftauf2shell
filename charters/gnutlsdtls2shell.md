# gnutlsdtls2shell — target mind

Durable area: the GnuTLS DTLS handshake-fragment reassembly heap overwrite
(CVE-2026-33846 / GNUTLS-SA-2026-04-29-1) and any reachable refinement of it.

Staged by frontier W286 from pinned 3.8.12 (vulnerable) and 3.8.13 (fixed)
tarballs, fix commit `65ab33fa54e34fba69d793735b7df3d383d1ff78`, and the
loopback-only DTLS server reproducer derived from upstream issue #1816.
`merge_handshake_packet()` matches fragments by handshake type alone; a first
fragment with `message_length=50` creates a 2048-byte reassembly buffer and
later fragments claiming `message_length=3000` are merged past its end. GCC ASan
on the shipped library API reports `WRITE of size 1475` at
`lib/buffers.c:1035`, zero bytes after the 2048-byte region. The fixed build
rejects the same fragments with -9 (decode error); a consistent-length safe
input on the vulnerable build gives no ASan report. `run-all.sh` PASS=12
FAIL=0.

Brief `reports/frontier-gnutlsdtls2shell.md`, status
`reports/gnutlsdtls2shell-status.md`, harness
`lab/frontier/gnutlsdtls2shell/run-all.sh` (PROVENANCE.md has pins, traces and
negatives). Grade at handoff: rung 3 ASan-confirmed attacker-controlled heap
overwrite via the shipped library API; rung 4 NOT CLAIMED (chosen bytes in ASan
poison, no adjacent live object, pointer, command buffer or socket shown to
change in a plain build); rung 5 NOT CLAIMED.

Cheapest rung-moving experiment: build a plain (non-ASan) loopback DTLS consumer
with a deliberate neighbouring allocation, reproduce the same fragment sequence
and observe whether attacker-chosen bytes land in a live object at a chosen
offset, then attempt a benign marker. Keep the consistent-length safe input,
the 3.8.13 fixed control and the 2048/2975-byte arithmetic. Preserve the
nettle-3.10 and included-unistring provisioning requirements. Do not infer RCE
from the advisory's network CVSS or from in-process markers.
