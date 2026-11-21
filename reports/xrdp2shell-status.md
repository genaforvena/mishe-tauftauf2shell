# Xrdp2Shell status

Admitted under standing approval #6 ~20:3xZ on frontier's #306 handoff. The
site charter (`.mishe-tauftauf/charters/xrdp2shell.md`) and docs/task.md entry
are live; the dedicated two-pane window 19 (inner socket) and restorer
registry entry were already live from frontier. Wake trigger units and the
presentation.json `active` entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`) — never a bare `mishe sync`. The operator re-ran
frontier's extracted harness from clean committed sources at ~20:25Z:
`bash lab/frontier/xrdp2shell/run.sh` prints `ALL CHECKS PASS`, rc 0; digests
`46735a43…` / `2da4d3ea…` match the brief.

## Target

xrdp server-side virtual channel forwarding to chansrv: fixed 8192-byte
`chan_trans` out stream plus client-controlled reassembled DYNVC payload,
GHSA-hh7r-2rmq-q4g4 / CVE-2026-44178 (CWE-122, CVSS 3.1 8.8 High,
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`). Affected `< 0.10.6.1`; fixed in
`0.10.6.1`. Fix commit `43dc9c3b71e5e46733d70ec0239c482ee264cd9f`. Default
posture is post-authentication (PR:L) with a dynamic channel open.

## Mechanism and reproduction

- `xrdp_mm_drdynvc_data_first()` (raw `xrdp_mm.c:2318-2346`, v0.10.6) asks
  `trans_get_out_s(trans, 8192)` (:2330), writes a 28-byte header and then
  `out_uint8a(s, data, bytes)` (:2343); `data()` (:2351-2377) uses a 24-byte
  header; `xrdp_mm_process_channel_data()` (:2763-2809) uses 26. `init_stream`
  keeps the 8192 buffer (`common/parse.h:248-259`) and `out_uint8a` is a plain
  `g_memcpy` unless `USE_DEVEL_STREAMCHECK` is compiled in (`:563-572`, `:82-90`).
- `drdynvc_process_data_first()` (`libxrdp/xrdp_channel.c:425-498`) checks only
  `total_bytes >= 1590 && bytes <= total_bytes` (:472); the DYNVC reassembly
  path (`:547-658`) stages a client-sized `total_length` stream (:586), so a
  multi-chunk message can drive `bytes` far past the 8164-byte threshold.
- The 0.10.6.1 fix allocates the exact `pdu_size` in all three writers and
  rejects `length > 65535`.
- Harness (pinned digests above): rung 1 28+20000 bytes gives
  `oob_writes=11836 first_oob=8192 last_oob=20027`; static 26-byte path gives
  `oob_writes=11834`; rung 2 chosen `ab`/`cd` land at OOB offsets 8228/12028;
  rung 3 ASan `heap-buffer-overflow`, `WRITE of size 20000`, 0 bytes after the
  8192-byte region; rung 4 `de`/`ad` across two messages at OOB offsets
  8228/12024; exact-size and benign controls `oob_writes=0`; 5/5 traces
  byte-identical.

## Real compiled-code confirmation (2026-11-21)

Reproducible sources:
`lab/xrdp2shell-real/{real_drdynvc_driver.c,chosen_bytes_real_path.c,RUNBOOK.md}`.
The frontier harness is a reimplementation; a second harness,
`real_drdynvc_driver.c` (digest `a05ba8ac…`), links against the actual
ASan-instrumented xrdp 0.10.6 `build-asan/libxrdp/.libs/libxrdp.a` and
`libcommon.a` and drives
`xrdp_channel_process()` → `xrdp_channel_process_drdynvc()` → real
`drdynvc_process_data_first()` (`libxrdp/xrdp_channel.c:490`) with a crafted
DYNVC_DATA_FIRST in a CHANNEL_FLAG_FIRST|LAST virtual-channel PDU. The
callback re-creates `xrdp_mm_drdynvc_data_first()`'s body with real
`trans_create` / `trans_get_out_s` / `out_uint8a`.

- Rung 3, real ASan (`vuln.txt`): `WRITE of size 20000` in `memcpy`,
  0 bytes after an 8192-byte region allocated by `trans_create`
  (`common/trans.c:110`); stack `memcpy` → `sink_data_first` →
  `drdynvc_process_data_first` → `xrdp_channel_process_drdynvc` →
  `xrdp_channel_process`. The chosen marker `XRDP2SHELL-CHOSEN-MARKER`
  is in the copied data.
- Exact threshold (`threshold.txt`): payload 8164 rc 0 clean, 8165 ASan OOB;
  28-byte sink header + payload vs the 8192 buffer. 5/5 runs identical
  modulo ASLR (`determinism.txt`).
- Rung 4, chosen bytes in real compiled code (`chosen_bytes.txt`, non-ASan
  build so bytes can be read back): markers `DEADBEEF-CR` and `C0FFEE00-CR`
  land in an adjacent malloc chunk 8208 bytes after the buffer start, at
  offsets 84 and 484; `CHOSEN_BYTES m1=PASS m2=PASS`, `callback_calls=1`,
  `bytes_seen=20000`. A variant that called `free()` after the overflow
  aborted with `malloc(): corrupted top size` (glibc heap corruption).
  No pointer-sized field or control-flow target was controlled.
- Gate controls (`gate.txt`): payload 20000/declared 1000 and 19000 →
  callback_calls=0, clean; 20000/20000 → ASan OOB; 1600/1590 → reject;
  1600/1600 → callback_calls=1, clean. The only gate is
  `total_bytes >= 1590 && bytes <= total_bytes`, trivially satisfied.
- Separate negative finding (do not conflate with the CVE sink): multi-chunk
  FIRST/MIDDLE/LAST reassembly has an OOB read at
  `libxrdp/xrdp_channel.c:630` — `out_uint8a` leaves `self->s->p` at the
  buffer end and nothing resets it before `in_uint8(ls, cmd)`. The single
  FIRST|LAST path avoids it.
- A synthetic fixed control that caps the copy at 8128 is clean; that cap is
  NOT the real 0.10.6.1 fix, only a control on the same sink.
- Loopback reachability: the real ASan `xrdp` was started from
  `lab/build/xrdp2shell-live/run/` bound to 127.0.0.1:3390 only; a Python
  X.224 Connection Request carrying RDP_NEG_REQ drew the COTP reply
  `03 00 00 09 02 f0 80 21 80`. This proves the lab listener is reachable,
  not that a full RDP session reaches the sink.


## Wire-format receive-chain confirmation (2026-11-21)

`lab/xrdp2shell-real/wire_drdynvc_driver.c` goes one layer beyond the direct
driver above. It builds one wire-formatted RDP PDU — TPKT, X.224 DT-TPDU,
MCS SendDataRequest with a two-byte PER length determinant, no security
header (the `is_security_header_present = 0` / TLS posture), then
CHANNEL_PDU_HEADER and DYNVC_DATA_FIRST — and feeds that byte buffer to the
real `xrdp_rdp_recv()`. No function is reimplemented. Observed ASan stack:
`memcpy` → `sink_data_first` → `drdynvc_process_data_first`
(`xrdp_channel.c:490`) → `xrdp_channel_process_drdynvc` (:647) →
`xrdp_channel_process` (:700) → `xrdp_rdp_recv` (`xrdp_rdp.c:512`) → main.

- Payload 8191: ASan `WRITE of size 8191`, 0 bytes after the 8192-byte
  `trans_create` region; the 28-byte sink header makes 8191 the first
  overflowing payload on the wire path. Payload 8164: rc 0, clean,
  `callback_calls=1 bytes_seen=8164`. Payload 8200: ASan `WRITE of size
  8200`, same stack.
- Payload 20000 (the extracted-harness size): `WIRE rv=1 callback_calls=0`,
  rejected before the sink. `xrdp_mcs_recv()` rejects MCS userData above
  16K (`xrdp_mcs.c:230`), so the 20000-byte harness configuration is NOT
  wire-reachable in one PDU. An on-wire exploit needs 8165–~16375 bytes;
  8191/8200 are demonstrated. Multi-chunk reassembly is a separate path
  with its own OOB read (above), not conflated here.
- UBSan reports misaligned `in_uint32_le` on the wire buffer. This is an
  artifact of the `-fsanitize=undefined` ASan build and xrdp's byte-macro
  parser, not part of the finding; ASan's OOB write is the observation.

This exercises the real receive parser from wire bytes, but it is still an
in-process driver: no live socket, no completed logon, no chansrv, and the
`drdynvcs[1].data_first` callback is installed directly rather than by a
negotiated dynamic-channel open. Those remain UNKNOWN.

## Evidence boundary

Rungs 1/2/3 established; rung 4 PASS both in the extracted harness and in
the real compiled xrdp 0.10.6 code, with client-chosen bytes read back at
client-chosen offsets in an adjacent heap chunk. The wire-format driver
above additionally proves that a wire-parsed TPKT/X.224/MCS/channel/DYNVC
PDU reaches the same sink through the real `xrdp_rdp_recv()` chain and
overflows at 8191 bytes; the 20000-byte harness size is rejected by the MCS
16K limit on the wire. Both drivers are in-process. A completed RDP logon,
a chansrv-created dynamic channel, a live-session allocator layout and a
full socket-level network trace remain UNKNOWN: xrdp needs PAM plus a
session, the PyRDP checkout in the plant supplies wire codecs but no client
(and no client-side NLA), and creating a host account is out of lab scope.
The post-auth (PR:L) precondition is intrinsic to the CVE, not a lab
artifact. No off-loopback probe. Author report is not independent
acceptance; witness replay of `ab93fcc` is still owed.

Brief: `reports/frontier-xrdp2shell.md`; harness:
`lab/frontier/xrdp2shell/{xrdp_overflow.c,run.sh}`. Witness replay requested;
author report is not acceptance.
