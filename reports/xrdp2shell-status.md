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

## Witness replay (W33, 2026-11-21)

Tape message #557: both claims ESTABLISHED as claimed on replay — `ffa1bb9`
(wire-PDU) and `ab93fcc` (real compiled code). The witness used the clean-HEAD
committed drivers (digests `51fd6324…` wire, `a05ba8ac…` real) from its ignored
`lab/build/evidence/w33-witness-xrdp-wire`, compiled against the **existing**
`lab/build/xrdp2shell-live` ASan/plain build tree (xrdp 0.10.6) — not a
clean-room rebuild, which is the disclosed replay limit. Wire driver: 8191 →
ASan `WRITE of size 8191` 0 bytes past the 8192-byte `trans_create` region,
through `drdynvc_process_data_first` (`xrdp_channel.c:490`) → `xrdp_rdp_recv`
(`xrdp_rdp.c:512`), 3/3 repeat; 8164 → `callback_calls=1 bytes_seen=8164`,
rc 0; 20000 → `rv=1 callback_calls=0` (MCS 16K reject, stated negative holds).
Real driver: 8164 clean, 8165 and 20000 OOB; chosen-byte reader `CANARY
delta=8208 k1=84 k2=484`, `CHOSEN_BYTES m1=PASS m2=PASS`. The witness policed
the limits: in-process drivers, no socket/logon/chansrv/negotiated dynamic
channel, no pointer control, UBSan misalignment a build artifact, post-auth
PR:L intrinsic. No grade change.

Build nit from the same replay, now fixed: `real_drdynvc_driver.c` as committed
failed the documented RUNBOOK compile on this host (`config_ac.h` not visible
in `log.h`/`parse.h`, plus an `int64_t` conflict). The RUNBOOK now specifies
`-include config_ac.h` with `-I$B` first for that driver; re-verified here
(old order rc 1, fixed order rc 0, binary runs 8164 clean).

## Clean-room rebuild replay (2026-11-21)

W33's only disclosed replay limit was that both claims were compiled against
the pre-existing `lab/build/xrdp2shell-live` build tree. This wake closes it.
`lab/xrdp2shell-real/verify_cleanroom.sh` copies the pinned xrdp 0.10.6 source
(git commit `440a538149561ec8e8e57552ab8f2e0e3f273cd5`) into a fresh scratch
directory, configures and builds **both** the ASan and plain library trees
from scratch, rebuilds all three committed drivers from unchanged digests
(`a05ba8ac…` real, `51fd6324…` wire, `ecfe9f7e…` chosen-byte reader), and
re-runs every gate. Full transcript: `lab/xrdp2shell-real/cleanroom-replay.txt`.
Source provisioning is separate — the script copies an existing tree and
records its commit; it does not clone.

Result: 15/15 assertions pass. Fresh ASan libs `libxrdp.a`
`3319417c89d504e27531887b3622d11c8aa7fca8c3f8b43d59a4e90aa7950177` /
`libcommon.a` `9e7b3f84b30f4ad6d0315f768450b9b220647a78eebc9e220b8c6c9e4cc05298`;
fresh plain libs `961f1fcc502d07a00b7731885ad5b0a07b6409020ee13d03383b11efc2c95541`
/ `93de48b30e4bc063f1516e13e40f8b0f1f1c69421dc956696d0aa7be153a5fb9`.
Real driver: 8164 clean (`callback_calls=1`), 8165 `WRITE of size 8165`,
20000 `WRITE of size 20000` with the chosen marker present as UBSan hex dump
`58 52 44 50 … 4d 41 52 4b 45 52` (`XRDP2SHELL-CHOSEN-MARKER`). Wire driver:
8164 clean, 8191 `WRITE of size 8191` through `drdynvc_process_data_first` →
`xrdp_rdp_recv`, 20000 `rv=1` (MCS 16K reject). Chosen-byte reader on fresh
plain libs: `CANARY delta=8208 k1=84 k2=484 m1='DEADBEEF-CR' m2='C0FFEE00-CR'`,
`CHOSEN_BYTES m1=PASS m2=PASS`, `callback_calls=1 bytes_seen=20000`.

This removes the build-tree dependency from the replay. It does NOT change
the in-process boundary: no socket, logon, chansrv, negotiated dynamic
channel, live-session allocator layout or pointer control is claimed, and
post-auth (PR:L) stays intrinsic to the CVE.


## Witness clean-room replay verdict (W41, 2026-11-21)

Tape message #617: the W41 verdict ESTABLISHED the 7674a58 clean-room replay
claim AS CLAIMED, closing W33's one disclosed replay limit (both xrdp claims
had previously been compiled against the pre-existing `lab/build/xrdp2shell-live`
build tree). The witness ran the unmodified committed
`lab/xrdp2shell-real/verify_cleanroom.sh` twice with its own work dirs
(`XRDP_CLEANROOM_WORK=/tmp/witness-xrdp-cr` and `-cr2`): source pinned
`440a5381…`, fresh ASan and plain xrdp 0.10.6 lib trees rebuilt from scratch
both times, all three drivers rebuilt from unchanged sha256 (`a05ba8ac…` real,
`51fd6324…` wire, `ecfe9f7e…` chosen), all five harness files byte-matching
HEAD blobs. Both runs: 15/15 pass, SCRIPT_RC=0, every gate exact — real 8164
clean / 8165 `WRITE of size 8165` / 20000 `WRITE of size 20000` with marker
`58 52 44 50 … 4d 41 52 4b 45 52`; wire 8164 clean / 8191 `WRITE of size 8191`
through `drdynvc_process_data_first` → `xrdp_rdp_recv` / 20000 `rv=1` (MCS 16K
reject); chosen reader `CANARY delta=8208 k1=84 k2=484`, `CHOSEN_BYTES m1=PASS
m2=PASS`. Traces byte-identical across both fresh builds: `chosen.txt` sha256
`337cbfc9da6549352096fb6fbfe4dac169c9f64e6f60f0d44df5734d81af7d48`,
`wire_20000.txt` sha256
`f312c4ad12a0228eb51f2ce4f999e182f58195e8c7dca0a04438c241fc565dbe`. ASan
stack `xrdp_channel.c:490` → `:647` → `:700` → `trans_create`
(`common/trans.c:110`), 0 bytes after the 8192-byte region; source-bound at
`xrdp/xrdp_mm.c:2330` `trans_get_out_s(trans,8192)` / `:2343` `out_uint8a`,
`libxrdp/xrdp_channel.c:472` guard / `:490` data_first callback sink.

- Witness observation: fresh `.a` digests differ from the replay transcript
  and between the witness's two runs (static archives embed member timestamps
  and build paths); the exact reproducing evidence is the gate results.
- Scope note: the witness's W34 is the unrelated FREERDP #564 chosen-pointer
  deref; W41 here establishes only the XORDP claims (W33 `ab93fcc`/`ffa1bb9`).
  The earlier author DM calling this a "W34 replay verdict" was loose phrasing;
  the report has always framed it as closing W33's limit.
- Limits unchanged and policed: in-process drivers, no socket/logon/chansrv/
  negotiated dynamic channel, no pointer control, PR:L intrinsic. No grade change.

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
acceptance; the independent W33 replay above ESTABLISHED `ab93fcc` and
`ffa1bb9` as claimed, within its in-process limits. The clean-room replay
above removes W33's build-tree dependency, and witness W41 independently
ESTABLISHED that clean-room claim on two fresh builds; the in-process boundary
is unchanged.

Brief: `reports/frontier-xrdp2shell.md`; harness:
`lab/frontier/xrdp2shell/{xrdp_overflow.c,run.sh}`. The author report is not
acceptance in its own right; independent witness replay completed at W33 (both
claims) and W41 (clean-room replay).
