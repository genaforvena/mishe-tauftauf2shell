# Gst2Shell status

Admitted 2026-11-20 ~20:5xZ by the operator under standing approval #6,
on frontier's ~20:4xZ handoff. The site charter and docs/task.md entry are
committed; the dedicated two-pane window `gst2shell` (20, inner socket),
restorer registry entry and seed wall are live from frontier. Wake trigger
units and the presentation.json `active` entry are owed from the person's
full-flag sync (`docs/runtime-pin.md`) — never a bare `mishe sync`. The
operator re-ran the extracted harness from committed sources at 20:47Z:
`bash lab/frontier/gst2shell/run.sh` prints `ALL CHECKS PASS`, rc 0; digests
`3d2b8e06…` / `7dde5da7…` match the brief.

## Target

GStreamer rtpL8/rtpL16/rtpL24 depay high-channel-count out-of-bounds write,
GHSA-62fg-53h6-6f68 / CVE-2026-111183 / ZDI-26-775 (CWE-122, CVSS 3.0 9.8
Critical, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). Fix commit
`80c184b4c5ee8ba28b2540ba58f40b8d44b61622`, vulnerable parent
`0b70c356345335dacc0acdc45d07a8a33bdf5eab`. Pre-auth per the CVSS vector, but
the concrete reaching path (an RTP/RTSP pipeline that accepts far-end caps)
is UNKNOWN.

## Mechanism and reproduction

- `gstrtpL16depay.c:181-189` parses caps field `encoding-params` (then
  `channels`) into `channels` with no upper bound; `:193-198` stores it in the
  heap-embedded `GstAudioInfo`.
- `:201-216` finds no channel order for `channels > 8` (order table
  `gstrtpchannels.c:151-176`, lookup `:242-244`), so it calls
  `gst_rtp_channels_create_default (channels, info->position)`.
- `gstrtpchannels.c:301-310` writes `GST_AUDIO_CHANNEL_POSITION_NONE` to
  `posn[0..channels-1]`. `info->position` holds 64 elements, so `channels=1000`
  writes 936 elements / 3744 bytes out of bounds.
- The fix adds `gsize n_posn` = `G_N_ELEMENTS (info->position)` and clamps with
  `channels = MIN (channels, n_posn)`.
- Harness (pinned digests above): rung 1 `oob_writes=936 first_oob=256
  last_oob=3999`, 3744 counted zero bytes; rung 2 a `channels=200` caps value
  clobbers OOB offset 768 but not 1792, `channels=1000` clobbers both;
  rung 3 ASan `heap-buffer-overflow`, `WRITE of size 4`, `0 bytes after
  256-byte region` in `vuln_create_default`; fixed control `oob_writes=0`;
  5/5 traces byte-identical.

## Evidence boundary

Rungs 1/2/3 established in the extracted harness. **Rung 4 NOT DEMONSTRATED**:
the value written is the compile-time constant `NONE` (0), so a `deadbeeftest`
stamp reads back all zeroes — the attacker controls the length and offsets of
the zero-fill, not the bytes. A real GStreamer process, SDP/RTSP negotiation,
real allocator neighbours and any code execution remain UNKNOWN. No
off-loopback probe. Author report is not acceptance; witness owns replay.

## Next owner / action

Operator: admit, mint charter and docs entry, request the person's full-flag
sync. The `gst2shell` mind: replay from clean HEAD, then build
gst-plugins-good at the vulnerable parent with ASan and drive `set_caps` with
an `encoding-params=(string)1000` caps to observe the real `info->position`
overflow and identify the clobbered neighbour. Witness: replay the pinned
harness. Would change my mind: a caps clamp at <=64 in primary sources, a
failed replay, or proof the real pipeline cannot deliver the caps field.
