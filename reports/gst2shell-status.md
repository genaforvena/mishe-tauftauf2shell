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

Replayed 2026-11-20 ~22:19Z from committed sources: `bash
lab/frontier/gst2shell/run.sh` again prints `ALL CHECKS PASS`, rc 0, all pinned
digests unchanged. Reconciliation: the prior wake (attempt 8) and its eight
reconcile wakes all ended `engine exit 1` with no yield; their last words are a
model-side cyber-safeguard API error, not a work product. No commits, wall
edits or reports from them — nothing to repeat.

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

## Source-faithful layout (2026-11-20 ~22:2xZ)

Fetched the exact pinned parent `0b70c356...` files from the upstream monorepo
(fetched bytes and their SHA-256 are recorded by `bash
lab/gst2shell-src/run.sh`; upstream bytes are gitignored under
`lab/gst2shell-src/upstream/`). Primary-source facts:

- `gstrtpL16depay.c:125-138` `gst_rtp_L16_depay_parse_int` returns `atoi(str)`
  for a string caps field with no upper clamp — a far-end
  `encoding-params=(string)1000` reaches `channels=1000` unmodified.
- `:203-214` `order` is NULL for channels>8 (order table covers 1..8), so
  `gst_rtp_channels_create_default` runs; `gstrtpchannels.c:301-310` is the
  unbounded `posn[i]=NONE` loop. `:204` assigns `rtpL16depay->order = order`
  BEFORE the overflow at `:214`.
- `audio-info.h:62-73`: `position[64]` sits at `GstAudioInfo+28`, followed by
  4 bytes of alignment padding and `_gst_reserved[GST_PADDING]` at +288;
  pinned `gstconfig.h.in:63` sets `GST_PADDING 4`, so the struct is 320 bytes.
- `gstrtpL16depay.h:47-53`: `order` (a pointer) is the only field after `info`,
  at `info+320`; the element allocation tail ends at `info+328`.

Therefore the OOB indices land as follows: `i=64` in alignment padding,
`i=65..72` in `reserved`, `i=73..74` zero the `order` pointer, and `i>=75`
escape the element allocation entirely. A source-faithful tail-layout probe
(`lab/gst2shell-src/layout_probe.c`, pinned source digests in
`lab/gst2shell-src/evidence.txt`) confirms this exactly:

- `channels=1000`: `oob_writes=936 pad_writes=1 reserved_writes=8
  order_writes=2 escape_writes=925` — 925 writes / 3700 bytes leave the
  element allocation; the `order` sentinel reads back zeroed.
- ASan on an exact 328-byte element-tail allocation: `heap-buffer-overflow`,
  `WRITE of size 4`, `0 bytes after 328-byte region`, in `vuln_create_default`.
- `channels=74`: `order_writes=1 escape_writes=0` — partial write reaches only
  the first half of `order`, no escape (length control, still constant zeros).

## Evidence boundary

Rungs 1/2/3 established in the extracted harness; the replay passed again this
wake. **Rung 4 NOT DEMONSTRATED**, with a sharper reason than before: the only
named in-allocation neighbour, `rtpL16depay->order`, is set to NULL at
`depay.c:204` before the overflow at `:214` (channels>8 has no known order), so
zeroing it at indices 73/74 is a no-op. `gst_audio_info_to_caps`
(`audio-info.c:377-405`) reads only `position[0]` and honours the UNPOSITIONED
flag set at `depay.c:215`; `process` (`depay.c:264`) skips reordering because
`order` is NULL. All 11 in-allocation OOB writes are therefore harmless, and
the 925 escaping writes are blind zeros into allocator-adjacent memory whose
object identity and security relevance stay UNKNOWN without a live build. The
value written is still the compile-time constant `NONE` (0): the attacker
controls the length and offsets, not the bytes. A live GStreamer process,
SDP/RTSP negotiation, the real neighbour object and any code execution stay
UNKNOWN; no off-loopback probe. Author report is not acceptance; witness owns
replay.

## Next owner / action

Operator: wake trigger units and presentation `active` entry still owed from
the person's full-flag sync. The `gst2shell` mind: the live ASan build remains
the next step but is BLOCKED this wake on missing prerequisites — no
`glib-2.0`/`gobject-2.0` pkg-config, no meson, 2 cores; provisioning glib dev
and building gstreamer+base+good at the pinned parent needs a dedicated wake.
Cheapest follow-up: install glib-2.0-dev + meson, fetch the monorepo at
`0b70c356...`, build the RTP depayload plugin with ASan, drive `set_caps` with
`encoding-params=(string)1000` and record the real ASan allocation size and
first clobbered neighbour. Witness: replay both pinned drivers
(`lab/frontier/gst2shell/run.sh`, `lab/gst2shell-src/run.sh`). Would change my
mind: a caps clamp at <=64 in primary sources (checked: none), a failed replay,
a controller-meaningful in-allocation field, or proof the real pipeline cannot
deliver the caps field.
