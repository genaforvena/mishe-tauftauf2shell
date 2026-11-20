# Frontier brief — GStreamer rtpL16depay high-channel-count heap overflow (Gst2Shell)

**Status: NEW FIND, handed off 2026-11-20 ~20:4xZ under standing approval #6.
Rungs 1/2/3 established in an extracted, source-bound harness; rung 4 NOT
DEMONSTRATED because the overflow writes only the constant
`GST_AUDIO_CHANNEL_POSITION_NONE` (0), not sender-chosen bytes. Live GStreamer
pipeline, real SDP/RTSP negotiation, real heap layout and actual code
execution are UNKNOWN. Dedicated two-pane window `gst2shell`, seed wall and
registry entry created by frontier; operator admission, charter and wake units
follow the standing path.**

## Verified ground truth (claim sources + this lab, 2026-11-20)

- **Advisory**: GHSA-62fg-53h6-6f68 / CVE-2026-111183, "GStreamer rtpL16depay
  Heap-based Buffer Overflow Remote Code Execution", ZDI-CAN-31143 /
  ZDI-26-775 (published 2026-10-15, NVD/GHSA 2026-10-21). Critical **9.8**,
  `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-122. Claim: lack of
  length validation before copying user-supplied data into a heap buffer;
  code execution in the current process is claimed, not demonstrated.
- **Fix commit**: `80c184b4c5ee8ba28b2540ba58f40b8d44b61622`, "rtpL8depay,
  rtpL16depay, rtpL24depay: fix out of bounds write for high channel count"
  (2026-10-08). Parent / vulnerable commit
  `0b70c356345335dacc0acdc45d07a8a33bdf5eab`.
- **Claim sources read (external claims, not lab findings)**: GHSA page, ZDI
  advisory ZDI-26-775, the fix commit `.diff`, GitLab commit API metadata, and
  raw source of `gstrtpL16depay.c`, `gstrtpchannels.c`, `gstrtpchannels.h` at
  the vulnerable parent. Read-only provisioning only; **no external probe, no
  traffic to any non-loopback address**.
- **Deployment condition (claim)**: an RTP/RTSP pipeline that accepts caps
  from the far end (e.g. an SDP `fmtp` line supplying `encoding-params`).
  Network-reachable, pre-auth by the CVSS vector; "interaction with this
  library is required" per ZDI, so the concrete reaching path is UNKNOWN here.
- **Ranking**: tractable. The defect is a pure length-check omission in one
  small C function with a 3-line fix; no heap grooming, protocol state or
  credential is needed for rungs 1–3. Ranked above Asterisk
  CVE-2026-57197 (admin must supply the file) and the screened-out lanes on
  the wall.

## Source-bound mechanism (read from the fix, not inferred)

Raw-file lines are from the exact provisioned vulnerable parent; digests of
the three fetched files are in `lab/frontier/gst2shell/src/`.

1. `gstrtpL16depay.c:181-189`: `channels` is parsed from the caps field
   `encoding-params`, then `channels`, then defaults to 1. No upper bound.
2. `gstrtpL16depay.c:193-198`: `info = &rtpL16depay->info` (an element-private,
   heap-embedded `GstAudioInfo`); `info->channels = channels`.
3. `gstrtpL16depay.c:201-216`: `order = gst_rtp_channels_get_by_order
   (channels, channel_order)`. The table at `gstrtpchannels.c:151-176` has
   orders only for 1–8 channels, and `:242-244` rejects any other count, so
   for `channels > 8` the `else` branch always runs
   `gst_rtp_channels_create_default (channels, info->position)`.
4. `gstrtpchannels.c:301-310`: the vulnerable function loops
   `for (i = 0; i < channels; i++) posn[i] = GST_AUDIO_CHANNEL_POSITION_NONE;`
   with no bound on `posn`. `GstAudioInfo.position` is a fixed 64-entry array,
   so `channels = 1000` writes 936 elements (3744 bytes) past it.
5. The fix adds a `gsize n_posn` parameter, passes
   `G_N_ELEMENTS (info->position)` at each of the three call sites, and clamps
   with `channels = MIN (channels, n_posn)` before the loop.

**Value control matters**: every OOB element is the compile-time constant
`NONE` (0). The attacker controls the *count* and hence which offsets are
reached, but not the value written. This is the reason for the honest rung-4
grade below and it is not a lab-layout artifact.

## Local harness evidence

Files: `lab/frontier/gst2shell/{rtp_channels_overflow.c,run.sh}`. Digests at
the named tag: `3d2b8e06da30fca138d120ac1445debb4b45815c4fd1eacd6ffe4eed39373525`
(C) and `7dde5da764767183763328f8ffe7be759b7e5cf907726353e2c47058d2437567`
(run.sh). `bash lab/frontier/gst2shell/run.sh` printed **ALL CHECKS PASS,
rc 0**:

- **Rung 1 (reproducible trigger)**: `channels=1000 position_capacity=64
  oob_writes=936 first_oob=256 last_oob=3999`, counted `3744` zeroed OOB bytes;
  `verdict=TRIGGER`. The parse path reads `encoding-params=(string)1000` from
  a synthesized caps string using the same parse order as
  `gst_rtp_L16_depay_parse_int`.
- **Rung 2 (observed state failure)**: two stamps at byte offsets 768 and
  1792; `channels=200` clobbers only the first (`oob_bytes=544`),
  `channels=1000` clobbers both (`oob_bytes=3744`) —
  `verdict=LENGTH_CONTROL_OBSERVED`. Offsets are chosen by the caps value.
- **Rung 3 (ASan-confirmed corruption)**: gcc 13.3.0,
  `-fsanitize=address`, exact 256-byte allocation:
  `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 4`,
  `0 bytes after 256-byte region [..,..)`, stack
  `vuln_create_default ...:70 <- main ...:218`, rc 1.
- **Rung 4 (honest negative)**: a `deadbeeftest` stamp at OOB offset 1024
  reads back `000000000000000000000000`; `chosen_bytes_written=0`,
  `written_value_constant=NONE(0)`, `verdict=NOT_DEMONSTRATED`. No chosen
  value, chosen pointer or marker execution is possible through this sink.
- **Fixed control**: the `MIN`-clamped function with `n_posn=64` and the same
  `channels=1000` gives `oob_writes=0 verdict=PASS`.
- **Determinism**: two independent 5-run groups hash to the same
  `sha256=c96ad6f616edf4765240bf0bb936ae3e30ca2c11f13b1edef70d46a16119f056`.

### Grade

Rungs **1/2/3 ESTABLISHED** in the extracted harness; rung **4 NOT
DEMONSTRATED** (constant-value write). Real GStreamer process, SDP/RTSP
negotiation path, GStreamer's actual allocator/adjacent-object layout, side
effects on real neighbours, and any pre-auth reachability are **UNKNOWN**.
This is a claim to be replayed by the witness, not acceptance.

## Cheapest local experiment to move it up a rung

1. Build gst-plugins-good at the parent commit with ASan and drive
   `rtpL16depay` directly through `gst_pad_set_caps` on a synthesized
   `application/x-rtp` caps with `encoding-params=(string)1000`; confirm the
   real `info->position[64]` overflow and see which genuine neighbour object
   is clobbered. This converts the extracted struct into the live one and
   resolves the allocator-layout UNKNOWN.
2. For rung 4, look for a neighbouring heap field whose *zeroing* is useful
   (e.g. a length or free-function pointer) — that is control of effect, not
   of bytes, and must be labelled as such. Do not claim chosen-byte control
   unless a different sink is found.

## Handoff state

Two artifact rule satisfied: this brief is committed and a live two-pane
window named `gst2shell` (top: seed wall / brief, bottom: chat and wake log)
exists on the inner tmux socket, with a `kind:target` entry in
`operator/window-registry.json` and seed wall
`.mishe-tauftauf/walls/gst2shell.md`. Witness replay request and operator
handoff are filed on the tape. Owed by operator/person: site charter,
docs/task.md entry and wake trigger units (only via the person's full-flag
sync, never a bare `mishe sync`). Frontier does not duplicate this lane.

## What would change my mind

A primary source showing caps `channels` is clamped to <=64 before the write;
a replay losing ASan or the fixed control; proof that a real pipeline cannot
deliver attacker-chosen `encoding-params`; or a discovery that the neighbouring
object makes a zero-write equivalent to chosen-byte control (which would need
a fresh, honest rung-4 claim, not a relabel of this one).
